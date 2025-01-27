# Some python interpreters run in environments with restrictive ACLs (no Users/* execute) on bundled DLLs. 
# The Microsoft Store version of python is the prime example of this. 
# 
# Remote execution of python is still possible by creating a minimal set of the dependencies outside of the restricted directory. 
#
# This can be very helpful when operating PFW in environments with restrive GPOs / AppLocker.


import ctypes
import glob
import os
import shutil
import tempfile
import time

import windows
from windows.generated_def.ntstatus import STATUS_THREAD_IS_TERMINATING
from windows.generated_def.windef import CREATE_SUSPENDED
from windows.generated_def.winstructs import PROCESS_INFORMATION, STARTUPINFOW
from windows.injection import RemotePythonError, \
    find_python_dll_to_inject, get_dll_name_from_python_version, inject_python_command, load_dll_in_remote_process, retrieve_last_exception_data


CACHE_DIR = os.path.join(tempfile.gettempdir(), 'pfw_dllcache')
INTERPRETER_DIR = os.path.dirname(find_python_dll_to_inject(64)) # Tailor bitness to your needs


def mspython_acl_workaround(target, pydll_path):
    """
    Works around mspython ACL restrictions on mspython interpreters
    by copying the critical DLLs to a TEMP dir and orienting the interpreter 
    against that TEMP dir. 
    """

    if not os.path.exists(CACHE_DIR):
        os.mkdir(CACHE_DIR)

    for dll in [os.path.join(INTERPRETER_DIR, 'vcruntime140.dll'), pydll_path]:
        cache_dll_path = os.path.join(CACHE_DIR, os.path.basename(dll))
        try:
            # Creates a copy of the DLL without bringing over restrictive ACLs
            shutil.copyfile(dll, cache_dll_path)
        except:
            # If its not writeable good chance these DLLs are just already loaded somewhere
            pass
        # Preloading python DLL and vcruntime so they don't get loaded from the path tree with restrictive ACLs
        load_dll_in_remote_process(target, cache_dll_path)

    for dll in glob.glob(os.path.join(INTERPRETER_DIR, 'dlls', '*')):
        cache_dll_path = os.path.join(CACHE_DIR, os.path.basename(dll))
        try:
            # Dynamic lib DLLs with restrictive ACLs copied to unrestricted parent
            shutil.copyfile(dll, cache_dll_path)
        except:
            pass


# Adapted from windows\winobject\process.py
def execute_python_code(process, code):
    py_dll_name = get_dll_name_from_python_version()
    pydll_path = find_python_dll_to_inject(process.bitness)
    
    mspython_acl_workaround(process, pydll_path)
    shellcode, pythoncode = inject_python_command(process, code, py_dll_name)
    t = process.create_thread(shellcode, pythoncode)
    return t


def safe_execute_python(process, code):
    t = execute_python_code(process, code)
    t.wait() # Wait termination of the thread
    if t.exit_code == 0:
        return True
    if t.exit_code == STATUS_THREAD_IS_TERMINATING or process.is_exit:
        raise WindowsError("{0} died during execution of python command".format(process))
    if t.exit_code != 0xffffffff:
        raise ValueError("Unknown exit code {0}".format(hex(t.exit_code)))
    data = retrieve_last_exception_data(process)
    raise RemotePythonError(data)


print("Starting target")
proc_info = PROCESS_INFORMATION()
StartupInfo = STARTUPINFOW()
StartupInfo.cb = ctypes.sizeof(StartupInfo)
windows.winproxy.CreateProcessW(
    r"C:\Windows\system32\winver.exe", 
    dwCreationFlags=CREATE_SUSPENDED, 
    # Point PYTHONHOME to the interpreter dir so non-DLL libs can load
    # Point PYTHONPATH to the newly created cache directory so DLL libs are loaded from there
    lpEnvironment=('\0'.join('{}={}'.format(e, v) for e, v in os.environ.items()) + \
                   '\0PYTHONHOME={}\0PYTHONPATH={}\0\0'.format(INTERPRETER_DIR, CACHE_DIR)).encode(),
    lpProcessInformation=ctypes.byref(proc_info), 
    lpStartupInfo=ctypes.byref(StartupInfo))
process = windows.winobject.process.WinProcess(pid=proc_info.dwProcessId, handle=proc_info.hProcess)

print("Executing python code!")
safe_execute_python(process, """
import windows
windows.utils.create_console()
print('hello from inside the suspended process!', flush=True)
""")

process.threads[0].resume()

print("Executing more python code!")
safe_execute_python(process, """
print('hello from inside the resumed process!', flush=True)
""")

process.wait()