import struct
import ctypes
import os
import sys

import windows
import windows.utils as utils
import windows.generated_def as gdef

from .native_exec import simple_x86 as x86
from .native_exec import simple_x64 as x64

from windows.generated_def import STATUS_THREAD_IS_TERMINATING
from windows.native_exec.nativeutils import GetProcAddress64, GetProcAddress32
from windows.dbgprint import dbgprint


class InjectionFailedError(WindowsError):
    pass

def get_kernel32_dll_name():
    # Our injected shellcode search for 'kernel32.dll' with a strcmp
    # The BaseDllName of k32 might be 'KERNEL32.DLL' or 'kernel32.dll' on different system32
    # We base the name on our own loaded kernel32
    k32 = [m for m in windows.current_process.peb.modules if m.name == "kernel32.dll"]
    assert len(k32) == 1
    k32name = k32[0].BaseDllName.str
    return (k32name + "\x00").encode("utf-16-le")

def perform_manual_getproc_loadlib_32(target, dll_name):
    dll = get_kernel32_dll_name()
    api = "LoadLibraryA\x00"
    dll_to_load = dll_name + "\x00"

    RemoteManualLoadLibray = x86.MultipleInstr()
    code = RemoteManualLoadLibray
    code += x86.Mov("ECX", x86.mem("[ESP + 4]"))
    code += x86.Push(x86.mem("[ECX + 4]"))
    code += x86.Push(x86.mem("[ECX]"))
    code += x86.Call(":FUNC_GETPROCADDRESS32")
    code += x86.Push(x86.mem("[ECX + 8]"))
    code += x86.Call("EAX") # LoadLibrary
    code += x86.Pop("ECX")
    code += x86.Pop("ECX")
    code += x86.Ret()

    RemoteManualLoadLibray += GetProcAddress32

    with target.allocated_memory(0x1000) as addr:
        addr2 = addr + len(dll)
        addr3 = addr2 + len(api)
        addr4 = addr3 + len(dll_to_load)

        target.write_memory(addr, dll)
        target.write_memory(addr2, api)
        target.write_memory(addr3, dll_to_load)
        target.write_qword(addr4, addr)
        target.write_qword(addr4 + 4, addr2)
        target.write_qword(addr4 + 0x8, addr3)

        t = target.execute(RemoteManualLoadLibray.get_code(), addr4)
        t.wait()
        if not t.exit_code:
            raise InjectionFailedError("Injection of <{0}> failed".format(dll_name))
    return True

def perform_manual_getproc_loadlib_64(target, dll_name):
    dll = get_kernel32_dll_name()
    api = "LoadLibraryA\x00"
    dll_to_load = dll_name + "\x00"

    RemoteManualLoadLibray = x64.MultipleInstr()
    code = RemoteManualLoadLibray
    code += x64.Mov("R15", "RCX")
    code += x64.Mov("RCX", x64.mem("[R15 + 0]"))
    code += x64.Mov("RDX", x64.mem("[R15 + 8]"))
    code += x64.Call(":FUNC_GETPROCADDRESS64")
    code += x64.Mov("RCX", x64.mem("[R15 + 0x10]"))
    code += x64.Push("RCX")
    code += x64.Push("RCX")
    code += x64.Push("RCX")
    code += x64.Call("RAX") # LoadLibrary
    code += x64.Pop("RCX")
    code += x64.Pop("RCX")
    code += x64.Pop("RCX")
    code += x64.Ret()

    RemoteManualLoadLibray += GetProcAddress64

    with target.allocated_memory(0x1000) as addr:
        addr2 = addr + len(dll)
        addr3 = addr2 + len(api)
        addr4 = addr3 + len(dll_to_load)

        target.write_memory(addr, dll)
        target.write_memory(addr2, api)
        target.write_memory(addr3, dll_to_load)
        target.write_qword(addr4, addr)
        target.write_qword(addr4 + 8, addr2)
        target.write_qword(addr4 + 0x10, addr3)

        t = target.execute(RemoteManualLoadLibray.get_code(), addr4)
        t.wait()
        if not t.exit_code:
            raise InjectionFailedError("Injection of <{0}> failed".format(dll_name))
    return True

def generate_simple_LoadLibraryW_64(load_libraryW, remote_store):
    code = RemoteLoadLibrayStub = x64.MultipleInstr()
    code += x64.Mov("RAX", load_libraryW)
    code += (x64.Push("RDI") * 5) # Prepare stack
    code += x64.Call("RAX")
    code += (x64.Pop("RDI") * 5) # Clean stack
    code += x64.Mov(x64.deref(remote_store), "RAX")
    code += x64.Ret()
    return RemoteLoadLibrayStub.get_code()



def perform_manual_getproc_loadlib(target, *args, **kwargs):
    if target.bitness == 32:
        return perform_manual_getproc_loadlib_32(target, *args, **kwargs)
    return perform_manual_getproc_loadlib_64(target, *args, **kwargs)


def load_dll_in_remote_process(target, dll_path):
    rpeb = target.peb
    if rpeb.Ldr:
        # LDR est parcourable, ca va etre deja plus simple..
        modules = rpeb.modules
        if any(mod.fullname.lower() == dll_path.lower() for mod in modules):
            # DLL already loaded
            dbgprint("DLL already present in target", "DLLINJECT")
            return False
        k32 = [mod for mod in modules if mod.name.lower() == "kernel32.dll"]
        if k32:
            # We have kernel32 \o/
            k32 = k32[0]
            try:
                load_libraryW = k32.pe.exports["LoadLibraryW"]
            except KeyError:
                raise ValueError("Kernel32 have no export <LoadLibraryA> (wtf)")

            with target.allocated_memory(0x1000) as addr:
                if target.bitness == 32:
                    target.write_memory(addr, (dll_path + "\x00").encode('utf-16le'))
                    t = target.create_thread(load_libraryW, addr)
                    t.wait()
                    module_baseaddr = t.exit_code
                else:
                    # For 64b target we need a special stub as the return value of
                    # load_libraryW does not fit in t.exit_code (DWORD)
                    retval_addr = addr
                    target.write_ptr(retval_addr, 0)
                    addr += ctypes.sizeof(ctypes.c_ulonglong)
                    full_dll_name = (dll_path + "\x00").encode('utf-16le')
                    target.write_memory(addr, full_dll_name)
                    param_addr = addr
                    addr += len(full_dll_name)
                    shellcode_addr = addr
                    shellcode = generate_simple_LoadLibraryW_64(load_libraryW, retval_addr)
                    target.write_memory(shellcode_addr, shellcode)
                    t = target.create_thread(shellcode_addr, param_addr)
                    t.wait()
                    module_baseaddr = target.read_ptr(retval_addr)

            if not module_baseaddr:
                raise InjectionFailedError(u"Injection of <{0}> failed".format(dll_path))
            dbgprint("DLL Injected via LoadLibray", "DLLINJECT")
            # Cannot return the full return value of load_libraryW in 64b target.. (exit_code is a DWORD)
            return module_baseaddr
    # Hardcore mode
    # We don't have k32 or PEB->Ldr
    # Go inject a GetProcAddress(LoadLib) + LoadLib shellcode :D
    dbgprint("DLL Via manual getproc / loadlib", "DLLINJECT")
    if target.bitness == 32:
        return perform_manual_getproc_loadlib_32(target, dll_path)
    return perform_manual_getproc_loadlib_64(target, dll_path)

python_function_32_bits = {}

def generate_python_exec_shellcode_32(target, PyDll):
    pymodule = [mod for mod in target.peb.modules if mod.name == PyDll][0]
    base = pymodule.baseaddr
    if not python_function_32_bits:
        Py_exports = pymodule.pe.exports
        python_function_32_bits["PyEval_InitThreads"] = Py_exports["PyEval_InitThreads"] - base
        python_function_32_bits["Py_IsInitialized"] = Py_exports["Py_IsInitialized"] - base
        python_function_32_bits["PyGILState_Release"] = Py_exports["PyGILState_Release"] - base
        python_function_32_bits["PyGILState_Ensure"] = Py_exports["PyGILState_Ensure"] - base
        python_function_32_bits["PyEval_SaveThread"] = Py_exports["PyEval_SaveThread"] - base
        python_function_32_bits["Py_Initialize"] = Py_exports["Py_Initialize"] - base
        python_function_32_bits["PyRun_SimpleString"] = Py_exports["PyRun_SimpleString"] - base
    Py_exports = python_function_32_bits
    PyEval_InitThreads = Py_exports["PyEval_InitThreads"] + base
    Py_IsInitialized = Py_exports["Py_IsInitialized"] + base
    PyGILState_Release = Py_exports["PyGILState_Release"] + base
    PyGILState_Ensure = Py_exports["PyGILState_Ensure"] + base
    PyEval_SaveThread = Py_exports["PyEval_SaveThread"] + base
    Py_Initialize = Py_exports["Py_Initialize"] + base
    PyRun_SimpleString = Py_exports["PyRun_SimpleString"] + base

    code = x86.MultipleInstr()
    code += x86.Mov('EAX', Py_IsInitialized)
    code += x86.Call('EAX')
    code += x86.Mov("EDI", "EAX")
    code += x86.Cmp("EAX", 0)
    code += x86.Jnz(":DO_ENSURE")
    code +=     x86.Mov('EAX', Py_Initialize)
    code +=     x86.Call('EAX')
    # https://docs.python.org/3/c-api/init.html#c.PyEval_InitThreads
    code +=     x86.Mov('EAX', PyEval_InitThreads)
    code +=     x86.Call('EAX')
    code += x86.Label(":DO_ENSURE")
    code += x86.Mov('EAX', PyGILState_Ensure)
    code += x86.Call('EAX')
    code += x86.Push('EAX')
    # Get the string to execute from parameters
    code += x86.Mov("EAX", x86.mem("[ESP + 0x8]"))
    code += x86.Push('EAX')
    code += x86.Mov('EAX', PyRun_SimpleString)
    code += x86.Call('EAX')
    code += x86.Mov("ESI", "EAX")
    code += x86.Mov('EAX', PyGILState_Release)
    code += x86.Call('EAX')
    code += x86.Pop('EAX')
    code += x86.Cmp("EDI", 0)
    code += x86.Jnz(":RETURN")
    # If PyEval_InitThreads was called (init done in this thread)
    # We must release the GIL
    code +=     x86.Mov('EAX', PyEval_SaveThread)
    code +=     x86.Call('EAX')
    code += x86.Label(":RETURN")
    code += x86.Mov("EAX", "ESI")
    code += x86.Pop("EDI")
    code += x86.Ret()
    return code.get_code()


python_function_64_bits = {}

def generate_python_exec_shellcode_64(target, PyDll):
    pymodule = [mod for mod in target.peb.modules if mod.name == PyDll][0]
    base = pymodule.baseaddr
    if not python_function_64_bits:
        Py_exports = pymodule.pe.exports
        python_function_64_bits["PyEval_InitThreads"] = Py_exports["PyEval_InitThreads"] - base
        python_function_64_bits["Py_IsInitialized"] = Py_exports["Py_IsInitialized"] - base
        python_function_64_bits["PyGILState_Release"] = Py_exports["PyGILState_Release"] - base
        python_function_64_bits["PyGILState_Ensure"] = Py_exports["PyGILState_Ensure"] - base
        python_function_64_bits["PyEval_SaveThread"] = Py_exports["PyEval_SaveThread"] - base
        python_function_64_bits["Py_Initialize"] = Py_exports["Py_Initialize"] - base
        python_function_64_bits["PyRun_SimpleString"] = Py_exports["PyRun_SimpleString"] - base
    Py_exports = python_function_64_bits
    PyEval_InitThreads = Py_exports["PyEval_InitThreads"] + base
    Py_IsInitialized = Py_exports["Py_IsInitialized"] + base
    PyGILState_Release = Py_exports["PyGILState_Release"] + base
    PyGILState_Ensure = Py_exports["PyGILState_Ensure"] + base
    PyEval_SaveThread = Py_exports["PyEval_SaveThread"] + base
    Py_Initialize = Py_exports["Py_Initialize"] + base
    PyRun_SimpleString = Py_exports["PyRun_SimpleString"] + base

    Reserve_space_for_call = x64.MultipleInstr([x64.Push('RDI')] * 4)
    Clean_space_for_call = x64.MultipleInstr([x64.Pop('RDI')] * 4)
    code = x64.MultipleInstr()
    # Do stack alignement
    code += x64.Push('RCX')
    code += Reserve_space_for_call
    code += x64.Mov('RAX', Py_IsInitialized)
    code += x64.Call('RAX')
    code += x64.Mov("RDI", "RAX")
    code += x64.Cmp("RAX", 0)
    code += x64.Jnz(":DO_ENSURE")
    code +=     x64.Mov('RAX', Py_Initialize)
    code +=     x64.Call('RAX')
    # https://docs.python.org/3/c-api/init.html#c.PyEval_InitThreads
    code +=     x64.Mov('RAX', PyEval_InitThreads)
    code +=     x64.Call('RAX')
    code += x64.Label(":DO_ENSURE")
    code += x64.Mov('RAX', PyGILState_Ensure)
    code += x64.Call('RAX')
    code += x64.Mov('R15', 'RAX')
    code += x64.Mov("RCX", x64.mem("[RSP + 0x20]"))
    code += x64.Mov('RAX', PyRun_SimpleString)
    code += x64.Call('RAX')
    code += x64.Mov('RCX', 'R15')
    code += x64.Mov('R15', 'RAX')
    code += x64.Mov('RAX', PyGILState_Release)
    code += x64.Call('RAX')
    code += x64.Cmp("RDI", 0)
    code += x64.Jnz(":RETURN")
    # If PyEval_InitThreads was called (init done in this thread)
    # We must release the GIL
    code +=     x64.Mov('RAX', PyEval_SaveThread)
    code +=     x64.Call('RAX')
    code += x64.Label(":RETURN")
    code += Clean_space_for_call
    # Remove stack alignement
    code += x64.Pop('RCX')
    code += x64.Mov("RAX", "R15")
    code += x64.Ret()
    return code.get_code()


def inject_python_command(target, code_injected, PYDLL):
    """Postulate: PYDLL is already loaded in target process"""
    PYCODE = code_injected + "\x00"
    # TODO: free this (how ? when ?)
    remote_python_code_addr = target.virtual_alloc(len(PYCODE))
    target.write_memory(remote_python_code_addr, PYCODE)
    shellcode_addr = getattr(target, "_execute_python_shellcode", None)
    if shellcode_addr is not None:
        return shellcode_addr, remote_python_code_addr
    if target.bitness == 32:
        shellcode_generator = generate_python_exec_shellcode_32
    else:
        shellcode_generator = generate_python_exec_shellcode_64

    shellcode = shellcode_generator(target, PYDLL)
    shellcode_addr = target.virtual_alloc(len(shellcode))
    target.write_memory(shellcode_addr, shellcode)
    target._execute_python_shellcode = shellcode_addr
    return shellcode_addr, remote_python_code_addr

def get_dll_name_from_python_version():
    version = sys.version_info
    return "python{v.major}{v.minor}.dll".format(v=version)

def find_python_dll_to_inject(target_bitness):
    pydll_name = get_dll_name_from_python_version()
    if windows.current_process.bitness == target_bitness:
        # We can inject our own DLL
        pymodules = [m for m in windows.current_process.peb.modules if m.name == pydll_name]
        assert len(pymodules) == 1
        return pymodules[0].fullname
    # Okay, so we need to find the DLL to inject.
    # Problem is, for py3 the DLL is not un system32, so we need for search for it
    # Simpler solution is the registry
    # Add a check using %PATH% ?
    assert windows.system.bitness == 64, "How can we have process of different bitness on 32b system ?"
    if sys.version_info.major == 2:
        # Python2 DLL are located in system32/syswow64
        # We know that we are looking to DLL of the other bitness
        if windows.current_process.bitness == 32:
            # We need to check that the real system32\pythonXX.dll exists
            systempath = "sysnative"
        else:
            # We need to check that the wow64 system32\pythonXX.dll exists
            systempath = "syswow64"
        if os.path.exists(os.path.join(os.environ["windir"], systempath, pydll_name)):
            # In any way (32b ou 64b) the target process will load system32\pydll
            # If the target is 32b the wow64 layer will translate it
            return os.path.join(os.environ["windir"], "system32", pydll_name)
        # If not found this way -> may mean we have a install only for a user, give registry a try

    # Python 3 dll must be located using the registry
    for base_key in "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER":
        # Open the registry in 64b view regardless of current process bitness
        regbase = windows.system.registry(base_key, gdef.KEY_WOW64_64KEY | gdef.KEY_READ)
        # we cannot use sys.winver as we are looking for the OTHER version
        # But from Python <PCbuild/python.props> it looks like format is
        # {Major}.{Minor}{-32}(for 32b build)
        # This code do not handle -test version
        winver_base = sys.winver[:3] # major-minor
        if target_bitness == 64:
            pyinstallkeys = [regbase(r"SOFTWARE\Python\PythonCore")(winver_base)]
        else:
            pyinstallkeys = [regbase(r"SOFTWARE\Python\PythonCore")(winver_base + "-32"),
                                regbase(r"SOFTWARE\WOW6432Node\Python\PythonCore")(winver_base + "-32")]
        for pyinstallkey in pyinstallkeys:
            if not pyinstallkey.exists:
                continue
            try:
                pyinstallpath = pyinstallkey("InstallPath")[""].value
                final_path = os.path.join(pyinstallpath, pydll_name)
                assert os.path.exists(final_path), "Could not find <{0}> pydll referenced from registry".format(final_path)
                return final_path
            except WindowsError as e:
                if e.winerror != gdef.ERROR_FILE_NOT_FOUND:
                    raise
                # Not found
                continue
    # Could not find a valid installation
    raise ValueError("Could not find a path for python-dll <{0}>({1}bits)".format(sys.winver, target_bitness))



def execute_python_code(process, code):
    # Cache the value ?
    py_dll_name = get_dll_name_from_python_version()
    pydll_path = find_python_dll_to_inject(process.bitness)
    if sys.version_info.major == 3:
        # FOr py3, we may have a per-user install.
        # Meaning that the vcruntime140.dll will not be in the injected process path
        # Find it & load-it as well, it should be in the same directory as pythonxx.dll
        vc_runtime_dll = os.path.join(os.path.dirname(pydll_path), "vcruntime140.dll")
        load_dll_in_remote_process(process, vc_runtime_dll)
        # Try to inject the vcrunt
    load_dll_in_remote_process(process, pydll_path)
    shellcode, pythoncode = inject_python_command(process, code, py_dll_name)
    t = process.create_thread(shellcode, pythoncode)
    return t


retrieve_exc = r"""
import traceback
import sys
addr = {0}
txt = "".join(traceback.format_exception(sys.last_type, sys.last_value, sys.last_traceback))
import ctypes

size = ctypes.c_uint.from_address(addr)
size.value = len(txt)
buff = (ctypes.c_char * len(txt)).from_address(addr + ctypes.sizeof(ctypes.c_uint))
buff[:] = txt.encode()
"""

def retrieve_last_exception_data(process):
    with process.allocated_memory(0x1000) as mem:
        execute_python_code(process, retrieve_exc.format(mem)).wait()
        size = struct.unpack("<I", process.read_memory(mem, ctypes.sizeof(ctypes.c_uint)))[0]
        data = process.read_memory(mem + ctypes.sizeof(ctypes.c_uint), size)
    return data

class RemotePythonError(Exception):
    pass

def safe_execute_python(process, code):
    t = execute_python_code(process, code)
    t.wait() # Wait terminaison of the thread
    if t.exit_code == 0:
        return True
    if t.exit_code == STATUS_THREAD_IS_TERMINATING or process.is_exit:
        raise WindowsError("{0} died during execution of python command".format(process))
    if t.exit_code != 0xffffffff:
        raise ValueError("Unknown exit code {0}".format(hex(t.exit_code)))
    data = retrieve_last_exception_data(process)
    raise RemotePythonError(data)
