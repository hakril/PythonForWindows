import struct
import ctypes
import os

import windows
import windows.utils as utils

from .native_exec import simple_x86 as x86
from .native_exec import simple_x64 as x64

from windows.native_exec.nativeutils import GetProcAddress64

from windows.dbgprint import dbgprint


def load_dll_in_remote_process(target, dll_name):
    rpeb = target.peb
    if rpeb.Ldr:
        # LDR est parcourable, ca va etre deja plus simple..
        modules = rpeb.modules
        if any(mod.name == dll_name for mod in modules):
            # DLL already loaded
            dbgprint("DLL already present in DLL", "DLLINJECT")
            return True
        k32 = [mod for mod in modules if mod.name.lower() == "kernel32.dll"]
        if k32:
            # We have kernel32 \o/
            k32 = k32[0]
            try:
                load_libraryA = k32.pe.exports["LoadLibraryA"]
            except KeyError:
                raise ValueError("Kernel32 have no export <LoadLibraryA> (wtf)")

            addr = target.virtual_alloc(0x1000)
            target.write_memory(addr, dll_name + "\x00")
            t = target.create_thread(load_libraryA, addr)
            t.wait()
            windows.winproxy.VirtualFreeEx(target.handle, addr)
            dbgprint("DLL Injected via (LoadLibray)", "DLLINJECT")
            return True
    # Hardcore mode
    # We don't have k32 or PEB->Ldr
    # Go inject a GetProcAddress(LoadLib) + LoadLib shellcode :D
    if target.bitness == 32:
        raise NotImplementedError("Manuel GetProcAddress 32bits")

    dll = "KERNEL32.DLL\x00".encode("utf-16-le")
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

    addr = target.virtual_alloc(0x1000)
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
    dbgprint("DLL Injected via manual GetProc(LoadLibray)", "DLLINJECT")
    return True


# 32 to 32 injection
def generate_python_exec_shellcode_32(target, PyInit, PyRun, PYCODE_ADDR):
    code = x86.MultipleInstr()
    # Call PyInit

    code += x86.Mov('EAX', PyInit)
    code += x86.Call('EAX')
    # Get PyRun function into pythondll
    # Call PyRun with python code to exec
    code += x86.Push(PYCODE_ADDR)
    code += x86.Mov('EAX', PyRun)
    code += x86.Call('EAX')
    code += x86.Pop("EDI")
    code += x86.Ret()
    return code.get_code()


# 64 to 64 injection
def generate_python_exec_shellcode_64(target, PyInit, PyRun, PYCODE_ADDR):
    Reserve_space_for_call = x64.MultipleInstr([x64.Push('RDI')] * 4)
    Clean_space_for_call = x64.MultipleInstr([x64.Pop('RDI')] * 4)

    code = x64.MultipleInstr()
    # Do stack alignement
    code += x64.Push('RCX')
    # Load python27.dll
    # Get PyInit function into pythondll
    code += Reserve_space_for_call
    code += x64.Mov('RAX', PyInit)
    # Call PyInit
    code += x64.Call('RAX')
    code += Clean_space_for_call
    code += Reserve_space_for_call
    code += x64.Mov('RAX', PyRun)
    code += x64.Mov('RCX', PYCODE_ADDR)
    # Call PyRun
    code += x64.Call('RAX')
    code += Clean_space_for_call
    # Remove stack alignement
    code += x64.Pop('RCX')
    code += x64.Ret()
    return code.get_code()


def inject_python_command(target, code_injected, PYDLL):
    """Postulate: PYDLL is already loaded in target process"""
    PyInit = "Py_Initialize\x00"
    Pyrun = "PyRun_SimpleString\x00"
    PYCODE = code_injected + "\x00"

    pymodule = [mod for mod in target.peb.modules if mod.name == PYDLL][0]
    Py_exports = pymodule.pe.exports
    PyInit = Py_exports["Py_Initialize"]
    Pyrun = Py_exports["PyRun_SimpleString"]

    remote_addr = target.virtual_alloc(len(PYCODE) + 0x100)
    target.write_memory(remote_addr, PYCODE)
    SHELLCODE_ADDR = remote_addr + len(PYCODE)

    if target.bitness == 32:
        shellcode_generator = generate_python_exec_shellcode_32
    else:
        shellcode_generator = generate_python_exec_shellcode_64

    shellcode = shellcode_generator(target, PyInit, Pyrun, remote_addr)
    target.write_memory(SHELLCODE_ADDR, shellcode)
    return SHELLCODE_ADDR


def validate_python_dll_presence_on_disk(process):
    if windows.current_process.bitness == process.bitness:
        return True
    if windows.current_process.bitness == 32 and process.bitness == 64:
        with windows.utils.DisableWow64FsRedirection():
            if not os.path.exists(r"C:\Windows\system32\python27.dll"):
                raise ValueError("Could not find Python DLL to inject")
            return True
    if windows.current_process.bitness == 64 and process.bitness == 32:
        if not os.path.exists(r"C:\Windows\SysWOW64\python27.dll"):
            raise ValueError("Could not find Python DLL to inject")
        return True
    raise NotImplementedError("Unknown bitness")

def execute_python_code(process, code):
    validate_python_dll_presence_on_disk(process)
    load_dll_in_remote_process(process, "python27.dll")
    addr = inject_python_command(process, code, "python27.dll")
    t = process.create_thread(addr, 0)
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
buff[:] = txt
"""

def retrieve_last_exception_data(process):
    # TODO : FREE THIS
    mem = process.virtual_alloc(0x1000)
    execute_python_code(process, retrieve_exc.format(mem))
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
    if t.exit_code != 0xffffffff:
        raise ValueError("Unknown exit code {0}".format(hex(t.exit_code)))
    data = retrieve_last_exception_data(process)
    raise RemotePythonError(data)


