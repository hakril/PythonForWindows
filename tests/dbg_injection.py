import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64
from windows.native_exec import nativeutils

def perform_manual_getproc_loadlib_32_for_dbg(target, dll_name):
        dll = "KERNEL32.DLL\x00".encode("utf-16-le")
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
        RemoteManualLoadLibray += nativeutils.GetProcAddress32

        addr = target.virtual_alloc(0x1000)
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
        return t

def perform_manual_getproc_loadlib_64_for_dbg(target, dll_name):
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
    RemoteManualLoadLibray += nativeutils.GetProcAddress64

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
    return t

def perform_manual_getproc_loadlib_for_dbg(target, *args, **kwargs):
    if target.bitness == 32:
        return perform_manual_getproc_loadlib_32_for_dbg(target, *args, **kwargs)
    return perform_manual_getproc_loadlib_64_for_dbg(target, *args, **kwargs)