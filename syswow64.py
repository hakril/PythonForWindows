import struct
import ctypes
import codecs
import windows
import windows.native_exec.simple_x64 as x64
from generated_def.winstructs import *

# Special code for syswow64 process
CS_32bits = 0x23
CS_64bits = 0x33


def genere_return_32bits_stub(ret_addr):
    ret_32b = x64.MultipleInstr()
    ret_32b += x64.Mov('RCX', (CS_32bits << 32) + ret_addr)
    ret_32b += x64.Push('RCX')
    ret_32b += x64.Retf32()  # 32 bits return addr
    return ret_32b.get_code()

# The format of a jump to 64bits mode
dummy_jump = "\xea" + struct.pack("<I", 0) + chr(CS_64bits) + "\x00\x00"


def execute_64bits_code_from_syswow(shellcode):
    """shellcode must not end by a ret"""
    if not windows.current_process.is_wow_64:
        raise ValueError("Calling execute_64bits_code_from_syswow from non-syswow process")
    addr = windows.winproxy.VirtualAlloc(dwSize=0x1000)
    # post-exec 32bits stub (xor eax, eax; ret)
    ret = "\xC3"
    ret_addr = addr
    shell_code_addr = ret_addr + len(ret) + len(dummy_jump)
    # ljmp
    jump = "\xea" + struct.pack("<I", shell_code_addr) + chr(CS_64bits) + "\x00\x00"
    jump_addr = ret_addr + len(ret)
    # Return to 32bits stub
    shellcode += genere_return_32bits_stub(ret_addr)
    # WRITE ALL THE STUBS
    windows.current_process.write_memory(ret_addr, ret)
    windows.current_process.write_memory(jump_addr, jump)
    windows.current_process.write_memory(shell_code_addr, shellcode)
    # Execute
    exec_stub = ctypes.CFUNCTYPE(HRESULT)(jump_addr)
    return exec_stub()


def NtCreateThreadEx_32_to_64(process, addr, param):
    NtCreateThreadEx = get_NtCreateThreadEx_syswow_addr()
    create_thread = x64.MultipleInstr()
    # Save registers
    create_thread += x64.Push('RBX')
    create_thread += x64.Push('RCX')
    create_thread += x64.Push('RDX')
    create_thread += x64.Push('RSI')
    create_thread += x64.Push('RDI')
    create_thread += x64.Push('R8')
    create_thread += x64.Push('R9')
    create_thread += x64.Push('R10')
    create_thread += x64.Push('R11')
    create_thread += x64.Push('R12')
    create_thread += x64.Push('R13')
    # Setup args
    create_thread += x64.Push(0)
    create_thread += x64.Mov('RCX', 'RSP')  # Arg1
    create_thread += x64.Mov('RDX', 0x1fffff)  # Arg2
    create_thread += x64.Mov('R8', 0)  # Arg3
    create_thread += x64.Mov('R9', process.handle)  # Arg4
    create_thread += x64.Mov('RAX', 0)
    create_thread += x64.Push('RAX')  # Arg11
    create_thread += x64.Push('RAX')  # Arg10
    create_thread += x64.Push('RAX')  # Arg9
    create_thread += x64.Push('RAX')  # Arg8
    create_thread += x64.Push('RAX')  # Arg7
    create_thread += x64.Mov('RAX', param)
    create_thread += x64.Push('RAX')  # Arg6
    create_thread += x64.Mov('RAX', addr)
    create_thread += x64.Push('RAX')  # Arg5
    # reserve space for register (calling convention)
    create_thread += x64.Push('R9')
    create_thread += x64.Push('R8')
    create_thread += x64.Push('RDX')
    create_thread += x64.Push('RCX')
    # Call
    create_thread += x64.Mov('R13', NtCreateThreadEx)
    create_thread += x64.Call('R13')
    # Clean stack
    create_thread += x64.Add('RSP', 12 * 8)
    create_thread += x64.Pop('R13')
    create_thread += x64.Pop('R12')
    create_thread += x64.Pop('R11')
    create_thread += x64.Pop('R10')
    create_thread += x64.Pop('R9')
    create_thread += x64.Pop('R8')
    create_thread += x64.Pop('RDI')
    create_thread += x64.Pop('RSI')
    create_thread += x64.Pop('RDX')
    create_thread += x64.Pop('RCX')
    create_thread += x64.Pop('RBX')
    return execute_64bits_code_from_syswow(create_thread.get_code())


def get_NtCreateThreadEx_syswow_addr():
    if get_NtCreateThreadEx_syswow_addr.value is not None:
        return get_NtCreateThreadEx_syswow_addr.value
    peb64 = get_current_process_syswow_peb()
    ntdll64 = [m for m in peb64.modules if m.name == "ntdll.dll"]
    if not ntdll64:
        raise ValueError("Could not find ntdll.dll in syswow peb")
    ntdll64 = ntdll64[0]
    try:
        get_NtCreateThreadEx_syswow_addr.value = ntdll64.pe.exports['NtCreateThreadEx']
    except KeyError:
        raise ValueError("Could not find NtCreateThreadEx in syswow ntdll.dll")
    return get_NtCreateThreadEx_syswow_addr.value
get_NtCreateThreadEx_syswow_addr.value = None


def get_current_process_syswow_peb_addr():
    current_process = windows.current_process
    dest = current_process.virtual_alloc(0x1000)
    get_peb_64_code = codecs.decode(b"65488B042560000000", 'hex')
    store_peb = x64.MultipleInstr()
    store_peb += x64.Mov(x64.create_displacement(disp=dest), 'RAX')
    get_peb_64_code += store_peb.get_code()
    current_process.write_memory(dest, "\x00" * 8)
    windows.syswow64.execute_64bits_code_from_syswow(get_peb_64_code)
    peb_addr = struct.unpack("<Q", current_process.read_memory(dest, 8))[0]
    return peb_addr


def get_current_process_syswow_peb():
    current_process = windows.current_process

    class CurrentProcessReadSyswow():
        def read_memory(self, addr, size):
            buffer_addr = ctypes.create_string_buffer(size)
            windows.winproxy.NtWow64ReadVirtualMemory64(current_process.handle, addr, buffer_addr, size)
            return buffer_addr[:]
        bitness = 64
    peb_addr = get_current_process_syswow_peb_addr()
    return windows.winobject.RemotePEB64(peb_addr, CurrentProcessReadSyswow())
