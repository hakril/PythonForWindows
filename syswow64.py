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
    """shellcode must NOT end by a ret"""
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
    NtCreateThreadEx = get_syswow_ntdll_exports()['NtCreateThreadEx']
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

# We will soon need to generate thoses stub...

def NtQueryVirtualMemory_32_to_64(process, addr, result):
    size = ctypes.sizeof(result)
    MemoryBasicInformation = 0
    LEN = SIZE_T()

    NtQueryVirtualMemory = get_syswow_ntdll_exports()['NtQueryVirtualMemory']

    query_memory = x64.MultipleInstr()
    # Save registers
    query_memory += x64.Push('RBX')
    query_memory += x64.Push('RCX')
    query_memory += x64.Push('RDX')
    query_memory += x64.Push('RSI')
    query_memory += x64.Push('RDI')
    query_memory += x64.Push('R8')
    query_memory += x64.Push('R9')
    query_memory += x64.Push('R10')
    query_memory += x64.Push('R11')
    query_memory += x64.Push('R12')
    query_memory += x64.Push('R13')
    # Setup args

    query_memory += x64.Mov('RCX', process.handle)  # Arg1
    query_memory += x64.Mov('RDX', addr)  # Arg2
    query_memory += x64.Mov('R8', MemoryBasicInformation)  # Arg3
    query_memory += x64.Mov('R9', ctypes.addressof(result))  # Arg4
    query_memory += x64.Mov('RAX', ctypes.addressof(LEN))
    query_memory += x64.Push('RAX')  # Arg6
    query_memory += x64.Mov('RAX', size)
    query_memory += x64.Push('RAX')  # Arg5
    # reserve space for register (calling convention)
    query_memory += x64.Push('R9')
    query_memory += x64.Push('R8')
    query_memory += x64.Push('RDX')
    query_memory += x64.Push('RCX')
    # Call
    query_memory += x64.Mov('R13', NtQueryVirtualMemory)
    query_memory += x64.Call('R13')
    # Clean stack
    query_memory += x64.Add('RSP', 6 * 8)
    query_memory += x64.Pop('R13')
    query_memory += x64.Pop('R12')
    query_memory += x64.Pop('R11')
    query_memory += x64.Pop('R10')
    query_memory += x64.Pop('R9')
    query_memory += x64.Pop('R8')
    query_memory += x64.Pop('RDI')
    query_memory += x64.Pop('RSI')
    query_memory += x64.Pop('RDX')
    query_memory += x64.Pop('RCX')
    query_memory += x64.Pop('RBX')
    return execute_64bits_code_from_syswow(query_memory.get_code())


def NtQueryInformationProcess_32_to_64(process, result, size=None):
    ProcessBasicInformation = 0
    if size is None:
        size = ctypes.sizeof(size)
    ReturnLen = ULONG()

    NtQueryInformationProcess = get_syswow_ntdll_exports()['NtQueryInformationProcess']

    query_memory = x64.MultipleInstr()
    # Save registers
    query_memory += x64.Push('RBX')
    query_memory += x64.Push('RCX')
    query_memory += x64.Push('RDX')
    query_memory += x64.Push('RSI')
    query_memory += x64.Push('RDI')
    query_memory += x64.Push('R8')
    query_memory += x64.Push('R9')
    query_memory += x64.Push('R10')
    query_memory += x64.Push('R11')
    query_memory += x64.Push('R12')
    query_memory += x64.Push('R13')
    # Setup args

    query_memory += x64.Mov('RCX', process.handle)  # Arg1
    query_memory += x64.Mov('RDX', ProcessBasicInformation)  # Arg2
    query_memory += x64.Mov('R8', ctypes.addressof(result))  # Arg3
    query_memory += x64.Mov('R9', size)  # Arg4
    query_memory += x64.Mov('RAX', ctypes.addressof(ReturnLen))
    query_memory += x64.Push('RAX')  # Arg5
    # reserve space for register (calling convention)
    query_memory += x64.Push('R9')
    query_memory += x64.Push('R8')
    query_memory += x64.Push('RDX')
    query_memory += x64.Push('RCX')
    # Call
    query_memory += x64.Mov('R13', NtQueryInformationProcess)
    query_memory += x64.Call('R13')
    # Clean stack
    query_memory += x64.Add('RSP', 5 * 8)
    query_memory += x64.Pop('R13')
    query_memory += x64.Pop('R12')
    query_memory += x64.Pop('R11')
    query_memory += x64.Pop('R10')
    query_memory += x64.Pop('R9')
    query_memory += x64.Pop('R8')
    query_memory += x64.Pop('RDI')
    query_memory += x64.Pop('RSI')
    query_memory += x64.Pop('RDX')
    query_memory += x64.Pop('RCX')
    query_memory += x64.Pop('RBX')
    return execute_64bits_code_from_syswow(query_memory.get_code())

    
def generate_syswow64_call(target):
    nb_args = len(target.prototype._argtypes_)
    target_addr = get_syswow_ntdll_exports()[target.__name__]
    print hex(target_addr)

    argument_buffer_len = (nb_args * 8)
    argument_buffer = windows.current_process.allocator.reserve_size(argument_buffer_len)

    nb_args_on_stack = nb_args - 4

    code_64b = x64.MultipleInstr()
    # Save registers
    code_64b += x64.Push('RBX')
    code_64b += x64.Push('RCX')
    code_64b += x64.Push('RDX')
    code_64b += x64.Push('RSI')
    code_64b += x64.Push('RDI')
    code_64b += x64.Push('R8')
    code_64b += x64.Push('R9')
    code_64b += x64.Push('R10')
    code_64b += x64.Push('R11')
    code_64b += x64.Push('R12')
    code_64b += x64.Push('R13')

    # retrieve argument from the argument buffer
    if nb_args >= 1:
        code_64b += x64.Mov('RCX', x64.create_displacement(disp=argument_buffer))
    if nb_args >= 2:
        code_64b += x64.Mov('RDX', x64.create_displacement(disp=argument_buffer + (8 * 1)))
    if nb_args >= 3:
        code_64b += x64.Mov('R8', x64.create_displacement(disp=argument_buffer + (8 * 2)))
    if nb_args >= 4:
        code_64b += x64.Mov('R9', x64.create_displacement(disp=argument_buffer + (8 * 3)))
    for i in range(nb_args_on_stack):
        code_64b += x64.Mov('RAX',  x64.create_displacement(disp=argument_buffer + 8 * (nb_args - 1 - i)))
        code_64b += x64.Push('RAX')

    # reserve space for register (calling convention)
    code_64b += x64.Push('R9')
    code_64b += x64.Push('R8')
    code_64b += x64.Push('RDX')
    code_64b += x64.Push('RCX')
    # Call
    code_64b += x64.Mov('R13', target_addr)
    code_64b += x64.Call('R13')
    # Clean stack
    code_64b += x64.Add('RSP', (4 + nb_args_on_stack) * 8)
    code_64b += x64.Pop('R13')
    code_64b += x64.Pop('R12')
    code_64b += x64.Pop('R11')
    code_64b += x64.Pop('R10')
    code_64b += x64.Pop('R9')
    code_64b += x64.Pop('R8')
    code_64b += x64.Pop('RDI')
    code_64b += x64.Pop('RSI')
    code_64b += x64.Pop('RDX')
    code_64b += x64.Pop('RCX')
    code_64b += x64.Pop('RBX')
    return try_generate_stub_target(code_64b.get_code(), argument_buffer, target)
    # TODO: this code should be a winfuct of type prototype :)


def try_generate_stub_target(shellcode, argument_buffer, target):
    """shellcode must NOT end by a ret"""
    if not windows.current_process.is_wow_64:
        raise ValueError("Calling execute_64bits_code_from_syswow from non-syswow process")
    addr = windows.winproxy.VirtualAlloc(dwSize=0x1000)
    # post-exec 32bits stub (ret)
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
    native_caller = ctypes.CFUNCTYPE(c_ulong)(jump_addr)
    # Generate the wrapper function that fill the argument_buffer
    expected_arguments_number = len(target.prototype._argtypes_)

    def wrapper(*args):
        if len(args) != expected_arguments_number:
            raise ValueError("{0} syswow accept {1} args ({2} given)".format(target.__name__, expected_arguments_number, len(args)))
        # Transform args (ctypes byref possibly) to int
        writable_args = []
        for value in args:
            if not isinstance(value, (int, long)):
                value = ctypes.cast(value, ctypes.c_void_p).value
            writable_args.append(value)

        # Build buffer
        buffer = struct.pack("<" + "Q" * len(writable_args), *writable_args)
        ctypes.memmove(argument_buffer, buffer, len(buffer))
        # TODO : get 64bits returned value ?
        return native_caller()
    wrapper.__name__ = "{0}<syswow64>".format(target.__name__,)
    wrapper.__doc__ = "This is a wrapper to {0} in 64b mode, it accept <{1}> args".format(target.__name__, expected_arguments_number)
    return wrapper


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

def get_syswow_ntdll_exports():
    if get_syswow_ntdll_exports.value is not None:
        return get_syswow_ntdll_exports.value
    peb64 = get_current_process_syswow_peb()
    ntdll64 = [m for m in peb64.modules if m.name == "ntdll.dll"]
    if not ntdll64:
        raise ValueError("Could not find ntdll.dll in syswow peb")
    ntdll64 = ntdll64[0]
    exports = ntdll64.pe.exports
    get_syswow_ntdll_exports.value = exports
    return exports
get_syswow_ntdll_exports.value = None