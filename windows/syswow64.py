import struct
import ctypes
from ctypes import byref
import codecs
import functools

import windows
import windows.native_exec.simple_x64 as x64
from generated_def.winstructs import *
from windows.winproxy import NeededParameter, OptionalExport, NtdllProxy, error_ntstatus

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
    current_process = windows.current_process
    if not current_process.is_wow_64:
        raise ValueError("Calling execute_64bits_code_from_syswow from non-syswow process")
    # 1 -> ret | 8 -> ljump
    size_to_alloc = len(shellcode) + len(genere_return_32bits_stub(0xffffffff)) + 1 + 8
    addr = windows.current_process.allocator.reserve_size(size_to_alloc)
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
    current_process.write_memory(ret_addr, ret)
    current_process.write_memory(jump_addr, jump)
    current_process.write_memory(shell_code_addr, shellcode)
    # Execute
    exec_stub = ctypes.CFUNCTYPE(HRESULT)(jump_addr)
    return exec_stub()


def generate_syswow64_call(target):
    nb_args = len(target.prototype._argtypes_)
    target_addr = get_syswow_ntdll_exports()[target.__name__]
    argument_buffer_len = (nb_args * 8)
    argument_buffer = windows.current_process.allocator.reserve_size(argument_buffer_len)
    alignement_information = windows.current_process.allocator.reserve_size(8)

    nb_args_on_stack = max(nb_args - 4, 0)

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

    # Alignment stuff :)
    code_64b += x64.Mov('RCX', 'RSP')
    code_64b += x64.And('RCX', 0x0f)
    code_64b += x64.Mov(x64.deref(alignement_information), 'RCX')
    code_64b += x64.Sub('RSP', 'RCX')
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
    # Realign stack :)
    code_64b += x64.Add('RSP', x64.deref(alignement_information))
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


def try_generate_stub_target(shellcode, argument_buffer, target):
    """shellcode must NOT end by a ret"""
    if not windows.current_process.is_wow_64:
        raise ValueError("Calling execute_64bits_code_from_syswow from non-syswow process")
    size_to_alloc = len(shellcode) + len(genere_return_32bits_stub(0xffffffff)) + 1 + 8
    addr = windows.current_process.allocator.reserve_size(size_to_alloc)
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
    native_caller.errcheck = target.errcheck
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
    dest = current_process.allocator.reserve_size(8)
    get_peb_64_code = x64.MultipleInstr()
    get_peb_64_code += x64.Mov('RAX', x64.mem('gs:[0x60]'))
    get_peb_64_code += x64.Mov(x64.create_displacement(disp=dest), 'RAX')
    current_process.write_memory(dest, "\x00" * 8)
    execute_64bits_code_from_syswow(get_peb_64_code.get_code())
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


class Syswow64ApiProxy(object):
    """Create a python wrapper around a function"""
    def __init__(self, winproxy_function):
        self.winproxy_function = winproxy_function
        self.raw_call = None
        self.params_name = [param[1] for param in winproxy_function.params]

    def __call__(self, python_proxy):
        def perform_call(*args):
            if len(self.params_name) != len(args):
                print("ERROR:")
                print("Expected params: {0}".format(self.params_name))
                print("Just Got params: {0}".format(args))
                raise ValueError("I do not have all parameters: how is that possible ?")
            for param_name, param_value in zip(self.params_name, args):
                if param_value is NeededParameter:
                    raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.winproxy_function.__name__, param_name))

            if self.raw_call is None:
                self.raw_call = generate_syswow64_call(self.winproxy_function)
            return self.raw_call(*args)
        setattr(python_proxy, "ctypes_function", perform_call)
        return python_proxy


@Syswow64ApiProxy(windows.winproxy.NtCreateThreadEx)
def NtCreateThreadEx_32_to_64(ThreadHandle=None, DesiredAccess=0x1fffff, ObjectAttributes=0, ProcessHandle=NeededParameter, lpStartAddress=NeededParameter, lpParameter=NeededParameter, CreateSuspended=0, dwStackSize=0, Unknown1=0, Unknown2=0, Unknown3=0):
    if ThreadHandle is None:
        ThreadHandle = byref(HANDLE())
    return NtCreateThreadEx_32_to_64.ctypes_function(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3)


ProcessBasicInformation = 0
@Syswow64ApiProxy(windows.winproxy.NtQueryInformationProcess)
def NtQueryInformationProcess_32_to_64(ProcessHandle, ProcessInformationClass=ProcessBasicInformation, ProcessInformation=NeededParameter, ProcessInformationLength=0, ReturnLength=None):
    if ProcessInformation is not None and ProcessInformationLength == 0:
        ProcessInformationLength = ctypes.sizeof(ProcessInformation)
    if type(ProcessInformation) == PROCESS_BASIC_INFORMATION:
        ProcessInformation = byref(ProcessInformation)
    if ReturnLength is None:
        ReturnLength = byref(ULONG())
    return NtQueryInformationProcess_32_to_64.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)


@Syswow64ApiProxy(windows.winproxy.NtQueryInformationThread)
def NtQueryInformationThread_32_to_64(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = byref(ULONG())
    if ThreadInformation is not None and ThreadInformationLength == 0:
        ThreadInformationLength = ctypes.sizeof(ThreadInformation)
    return NtQueryInformationThread_32_to_64.ctypes_function(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)



@Syswow64ApiProxy(windows.winproxy.NtQueryVirtualMemory)
def NtQueryVirtualMemory_32_to_64(ProcessHandle, BaseAddress, MemoryInformationClass=MemoryBasicInformation, MemoryInformation=NeededParameter, MemoryInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = byref(ULONG())
    if MemoryInformation is not None and MemoryInformationLength == 0:
        MemoryInformationLength = ctypes.sizeof(MemoryInformation)
    if type(MemoryInformation) == MEMORY_BASIC_INFORMATION64:
        MemoryInformation = byref(MemoryInformation)
    return NtQueryVirtualMemory_32_to_64.ctypes_function(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength)


@Syswow64ApiProxy(windows.winproxy.NtGetContextThread)
def NtGetContextThread_32_to_64(hThread, lpContext):
    if type(lpContext) == windows.vectored_exception.EnhancedCONTEXT64:
        lpContext = byref(lpContext)
    return NtGetContextThread_32_to_64.ctypes_function(hThread, lpContext)


