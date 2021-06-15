import struct
import ctypes
from ctypes import byref
import codecs
import functools
import threading

import windows
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64
from .generated_def.winstructs import *
from windows.winobject import process
from windows import winproxy
from .winproxy import NeededParameter
from .pycompat import int_types

# Special code for syswow64 process
CS_32bits = 0x23
CS_64bits = 0x33

# Allow to keep per-thread state of asm stub
class ThreadState(threading.local):
    def __init__(self): # Called once per thread
        self.allocator =  windows.native_exec.native_function.CustomAllocator()
        self.raw_call_per_function = {}
        self.current_original_args = None

thread_state = ThreadState()


def generate_64bits_execution_stub_from_syswow(x64shellcode):
    """shellcode must NOT end by a ret"""
    current_process = windows.current_process
    if not current_process.is_wow_64:
        raise ValueError("Calling generate_64bits_execution_stub_from_syswow from non-syswow process")

    transition64 = x64.MultipleInstr()
    transition64 += x64.Call(":TOEXEC")
    transition64 += x64.Mov("RDX", "RAX")
    transition64 += x64.Shr("RDX", 32)
    transition64 += x64.Retf32()  # 32 bits return addr
    transition64 += x64.Label(":TOEXEC")
    x64shellcodeaddr = thread_state.allocator.write_code(transition64.get_code() + x64shellcode)

    transition =     x86.MultipleInstr()
    transition +=    x86.Call(CS_64bits, x64shellcodeaddr)
    # Reset the SS segment selector.
    # We need to do that due to a bug in AMD CPUs with RETF & SS
    # https://github.com/hakril/PythonForWindows/issues/10
    # http://blog.rewolf.pl/blog/?p=1484
    transition +=    x86.Mov("ECX", "SS")
    transition +=    x86.Mov("SS", "ECX")
    transition +=    x86.Ret()

    stubaddr = thread_state.allocator.write_code(transition.get_code())
    exec_stub = ctypes.CFUNCTYPE(ULONG64)(stubaddr)
    return exec_stub

def execute_64bits_code_from_syswow(x64shellcode):
    return generate_64bits_execution_stub_from_syswow(x64shellcode)()

def generate_syswow64_call(target, errcheck=None):
    nb_args = len(target.prototype._argtypes_)
    target_addr = get_syswow_ntdll_exports()[target.__name__]
    argument_buffer_len = (nb_args * 8)
    argument_buffer = thread_state.allocator.reserve_size(argument_buffer_len)
    alignement_information = thread_state.allocator.reserve_size(8)

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
    code_64b += x64.Ret()
    return try_generate_stub_target(code_64b.get_code(), argument_buffer, target, errcheck=errcheck)


def try_generate_stub_target(shellcode, argument_buffer, target, errcheck=None):
    if not windows.current_process.is_wow_64:
        raise ValueError("Calling execute_64bits_code_from_syswow from non-syswow process")
    native_caller = generate_64bits_execution_stub_from_syswow(shellcode)
    native_caller.errcheck = errcheck if errcheck is not None else target.errcheck
    # Generate the wrapper function that fill the argument_buffer
    expected_arguments_number = len(target.prototype._argtypes_)
    def wrapper(*args):
        if len(args) != expected_arguments_number:
            raise ValueError("{0} syswow accept {1} args ({2} given)".format(target.__name__, expected_arguments_number, len(args)))
        # Transform args (ctypes byref possibly) to int
        writable_args = []
        for i, value in enumerate(args):
            if not isinstance(value, int_types):
                try:
                    value = ctypes.cast(value, ctypes.c_void_p).value
                except ctypes.ArgumentError as e:
                    raise ctypes.ArgumentError("Argument {0}: wrong type <{1}>".format(i, type(value).__name__))
            writable_args.append(value)
        # Build buffer
        buffer = struct.pack("<" + "Q" * len(writable_args), *writable_args)
        ctypes.memmove(argument_buffer, buffer, len(buffer))
        # Copy origincal args in function, for errcheck if needed
        thread_state.current_original_args = args

        return native_caller()
    wrapper.__name__ = "{0}<syswow64>".format(target.__name__,)
    wrapper.__doc__ = "This is a wrapper to {0} in 64b mode, it accept <{1}> args".format(target.__name__, expected_arguments_number)
    return wrapper


def get_current_process_syswow_peb_addr():
    get_peb_64_code = x64.assemble("mov rax, gs:[0x60]; ret")
    return execute_64bits_code_from_syswow(get_peb_64_code)

def get_current_process_syswow_peb():
    current_process = windows.current_process

    class CurrentProcessReadSyswow(process.Process):
        bitness = 64
        def _get_handle(self):
            return winproxy.OpenProcess(dwProcessId=current_process.pid)

        def read_memory(self, addr, size):
            buffer_addr = ctypes.create_string_buffer(size)
            winproxy.NtWow64ReadVirtualMemory64(self.handle, addr, buffer_addr, size)
            return buffer_addr[:]
    peb_addr = get_current_process_syswow_peb_addr()
    return windows.winobject.process.RemotePEB64(peb_addr, CurrentProcessReadSyswow())


class ReadSyswow64Process(process.Process):
        def __init__(self, target):
            self.target = target
            self._bitness = target.bitness

        def _get_handle(self):
            return self.target.handle

        def read_memory(self, addr, size):
            buffer_addr = ctypes.create_string_buffer(size)
            winproxy.NtWow64ReadVirtualMemory64(self.target.handle, addr, buffer_addr, size)
            return buffer_addr[:]

        #read_string = process.Process.read_string


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
    def __init__(self, winproxy_function, errcheck=None):
        self.winproxy_function = winproxy_function
        self.errcheck = errcheck
        if winproxy_function is not None:
            self.params_name = [param[1] for param in winproxy_function.params]

    def __call__(self, python_proxy):
        if not windows.winproxy.is_implemented(self.winproxy_function):
            return None

        def force_resolution():
            if self.winproxy_function in thread_state.raw_call_per_function:
                return True
            try:
                stub = generate_syswow64_call(self.winproxy_function, errcheck=self.errcheck)
                thread_state.raw_call_per_function[self.winproxy_function] = stub
            except KeyError:
                raise windows.winproxy.ExportNotFound(self.winproxy_function.__name__, "SysWow[ntdll64]")


        def perform_call(*args):
            if len(self.params_name) != len(args):
                print("ERROR:")
                print("Expected params: {0}".format(self.params_name))
                print("Just Got params: {0}".format(args))
                raise ValueError("I do not have all parameters: how is that possible ?")
            for param_name, param_value in zip(self.params_name, args):
                if param_value is NeededParameter:
                    raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.winproxy_function.__name__, param_name))

            if self.winproxy_function not in thread_state.raw_call_per_function:
                force_resolution()
            return thread_state.raw_call_per_function[self.winproxy_function](*args)


        setattr(python_proxy, "ctypes_function", perform_call)
        setattr(python_proxy, "force_resolution", force_resolution)
        return python_proxy

def ntquerysysteminformation_syswow64_error_check(result, func, args):
    args = thread_state.current_original_args
    if result == 0:
        return args
    # Ignore STATUS_INFO_LENGTH_MISMATCH if SystemInformation is None
    if result == STATUS_INFO_LENGTH_MISMATCH and not args[1]:
        return args
    raise winproxy.WinproxyError("NtQuerySystemInformation failed with NTStatus {0}".format(hex(result)))

@Syswow64ApiProxy(winproxy.NtQuerySystemInformation, errcheck=ntquerysysteminformation_syswow64_error_check)
# @Syswow64ApiProxy(winproxy.NtQuerySystemInformation)
def NtQuerySystemInformation_32_to_64(SystemInformationClass, SystemInformation=None, SystemInformationLength=0, ReturnLength=NeededParameter):
    if SystemInformation is not None and SystemInformationLength == 0:
        SystemInformationLength = ctypes.sizeof(SystemInformation)
    if SystemInformation is None:
        SystemInformation = 0
    return NtQuerySystemInformation_32_to_64.ctypes_function(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)


@Syswow64ApiProxy(winproxy.NtCreateThreadEx)
def NtCreateThreadEx_32_to_64(ThreadHandle=None, DesiredAccess=0x1fffff, ObjectAttributes=0, ProcessHandle=NeededParameter, lpStartAddress=NeededParameter, lpParameter=NeededParameter, CreateSuspended=0, dwStackSize=0, Unknown1=0, Unknown2=0, Unknown3=0):
    if ThreadHandle is None:
        ThreadHandle = byref(HANDLE())
    return NtCreateThreadEx_32_to_64.ctypes_function(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3)


ProcessBasicInformation = 0
@Syswow64ApiProxy(winproxy.NtQueryInformationProcess)
def NtQueryInformationProcess_32_to_64(ProcessHandle, ProcessInformationClass=ProcessBasicInformation, ProcessInformation=NeededParameter, ProcessInformationLength=0, ReturnLength=None):
    if ProcessInformation is not None and ProcessInformationLength == 0:
        ProcessInformationLength = ctypes.sizeof(ProcessInformation)
    if type(ProcessInformation) == PROCESS_BASIC_INFORMATION:
        ProcessInformation = byref(ProcessInformation)
    if ReturnLength is None:
        ReturnLength = byref(ULONG())
    return NtQueryInformationProcess_32_to_64.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)


@Syswow64ApiProxy(winproxy.NtQueryInformationThread)
def NtQueryInformationThread_32_to_64(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = byref(ULONG())
    if ThreadInformation is not None and ThreadInformationLength == 0:
        ThreadInformationLength = ctypes.sizeof(ThreadInformation)
    return NtQueryInformationThread_32_to_64.ctypes_function(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)



@Syswow64ApiProxy(winproxy.NtQueryVirtualMemory)
def NtQueryVirtualMemory_32_to_64(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation=NeededParameter, MemoryInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = byref(ULONG())
    if MemoryInformation is not None and MemoryInformationLength == 0:
        MemoryInformationLength = ctypes.sizeof(MemoryInformation)
    if isinstance(MemoryInformation, ctypes.Structure):
        MemoryInformation = byref(MemoryInformation)
    return NtQueryVirtualMemory_32_to_64.ctypes_function(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength)


@Syswow64ApiProxy(winproxy.NtProtectVirtualMemory)
def NtProtectVirtualMemory_32_to_64(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection=None):
    if OldAccessProtection is None:
        XOldAccessProtection = DWORD()
        OldAccessProtection = ctypes.addressof(XOldAccessProtection)
    return NtProtectVirtualMemory_32_to_64.ctypes_function(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection)


@Syswow64ApiProxy(winproxy.NtGetContextThread)
def NtGetContextThread_32_to_64(hThread, lpContext):
    if type(lpContext) == windows.winobject.exception.ECONTEXT64:
        lpContext = byref(lpContext)
    return NtGetContextThread_32_to_64.ctypes_function(hThread, lpContext)

@Syswow64ApiProxy(winproxy.LdrLoadDll)
def LdrLoadDll_32_to_64(PathToFile, Flags, ModuleFileName, ModuleHandle):
    return LdrLoadDll_32_to_64.ctypes_function(PathToFile, Flags, ModuleFileName, ModuleHandle)

@Syswow64ApiProxy(winproxy.NtSetContextThread)
def NtSetContextThread_32_to_64(hThread, lpContext):
    return NtSetContextThread_32_to_64.ctypes_function(hThread, lpContext)
