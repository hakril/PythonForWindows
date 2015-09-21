import ctypes
import msvcrt
import os
import copy
import sys
import code

import windows
from . import k32testing as kernel32proxy
from .generated_def import windef
from .generated_def.winstructs import *


def fixedpropety(f):
    cache_name = "_" + f.__name__
    def prop(self):
        try:
            return getattr(self, cache_name)
        except AttributeError:
            setattr(self, cache_name, f(self))
            return getattr(self, cache_name)
    return property(prop)

def swallow_ctypes_copy(ctypes_object):
    new_copy = type(ctypes_object)()
    ctypes.memmove(ctypes.byref(new_copy), ctypes.byref(ctypes_object), ctypes.sizeof(new_copy))
    return new_copy


# Function resolution !

def get_func_addr(dll_name, func_name):
        dll = ctypes.WinDLL(dll_name)
        modules = windows.current_process.peb.modules
        if not dll_name.lower().endswith(".dll"):
            dll_name += ".dll"
        mod = [x for x in modules if x.name == dll_name][0]
        return mod.pe.exports[func_name]

def get_remote_func_addr(target, dll_name, func_name):
        name_modules = [m for m in target.peb.modules if m.name == dll_name]
        if not len(name_modules):
            raise ValueError("Module <{0}> not loaded in target <{1}>".format(dll_name, target))
        mod = name_modules[0]
        return mod.pe.exports[func_name]

def is_wow_64(hProcess):
    try:
        fnIsWow64Process =  get_func_addr("kernel32.dll", "IsWow64Process")
    except kernel32proxy.Kernel32Error:
        return False
    IsWow64Process  = ctypes.WINFUNCTYPE(BOOL, HANDLE, ctypes.POINTER(BOOL))(fnIsWow64Process)
    Wow64Process = BOOL()
    res = IsWow64Process(hProcess, ctypes.byref(Wow64Process))
    if res:
        return bool(Wow64Process)
    raise ctypes.WinError()

def create_file_from_handle(handle, mode="r"):
    """Return a Python :class:`file` arround a windows HANDLE"""
    fd = msvcrt.open_osfhandle(handle, os.O_TEXT)
    return os.fdopen(fd, mode, 0)

def get_handle_from_file(f):
    """Get the windows HANDLE of a python :class:`file`"""
    return msvcrt.get_osfhandle(f.fileno())

def create_console():
    """| Create a new console displaying STDOUT
    | Useful in injection of GUI process
    """
    kernel32proxy.AllocConsole()
    stdout_handle = kernel32proxy.GetStdHandle(windef.STD_OUTPUT_HANDLE)
    console_stdout = create_file_from_handle(stdout_handle, "w")
    sys.stdout = console_stdout

    stdin_handle = kernel32proxy.GetStdHandle(windef.STD_INPUT_HANDLE)
    console_stdin = create_file_from_handle(stdin_handle, "r+")
    sys.stdin = console_stdin

    stderr_handle = kernel32proxy.GetStdHandle(windef.STD_ERROR_HANDLE)
    console_stderr = create_file_from_handle(stderr_handle, "w")
    #print(stderr_handle, console_stderr)
    import os
    #os.dup2(console_stderr.fileno(), 2)
    sys.stderr = console_stderr

def create_process(path, show_windows=False):
    proc_info = PROCESS_INFORMATION()
    lpStartupInfo = None
    if show_windows:
        StartupInfo = STARTUPINFOA()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = 0
        #StartupInfo.wShowWindow = SW_HIDE
        lpStartupInfo = ctypes.byref(StartupInfo)
    windows.k32testing.CreateProcessA(path, lpProcessInformation=ctypes.byref(proc_info), lpStartupInfo=lpStartupInfo)
    proc = [p for p in windows.system.processes if p.pid == proc_info.dwProcessId][0]
    return proc


class FixedInteractiveConsole(code.InteractiveConsole):
    def raw_input(self, prompt=">>>"):
        sys.stdout.write(prompt)
        return raw_input("")

def pop_shell():
    create_console()
    FixedInteractiveConsole(locals()).interact()

def get_kernel_modules():
    cbsize = DWORD()
    kernel32proxy.NtQuerySystemInformation(SystemModuleInformation, None, 0, byref(cbsize))
    raw_buffer = (cbsize.value * c_char)()
    buffer = SYSTEM_MODULE_INFORMATION.from_address(ctypes.addressof(raw_buffer))
    kernel32proxy.NtQuerySystemInformation(SystemModuleInformation, byref(raw_buffer), sizeof(raw_buffer), byref(cbsize))
    modules = (SYSTEM_MODULE * buffer.ModulesCount).from_address(addressof(buffer) + SYSTEM_MODULE_INFORMATION.Modules.offset)
    return list(modules)

class VirtualProtected(object):
    """A context manager usable like `VirtualProtect` that will restore the old protection at exit

    Example::

        with utils.VirtualProtected(IATentry.addr, ctypes.sizeof(PVOID), windef.PAGE_EXECUTE_READWRITE):
            IATentry.value = 0x42424242
    """
    def __init__(self, addr, size, new_protect):
        if (addr % 0x1000):
            addr = addr - addr % 0x1000
        self.addr = addr
        self.size = size
        self.new_protect = new_protect

    def __enter__(self):
        self.old_protect = DWORD()
        kernel32proxy.VirtualProtect(self.addr, self.size, self.new_protect, ctypes.byref(self.old_protect))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        kernel32proxy.VirtualProtect(self.addr, self.size, self.old_protect.value, ctypes.byref(self.old_protect))
        return False

class DisableWow64FsRedirection(object):
    def __enter__(self):
        self.OldValue = PVOID()
        kernel32proxy.Wow64DisableWow64FsRedirection(ctypes.byref(self.OldValue))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        kernel32proxy.Wow64RevertWow64FsRedirection(self.OldValue)
        return False
