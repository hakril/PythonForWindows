import ctypes
import msvcrt
import os
import copy
import sys

from . import k32testing as kernel32proxy
from .generated_def import windef
from .generated_def.winstructs import *

# Function resolution !

def swallow_ctypes_copy(ctypes_object):
    new_copy = type(ctypes_object)()
    ctypes.memmove(ctypes.byref(new_copy), ctypes.byref(ctypes_object), ctypes.sizeof(new_copy))
    return new_copy

def get_func_addr(dll_name, func_name):
        dll = ctypes.WinDLL(dll_name)
        return kernel32proxy.GetProcAddress(dll._handle, func_name)



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