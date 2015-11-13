import ctypes
import msvcrt
import os
import sys
import code

import windows
from .. import winproxy
from ..generated_def import windef
from ..generated_def.winstructs import *


# Function resolution !
def get_func_addr(dll_name, func_name):
        # Load the DLL
        ctypes.WinDLL(dll_name)
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
    import ipdb;ipdb.set_trace()
    try:
        fnIsWow64Process = get_func_addr("kernel32.dll", "IsWow64Process")
    except winproxy.Kernel32Error:
        return False
    IsWow64Process = ctypes.WINFUNCTYPE(BOOL, HANDLE, ctypes.POINTER(BOOL))(fnIsWow64Process)
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
    """Create a new console displaying STDOUT
       Useful in injection of GUI process"""
    winproxy.AllocConsole()
    stdout_handle = winproxy.GetStdHandle(windef.STD_OUTPUT_HANDLE)
    console_stdout = create_file_from_handle(stdout_handle, "w")
    sys.stdout = console_stdout

    stdin_handle = winproxy.GetStdHandle(windef.STD_INPUT_HANDLE)
    console_stdin = create_file_from_handle(stdin_handle, "r+")
    sys.stdin = console_stdin

    stderr_handle = winproxy.GetStdHandle(windef.STD_ERROR_HANDLE)
    console_stderr = create_file_from_handle(stderr_handle, "w")
    sys.stderr = console_stderr


def create_process(path, show_windows=False):
    proc_info = PROCESS_INFORMATION()
    lpStartupInfo = None
    if show_windows:
        StartupInfo = STARTUPINFOA()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = 0
        lpStartupInfo = ctypes.byref(StartupInfo)
    windows.winproxy.CreateProcessA(path, lpProcessInformation=ctypes.byref(proc_info), lpStartupInfo=lpStartupInfo)
    proc = [p for p in windows.system.processes if p.pid == proc_info.dwProcessId][0]
    return proc


def enable_privilege(lpszPrivilege, bEnablePrivilege):
    """Enable of disable a privilege: enable_privilege(SE_DEBUG_NAME, True)"""
    tp = TOKEN_PRIVILEGES()
    luid = LUID()
    hToken = HANDLE()

    winproxy.OpenProcessToken(winproxy.GetCurrentProcess(), TOKEN_ALL_ACCESS, byref(hToken))
    winproxy.LookupPrivilegeValueA(None, lpszPrivilege, byref(luid))
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    if bEnablePrivilege:
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    else:
        tp.Privileges[0].Attributes = 0
    winproxy.AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(TOKEN_PRIVILEGES))
    winproxy.CloseHandle(hToken)
    if winproxy.GetLastError() == windef.ERROR_NOT_ALL_ASSIGNED:
        raise ValueError("Failed to get privilege {0}".format(lpszPrivilege))
    return True


def check_is_elevated():
    """Return True if process is Admin"""
    hToken = HANDLE()
    elevation = TOKEN_ELEVATION()
    cbsize = DWORD()

    winproxy.OpenProcessToken(winproxy.GetCurrentProcess(), TOKEN_ALL_ACCESS, byref(hToken))
    winproxy.GetTokenInformation(hToken, TokenElevation, byref(elevation), sizeof(elevation), byref(cbsize))
    winproxy.CloseHandle(hToken)
    return elevation.TokenIsElevated


def check_debug():
    """Check that kernel is in debug mode
       beware if NOUMEX (https://msdn.microsoft.com/en-us/library/windows/hardware/ff556253(v=vs.85).aspx#_______noumex______)"""
    hkresult = HKEY()
    cbsize = DWORD(1024)
    bufferres = (c_char * cbsize.value)()

    winproxy.RegOpenKeyExA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control", 0, KEY_READ, byref(hkresult))
    winproxy.RegGetValueA(hkresult, None, "SystemStartOptions", RRF_RT_REG_SZ, None, byref(bufferres), byref(cbsize))
    winproxy.RegCloseKey(hkresult)

    control = bufferres[:]
    if "DEBUG" not in control:
        # print "[-] Enable debug boot!"
        # print "> bcdedit /debug on"
        return False
    if "DEBUG=NOUMEX" not in control:
        pass
        # print "[*] Warning noumex not set!"
        # print "> bcdedit /set noumex on"
    return True


class FixedInteractiveConsole(code.InteractiveConsole):
    def raw_input(self, prompt=">>>"):
        sys.stdout.write(prompt)
        return raw_input("")


def pop_shell():
    """Pop a console with an InterativeConsole"""
    create_console()
    FixedInteractiveConsole(locals()).interact()


def get_kernel_modules():
    cbsize = DWORD()

    winproxy.NtQuerySystemInformation(SystemModuleInformation, None, 0, byref(cbsize))
    raw_buffer = (cbsize.value * c_char)()
    buffer = SYSTEM_MODULE_INFORMATION.from_address(ctypes.addressof(raw_buffer))
    winproxy.NtQuerySystemInformation(SystemModuleInformation, byref(raw_buffer), sizeof(raw_buffer), byref(cbsize))
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
        winproxy.VirtualProtect(self.addr, self.size, self.new_protect, ctypes.byref(self.old_protect))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        winproxy.VirtualProtect(self.addr, self.size, self.old_protect.value, ctypes.byref(self.old_protect))
        return False


class DisableWow64FsRedirection(object):
    """A context manager that disable the Wow64 Fs Redirection"""
    def __enter__(self):
        if windows.current_process.bitness == 64:
            return self
        self.OldValue = PVOID()
        winproxy.Wow64DisableWow64FsRedirection(ctypes.byref(self.OldValue))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if windows.current_process.bitness == 64:
            return False
        winproxy.Wow64RevertWow64FsRedirection(self.OldValue)
        return False
