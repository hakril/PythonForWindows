import ctypes
import functools

from ctypes.wintypes import *
from windows.generated_def.winstructs import *
from windows.generated_def.windef import *
import windows.generated_def.winfuncs as winfuncs
from windows.generated_def.ntstatus import NtStatusException
from windows.dbgprint import dbgprint


kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.Advapi32
iphlpapi = ctypes.windll.iphlpapi
ntdll = ctypes.windll.ntdll


class Kernel32Error(WindowsError):
    def __new__(cls, func_name):
        win_error = ctypes.WinError()
        api_error = super(Kernel32Error, cls).__new__(cls)
        api_error.api_name = func_name
        api_error.winerror = win_error.winerror
        api_error.strerror = win_error.strerror
        api_error.args = (func_name, win_error.winerror, win_error.strerror)
        return api_error

    def __repr__(self):
        return "{0}: {1}".format(self.api_name, super(Kernel32Error, self).__repr__())

    def __str__(self):
        return "{0}: {1}".format(self.api_name, super(Kernel32Error, self).__str__())


class IphlpapiError(Kernel32Error):

    def __new__(cls, func_name, code):
        win_error = ctypes.WinError(code)
        api_error = super(Kernel32Error, cls).__new__(cls)
        api_error.api_name = func_name
        api_error.winerror = win_error.winerror
        api_error.strerror = win_error.strerror
        api_error.args = (func_name, win_error.winerror, win_error.strerror)
        return api_error

    def __init__(self, func_name, code):
        pass


# Error check method
def no_error_check(func_name, result, func, args):
    """Nothing special"""
    return args


def minus_one_error_check(func_name, result, func, args):
    if result == -1:
        raise Kernel32Error(func_name)
    return args


def kernel32_error_check(func_name, result, func, args):
    """raise Kernel32Error if result is 0"""
    if not result:
        raise Kernel32Error(func_name)
    return args


def kernel32_zero_check(func_name, result, func, args):
    """raise Kernel32Error if result is NOT 0"""
    if result:
        raise Kernel32Error(func_name)
    return args


def iphlpapi_error_check(func_name, result, func, args):
    """raise IphlpapiError if result is NOT 0"""
    if result:
        raise IphlpapiError(func_name, result)
    return args


def error_ntstatus(func_name, result, func, args):
    if result:
        raise NtStatusException(result & 0xffffffff)
    return args


class ExportNotFound(AttributeError):
        def __init__(self, func_name, api_name):
            self.func_name = func_name
            self.api_name = api_name
            super(ExportNotFound, self).__init__("Function {0} not found into {1}".format(func_name, api_name))


class ApiProxy(object):
    APIDLL = None
    """Create a python wrapper around a kernel32 function"""
    def __init__(self, func_name, error_check=None):
        self.func_name = func_name
        if error_check is None:
            error_check = self.default_error_check
        self.error_check = functools.wraps(error_check)(functools.partial(error_check, func_name))

    def __call__(self, python_proxy, ):
        prototype = getattr(winfuncs, self.func_name + "Prototype")
        params = getattr(winfuncs, self.func_name + "Params")
        try:
            c_prototyped = prototype((self.func_name, self.APIDLL), params)
        except AttributeError:
            raise ExportNotFound(self.func_name, self.APIDLL._name)
        c_prototyped.errcheck = self.error_check
        if (self.error_check.__doc__):
            doc = python_proxy.__doc__
            doc = doc if doc else ""
            python_proxy.__doc__ = doc + "\nErrcheck:\n   " + self.error_check.__doc__
        params_name = [param[1] for param in params]

        def perform_call(*args):
            if len(params_name) != len(args):
                print("ERROR:")
                print("Expected params: {0}".format(params_name))
                print("Just Got params: {0}".format(args))
                raise ValueError("I do not have all parameters: how is that possible ?")
            for param_name, param_value in zip(params_name, args):
                if param_value is NeededParameter:
                    raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.func_name, param_name))
            return c_prototyped(*args)
        setattr(python_proxy, "ctypes_function", perform_call)
        return python_proxy


class Kernel32Proxy(ApiProxy):
    APIDLL = kernel32
    default_error_check = staticmethod(kernel32_error_check)


class Advapi32Proxy(ApiProxy):
    APIDLL = advapi32
    default_error_check = staticmethod(kernel32_error_check)


class IphlpapiProxy(ApiProxy):
    APIDLL = iphlpapi
    default_error_check = staticmethod(iphlpapi_error_check)


class NtdllProxy(ApiProxy):
    APIDLL = ntdll
    default_error_check = staticmethod(kernel32_zero_check)


class OptionalExport(object):
    """used 'around' a Proxy decorator
       Should be used for export that are not available everywhere (ntdll internals | 32/64 bits stuff)
       If the export is not found the function will be None

       Example:
            @OptionalExport(NtdllProxy('NtWow64ReadVirtualMemory64'))
            def NtWow64ReadVirtualMemory64(...)
            ...
    """
    def __init__(self, subdecorator):
        self.subdecorator = subdecorator

    def __call__(self, f):
        try:
            return self.subdecorator(f)
        except ExportNotFound as e:
            dbgprint("Export <{e.func_name}> not found in <{e.api_name}>".format(e=e), "EXPORTNOTFOUND")
            return None


def TransparentApiProxy(APIDLL, func_name, error_check):
    """Create a ctypes function for 'func_name' with no python arg pre-check"""

    prototype = getattr(winfuncs, func_name + "Prototype")
    args = getattr(winfuncs, func_name + "Params")
    try:
        c_prototyped = prototype((func_name, APIDLL), args)
    except AttributeError:
        raise ExportNotFound(func_name, APIDLL._name)
    c_prototyped.errcheck = functools.wraps(error_check)(functools.partial(error_check, func_name))
    return c_prototyped


TransparentKernel32Proxy = lambda func_name, error_check=kernel32_error_check: TransparentApiProxy(kernel32, func_name, error_check)
TransparentAdvapi32Proxy = lambda func_name, error_check=kernel32_error_check: TransparentApiProxy(advapi32, func_name, error_check)
TransparentIphlpapiProxy = lambda func_name, error_check=iphlpapi_error_check: TransparentApiProxy(iphlpapi, func_name, error_check)


class NeededParameterType(object):
    _inst = None

    def __new__(cls):
        if cls._inst is None:
            cls._inst = super(NeededParameterType, cls).__new__(cls)
        return cls._inst

    def __repr__(self):
        return "NeededParameter"
NeededParameter = NeededParameterType()

ExitProcess = TransparentKernel32Proxy("ExitProcess")
TerminateProcess = TransparentKernel32Proxy("TerminateProcess")
CloseHandle = TransparentKernel32Proxy("CloseHandle")
GetProcAddress = TransparentKernel32Proxy("GetProcAddress")
LoadLibraryA = TransparentKernel32Proxy("LoadLibraryA")
LoadLibraryW = TransparentKernel32Proxy("LoadLibraryW")
GetLastError = TransparentKernel32Proxy("GetLastError", no_error_check)
GetCurrentProcess = TransparentKernel32Proxy("GetCurrentProcess")
GetCurrentProcessorNumber = TransparentKernel32Proxy("GetCurrentProcessorNumber", no_error_check)
GetCurrentThread = TransparentKernel32Proxy("GetCurrentThread")
AllocConsole = TransparentKernel32Proxy("AllocConsole")
FreeConsole = TransparentKernel32Proxy("FreeConsole")
GetStdHandle = TransparentKernel32Proxy("GetStdHandle")
SetStdHandle = TransparentKernel32Proxy("SetStdHandle")
GetCurrentThreadId = TransparentKernel32Proxy("GetCurrentThreadId")
TerminateThread = TransparentKernel32Proxy("TerminateThread")
ExitThread = TransparentKernel32Proxy("ExitThread")
SuspendThread = TransparentKernel32Proxy("SuspendThread", minus_one_error_check)
ResumeThread = TransparentKernel32Proxy("ResumeThread", minus_one_error_check)
GetThreadId = TransparentKernel32Proxy("GetThreadId")

Wow64DisableWow64FsRedirection = OptionalExport(TransparentKernel32Proxy)("Wow64DisableWow64FsRedirection")
Wow64RevertWow64FsRedirection = OptionalExport(TransparentKernel32Proxy)("Wow64RevertWow64FsRedirection")
Wow64EnableWow64FsRedirection = OptionalExport(TransparentKernel32Proxy)("Wow64EnableWow64FsRedirection")


@Kernel32Proxy("CreateFileA")
def CreateFileA(lpFileName, dwDesiredAccess=GENERIC_READ, dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=OPEN_EXISTING, dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL, hTemplateFile=None):
    return CreateFileA.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)


@Kernel32Proxy("CreateFileW")
def CreateFileW(lpFileName, dwDesiredAccess=GENERIC_READ, dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=OPEN_EXISTING, dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL, hTemplateFile=None):
    return CreateFileA.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)


@Kernel32Proxy("VirtualAlloc")
def VirtualAlloc(lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT, flProtect=PAGE_EXECUTE_READWRITE):
    return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)


@Kernel32Proxy("VirtualFree")
def VirtualFree(lpAddress, dwSize=0, dwFreeType=MEM_RELEASE):
    return VirtualFree.ctypes_function(lpAddress, dwSize, dwFreeType)


@Kernel32Proxy("VirtualAllocEx")
def VirtualAllocEx(hProcess, lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT, flProtect=PAGE_EXECUTE_READWRITE):
    return VirtualAllocEx.ctypes_function(hProcess, lpAddress, dwSize, flAllocationType, flProtect)


@Kernel32Proxy("VirtualFreeEx")
def VirtualFreeEx(hProcess, lpAddress, dwSize=0, dwFreeType=MEM_RELEASE):
    return VirtualFreeEx.ctypes_function(hProcess, lpAddress, dwSize, dwFreeType)


@Kernel32Proxy("CreateThread")
def CreateThread(lpThreadAttributes=None, dwStackSize=0, lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None):
    return CreateThread.ctypes_function(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)


@Kernel32Proxy("CreateRemoteThread")
def CreateRemoteThread(hProcess=NeededParameter, lpThreadAttributes=None, dwStackSize=0,
                       lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None):
    return CreateRemoteThread.ctypes_function(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)


@Kernel32Proxy("VirtualProtect")
def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect=0):
    return VirtualProtect.ctypes_function(lpAddress, dwSize, flNewProtect, lpflOldProtect)


@Kernel32Proxy("CreateProcessA")
def CreateProcessA(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False,
                   dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None):
    if lpStartupInfo is None:
        StartupInfo = STARTUPINFOA()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = STARTF_USESHOWWINDOW
        StartupInfo.wShowWindow = SW_HIDE
        lpStartupInfo = ctypes.byref(StartupInfo)
    if lpProcessInformation is None:
        lpProcessInformation = ctypes.byref(PROCESS_INFORMATION())
    return CreateProcessA.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)


@Kernel32Proxy("CreateProcessW")
def CreateProcessW(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False,
                   dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None):
    if lpStartupInfo is None:
        StartupInfo = STARTUPINFOW()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = STARTF_USESHOWWINDOW
        StartupInfo.wShowWindow = SW_HIDE
        lpStartupInfo = ctypes.byref(StartupInfo)
    if lpProcessInformation is None:
        lpProcessInformation = ctypes.byref(PROCESS_INFORMATION())
    return CreateProcessW.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)


@Kernel32Proxy("GetThreadContext")
def GetThreadContext(hThread, lpContext=None):
    if lpContext is None:
        Context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        lpContext = ctypes.byref(Context)
    return GetThreadContext.ctypes_function(hThread, lpContext)


@Kernel32Proxy("SetThreadContext")
def SetThreadContext(hThread, lpContext):
    """ Allows to directly pass a CONTEXT and will call with byref(CONTEXT) by itself"""
    if type(lpContext) == CONTEXT:
        lpContext = ctypes.byref(lpContext)
    return SetThreadContext.ctypes_function(hThread, lpContext)


@Kernel32Proxy("OpenThread")
def OpenThread(dwDesiredAccess=THREAD_ALL_ACCESS, bInheritHandle=0, dwThreadId=NeededParameter):
    return OpenThread.ctypes_function(dwDesiredAccess, bInheritHandle, dwThreadId)


@Kernel32Proxy("OpenProcess")
def OpenProcess(dwDesiredAccess=PROCESS_ALL_ACCESS, bInheritHandle=0, dwProcessId=NeededParameter):
    return OpenProcess.ctypes_function(dwDesiredAccess, bInheritHandle, dwProcessId)


@Kernel32Proxy("ReadProcessMemory")
def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None):
    return ReadProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)


@Kernel32Proxy("WriteProcessMemory")
def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize=None, lpNumberOfBytesWritten=None):
    """Computer nSize with len(lpBuffer) if not given"""
    if nSize is None:
        nSize = len(lpBuffer)
    return WriteProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)


@Kernel32Proxy('SetThreadAffinityMask')
def SetThreadAffinityMask(hThread=None, dwThreadAffinityMask=NeededParameter):
    """If hThread is not given, it will be the current thread"""
    if hThread is None:
        hThread = GetCurrentThread()
    return SetThreadAffinityMask.ctypes_function(hThread, dwThreadAffinityMask)


@Kernel32Proxy("CreateToolhelp32Snapshot")
def CreateToolhelp32Snapshot(dwFlags, th32ProcessID=0):
    return CreateToolhelp32Snapshot.ctypes_function(dwFlags, th32ProcessID)


@Kernel32Proxy("Thread32First", no_error_check)
def Thread32First(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return Thread32First.ctypes_function(hSnapshot, lpte)


@Kernel32Proxy("Thread32Next", no_error_check)
def Thread32Next(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return Thread32Next.ctypes_function(hSnapshot, lpte)


@Kernel32Proxy("Process32First", no_error_check)
def Process32First(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return Process32First.ctypes_function(hSnapshot, lpte)


@Kernel32Proxy("Process32Next", no_error_check)
def Process32Next(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return Process32Next.ctypes_function(hSnapshot, lpte)


# File stuff
@Kernel32Proxy("WriteFile")
def WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite=None, lpNumberOfBytesWritten=None, lpOverlapped=None):
    if nNumberOfBytesToWrite is None:
        nNumberOfBytesToWrite = len(lpBuffer)
    if lpOverlapped is None and lpNumberOfBytesWritten is None:
        lpNumberOfBytesWritten = ctypes.byref(DWORD())
    return WriteFile.ctypes_function(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)


# Exception stuff
@Kernel32Proxy("AddVectoredContinueHandler")
def AddVectoredContinueHandler(FirstHandler=1, VectoredHandler=NeededParameter):
    return AddVectoredContinueHandler.ctypes_function(FirstHandler, VectoredHandler)


@Kernel32Proxy("AddVectoredExceptionHandler")
def AddVectoredExceptionHandler(FirstHandler=1, VectoredHandler=NeededParameter):
    return AddVectoredExceptionHandler.ctypes_function(FirstHandler, VectoredHandler)


@Kernel32Proxy("RemoveVectoredExceptionHandler")
def RemoveVectoredExceptionHandler(Handler):
    return RemoveVectoredExceptionHandler.ctypes_function(Handler)


@Kernel32Proxy("WaitForSingleObject", kernel32_zero_check)
def WaitForSingleObject(hHandle, dwMilliseconds=INFINITE):
    return WaitForSingleObject.ctypes_function(hHandle, dwMilliseconds)


@Kernel32Proxy("DeviceIoControl")
def DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize=None, lpOutBuffer=NeededParameter, nOutBufferSize=None, lpBytesReturned=None, lpOverlapped=None):
    if nInBufferSize is None:
        nInBufferSize = len(lpInBuffer)
    if nOutBufferSize is None:
        nOutBufferSize = len(lpOutBuffer)
    if lpBytesReturned is None:
        # Some windows check 0 / others does not
        lpBytesReturned = ctypes.byref(DWORD())
    return DeviceIoControl.ctypes_function(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)


# ### NTDLL #### #

@OptionalExport(NtdllProxy('NtWow64ReadVirtualMemory64', error_ntstatus))
def NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None):
    return NtWow64ReadVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)


def ntquerysysteminformation_error_check(func_name, result, func, args):
    if result == 0:
        return args
    # Ignore STATUS_INFO_LENGTH_MISMATCH if SystemInformation is None
    if result == STATUS_INFO_LENGTH_MISMATCH and args[1] is None:
        return args
    raise Kernel32Error("{0} failed with NTStatus {1}".format(func_name, hex(result)))


@NtdllProxy('NtQuerySystemInformation', ntquerysysteminformation_error_check)
def NtQuerySystemInformation(SystemInformationClass, SystemInformation=None, SystemInformationLength=0, ReturnLength=NeededParameter):
    if SystemInformation is not None and SystemInformation == 0:
        SystemInformationLength = ctypes.sizeof(SystemInformation)
    return NtQuerySystemInformation.ctypes_function(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)


# ##### ADVAPI32 ####### #

@Advapi32Proxy('OpenProcessToken')
def OpenProcessToken(ProcessHandle=None, DesiredAccess=NeededParameter, TokenHandle=NeededParameter):
    """If ProcessHandle is None: take the current process"""
    if ProcessHandle is None:
        ProcessHandle = GetCurrentProcess()
    return OpenProcessToken.ctypes_function(ProcessHandle, DesiredAccess, TokenHandle)


@Advapi32Proxy('LookupPrivilegeValueA')
def LookupPrivilegeValueA(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter):
    return LookupPrivilegeValueA.ctypes_function(lpSystemName, lpName, lpLuid)


@Advapi32Proxy('LookupPrivilegeValueW')
def LookupPrivilegeValueW(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter):
    return LookupPrivilegeValueW.ctypes_function(lpSystemName, lpName, lpLuid)


@Advapi32Proxy('AdjustTokenPrivileges')
def AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges=False, NewState=NeededParameter, BufferLength=None, PreviousState=None, ReturnLength=None):
    if BufferLength is None:
        BufferLength = ctypes.sizeof(NewState)
    return AdjustTokenPrivileges.ctypes_function(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength)


# Registry stuff

@Advapi32Proxy('GetTokenInformation')
def GetTokenInformation(TokenHandle=NeededParameter, TokenInformationClass=NeededParameter, TokenInformation=None, TokenInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = ctypes.byref(DWORD())
    return GetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength)


@Advapi32Proxy('RegOpenKeyExA', kernel32_zero_check)
def RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult):
    return RegOpenKeyExA.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)


# TODO: default values? which ones ?

@Advapi32Proxy('RegOpenKeyExW', kernel32_zero_check)
def RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult):
    return RegOpenKeyExW.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)


@Advapi32Proxy('RegGetValueA', kernel32_zero_check)
def RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
    return RegGetValueA.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)


@Advapi32Proxy('RegGetValueW', kernel32_zero_check)
def RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
    return RegGetValueW.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)


@Advapi32Proxy('RegCloseKey', kernel32_zero_check)
def RegCloseKey(hKey):
    return RegCloseKey.ctypes_function(hKey)


# ##### Iphlpapi (network list and stuff) ###### #
SetTcpEntry = TransparentIphlpapiProxy('SetTcpEntry')


@OptionalExport(IphlpapiProxy('GetExtendedTcpTable'))
def GetExtendedTcpTable(pTcpTable, pdwSize=None, bOrder=True, ulAf=NeededParameter, TableClass=TCP_TABLE_OWNER_PID_ALL, Reserved=0):
    if pdwSize is None:
        ctypes.sizeof(pTcpTable)
    return GetExtendedTcpTable.ctypes_function(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)
