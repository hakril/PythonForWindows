import ctypes
import functools

from ctypes.wintypes import *
from windows.generated_def.winstructs import *
from windows.generated_def.windef import *
import windows.generated_def.winfuncs as winfuncs
from windows.generated_def.ntstatus import NtStatusException
from windows.dbgprint import dbgprint


def is_implemented(winfunc):
    try:
        winfunc.force_resolution()
    except ExportNotFound:
        return False
    return True

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

    def __new__(cls, func_name, code, strerror=None):
        win_error = ctypes.WinError(code)
        api_error = super(Kernel32Error, cls).__new__(cls)
        api_error.api_name = func_name
        api_error.winerror = win_error.winerror
        if strerror is not None:
            api_error.strerror = strerror
        else:
            api_error.strerror = win_error.strerror
        api_error.args = (func_name, api_error.winerror, api_error.strerror)
        return api_error

    def __init__(self, func_name, code, strerror=None):
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


class ExportNotFound(RuntimeError):
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
        self._cprototyped = None

    def __call__(self, python_proxy, ):
        prototype = getattr(winfuncs, self.func_name + "Prototype")
        params = getattr(winfuncs, self.func_name + "Params")
        python_proxy.prototype = prototype
        python_proxy.params = params
        python_proxy.errcheck = self.error_check
        params_name = [param[1] for param in params]
        if (self.error_check.__doc__):
            doc = python_proxy.__doc__
            doc = doc if doc else ""
            python_proxy.__doc__ = doc + "\nErrcheck:\n   " + self.error_check.__doc__


        def generate_ctypes_function():
            try:
                c_prototyped = prototype((self.func_name, getattr(ctypes.windll, self.APIDLL)), params)
            except (AttributeError, WindowsError):
                raise ExportNotFound(self.func_name, self.APIDLL)
            c_prototyped.errcheck = self.error_check
            self._cprototyped = c_prototyped


        def perform_call(*args):
            if len(params_name) != len(args):
                print("ERROR:")
                print("Expected params: {0}".format(params_name))
                print("Just Got params: {0}".format(args))
                raise ValueError("I do not have all parameters: how is that possible ?")
            for param_name, param_value in zip(params_name, args):
                if param_value is NeededParameter:
                    raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.func_name, param_name))
            if self._cprototyped is None:
                generate_ctypes_function()
            return self._cprototyped(*args)

        setattr(python_proxy, "ctypes_function", perform_call)
        setattr(python_proxy, "force_resolution", generate_ctypes_function)
        return python_proxy


class Kernel32Proxy(ApiProxy):
    APIDLL = "kernel32"
    default_error_check = staticmethod(kernel32_error_check)


class Advapi32Proxy(ApiProxy):
    APIDLL = "advapi32"
    default_error_check = staticmethod(kernel32_error_check)


class IphlpapiProxy(ApiProxy):
    APIDLL = "iphlpapi"
    default_error_check = staticmethod(iphlpapi_error_check)

class NtdllProxy(ApiProxy):
    APIDLL = "ntdll"
    default_error_check = staticmethod(kernel32_zero_check)

class WinTrustProxy(ApiProxy):
    APIDLL = "wintrust"
    default_error_check = staticmethod(no_error_check)

class Ole32Proxy(ApiProxy):
    APIDLL = "ole32"
    default_error_check = staticmethod(no_error_check)

class PsapiProxy(ApiProxy):
    APIDLL = "psapi"
    default_error_check = staticmethod(kernel32_error_check)

class User32Proxy(ApiProxy):
    APIDLL = "user32"
    default_error_check = staticmethod(kernel32_error_check)

class VersionProxy(ApiProxy):
    APIDLL = "version"
    default_error_check = staticmethod(kernel32_error_check)

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
            x = self.subdecorator(f)
            x.force_resolution()
            return x
        except ExportNotFound as e:
            dbgprint("Export <{e.func_name}> not found in <{e.api_name}>".format(e=e), "EXPORTNOTFOUND")
            return None

class TransparentApiProxy(object):
    def __init__(self, DLLNAME, func_name, error_check):
        self.dll_name = DLLNAME
        self.func_name = func_name
        self.error_check = error_check
        self._ctypes_function = None

        self.prototype = getattr(winfuncs, func_name + "Prototype")
        # TODO: fix double name..
        self.params = getattr(winfuncs, func_name + "Params")
        self.args = getattr(winfuncs, func_name + "Params")

    def __call__(self, *args, **kwargs):
        if self._ctypes_function is None:
            self.force_resolution()
        return self._ctypes_function(*args, **kwargs)

    def force_resolution(self):
        try:
            c_prototyped = self.prototype((self.func_name, getattr(ctypes.windll, self.dll_name)), self.args)
        except AttributeError:
            raise ExportNotFound(self.func_name, self.dll_name)
        c_prototyped.errcheck = functools.wraps(self.error_check)(functools.partial(self.error_check, self.func_name))
        self._ctypes_function = c_prototyped


TransparentKernel32Proxy = lambda func_name, error_check=kernel32_error_check: TransparentApiProxy("kernel32", func_name, error_check)
TransparentUser32Proxy = lambda func_name, error_check=kernel32_error_check: TransparentApiProxy("user32", func_name, error_check)
TransparentAdvapi32Proxy = lambda func_name, error_check=kernel32_error_check: TransparentApiProxy("advapi32", func_name, error_check)
TransparentIphlpapiProxy = lambda func_name, error_check=iphlpapi_error_check: TransparentApiProxy("iphlpapi", func_name, error_check)


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
VirtualQueryEx = TransparentKernel32Proxy("VirtualQueryEx")
GetExitCodeThread = TransparentKernel32Proxy("GetExitCodeThread")
GetExitCodeProcess = TransparentKernel32Proxy("GetExitCodeProcess")
GetProcessId = TransparentKernel32Proxy("GetProcessId")
lstrcmpA = TransparentKernel32Proxy("lstrcmpA")
lstrcmpW = TransparentKernel32Proxy("lstrcmpW")
GetVersionExA = TransparentKernel32Proxy("GetVersionExA")
GetVersionExW = TransparentKernel32Proxy("GetVersionExW")
GetComputerNameA = TransparentKernel32Proxy("GetComputerNameA")
GetComputerNameW = TransparentKernel32Proxy("GetComputerNameW")



Wow64DisableWow64FsRedirection = OptionalExport(TransparentKernel32Proxy)("Wow64DisableWow64FsRedirection")
Wow64RevertWow64FsRedirection = OptionalExport(TransparentKernel32Proxy)("Wow64RevertWow64FsRedirection")
Wow64EnableWow64FsRedirection = OptionalExport(TransparentKernel32Proxy)("Wow64EnableWow64FsRedirection")
Wow64GetThreadContext = OptionalExport(TransparentKernel32Proxy)("Wow64GetThreadContext")


def CreateFile_error_check(func_name, result, func, args):
    """raise Kernel32Error if result is NOT 0"""
    if result == INVALID_HANDLE_VALUE:
        raise Kernel32Error(func_name)
    return args


@Kernel32Proxy("CreateFileA", error_check=CreateFile_error_check)
def CreateFileA(lpFileName, dwDesiredAccess=GENERIC_READ, dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=OPEN_EXISTING, dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL, hTemplateFile=None):
    return CreateFileA.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)


@Kernel32Proxy("CreateFileW", error_check=CreateFile_error_check)
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
def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect=None):
    if lpflOldProtect is None:
        lpflOldProtect = ctypes.byref(DWORD())
    return VirtualProtect.ctypes_function(lpAddress, dwSize, flNewProtect, lpflOldProtect)


@Kernel32Proxy("VirtualProtectEx")
def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect=None):
    if lpflOldProtect is None:
        lpflOldProtect = ctypes.byref(DWORD())
    return VirtualProtectEx.ctypes_function(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)

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
    return SetThreadContext.ctypes_function(hThread, lpContext)

@Kernel32Proxy("Wow64SetThreadContext")
def Wow64SetThreadContext(hThread, lpContext):
    return Wow64SetThreadContext.ctypes_function(hThread, lpContext)


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


@Kernel32Proxy("GetProcessTimes")
def GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime):
    return GetProcessTimes.ctypes_function(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime)

@Kernel32Proxy('SetThreadAffinityMask')
def SetThreadAffinityMask(hThread=None, dwThreadAffinityMask=NeededParameter):
    """If hThread is not given, it will be the current thread"""
    if hThread is None:
        hThread = GetCurrentThread()
    return SetThreadAffinityMask.ctypes_function(hThread, dwThreadAffinityMask)


@Kernel32Proxy("CreateToolhelp32Snapshot")
def CreateToolhelp32Snapshot(dwFlags, th32ProcessID=0):
    return CreateToolhelp32Snapshot.ctypes_function(dwFlags, th32ProcessID)


@Kernel32Proxy("Thread32First")
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


@Kernel32Proxy("Process32First")
def Process32First(hSnapshot, lpte):
    return Process32First.ctypes_function(hSnapshot, lpte)


@Kernel32Proxy("Process32Next", no_error_check)
def Process32Next(hSnapshot, lpte):
    return Process32Next.ctypes_function(hSnapshot, lpte)

@Kernel32Proxy("OpenEventA")
def OpenEventA(dwDesiredAccess, bInheritHandle, lpName):
    return OpenEventA.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)

@Kernel32Proxy("OpenEventW")
def OpenEventW(dwDesiredAccess, bInheritHandle, lpName):
    return OpenEventA.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)

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



@Kernel32Proxy("CreateFileMappingA")
def CreateFileMappingA(hFile, lpFileMappingAttributes=None, flProtect=PAGE_READWRITE, dwMaximumSizeHigh=0, dwMaximumSizeLow=NeededParameter, lpName=NeededParameter):
    return CreateFileMappingA.ctypes_function(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)


@Kernel32Proxy("CreateFileMappingW")
def CreateFileMappingW(hFile, lpFileMappingAttributes=None, flProtect=PAGE_READWRITE, dwMaximumSizeHigh=0, dwMaximumSizeLow=0, lpName=NeededParameter):
    return CreateFileMappingW.ctypes_function(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)


@Kernel32Proxy("MapViewOfFile")
def MapViewOfFile(hFileMappingObject, dwDesiredAccess=FILE_MAP_ALL_ACCESS, dwFileOffsetHigh=0, dwFileOffsetLow=0, dwNumberOfBytesToMap=NeededParameter):
    return MapViewOfFile.ctypes_function(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)


@Kernel32Proxy("DuplicateHandle")
def DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess=0, bInheritHandle=False, dwOptions=0):
    return DuplicateHandle.ctypes_function(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions)

@Kernel32Proxy("GetLongPathNameA")
def GetLongPathNameA(lpszShortPath, lpszLongPath, cchBuffer=None):
    if cchBuffer is None:
        cchBuffer = len(lpszLongPath)
    return GetLongPathNameA.ctypes_function(lpszShortPath, lpszLongPath, cchBuffer)

@Kernel32Proxy("GetShortPathNameA")
def GetShortPathNameA(lpszLongPath, lpszShortPath, cchBuffer=None):
    if cchBuffer is None:
        cchBuffer = len(lpszShortPath)
    return GetShortPathNameA.ctypes_function(lpszLongPath, lpszShortPath, cchBuffer)

# TODO: might be in another DLL depending of version
# Should handle this..

def GetMappedFileNameWWrapper(hProcess, lpv, lpFilename, nSize=None):
    if nSize is None:
        nSize = ctypes.sizeof(lpFilename)
    return GetMappedFileNameWWrapper.ctypes_function(hProcess, lpv, lpFilename, nSize)
GetMappedFileNameW = OptionalExport(Kernel32Proxy("GetMappedFileNameW"))(GetMappedFileNameWWrapper)


def GetMappedFileNameAWrapper(hProcess, lpv, lpFilename, nSize=None):
    if nSize is None:
        nSize = ctypes.sizeof(lpFilename)
    return GetMappedFileNameAWrapper.ctypes_function(hProcess, lpv, lpFilename, nSize)
GetMappedFileNameA = OptionalExport(Kernel32Proxy("GetMappedFileNameA"))(GetMappedFileNameAWrapper)

def QueryWorkingSetWrapper(hProcess, pv, cb):
    return QueryWorkingSet.ctypes_function(hProcess, pv, cb)
QueryWorkingSet = OptionalExport(Kernel32Proxy("QueryWorkingSet"))(QueryWorkingSetWrapper)

def QueryWorkingSetExWrapper(hProcess, pv, cb):
    return QueryWorkingSetEx.ctypes_function(hProcess, pv, cb)
QueryWorkingSetEx = OptionalExport(Kernel32Proxy("QueryWorkingSetEx"))(QueryWorkingSetExWrapper)

if GetMappedFileNameA is None:
    GetMappedFileNameW = PsapiProxy("GetMappedFileNameW")(GetMappedFileNameWWrapper)
    GetMappedFileNameA = PsapiProxy("GetMappedFileNameA")(GetMappedFileNameAWrapper)
    QueryWorkingSet = PsapiProxy("QueryWorkingSet")(QueryWorkingSetWrapper)
    QueryWorkingSetEx = PsapiProxy("QueryWorkingSetEx")(QueryWorkingSetExWrapper)

def GetModuleBaseNameAWrapper(hProcess, hModule, lpBaseName, nSize=None):
    if nSize is None:
        nSize = len(lpBaseName)
    return GetModuleBaseNameAWrapper.ctypes_function(hProcess, hModule, lpBaseName, nSize)
GetModuleBaseNameA = OptionalExport(Kernel32Proxy("GetMappedFileNameA"))(GetModuleBaseNameAWrapper)


def GetModuleBaseNameWWrapper(hProcess, hModule, lpBaseName, nSize=None):
    if nSize is None:
        nSize = len(lpBaseName)
    return GetModuleBaseNameWWrapper.ctypes_function(hProcess, hModule, lpBaseName, nSize)
GetModuleBaseNameA = OptionalExport(Kernel32Proxy("GetModuleBaseNameW"))(GetModuleBaseNameWWrapper)

if GetModuleBaseNameA is None:
    GetModuleBaseNameA = PsapiProxy("GetModuleBaseNameA")(GetModuleBaseNameAWrapper)
    GetModuleBaseNameW = PsapiProxy("GetModuleBaseNameW")(GetModuleBaseNameWWrapper)


def GetProcessImageFileNameAWrapper(hProcess, lpImageFileName, nSize=None):
    if nSize is None:
        nSize = len(lpImageFileName)
    return GetProcessImageFileNameAWrapper.ctypes_function(hProcess, lpImageFileName, nSize)
GetProcessImageFileNameA = OptionalExport(Kernel32Proxy("GetProcessImageFileNameA"))(GetProcessImageFileNameAWrapper)

def GetProcessImageFileNameWWrapper(hProcess, lpImageFileName, nSize=None):
    if nSize is None:
        nSize = len(lpImageFileName)
    return GetProcessImageFileNameWWrapper.ctypes_function(hProcess, lpImageFileName, nSize)
GetProcessImageFileNameW = OptionalExport(Kernel32Proxy("GetProcessImageFileNameW"))(GetProcessImageFileNameWWrapper)

if GetProcessImageFileNameA is None:
    GetProcessImageFileNameA = PsapiProxy("GetProcessImageFileNameA")(GetProcessImageFileNameAWrapper)
    GetProcessImageFileNameW = PsapiProxy("GetProcessImageFileNameW")(GetProcessImageFileNameWWrapper)

# Debug API

DebugBreak = TransparentKernel32Proxy("DebugBreak")
ContinueDebugEvent = TransparentKernel32Proxy("ContinueDebugEvent")
DebugActiveProcess = TransparentKernel32Proxy("DebugActiveProcess")
DebugActiveProcessStop = TransparentKernel32Proxy("DebugActiveProcessStop")
DebugSetProcessKillOnExit = TransparentKernel32Proxy("DebugSetProcessKillOnExit")
DebugBreakProcess = TransparentKernel32Proxy("DebugBreakProcess")

@Kernel32Proxy("WaitForDebugEvent")
def WaitForDebugEvent(lpDebugEvent, dwMilliseconds=INFINITE):
    return WaitForDebugEvent.ctypes_function(lpDebugEvent, dwMilliseconds)


# Volumes stuff

GetLogicalDriveStringsA = TransparentKernel32Proxy("GetLogicalDriveStringsA")
GetLogicalDriveStringsW = TransparentKernel32Proxy("GetLogicalDriveStringsW")
GetDriveTypeA = TransparentKernel32Proxy("GetDriveTypeA")
GetDriveTypeW = TransparentKernel32Proxy("GetDriveTypeW")
QueryDosDeviceA = TransparentKernel32Proxy("QueryDosDeviceA")
QueryDosDeviceW = TransparentKernel32Proxy("QueryDosDeviceW")
GetVolumeNameForVolumeMountPointA = TransparentKernel32Proxy("GetVolumeNameForVolumeMountPointA")
GetVolumeNameForVolumeMountPointW = TransparentKernel32Proxy("GetVolumeNameForVolumeMountPointW")

@Kernel32Proxy("GetVolumeInformationA")
def GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize):
    if nVolumeNameSize == 0 and lpVolumeNameBuffer is not None:
        nVolumeNameSize = len(lpVolumeNameBuffer)
    if nFileSystemNameSize == 0 and lpFileSystemNameBuffer is not None:
        nFileSystemNameSize = len(lpFileSystemNameBuffer)
    return GetVolumeInformationA.ctypes_function(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)


@Kernel32Proxy("GetVolumeInformationW")
def GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer=None, nVolumeNameSize=0, lpVolumeSerialNumber=None, lpMaximumComponentLength=None, lpFileSystemFlags=None, lpFileSystemNameBuffer=None, nFileSystemNameSize=0):
    if nVolumeNameSize == 0 and lpVolumeNameBuffer is not None:
        nVolumeNameSize = len(lpVolumeNameBuffer)
    if nFileSystemNameSize == 0 and lpFileSystemNameBuffer is not None:
        nFileSystemNameSize = len(lpFileSystemNameBuffer)
    return GetVolumeInformationW.ctypes_function(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)


@Kernel32Proxy("SetConsoleCtrlHandler")
def SetConsoleCtrlHandler(HandlerRoutine, Add):
    return SetConsoleCtrlHandler.ctypes_function(HandlerRoutine, Add)

# ### NTDLL #### #

@OptionalExport(NtdllProxy('NtWow64ReadVirtualMemory64', error_ntstatus))
def NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None):
    return NtWow64ReadVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

@OptionalExport(NtdllProxy('NtWow64WriteVirtualMemory64', error_ntstatus))
def NtWow64WriteVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten=None):
    return NtWow64WriteVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)

def ntquerysysteminformation_error_check(func_name, result, func, args):
    if result == 0:
        return args
    # Ignore STATUS_INFO_LENGTH_MISMATCH if SystemInformation is None
    if result == STATUS_INFO_LENGTH_MISMATCH and args[1] is None:
        return args
    raise Kernel32Error("{0} failed with NTStatus {1}".format(func_name, hex(result)))

@NtdllProxy("NtGetContextThread", error_ntstatus)
def NtGetContextThread(hThread, lpContext):
    return NtGetContextThread.ctypes_function(hThread, lpContext)

@NtdllProxy("LdrLoadDll", error_ntstatus)
def LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle):
    return LdrLoadDll.ctypes_function(PathToFile, Flags, ModuleFileName, ModuleHandle)


@NtdllProxy('NtQuerySystemInformation', ntquerysysteminformation_error_check)
def NtQuerySystemInformation(SystemInformationClass, SystemInformation=None, SystemInformationLength=0, ReturnLength=NeededParameter):
    if SystemInformation is not None and SystemInformationLength == 0:
        SystemInformationLength = ctypes.sizeof(SystemInformation)
    return NtQuerySystemInformation.ctypes_function(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)


@OptionalExport(NtdllProxy('NtQueryInformationProcess', error_ntstatus))
def NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength=0, ReturnLength=None):
    if ProcessInformation is not None and ProcessInformationLength == 0:
        ProcessInformationLength = ctypes.sizeof(ProcessInformation)
    if type(ProcessInformation) == PROCESS_BASIC_INFORMATION:
        ProcessInformation = byref(ProcessInformation)
    if ReturnLength is None:
        ReturnLength = byref(ULONG())
    return NtQueryInformationProcess.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)


@NtdllProxy('NtQueryInformationThread', error_ntstatus)
def NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = byref(ULONG())
    if ThreadInformation is not None and ThreadInformationLength == 0:
        ThreadInformationLength = ctypes.sizeof(ThreadInformation)
    return NtQueryInformationThread.ctypes_function(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)


@NtdllProxy('NtProtectVirtualMemory', error_ntstatus)
def NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection=None):
    if OldAccessProtection is None:
        OldAccessProtection = DWORD()
    return NtProtectVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection)

@OptionalExport(NtdllProxy('NtQueryVirtualMemory', error_ntstatus))
def NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation=NeededParameter, MemoryInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = byref(ULONG())
    if MemoryInformation is not None and MemoryInformationLength == 0:
        ProcessInformationLength = ctypes.sizeof(MemoryInformation)
    if type(MemoryInformation) == MEMORY_BASIC_INFORMATION64:
        MemoryInformation = byref(MemoryInformation)
    return NtQueryVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation=NeededParameter, MemoryInformationLength=0, ReturnLength=None)


@NtdllProxy('NtQueryObject', error_ntstatus)
def NtQueryObject(Handle, ObjectInformationClass, ObjectInformation=None, ObjectInformationLength=0, ReturnLength=NeededParameter):
    return NtQueryObject.ctypes_function(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength)

@OptionalExport(NtdllProxy('NtCreateThreadEx', error_ntstatus))
def NtCreateThreadEx(ThreadHandle=None, DesiredAccess=0x1fffff, ObjectAttributes=0, ProcessHandle=NeededParameter, lpStartAddress=NeededParameter, lpParameter=NeededParameter, CreateSuspended=0, dwStackSize=0, Unknown1=0, Unknown2=0, Unknown=0):
    if ThreadHandle is None:
        ThreadHandle = byref(HANDLE())
    return NtCreateThreadEx.ctypes_function(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3)


@NtdllProxy("NtSetContextThread", error_ntstatus)
def NtSetContextThread(hThread, lpContext):
    return NtSetContextThread.ctypes_function(hThread, lpContext)

@NtdllProxy("NtOpenEvent", error_ntstatus)
def NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes):
    return NtOpenEvent.ctypes_function(EventHandle, DesiredAccess, ObjectAttributes)


@NtdllProxy("NtAlpcCreatePort", error_ntstatus)
def NtAlpcCreatePort(PortHandle, ObjectAttributes, PortAttributes):
    return NtAlpcCreatePort.ctypes_function(PortHandle, ObjectAttributes, PortAttributes)


@NtdllProxy("NtAlpcConnectPort", error_ntstatus)
def NtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout):
    return NtAlpcConnectPort.ctypes_function(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)


@NtdllProxy("NtAlpcAcceptConnectPort", error_ntstatus)
def NtAlpcAcceptConnectPort(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection):
    return NtAlpcAcceptConnectPort.ctypes_function(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection)

@NtdllProxy("NtAlpcSendWaitReceivePort", error_ntstatus)
def NtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout):
    return NtAlpcSendWaitReceivePort.ctypes_function(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout)


@NtdllProxy("AlpcInitializeMessageAttribute", error_ntstatus)
def AlpcInitializeMessageAttribute(AttributeFlags, Buffer, BufferSize, RequiredBufferSize):
    return AlpcInitializeMessageAttribute.ctypes_function(AttributeFlags, Buffer, BufferSize, RequiredBufferSize)


@NtdllProxy("AlpcGetMessageAttribute", no_error_check)
def AlpcGetMessageAttribute(Buffer, AttributeFlag):
    return AlpcGetMessageAttribute.ctypes_function(Buffer, AttributeFlag)


@NtdllProxy("NtOpenDirectoryObject", error_ntstatus)
def NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes):
    return NtOpenDirectoryObject.ctypes_function(DirectoryHandle, DesiredAccess, ObjectAttributes)


@NtdllProxy("NtQueryDirectoryObject", error_ntstatus)
def NtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength):
    return NtQueryDirectoryObject.ctypes_function(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength)


@NtdllProxy("NtQuerySymbolicLinkObject", error_ntstatus)
def NtQuerySymbolicLinkObject(LinkHandle, LinkTarget, ReturnedLength):
    return NtQuerySymbolicLinkObject.ctypes_function(LinkHandle, LinkTarget, ReturnedLength)


@NtdllProxy("NtOpenSymbolicLinkObject", error_ntstatus)
def NtOpenSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes):
    return NtOpenSymbolicLinkObject.ctypes_function(LinkHandle, DesiredAccess, ObjectAttributes)

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


@Advapi32Proxy('LookupAccountSidA')
def LookupAccountSidA(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
    return LookupAccountSidA.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)


@Advapi32Proxy('LookupAccountSidW')
def LookupAccountSidW(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
    return LookupAccountSidW.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)

# Token stuff

GetSidSubAuthorityCount = TransparentAdvapi32Proxy("GetSidSubAuthorityCount")
GetSidSubAuthority = TransparentAdvapi32Proxy("GetSidSubAuthority")

@Advapi32Proxy('GetTokenInformation')
def GetTokenInformation(TokenHandle=NeededParameter, TokenInformationClass=NeededParameter, TokenInformation=None, TokenInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = ctypes.byref(DWORD())
    return GetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength)


@Advapi32Proxy('RegOpenKeyExA', kernel32_zero_check)
def RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult):
    return RegOpenKeyExA.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)

    # Registry stuff

# TODO: default values? which ones ?

@Advapi32Proxy('RegOpenKeyExW', kernel32_zero_check)
def RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult):
    return RegOpenKeyExW.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)


@Advapi32Proxy('RegGetValueA', kernel32_zero_check)
def RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
    return RegGetValueA.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)


@Advapi32Proxy('RegGetValueW', kernel32_zero_check)
def RegGetValueW(hkey, lpSubKey=None, lpValue=NeededParameter, dwFlags=0, pdwType=None, pvData=None, pcbData=None):
    return RegGetValueW.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)


@Advapi32Proxy('RegCloseKey', kernel32_zero_check)
def RegCloseKey(hKey):
    return RegCloseKey.ctypes_function(hKey)


# Services
@Advapi32Proxy('OpenSCManagerA')
def OpenSCManagerA(lpMachineName=None, lpDatabaseName=None, dwDesiredAccess=SC_MANAGER_ALL_ACCESS):
    return OpenSCManagerA.ctypes_function(lpMachineName, lpDatabaseName, dwDesiredAccess)


@Advapi32Proxy('OpenSCManagerW')
def OpenSCManagerW(lpMachineName=None, lpDatabaseName=None, dwDesiredAccess=SC_MANAGER_ALL_ACCESS):
    return OpenSCManagerW.ctypes_function(lpMachineName, lpDatabaseName, dwDesiredAccess)


@Advapi32Proxy('EnumServicesStatusExA')
def EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
    return EnumServicesStatusExA.ctypes_function(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)


@Advapi32Proxy('EnumServicesStatusExW')
def EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
    return EnumServicesStatusExW.ctypes_function(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)



# ##### Iphlpapi (network list and stuff) ###### #

def set_tcp_entry_error_check(func_name, result, func, args):
    """raise IphlpapiError if result is NOT 0 -- pretty print error 317"""
    if result:
        if result == 317:
            raise IphlpapiError(func_name, result, "<require elevated process>".format(func_name))
        raise IphlpapiError(func_name, result)
    return args

SetTcpEntry = TransparentIphlpapiProxy('SetTcpEntry', error_check=set_tcp_entry_error_check)


@OptionalExport(IphlpapiProxy('GetExtendedTcpTable'))
def GetExtendedTcpTable(pTcpTable, pdwSize=None, bOrder=True, ulAf=NeededParameter, TableClass=TCP_TABLE_OWNER_PID_ALL, Reserved=0):
    if pdwSize is None:
        pdwSize = ULONG(ctypes.sizeof(pTcpTable))
    return GetExtendedTcpTable.ctypes_function(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)


@IphlpapiProxy('GetInterfaceInfo')
def GetInterfaceInfo(pIfTable, dwOutBufLen=None):
    if dwOutBufLen is None:
        dwOutBufLen = ULONG(ctypes.sizeof(pIfTable))
    return GetInterfaceInfo.ctypes_function(pIfTable, dwOutBufLen)


@IphlpapiProxy('GetIfTable')
def GetIfTable(pIfTable, pdwSize, bOrder=False):
    return GetIfTable.ctypes_function(pIfTable, pdwSize, bOrder)

@IphlpapiProxy('GetIpAddrTable')
def GetIpAddrTable(pIpAddrTable, pdwSize, bOrder=False):
    return GetIpAddrTable.ctypes_function(pIpAddrTable, pdwSize, bOrder)

# ## WinTrustProxy  PE signature##

@WinTrustProxy('WinVerifyTrust')
def WinVerifyTrust(hwnd, pgActionID, pWVTData):
    return WinVerifyTrust.ctypes_function(hwnd, pgActionID, pWVTData)


# ##Wintrust: catalog stuff ###

@WinTrustProxy('CryptCATAdminCalcHashFromFileHandle', error_check=kernel32_error_check)
def CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags):
    return CryptCATAdminCalcHashFromFileHandle.ctypes_function(hFile, pcbHash, pbHash, dwFlags)


@WinTrustProxy('CryptCATAdminEnumCatalogFromHash')
def CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo):
    return CryptCATAdminEnumCatalogFromHash.ctypes_function(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo)


@WinTrustProxy('CryptCATAdminAcquireContext', error_check=kernel32_error_check)
def CryptCATAdminAcquireContext(phCatAdmin, pgSubsystem, dwFlags):
    return CryptCATAdminAcquireContext.ctypes_function(phCatAdmin, pgSubsystem, dwFlags)


@WinTrustProxy('CryptCATCatalogInfoFromContext', error_check=kernel32_error_check)
def CryptCATCatalogInfoFromContext(hCatInfo, psCatInfo, dwFlags):
    return CryptCATCatalogInfoFromContext.ctypes_function(hCatInfo, psCatInfo, dwFlags)


@WinTrustProxy('CryptCATAdminReleaseCatalogContext')
def CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwFlags):
    return CryptCATAdminReleaseCatalogContext.ctypes_function(hCatAdmin, hCatInfo, dwFlags)


@WinTrustProxy('CryptCATAdminReleaseContext')
def CryptCATAdminReleaseContext(hCatAdmin, dwFlags):
    return CryptCATAdminReleaseContext.ctypes_function(hCatAdmin, dwFlags)


# ## User32 stuff ## #

EnumWindows = TransparentUser32Proxy('EnumWindows')
GetWindowTextA = TransparentUser32Proxy('GetWindowTextA', no_error_check)
GetWindowTextW = TransparentUser32Proxy('GetWindowTextW', no_error_check)
GetWindowModuleFileNameA = TransparentUser32Proxy('GetWindowModuleFileNameA', no_error_check)
GetWindowModuleFileNameW = TransparentUser32Proxy('GetWindowModuleFileNameW', no_error_check)
GetSystemMetrics = TransparentUser32Proxy('GetSystemMetrics', no_error_check)

# ## Version stuff ## #

@VersionProxy("GetFileVersionInfoA")
def GetFileVersionInfoA(lptstrFilename, dwHandle=0, dwLen=None, lpData=NeededParameter):
    if dwLen is None and lpData is not None:
        dwLen = len(lpData)
    return GetFileVersionInfoA.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)


@VersionProxy("GetFileVersionInfoW")
def GetFileVersionInfoW(lptstrFilename, dwHandle=0, dwLen=None, lpData=NeededParameter):
    if dwLen is None and lpData is not None:
        dwLen = len(lpData)
    return GetFileVersionInfoA.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)


@VersionProxy("GetFileVersionInfoSizeA")
def GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle=None):
    if lpdwHandle is None:
        lpdwHandle = ctypes.byref(DWORD())
    return GetFileVersionInfoSizeA.ctypes_function(lptstrFilename, lpdwHandle)


@VersionProxy("GetFileVersionInfoSizeW")
def GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle=None):
    if lpdwHandle is None:
        lpdwHandle = ctypes.byref(DWORD())
    return GetFileVersionInfoSizeW.ctypes_function(lptstrFilename, lpdwHandle)


@VersionProxy("VerQueryValueA")
def VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen):
    return VerQueryValueA.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)


@VersionProxy("VerQueryValueW")
def VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen):
    return VerQueryValueW.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)


# ## Ole32Proxy (COM STUFF) ## #

@Ole32Proxy('CoInitializeEx', no_error_check)
def CoInitializeEx(pvReserved=None, dwCoInit=COINIT_MULTITHREADED):
    return CoInitializeEx.ctypes_function(pvReserved, dwCoInit)


@Ole32Proxy('CoInitializeSecurity')
def CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3):
    return CoInitializeSecurity.ctypes_function(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3)


@Ole32Proxy('CoCreateInstance')
def CoCreateInstance(rclsid, pUnkOuter=None, dwClsContext=CLSCTX_INPROC_SERVER, riid=NeededParameter, ppv=NeededParameter):
    return CoCreateInstance.ctypes_function(rclsid, pUnkOuter, dwClsContext, riid, ppv)


