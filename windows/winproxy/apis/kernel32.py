import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import (fail_on_zero,
                        no_error_check,
                        result_is_handle,
                        succeed_on_zero,
                        fail_on_minus_one)


class Kernel32Proxy(ApiProxy):
    APIDLL = "kernel32"
    default_error_check = staticmethod(fail_on_zero)

# Process

@Kernel32Proxy()
def GetCurrentProcess():
    return GetCurrentProcess.ctypes_function()

@Kernel32Proxy()
def ExitProcess(uExitCode):
   return ExitProcess.ctypes_function(uExitCode)

@Kernel32Proxy()
def TerminateProcess(hProcess, uExitCode):
    return TerminateProcess.ctypes_function(hProcess, uExitCode)

@Kernel32Proxy()
def GetExitCodeProcess(hProcess, lpExitCode):
    return GetExitCodeProcess.ctypes_function(hProcess, lpExitCode)

@Kernel32Proxy()
def GetProcessId(Process):
    return GetProcessId.ctypes_function(Process)


@Kernel32Proxy()
def CreateProcessA(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False,
                   dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None):
    if lpStartupInfo is None:
        StartupInfo = gdef.STARTUPINFOA()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = gdef.STARTF_USESHOWWINDOW
        StartupInfo.wShowWindow = gdef.SW_HIDE
        lpStartupInfo = ctypes.byref(StartupInfo)
    if lpProcessInformation is None:
        lpProcessInformation = ctypes.byref(gdef.PROCESS_INFORMATION())
    return CreateProcessA.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)


@Kernel32Proxy()
def CreateProcessW(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False,
                   dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None):
    if lpStartupInfo is None:
        StartupInfo = gdef.STARTUPINFOW()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = gdef.STARTF_USESHOWWINDOW
        StartupInfo.wShowWindow = gdef.SW_HIDE
        lpStartupInfo = ctypes.byref(StartupInfo)
    if lpProcessInformation is None:
        lpProcessInformation = ctypes.byref(gdef.PROCESS_INFORMATION())
    return CreateProcessW.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

@Kernel32Proxy()
def OpenProcess(dwDesiredAccess=gdef.PROCESS_ALL_ACCESS, bInheritHandle=0, dwProcessId=NeededParameter):
    return OpenProcess.ctypes_function(dwDesiredAccess, bInheritHandle, dwProcessId)


## Process Infos
@Kernel32Proxy()
def GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime):
    return GetProcessTimes.ctypes_function(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime)

@Kernel32Proxy()
def GetPriorityClass(hProcess):
    return GetPriorityClass.ctypes_function(hProcess)

@Kernel32Proxy()
def SetPriorityClass(hProcess, dwPriorityClass):
    return SetPriorityClass.ctypes_function(hProcess, dwPriorityClass)


PROCESS_MITIGATION_STUCTS = (gdef.PROCESS_MITIGATION_ASLR_POLICY,
                                gdef.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
                                gdef.PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
                                gdef.PROCESS_MITIGATION_DEP_POLICY,
                                gdef.PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
                                gdef.PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
                                gdef.PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
                                gdef.PROCESS_MITIGATION_POLICY,
                                gdef.PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
                                gdef.PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY)

@Kernel32Proxy()
def GetProcessMitigationPolicy(hProcess, MitigationPolicy, lpBuffer, dwLength=None):
    if dwLength is None:
        dwLength = ctypes.sizeof(lpBuffer)
    return GetProcessMitigationPolicy.ctypes_function(hProcess, MitigationPolicy, lpBuffer, dwLength)


@Kernel32Proxy()
def SetProcessMitigationPolicy(MitigationPolicy, lpBuffer, dwLength=None):
    if dwLength is None:
        dwLength = ctypes.sizeof(lpBuffer)
    if isinstance(lpBuffer, PROCESS_MITIGATION_STUCTS):
        lpBuffer = ctypes.byref(lpBuffer)
    return SetProcessMitigationPolicy.ctypes_function(MitigationPolicy, lpBuffer, dwLength)

@Kernel32Proxy()
def GetProcessDEPPolicy(hProcess, lpFlags, lpPermanent):
    return GetProcessDEPPolicy.ctypes_function(hProcess, lpFlags, lpPermanent)

## Process Infos ThreadAttribute

# ProcThreadAttributeList
def initializeprocthreadattributelist_error_check(func_name, result, func, args):
    if result:
        return args
    error = GetLastError()
    if error == gdef.ERROR_INSUFFICIENT_BUFFER and args[0] is None:
        return args
    raise WinproxyError(func_name)

@Kernel32Proxy(error_check=initializeprocthreadattributelist_error_check)
def InitializeProcThreadAttributeList(lpAttributeList=None, dwAttributeCount=NeededParameter, dwFlags=0, lpSize=NeededParameter):
    return InitializeProcThreadAttributeList.ctypes_function(lpAttributeList, dwAttributeCount, dwFlags, lpSize)


@Kernel32Proxy()
def UpdateProcThreadAttribute(lpAttributeList, dwFlags=0, Attribute=NeededParameter, lpValue=NeededParameter, cbSize=NeededParameter, lpPreviousValue=None, lpReturnSize=None):
    return UpdateProcThreadAttribute.ctypes_function(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize)


@Kernel32Proxy()
def DeleteProcThreadAttributeList(lpAttributeList):
    return DeleteProcThreadAttributeList.ctypes_function(lpAttributeList)


## Process-module

@Kernel32Proxy()
def GetModuleHandleA(lpModuleName):
    return GetModuleHandleA.ctypes_function(lpModuleName)

@Kernel32Proxy()
def GetModuleHandleW(lpModuleName):
    return GetModuleHandleW.ctypes_function(lpModuleName)

@Kernel32Proxy()
def GetModuleFileNameA(hModule, lpFilename, nSize):
    return GetModuleFileNameA.ctypes_function(hModule, lpFilename, nSize)

@Kernel32Proxy()
def GetModuleFileNameW(hModule, lpFilename, nSize):
    return GetModuleFileNameW.ctypes_function(hModule, lpFilename, nSize)

## Thread

@Kernel32Proxy()
def GetExitCodeThread(hThread, lpExitCode):
    return GetExitCodeThread.ctypes_function(hThread, lpExitCode)

@Kernel32Proxy()
def GetCurrentThread():
    return GetCurrentThread.ctypes_function()

@Kernel32Proxy()
def GetCurrentThreadId():
    return GetCurrentThreadId.ctypes_function()

@Kernel32Proxy()
def TerminateThread(hThread, dwExitCode):
    return TerminateThread.ctypes_function(hThread, dwExitCode)

@Kernel32Proxy()
def ExitThread(dwExitCode):
    return ExitThread.ctypes_function(dwExitCode)

@Kernel32Proxy(error_check=fail_on_minus_one)
def ResumeThread(hThread):
    return ResumeThread.ctypes_function(hThread)

@Kernel32Proxy(error_check=fail_on_minus_one)
def SuspendThread(hThread):
    return SuspendThread.ctypes_function(hThread)

@Kernel32Proxy()
def GetThreadId(Thread):
    return GetThreadId.ctypes_function(Thread)


@Kernel32Proxy()
def CreateThread(lpThreadAttributes=None, dwStackSize=0, lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None):
    return CreateThread.ctypes_function(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)


@Kernel32Proxy()
def CreateRemoteThread(hProcess=NeededParameter, lpThreadAttributes=None, dwStackSize=0,
                       lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None):
    return CreateRemoteThread.ctypes_function(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)

@Kernel32Proxy()
def GetThreadContext(hThread, lpContext):
    # TODO: RM ME IF TEST PASS
    # if lpContext is None:
        # Context = CONTEXT()
        # context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        # lpContext = ctypes.byref(Context)
    return GetThreadContext.ctypes_function(hThread, lpContext)


@Kernel32Proxy()
def SetThreadContext(hThread, lpContext):
    return SetThreadContext.ctypes_function(hThread, lpContext)

@Kernel32Proxy()
def OpenThread(dwDesiredAccess=gdef.THREAD_ALL_ACCESS, bInheritHandle=0, dwThreadId=NeededParameter):
    return OpenThread.ctypes_function(dwDesiredAccess, bInheritHandle, dwThreadId)

@Kernel32Proxy()
def SetThreadAffinityMask(hThread=None, dwThreadAffinityMask=NeededParameter):
    """If hThread is not given, it will be the current thread"""
    if hThread is None:
        hThread = GetCurrentThread()
    return SetThreadAffinityMask.ctypes_function(hThread, dwThreadAffinityMask)


## Memory

@Kernel32Proxy(error_check=succeed_on_zero)
def LocalFree(hMem):
    return LocalFree.ctypes_function(hMem)

@Kernel32Proxy()
def VirtualAlloc(lpAddress=0, dwSize=NeededParameter, flAllocationType=gdef.MEM_COMMIT, flProtect=gdef.PAGE_EXECUTE_READWRITE):
    return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)

@Kernel32Proxy()
def VirtualFree(lpAddress, dwSize=0, dwFreeType=gdef.MEM_RELEASE):
    return VirtualFree.ctypes_function(lpAddress, dwSize, dwFreeType)

@Kernel32Proxy()
def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect=None):
    if lpflOldProtect is None:
        lpflOldProtect = ctypes.byref(gdef.DWORD())
    return VirtualProtect.ctypes_function(lpAddress, dwSize, flNewProtect, lpflOldProtect)


## Memory remote

@Kernel32Proxy()
def VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength):
    return VirtualQueryEx.ctypes_function(hProcess, lpAddress, lpBuffer, dwLength)

@Kernel32Proxy()
def VirtualAllocEx(hProcess, lpAddress=0, dwSize=NeededParameter, flAllocationType=gdef.MEM_COMMIT, flProtect=gdef.PAGE_EXECUTE_READWRITE):
    return VirtualAllocEx.ctypes_function(hProcess, lpAddress, dwSize, flAllocationType, flProtect)

@Kernel32Proxy()
def VirtualFreeEx(hProcess, lpAddress, dwSize=0, dwFreeType=gdef.MEM_RELEASE):
    return VirtualFreeEx.ctypes_function(hProcess, lpAddress, dwSize, dwFreeType)


@Kernel32Proxy()
def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect=None):
    if lpflOldProtect is None:
        lpflOldProtect = ctypes.byref(gdef.DWORD())
    return VirtualProtectEx.ctypes_function(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)


@Kernel32Proxy()
def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None):
    return ReadProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

@Kernel32Proxy()
def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize=None, lpNumberOfBytesWritten=None):
    """Computer nSize with len(lpBuffer) if not given"""
    if nSize is None:
        nSize = len(lpBuffer)
    return WriteProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)


## Error

@Kernel32Proxy(error_check=no_error_check)
def GetLastError():
    return GetLastError.ctypes_function()

## Handle

@Kernel32Proxy()
def CloseHandle(hObject):
    return CloseHandle.ctypes_function(hObject)

@Kernel32Proxy()
def DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess=0, bInheritHandle=False, dwOptions=0):
    return DuplicateHandle.ctypes_function(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions)



## Process Modules
@Kernel32Proxy()
def GetProcAddress(hModule, lpProcName):
    return GetProcAddress.ctypes_function(hModule, lpProcName)

@Kernel32Proxy()
def LoadLibraryA(lpFileName):
    return LoadLibraryA.ctypes_function(lpFileName)

@Kernel32Proxy()
def LoadLibraryW(lpFileName):
    return LoadLibraryW.ctypes_function(lpFileName)

@Kernel32Proxy()
def LoadLibraryExA(lpLibFileName, hFile, dwFlags):
    return LoadLibraryExA.ctypes_function(lpLibFileName, hFile, dwFlags)

@Kernel32Proxy()
def LoadLibraryExW(lpLibFileName, hFile, dwFlags):
    return LoadLibraryExW.ctypes_function(lpLibFileName, hFile, dwFlags)

@Kernel32Proxy()
def FreeLibrary(hLibModule):
    return FreeLibrary.ctypes_function(hLibModule)

## Version

@Kernel32Proxy()
def GetVersionExA(lpVersionInformation):
    return GetVersionExA.ctypes_function(lpVersionInformation)

@Kernel32Proxy()
def GetVersionExW(lpVersionInformation):
    return GetVersionExW.ctypes_function(lpVersionInformation)



## Hardware

@Kernel32Proxy()
def GetCurrentProcessorNumber():
    return GetCurrentProcessorNumber.ctypes_function()

## Console

@Kernel32Proxy()
def AllocConsole():
    return AllocConsole.ctypes_function()

@Kernel32Proxy()
def FreeConsole():
    return FreeConsole.ctypes_function()

@Kernel32Proxy()
def SetConsoleCtrlHandler(HandlerRoutine, Add):
    return SetConsoleCtrlHandler.ctypes_function(HandlerRoutine, Add)

@Kernel32Proxy()
def GetStdHandle(nStdHandle):
    return GetStdHandle.ctypes_function(nStdHandle)

@Kernel32Proxy()
def SetStdHandle(nStdHandle, hHandle):
    return SetStdHandle.ctypes_function(nStdHandle, hHandle)

## System

@Kernel32Proxy()
def GetComputerNameA(lpBuffer, lpnSize):
    return GetComputerNameA.ctypes_function(lpBuffer, lpnSize)

@Kernel32Proxy()
def GetComputerNameW(lpBuffer, lpnSize):
    return GetComputerNameW.ctypes_function(lpBuffer, lpnSize)

@Kernel32Proxy()
def GetComputerNameExA(NameType, lpBuffer, nSize):
    return GetComputerNameExA.ctypes_function(NameType, lpBuffer, nSize)

@Kernel32Proxy()
def GetComputerNameExW(NameType, lpBuffer, nSize):
    return GetComputerNameExW.ctypes_function(NameType, lpBuffer, nSize)

@Kernel32Proxy()
def GetWindowsDirectoryA(lpBuffer, uSize=None):
    if uSize is None:
        uSize = gdef.DWORD(len(lpBuffer))
    return GetWindowsDirectoryA.ctypes_function(lpBuffer, uSize)

@Kernel32Proxy()
def GetWindowsDirectoryW(lpBuffer, uSize=None):
    if uSize is None:
        uSize = gdef.DWORD(len(lpBuffer))
    return GetWindowsDirectoryW.ctypes_function(lpBuffer, uSize)

@Kernel32Proxy()
def GetProductInfo(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType):
   return GetProductInfo.ctypes_function(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType)




## Other

@Kernel32Proxy(error_check=no_error_check)
def lstrcmpA(lpString1, lpString2):
    return lstrcmpA.ctypes_function(lpString1, lpString2)

@Kernel32Proxy(error_check=no_error_check)
def lstrcmpW(lpString1, lpString2):
    return lstrcmpW.ctypes_function(lpString1, lpString2)

@Kernel32Proxy("Sleep", no_error_check)
def Sleep(dwMilliseconds):
    return Sleep.ctypes_function(dwMilliseconds)

@Kernel32Proxy("SleepEx", no_error_check)
def SleepEx(dwMilliseconds, bAlertable=False):
    return SleepEx.ctypes_function(dwMilliseconds, bAlertable)


@Kernel32Proxy(error_check=succeed_on_zero)
def WaitForSingleObject(hHandle, dwMilliseconds=gdef.INFINITE):
    return WaitForSingleObject.ctypes_function(hHandle, dwMilliseconds)

@Kernel32Proxy()
def DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize=None, lpOutBuffer=NeededParameter, nOutBufferSize=None, lpBytesReturned=None, lpOverlapped=None):
    if nInBufferSize is None:
        nInBufferSize = len(lpInBuffer)
    if nOutBufferSize is None:
        nOutBufferSize = len(lpOutBuffer)
    if lpBytesReturned is None:
        # Some windows check 0 / others does not
        lpBytesReturned = ctypes.byref(gdef.DWORD())
    return DeviceIoControl.ctypes_function(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)


# Wow64

@Kernel32Proxy()
def Wow64DisableWow64FsRedirection(OldValue=None):
    if OldValue is None:
        OldValue = gdef.PVOID()
    return Wow64DisableWow64FsRedirection.ctypes_function(OldValue)

@Kernel32Proxy()
def Wow64RevertWow64FsRedirection(OldValue=None):
    if OldValue is None:
        OldValue = gdef.PVOID()
    return Wow64RevertWow64FsRedirection.ctypes_function(OldValue)

@Kernel32Proxy()
def Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection):
    return Wow64EnableWow64FsRedirection.ctypes_function(Wow64FsEnableRedirection)

@Kernel32Proxy()
def Wow64GetThreadContext(hThread, lpContext):
    return Wow64GetThreadContext.ctypes_function(hThread, lpContext)

@Kernel32Proxy()
def Wow64SetThreadContext(hThread, lpContext):
    return Wow64SetThreadContext.ctypes_function(hThread, lpContext)



## File

@Kernel32Proxy(error_check=result_is_handle)
def CreateFileA(lpFileName, dwDesiredAccess=gdef.GENERIC_READ, dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=gdef.OPEN_EXISTING, dwFlagsAndAttributes=gdef.FILE_ATTRIBUTE_NORMAL, hTemplateFile=None):
    return CreateFileA.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)


@Kernel32Proxy(error_check=result_is_handle)
def CreateFileW(lpFileName, dwDesiredAccess=gdef.GENERIC_READ, dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=gdef.OPEN_EXISTING, dwFlagsAndAttributes=gdef.FILE_ATTRIBUTE_NORMAL, hTemplateFile=None):
    return CreateFileW.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)

@Kernel32Proxy(error_check=result_is_handle)
def CreateFileTransactedA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter):
    return CreateFileTransactedA.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter)

@Kernel32Proxy(error_check=result_is_handle)
def CreateFileTransactedW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter):
    return CreateFileTransactedW.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter)

@Kernel32Proxy()
def ReadFile(hFile, lpBuffer, nNumberOfBytesToRead=None, lpNumberOfBytesRead=None, lpOverlapped=None):
    if nNumberOfBytesToRead is None:
        nNumberOfBytesToRead = len(lpBuffer)
    if lpOverlapped is None and lpNumberOfBytesRead is None:
        lpNumberOfBytesRead = ctypes.byref(gdef.DWORD())
    return ReadFile.ctypes_function(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)


@Kernel32Proxy()
def WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite=None, lpNumberOfBytesWritten=None, lpOverlapped=None):
    if nNumberOfBytesToWrite is None:
        nNumberOfBytesToWrite = len(lpBuffer)
    if lpOverlapped is None and lpNumberOfBytesWritten is None:
        lpNumberOfBytesWritten = ctypes.byref(gdef.DWORD())
    return WriteFile.ctypes_function(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)


@Kernel32Proxy()
def CreateFileMappingA(hFile, lpFileMappingAttributes=None, flProtect=gdef.PAGE_READWRITE, dwMaximumSizeHigh=0, dwMaximumSizeLow=NeededParameter, lpName=NeededParameter):
    return CreateFileMappingA.ctypes_function(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)


@Kernel32Proxy()
def CreateFileMappingW(hFile, lpFileMappingAttributes=None, flProtect=gdef.PAGE_READWRITE, dwMaximumSizeHigh=0, dwMaximumSizeLow=0, lpName=NeededParameter):
    return CreateFileMappingW.ctypes_function(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)

@Kernel32Proxy()
def OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName):
    return OpenFileMappingW.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)

@Kernel32Proxy()
def OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName):
    return OpenFileMappingA.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)

@Kernel32Proxy()
def MapViewOfFile(hFileMappingObject, dwDesiredAccess=gdef.FILE_MAP_ALL_ACCESS, dwFileOffsetHigh=0, dwFileOffsetLow=0, dwNumberOfBytesToMap=NeededParameter):
    return MapViewOfFile.ctypes_function(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)

@Kernel32Proxy()
def UnmapViewOfFile(lpBaseAddress):
    return UnmapViewOfFile.ctypes_function(lpBaseAddress)

@Kernel32Proxy()
def FindFirstFileA(lpFileName, lpFindFileData):
    return FindFirstFileA.ctypes_function(lpFileName, lpFindFileData)


@Kernel32Proxy()
def FindFirstFileW(lpFileName, lpFindFileData):
    return FindFirstFileW.ctypes_function(lpFileName, lpFindFileData)


@Kernel32Proxy()
def FindNextFileA(hFindFile, lpFindFileData):
    return FindNextFileA.ctypes_function(hFindFile, lpFindFileData)


@Kernel32Proxy()
def FindNextFileW(hFindFile, lpFindFileData):
    return FindNextFileW.ctypes_function(hFindFile, lpFindFileData)


@Kernel32Proxy()
def FindClose(hFindFile):
    return FindClose.ctypes_function(hFindFile)

@Kernel32Proxy()
def FindFirstChangeNotificationA(lpPathName, bWatchSubtree, dwNotifyFilter):
    return FindFirstChangeNotificationA.ctypes_function(lpPathName, bWatchSubtree, dwNotifyFilter)

@Kernel32Proxy()
def FindFirstChangeNotificationW(lpPathName, bWatchSubtree, dwNotifyFilter):
    return FindFirstChangeNotificationW.ctypes_function(lpPathName, bWatchSubtree, dwNotifyFilter)

@Kernel32Proxy()
def FindNextChangeNotification(hChangeHandle):
    return FindNextChangeNotification.ctypes_function(hChangeHandle)

@Kernel32Proxy()
def FindCloseChangeNotification(hChangeHandle):
    return FindCloseChange
    Notification.ctypes_function(hChangeHandle)

@Kernel32Proxy()
def FindNextChangeNotification(hChangeHandle):
    return FindNextChangeNotification.ctypes_function(hChangeHandle)

@Kernel32Proxy()
def ReadDirectoryChangesW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine):
    return ReadDirectoryChangesW.ctypes_function(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine)

@Kernel32Proxy()
def ReadDirectoryChangesExW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine, ReadDirectoryNotifyInformationClass):
    return ReadDirectoryChangesExW.ctypes_function(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine, ReadDirectoryNotifyInformationClass)



## Tlhelp (snapshoot)

@Kernel32Proxy()
def CreateToolhelp32Snapshot(dwFlags, th32ProcessID=0):
    return CreateToolhelp32Snapshot.ctypes_function(dwFlags, th32ProcessID)

@Kernel32Proxy()
def Thread32First(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == gdef.THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return Thread32First.ctypes_function(hSnapshot, lpte)

@Kernel32Proxy(error_check=no_error_check)
def Thread32Next(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == gdef.THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return Thread32Next.ctypes_function(hSnapshot, lpte)

@Kernel32Proxy()
def Process32First(hSnapshot, lpte):
    return Process32First.ctypes_function(hSnapshot, lpte)

@Kernel32Proxy(error_check=no_error_check)
def Process32Next(hSnapshot, lpte):
    return Process32Next.ctypes_function(hSnapshot, lpte)

@Kernel32Proxy()
def Process32FirstW(hSnapshot, lppe):
    return Process32FirstW.ctypes_function(hSnapshot, lppe)

@Kernel32Proxy(error_check=no_error_check)
def Process32NextW(hSnapshot, lppe):
    return Process32NextW.ctypes_function(hSnapshot, lppe)


## VEH

@Kernel32Proxy()
def AddVectoredContinueHandler(FirstHandler=1, VectoredHandler=NeededParameter):
    return AddVectoredContinueHandler.ctypes_function(FirstHandler, VectoredHandler)


@Kernel32Proxy()
def AddVectoredExceptionHandler(FirstHandler=1, VectoredHandler=NeededParameter):
    return AddVectoredExceptionHandler.ctypes_function(FirstHandler, VectoredHandler)


@Kernel32Proxy()
def RemoveVectoredExceptionHandler(Handler):
    return RemoveVectoredExceptionHandler.ctypes_function(Handler)

## Event

@Kernel32Proxy()
def OpenEventA(dwDesiredAccess, bInheritHandle, lpName):
    return OpenEventA.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)

@Kernel32Proxy()
def OpenEventW(dwDesiredAccess, bInheritHandle, lpName):
    return OpenEventW.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)

@Kernel32Proxy()
def CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName):
    return CreateEventA.ctypes_function(lpEventAttributes, bManualReset, bInitialState, lpName)

@Kernel32Proxy()
def CreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName):
    return CreateEventW.ctypes_function(lpEventAttributes, bManualReset, bInitialState, lpName)

@Kernel32Proxy()
def CreateEventExA(lpEventAttributes, lpName, dwFlags, dwDesiredAccess):
    return CreateEventExA.ctypes_function(lpEventAttributes, lpName, dwFlags, dwDesiredAccess)

@Kernel32Proxy()
def CreateEventExW(lpEventAttributes, lpName, dwFlags, dwDesiredAccess):
    return CreateEventExW.ctypes_function(lpEventAttributes, lpName, dwFlags, dwDesiredAccess)


## Path

@Kernel32Proxy()
def GetLongPathNameA(lpszShortPath, lpszLongPath, cchBuffer=None):
    if cchBuffer is None:
        cchBuffer = len(lpszLongPath)
    return GetLongPathNameA.ctypes_function(lpszShortPath, lpszLongPath, cchBuffer)

@Kernel32Proxy()
def GetLongPathNameW(lpszShortPath, lpszLongPath, cchBuffer=None):
    if cchBuffer is None:
        cchBuffer = len(lpszLongPath)
    return GetLongPathNameW.ctypes_function(lpszShortPath, lpszLongPath, cchBuffer)

@Kernel32Proxy()
def GetShortPathNameA(lpszLongPath, lpszShortPath, cchBuffer=None):
    if cchBuffer is None:
        cchBuffer = len(lpszShortPath)
    return GetShortPathNameA.ctypes_function(lpszLongPath, lpszShortPath, cchBuffer)

@Kernel32Proxy()
def GetShortPathNameW(lpszLongPath, lpszShortPath, cchBuffer=None):
    if cchBuffer is None:
        cchBuffer = len(lpszShortPath)
    return GetShortPathNameW.ctypes_function(lpszLongPath, lpszShortPath, cchBuffer)


# Debug-API

@Kernel32Proxy(error_check=no_error_check)
def IsDebuggerPresent():
   return IsDebuggerPresent.ctypes_function()

@Kernel32Proxy()
def WaitForDebugEvent(lpDebugEvent, dwMilliseconds=gdef.INFINITE):
    return WaitForDebugEvent.ctypes_function(lpDebugEvent, dwMilliseconds)

@Kernel32Proxy()
def DebugBreak():
    return DebugBreak.ctypes_function()

@Kernel32Proxy()
def ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus):
    return ContinueDebugEvent.ctypes_function(dwProcessId, dwThreadId, dwContinueStatus)

@Kernel32Proxy()
def DebugActiveProcess(dwProcessId):
    return DebugActiveProcess.ctypes_function(dwProcessId)

@Kernel32Proxy()
def DebugActiveProcessStop(dwProcessId):
    return DebugActiveProcessStop.ctypes_function(dwProcessId)

@Kernel32Proxy()
def DebugSetProcessKillOnExit(KillOnExit):
    return DebugSetProcessKillOnExit.ctypes_function(KillOnExit)

@Kernel32Proxy()
def DebugBreakProcess(Process):
    return DebugBreakProcess.ctypes_function(Process)

# Volumes

@Kernel32Proxy()
def GetLogicalDriveStringsA(nBufferLength, lpBuffer):
    return GetLogicalDriveStringsA.ctypes_function(nBufferLength, lpBuffer)

@Kernel32Proxy()
def GetLogicalDriveStringsW(nBufferLength, lpBuffer):
    return GetLogicalDriveStringsW.ctypes_function(nBufferLength, lpBuffer)

@Kernel32Proxy()
def GetVolumeNameForVolumeMountPointA(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength):
    return GetVolumeNameForVolumeMountPointA.ctypes_function(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)

@Kernel32Proxy()
def GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength):
    return GetVolumeNameForVolumeMountPointW.ctypes_function(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)

@Kernel32Proxy()
def GetDriveTypeA(lpRootPathName):
    return GetDriveTypeA.ctypes_function(lpRootPathName)

@Kernel32Proxy()
def GetDriveTypeW(lpRootPathName):
    return GetDriveTypeW.ctypes_function(lpRootPathName)

@Kernel32Proxy()
def QueryDosDeviceA(lpDeviceName, lpTargetPath, ucchMax):
    return QueryDosDeviceA.ctypes_function(lpDeviceName, lpTargetPath, ucchMax)

@Kernel32Proxy()
def QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax):
    return QueryDosDeviceW.ctypes_function(lpDeviceName, lpTargetPath, ucchMax)


@Kernel32Proxy()
def GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize):
    if nVolumeNameSize == 0 and lpVolumeNameBuffer is not None:
        nVolumeNameSize = len(lpVolumeNameBuffer)
    if nFileSystemNameSize == 0 and lpFileSystemNameBuffer is not None:
        nFileSystemNameSize = len(lpFileSystemNameBuffer)
    return GetVolumeInformationA.ctypes_function(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)


@Kernel32Proxy()
def GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer=None, nVolumeNameSize=0, lpVolumeSerialNumber=None, lpMaximumComponentLength=None, lpFileSystemFlags=None, lpFileSystemNameBuffer=None, nFileSystemNameSize=0):
    if nVolumeNameSize == 0 and lpVolumeNameBuffer is not None:
        nVolumeNameSize = len(lpVolumeNameBuffer)
    if nFileSystemNameSize == 0 and lpFileSystemNameBuffer is not None:
        nFileSystemNameSize = len(lpFileSystemNameBuffer)
    return GetVolumeInformationW.ctypes_function(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)


@Kernel32Proxy()
def FindFirstVolumeA(lpszVolumeName, cchBufferLength):
    if cchBufferLength is None:
        cchBufferLength = len(lpszVolumeName)
    return FindFirstVolumeA.ctypes_function(lpszVolumeName, cchBufferLength)


@Kernel32Proxy()
def FindFirstVolumeW(lpszVolumeName, cchBufferLength):
    if cchBufferLength is None:
        cchBufferLength = len(lpszVolumeName)
    return FindFirstVolumeW.ctypes_function(lpszVolumeName, cchBufferLength)



@Kernel32Proxy()
def FindNextVolumeA(hFindVolume, lpszVolumeName, cchBufferLength):
    if cchBufferLength is None:
        cchBufferLength = len(lpszVolumeName)
    return FindNextVolumeA.ctypes_function(hFindVolume, lpszVolumeName, cchBufferLength)


@Kernel32Proxy()
def FindNextVolumeW(hFindVolume, lpszVolumeName, cchBufferLength):
    if cchBufferLength is None:
        cchBufferLength = len(lpszVolumeName)
    return FindNextVolumeW.ctypes_function(hFindVolume, lpszVolumeName, cchBufferLength)

# pipe

@Kernel32Proxy()
def CreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes):
    return CreateNamedPipeA.ctypes_function(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes)

@Kernel32Proxy()
def CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes):
    return CreateNamedPipeW.ctypes_function(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes)

@Kernel32Proxy()
def ConnectNamedPipe(hNamedPipe, lpOverlapped):
    return ConnectNamedPipe.ctypes_function(hNamedPipe, lpOverlapped)

@Kernel32Proxy()
def SetNamedPipeHandleState(hNamedPipe, lpMode, lpMaxCollectionCount, lpCollectDataTimeout):
    return SetNamedPipeHandleState.ctypes_function(hNamedPipe, lpMode, lpMaxCollectionCount, lpCollectDataTimeout)

@Kernel32Proxy()
def CreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize):
    return CreatePipe.ctypes_function(hReadPipe, hWritePipe, lpPipeAttributes, nSize)

# Firmware

@Kernel32Proxy()
def GetFirmwareEnvironmentVariableA(lpName, lpGuid, pBuffer, nSize):
    return GetFirmwareEnvironmentVariableA.ctypes_function(lpName, lpGuid, pBuffer, nSize)

@Kernel32Proxy()
def GetFirmwareEnvironmentVariableW(lpName, lpGuid, pBuffer, nSize):
    return GetFirmwareEnvironmentVariableW.ctypes_function(lpName, lpGuid, pBuffer, nSize)

@Kernel32Proxy()
def GetFirmwareEnvironmentVariableExA(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes):
    return GetFirmwareEnvironmentVariableExA.ctypes_function(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes)

@Kernel32Proxy()
def GetFirmwareEnvironmentVariableExW(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes):
    return GetFirmwareEnvironmentVariableExW.ctypes_function(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes)

#####

# Time

@Kernel32Proxy(error_check=fail_on_zero)
def FileTimeToSystemTime(lpFileTime, lpSystemTime):
   return FileTimeToSystemTime.ctypes_function(lpFileTime, lpSystemTime)

@Kernel32Proxy(error_check=fail_on_zero)
def SystemTimeToFileTime(lpSystemTime, lpFileTime):
   return SystemTimeToFileTime.ctypes_function(lpSystemTime, lpFileTime)

@Kernel32Proxy(error_check=None)
def GetSystemTime(lpSystemTime):
   return GetSystemTime.ctypes_function(lpSystemTime)

@Kernel32Proxy(error_check=None)
def GetSystemTimeAsFileTime(lpSystemTimeAsFileTime):
   return GetSystemTimeAsFileTime.ctypes_function(lpSystemTimeAsFileTime)


@Kernel32Proxy(error_check=fail_on_zero)
def GetSystemTimes(lpIdleTime, lpKernelTime, lpUserTime):
    return GetSystemTimes.ctypes_function(lpIdleTime, lpKernelTime, lpUserTime)

@Kernel32Proxy(error_check=None)
def GetLocalTime(lpSystemTime):
    return GetLocalTime.ctypes_function(lpSystemTime)

@Kernel32Proxy(error_check=None)
def GetTickCount():
    return GetTickCount.ctypes_function()

@Kernel32Proxy(error_check=None)
def GetTickCount64():
    return GetTickCount64.ctypes_function()

#####

# Heap

@Kernel32Proxy(error_check=fail_on_zero)
def HeapAlloc(hHeap, dwFlags, dwBytes):
    return HeapAlloc.ctypes_function(hHeap, dwFlags, dwBytes)


#####

# Resources

@Kernel32Proxy()
def FindResourceA(hModule, lpName, lpType):
    return FindResourceA.ctypes_function(hModule, lpName, lpType)

@Kernel32Proxy()
def FindResourceW(hModule, lpName, lpType):
    return FindResourceW.ctypes_function(hModule, lpName, lpType)

@Kernel32Proxy()
def SizeofResource(hModule, hResInfo):
    return SizeofResource.ctypes_function(hModule, hResInfo)

@Kernel32Proxy()
def LoadResource(hModule, hResInfo):
    return LoadResource.ctypes_function(hModule, hResInfo)

@Kernel32Proxy()
def LockResource(hResData):
    return LockResource.ctypes_function(hResData)

@Kernel32Proxy()
def FreeResource(hResData):
    return FreeResource.ctypes_function(hResData)

@Kernel32Proxy()
def EnumResourceTypesA(hModule, lpEnumFunc, lParam):
    return EnumResourceTypesA.ctypes_function(hModule, lpEnumFunc, lParam)

@Kernel32Proxy()
def EnumResourceTypesW(hModule, lpEnumFunc, lParam):
    return EnumResourceTypesW.ctypes_function(hModule, lpEnumFunc, lParam)

@Kernel32Proxy()
def EnumResourceNamesA(hModule, lpType, lpEnumFunc, lParam):
    return EnumResourceNamesA.ctypes_function(hModule, lpType, lpEnumFunc, lParam)

@Kernel32Proxy()
def EnumResourceNamesW(hModule, lpType, lpEnumFunc, lParam):
    return EnumResourceNamesW.ctypes_function(hModule, lpType, lpEnumFunc, lParam)