#Generated file


from ctypes import *
from ctypes.wintypes import *
from winstructs import *


functions = ['ExitProcess', 'TerminateProcess', 'GetLastError', 'GetCurrentProcess', 'CreateFileA', 'CreateFileW', 'NtCreateFile', 'LdrLoadDll', 'NtQuerySystemInformation', 'NtQueryInformationProcess', 'NtQueryVirtualMemory', 'NtCreateThreadEx', 'NtQueryInformationThread', 'GetExitCodeThread', 'GetExitCodeProcess', 'VirtualAlloc', 'VirtualAllocEx', 'NtProtectVirtualMemory', 'VirtualFree', 'VirtualFreeEx', 'VirtualProtect', 'VirtualProtectEx', 'VirtualQuery', 'VirtualQueryEx', 'QueryWorkingSet', 'QueryWorkingSetEx', 'GetModuleFileNameA', 'GetModuleFileNameW', 'CreateThread', 'CreateRemoteThread', 'VirtualProtect', 'CreateProcessA', 'CreateProcessW', 'GetThreadContext', 'NtGetContextThread', 'SetThreadContext', 'NtSetContextThread', 'OpenThread', 'OpenProcess', 'CloseHandle', 'ReadProcessMemory', 'NtWow64ReadVirtualMemory64', 'WriteProcessMemory', 'NtWow64WriteVirtualMemory64', 'CreateToolhelp32Snapshot', 'Thread32First', 'Thread32Next', 'Process32First', 'Process32Next', 'Process32FirstW', 'Process32NextW', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'OpenProcessToken', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 'AdjustTokenPrivileges', 'FindResourceA', 'FindResourceW', 'SizeofResource', 'LoadResource', 'LockResource', 'GetVersionExA', 'GetVersionExW', 'GetVersion', 'GetCurrentThread', 'GetCurrentThreadId', 'GetCurrentProcessorNumber', 'AllocConsole', 'FreeConsole', 'GetStdHandle', 'SetStdHandle', 'SetThreadAffinityMask', 'ReadFile', 'WriteFile', 'GetExtendedTcpTable', 'GetExtendedUdpTable', 'SetTcpEntry', 'AddVectoredContinueHandler', 'AddVectoredExceptionHandler', 'TerminateThread', 'ExitThread', 'RemoveVectoredExceptionHandler', 'ResumeThread', 'SuspendThread', 'WaitForSingleObject', 'GetThreadId', 'LoadLibraryExA', 'LoadLibraryExW', 'SymInitialize', 'SymFromName', 'SymLoadModuleEx', 'SymSetOptions', 'SymGetTypeInfo', 'DeviceIoControl', 'GetTokenInformation', 'RegOpenKeyExA', 'RegOpenKeyExW', 'RegGetValueA', 'RegGetValueW', 'RegCloseKey', 'Wow64DisableWow64FsRedirection', 'Wow64RevertWow64FsRedirection', 'Wow64EnableWow64FsRedirection', 'Wow64GetThreadContext', 'SetConsoleCtrlHandler', 'WinVerifyTrust', 'GlobalAlloc', 'GlobalFree', 'GlobalUnlock', 'GlobalLock', 'OpenClipboard', 'EmptyClipboard', 'CloseClipboard', 'SetClipboardData', 'GetClipboardData', 'EnumClipboardFormats', 'GetClipboardFormatNameA', 'GetClipboardFormatNameW', 'WinVerifyTrust', 'OpenProcessToken', 'OpenThreadToken', 'GetTokenInformation', 'SetTokenInformation', 'GetSidIdentifierAuthority', 'GetSidSubAuthority', 'GetSidSubAuthorityCount', 'DebugBreak', 'WaitForDebugEvent', 'ContinueDebugEvent', 'DebugActiveProcess', 'DebugActiveProcessStop', 'DebugSetProcessKillOnExit', 'DebugBreakProcess', 'GetProcessId', 'Wow64SetThreadContext', 'GetMappedFileNameW', 'GetMappedFileNameA', 'RtlInitString', 'RtlInitUnicodeString', 'RtlAnsiStringToUnicodeString', 'OpenEventA', 'OpenEventW', 'NtOpenEvent', 'NtAlpcCreatePort', 'NtAlpcConnectPort', 'NtAlpcConnectPortEx', 'NtAlpcAcceptConnectPort', 'AlpcInitializeMessageAttribute', 'AlpcGetMessageAttribute', 'NtAlpcSendWaitReceivePort', 'lstrcmpA', 'lstrcmpW', 'CreateFileMappingA', 'CreateFileMappingW', 'MapViewOfFile', 'OpenSCManagerA', 'OpenSCManagerW', 'EnumServicesStatusExA', 'EnumServicesStatusExW', 'EnumWindows', 'GetWindowTextA', 'GetWindowTextW', 'GetWindowModuleFileNameA', 'GetWindowModuleFileNameW', 'CryptCATAdminCalcHashFromFileHandle', 'CryptCATAdminEnumCatalogFromHash', 'CryptCATAdminAcquireContext', 'CryptCATCatalogInfoFromContext', 'CryptCATAdminReleaseCatalogContext', 'CryptCATAdminReleaseContext', 'GetLogicalDriveStringsA', 'GetLogicalDriveStringsW', 'GetVolumeInformationA', 'GetVolumeInformationW', 'GetVolumeNameForVolumeMountPointA', 'GetVolumeNameForVolumeMountPointW', 'GetDriveTypeA', 'GetDriveTypeW', 'QueryDosDeviceA', 'QueryDosDeviceW', 'NtQueryObject', 'DuplicateHandle', 'GetModuleBaseNameA', 'GetModuleBaseNameW', 'GetProcessImageFileNameA', 'GetProcessImageFileNameW', 'GetFileVersionInfoA', 'GetFileVersionInfoW', 'GetFileVersionInfoSizeA', 'GetFileVersionInfoSizeW', 'VerQueryValueA', 'VerQueryValueW', 'GetSystemMetrics', 'GetComputerNameA', 'GetComputerNameW', 'LookupAccountSidA', 'LookupAccountSidW', 'CoInitializeEx', 'CoInitializeSecurity', 'CoCreateInstance', 'GetInterfaceInfo', 'GetIfTable', 'GetIpAddrTable', 'NtOpenDirectoryObject', 'NtQueryDirectoryObject', 'NtQuerySymbolicLinkObject', 'NtOpenSymbolicLinkObject', 'GetProcessTimes', 'GetShortPathNameA', 'GetShortPathNameW', 'GetLongPathNameA', 'GetLongPathNameW', 'GetProcessDEPPolicy', 'GetCursorPos', 'WindowFromPoint', 'GetWindowRect', 'CryptQueryObject', 'CryptMsgGetParam', 'CryptDecodeObject', 'CertFindCertificateInStore', 'CertGetNameStringA', 'CertGetNameStringW', 'CertGetCertificateChain', 'CertCreateSelfSignCertificate', 'CertStrToNameA', 'CertStrToNameW', 'CertOpenStore', 'CertAddCertificateContextToStore', 'PFXExportCertStoreEx', 'PFXImportCertStore', 'CryptGenKey', 'CryptAcquireContextA', 'CryptAcquireContextW', 'CryptExportKey', 'CertGetCertificateContextProperty', 'CertEnumCertificateContextProperties', 'CryptEncryptMessage', 'CryptDecryptMessage', 'CryptAcquireCertificatePrivateKey', 'CertDuplicateCertificateContext', 'CertEnumCertificatesInStore', 'CryptEncodeObjectEx', 'CertCreateCertificateContext']


#def ExitProcess(uExitCode):
#    return ExitProcess.ctypes_function(uExitCode)
ExitProcessPrototype = WINFUNCTYPE(VOID, UINT)
ExitProcessParams = ((1, 'uExitCode'),)

#def TerminateProcess(hProcess, uExitCode):
#    return TerminateProcess.ctypes_function(hProcess, uExitCode)
TerminateProcessPrototype = WINFUNCTYPE(BOOL, HANDLE, UINT)
TerminateProcessParams = ((1, 'hProcess'), (1, 'uExitCode'))

#def GetLastError():
#    return GetLastError.ctypes_function()
GetLastErrorPrototype = WINFUNCTYPE(DWORD)
GetLastErrorParams = ()

#def GetCurrentProcess():
#    return GetCurrentProcess.ctypes_function()
GetCurrentProcessPrototype = WINFUNCTYPE(HANDLE)
GetCurrentProcessParams = ()

#def CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):
#    return CreateFileA.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
CreateFileAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
CreateFileAParams = ((1, 'lpFileName'), (1, 'dwDesiredAccess'), (1, 'dwShareMode'), (1, 'lpSecurityAttributes'), (1, 'dwCreationDisposition'), (1, 'dwFlagsAndAttributes'), (1, 'hTemplateFile'))

#def CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):
#    return CreateFileW.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
CreateFileWPrototype = WINFUNCTYPE(HANDLE, LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
CreateFileWParams = ((1, 'lpFileName'), (1, 'dwDesiredAccess'), (1, 'dwShareMode'), (1, 'lpSecurityAttributes'), (1, 'dwCreationDisposition'), (1, 'dwFlagsAndAttributes'), (1, 'hTemplateFile'))

#def NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength):
#    return NtCreateFile.ctypes_function(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength)
NtCreateFilePrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG)
NtCreateFileParams = ((1, 'FileHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'IoStatusBlock'), (1, 'AllocationSize'), (1, 'FileAttributes'), (1, 'ShareAccess'), (1, 'CreateDisposition'), (1, 'CreateOptions'), (1, 'EaBuffer'), (1, 'EaLength'))

#def LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle):
#    return LdrLoadDll.ctypes_function(PathToFile, Flags, ModuleFileName, ModuleHandle)
LdrLoadDllPrototype = WINFUNCTYPE(NTSTATUS, LPCWSTR, ULONG, PUNICODE_STRING, PHANDLE)
LdrLoadDllParams = ((1, 'PathToFile'), (1, 'Flags'), (1, 'ModuleFileName'), (1, 'ModuleHandle'))

#def NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength):
#    return NtQuerySystemInformation.ctypes_function(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)
NtQuerySystemInformationPrototype = WINFUNCTYPE(NTSTATUS, SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQuerySystemInformationParams = ((1, 'SystemInformationClass'), (1, 'SystemInformation'), (1, 'SystemInformationLength'), (1, 'ReturnLength'))

#def NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength):
#    return NtQueryInformationProcess.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)
NtQueryInformationProcessPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)
NtQueryInformationProcessParams = ((1, 'ProcessHandle'), (1, 'ProcessInformationClass'), (1, 'ProcessInformation'), (1, 'ProcessInformationLength'), (1, 'ReturnLength'))

#def NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength):
#    return NtQueryVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength)
NtQueryVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T)
NtQueryVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'MemoryInformationClass'), (1, 'MemoryInformation'), (1, 'MemoryInformationLength'), (1, 'ReturnLength'))

#def NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3):
#    return NtCreateThreadEx.ctypes_function(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3)
NtCreateThreadExPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, DWORD, DWORD, DWORD, LPVOID)
NtCreateThreadExParams = ((1, 'ThreadHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'ProcessHandle'), (1, 'lpStartAddress'), (1, 'lpParameter'), (1, 'CreateSuspended'), (1, 'dwStackSize'), (1, 'Unknown1'), (1, 'Unknown2'), (1, 'Unknown3'))

#def NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength):
#    return NtQueryInformationThread.ctypes_function(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)
NtQueryInformationThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQueryInformationThreadParams = ((1, 'ThreadHandle'), (1, 'ThreadInformationClass'), (1, 'ThreadInformation'), (1, 'ThreadInformationLength'), (1, 'ReturnLength'))

#def GetExitCodeThread(hThread, lpExitCode):
#    return GetExitCodeThread.ctypes_function(hThread, lpExitCode)
GetExitCodeThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD)
GetExitCodeThreadParams = ((1, 'hThread'), (1, 'lpExitCode'))

#def GetExitCodeProcess(hProcess, lpExitCode):
#    return GetExitCodeProcess.ctypes_function(hProcess, lpExitCode)
GetExitCodeProcessPrototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD)
GetExitCodeProcessParams = ((1, 'hProcess'), (1, 'lpExitCode'))

#def VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect):
#    return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)
VirtualAllocPrototype = WINFUNCTYPE(LPVOID, LPVOID, SIZE_T, DWORD, DWORD)
VirtualAllocParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flAllocationType'), (1, 'flProtect'))

#def VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect):
#    return VirtualAllocEx.ctypes_function(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
VirtualAllocExPrototype = WINFUNCTYPE(LPVOID, HANDLE, LPVOID, SIZE_T, DWORD, DWORD)
VirtualAllocExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'flAllocationType'), (1, 'flProtect'))

#def NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection):
#    return NtProtectVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection)
NtProtectVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, POINTER(PVOID), PULONG, ULONG, PULONG)
NtProtectVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'NumberOfBytesToProtect'), (1, 'NewAccessProtection'), (1, 'OldAccessProtection'))

#def VirtualFree(lpAddress, dwSize, dwFreeType):
#    return VirtualFree.ctypes_function(lpAddress, dwSize, dwFreeType)
VirtualFreePrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD)
VirtualFreeParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'dwFreeType'))

#def VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType):
#    return VirtualFreeEx.ctypes_function(hProcess, lpAddress, dwSize, dwFreeType)
VirtualFreeExPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, SIZE_T, DWORD)
VirtualFreeExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'dwFreeType'))

#def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect):
#    return VirtualProtect.ctypes_function(lpAddress, dwSize, flNewProtect, lpflOldProtect)
VirtualProtectPrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD, PDWORD)
VirtualProtectParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flNewProtect'), (1, 'lpflOldProtect'))

#def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect):
#    return VirtualProtectEx.ctypes_function(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)
VirtualProtectExPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, SIZE_T, DWORD, PDWORD)
VirtualProtectExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'flNewProtect'), (1, 'lpflOldProtect'))

#def VirtualQuery(lpAddress, lpBuffer, dwLength):
#    return VirtualQuery.ctypes_function(lpAddress, lpBuffer, dwLength)
VirtualQueryPrototype = WINFUNCTYPE(DWORD, LPCVOID, PMEMORY_BASIC_INFORMATION, DWORD)
VirtualQueryParams = ((1, 'lpAddress'), (1, 'lpBuffer'), (1, 'dwLength'))

#def VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength):
#    return VirtualQueryEx.ctypes_function(hProcess, lpAddress, lpBuffer, dwLength)
VirtualQueryExPrototype = WINFUNCTYPE(SIZE_T, HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T)
VirtualQueryExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'lpBuffer'), (1, 'dwLength'))

#def QueryWorkingSet(hProcess, pv, cb):
#    return QueryWorkingSet.ctypes_function(hProcess, pv, cb)
QueryWorkingSetPrototype = WINFUNCTYPE(BOOL, HANDLE, PVOID, DWORD)
QueryWorkingSetParams = ((1, 'hProcess'), (1, 'pv'), (1, 'cb'))

#def QueryWorkingSetEx(hProcess, pv, cb):
#    return QueryWorkingSetEx.ctypes_function(hProcess, pv, cb)
QueryWorkingSetExPrototype = WINFUNCTYPE(BOOL, HANDLE, PVOID, DWORD)
QueryWorkingSetExParams = ((1, 'hProcess'), (1, 'pv'), (1, 'cb'))

#def GetModuleFileNameA(hModule, lpFilename, nSize):
#    return GetModuleFileNameA.ctypes_function(hModule, lpFilename, nSize)
GetModuleFileNameAPrototype = WINFUNCTYPE(DWORD, HMODULE, LPSTR, DWORD)
GetModuleFileNameAParams = ((1, 'hModule'), (1, 'lpFilename'), (1, 'nSize'))

#def GetModuleFileNameW(hModule, lpFilename, nSize):
#    return GetModuleFileNameW.ctypes_function(hModule, lpFilename, nSize)
GetModuleFileNameWPrototype = WINFUNCTYPE(DWORD, HMODULE, LPWSTR, DWORD)
GetModuleFileNameWParams = ((1, 'hModule'), (1, 'lpFilename'), (1, 'nSize'))

#def CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
#    return CreateThread.ctypes_function(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)
CreateThreadPrototype = WINFUNCTYPE(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)
CreateThreadParams = ((1, 'lpThreadAttributes'), (1, 'dwStackSize'), (1, 'lpStartAddress'), (1, 'lpParameter'), (1, 'dwCreationFlags'), (1, 'lpThreadId'))

#def CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
#    return CreateRemoteThread.ctypes_function(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)
CreateRemoteThreadPrototype = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)
CreateRemoteThreadParams = ((1, 'hProcess'), (1, 'lpThreadAttributes'), (1, 'dwStackSize'), (1, 'lpStartAddress'), (1, 'lpParameter'), (1, 'dwCreationFlags'), (1, 'lpThreadId'))

#def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect):
#    return VirtualProtect.ctypes_function(lpAddress, dwSize, flNewProtect, lpflOldProtect)
VirtualProtectPrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD, PDWORD)
VirtualProtectParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flNewProtect'), (1, 'lpflOldProtect'))

#def CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
#    return CreateProcessA.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
CreateProcessAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)
CreateProcessAParams = ((1, 'lpApplicationName'), (1, 'lpCommandLine'), (1, 'lpProcessAttributes'), (1, 'lpThreadAttributes'), (1, 'bInheritHandles'), (1, 'dwCreationFlags'), (1, 'lpEnvironment'), (1, 'lpCurrentDirectory'), (1, 'lpStartupInfo'), (1, 'lpProcessInformation'))

#def CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
#    return CreateProcessW.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
CreateProcessWPrototype = WINFUNCTYPE(BOOL, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION)
CreateProcessWParams = ((1, 'lpApplicationName'), (1, 'lpCommandLine'), (1, 'lpProcessAttributes'), (1, 'lpThreadAttributes'), (1, 'bInheritHandles'), (1, 'dwCreationFlags'), (1, 'lpEnvironment'), (1, 'lpCurrentDirectory'), (1, 'lpStartupInfo'), (1, 'lpProcessInformation'))

#def GetThreadContext(hThread, lpContext):
#    return GetThreadContext.ctypes_function(hThread, lpContext)
GetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
GetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

#def NtGetContextThread(hThread, lpContext):
#    return NtGetContextThread.ctypes_function(hThread, lpContext)
NtGetContextThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
NtGetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

#def SetThreadContext(hThread, lpContext):
#    return SetThreadContext.ctypes_function(hThread, lpContext)
SetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
SetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

#def NtSetContextThread(hThread, lpContext):
#    return NtSetContextThread.ctypes_function(hThread, lpContext)
NtSetContextThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
NtSetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

#def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
#    return OpenThread.ctypes_function(dwDesiredAccess, bInheritHandle, dwThreadId)
OpenThreadPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, DWORD)
OpenThreadParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'dwThreadId'))

#def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
#    return OpenProcess.ctypes_function(dwDesiredAccess, bInheritHandle, dwProcessId)
OpenProcessPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, DWORD)
OpenProcessParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'dwProcessId'))

#def CloseHandle(hObject):
#    return CloseHandle.ctypes_function(hObject)
CloseHandlePrototype = WINFUNCTYPE(BOOL, HANDLE)
CloseHandleParams = ((1, 'hObject'),)

#def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
#    return ReadProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
ReadProcessMemoryPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCVOID, LPVOID, SIZE_T, POINTER(SIZE_T))
ReadProcessMemoryParams = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesRead'))

#def NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
#    return NtWow64ReadVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
NtWow64ReadVirtualMemory64Prototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, LPVOID, ULONG64, POINTER(PULONG64))
NtWow64ReadVirtualMemory64Params = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesRead'))

#def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten):
#    return WriteProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
WriteProcessMemoryPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemoryParams = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesWritten'))

#def NtWow64WriteVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten):
#    return NtWow64WriteVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
NtWow64WriteVirtualMemory64Prototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, LPVOID, ULONG64, POINTER(PULONG64))
NtWow64WriteVirtualMemory64Params = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesWritten'))

#def CreateToolhelp32Snapshot(dwFlags, th32ProcessID):
#    return CreateToolhelp32Snapshot.ctypes_function(dwFlags, th32ProcessID)
CreateToolhelp32SnapshotPrototype = WINFUNCTYPE(HANDLE, DWORD, DWORD)
CreateToolhelp32SnapshotParams = ((1, 'dwFlags'), (1, 'th32ProcessID'))

#def Thread32First(hSnapshot, lpte):
#    return Thread32First.ctypes_function(hSnapshot, lpte)
Thread32FirstPrototype = WINFUNCTYPE(BOOL, HANDLE, LPTHREADENTRY32)
Thread32FirstParams = ((1, 'hSnapshot'), (1, 'lpte'))

#def Thread32Next(hSnapshot, lpte):
#    return Thread32Next.ctypes_function(hSnapshot, lpte)
Thread32NextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPTHREADENTRY32)
Thread32NextParams = ((1, 'hSnapshot'), (1, 'lpte'))

#def Process32First(hSnapshot, lppe):
#    return Process32First.ctypes_function(hSnapshot, lppe)
Process32FirstPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32)
Process32FirstParams = ((1, 'hSnapshot'), (1, 'lppe'))

#def Process32Next(hSnapshot, lppe):
#    return Process32Next.ctypes_function(hSnapshot, lppe)
Process32NextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32)
Process32NextParams = ((1, 'hSnapshot'), (1, 'lppe'))

#def Process32FirstW(hSnapshot, lppe):
#    return Process32FirstW.ctypes_function(hSnapshot, lppe)
Process32FirstWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32W)
Process32FirstWParams = ((1, 'hSnapshot'), (1, 'lppe'))

#def Process32NextW(hSnapshot, lppe):
#    return Process32NextW.ctypes_function(hSnapshot, lppe)
Process32NextWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32W)
Process32NextWParams = ((1, 'hSnapshot'), (1, 'lppe'))

#def GetProcAddress(hModule, lpProcName):
#    return GetProcAddress.ctypes_function(hModule, lpProcName)
GetProcAddressPrototype = WINFUNCTYPE(FARPROC, HMODULE, LPCSTR)
GetProcAddressParams = ((1, 'hModule'), (1, 'lpProcName'))

#def LoadLibraryA(lpFileName):
#    return LoadLibraryA.ctypes_function(lpFileName)
LoadLibraryAPrototype = WINFUNCTYPE(HMODULE, LPCSTR)
LoadLibraryAParams = ((1, 'lpFileName'),)

#def LoadLibraryW(lpFileName):
#    return LoadLibraryW.ctypes_function(lpFileName)
LoadLibraryWPrototype = WINFUNCTYPE(HMODULE, LPCWSTR)
LoadLibraryWParams = ((1, 'lpFileName'),)

#def OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle):
#    return OpenProcessToken.ctypes_function(ProcessHandle, DesiredAccess, TokenHandle)
OpenProcessTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, PHANDLE)
OpenProcessTokenParams = ((1, 'ProcessHandle'), (1, 'DesiredAccess'), (1, 'TokenHandle'))

#def LookupPrivilegeValueA(lpSystemName, lpName, lpLuid):
#    return LookupPrivilegeValueA.ctypes_function(lpSystemName, lpName, lpLuid)
LookupPrivilegeValueAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPCSTR, PLUID)
LookupPrivilegeValueAParams = ((1, 'lpSystemName'), (1, 'lpName'), (1, 'lpLuid'))

#def LookupPrivilegeValueW(lpSystemName, lpName, lpLuid):
#    return LookupPrivilegeValueW.ctypes_function(lpSystemName, lpName, lpLuid)
LookupPrivilegeValueWPrototype = WINFUNCTYPE(BOOL, LPCWSTR, LPCWSTR, PLUID)
LookupPrivilegeValueWParams = ((1, 'lpSystemName'), (1, 'lpName'), (1, 'lpLuid'))

#def AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength):
#    return AdjustTokenPrivileges.ctypes_function(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength)
AdjustTokenPrivilegesPrototype = WINFUNCTYPE(BOOL, HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD)
AdjustTokenPrivilegesParams = ((1, 'TokenHandle'), (1, 'DisableAllPrivileges'), (1, 'NewState'), (1, 'BufferLength'), (1, 'PreviousState'), (1, 'ReturnLength'))

#def FindResourceA(hModule, lpName, lpType):
#    return FindResourceA.ctypes_function(hModule, lpName, lpType)
FindResourceAPrototype = WINFUNCTYPE(HRSRC, HMODULE, LPCSTR, LPCSTR)
FindResourceAParams = ((1, 'hModule'), (1, 'lpName'), (1, 'lpType'))

#def FindResourceW(hModule, lpName, lpType):
#    return FindResourceW.ctypes_function(hModule, lpName, lpType)
FindResourceWPrototype = WINFUNCTYPE(HRSRC, HMODULE, LPCWSTR, LPCWSTR)
FindResourceWParams = ((1, 'hModule'), (1, 'lpName'), (1, 'lpType'))

#def SizeofResource(hModule, hResInfo):
#    return SizeofResource.ctypes_function(hModule, hResInfo)
SizeofResourcePrototype = WINFUNCTYPE(DWORD, HMODULE, HRSRC)
SizeofResourceParams = ((1, 'hModule'), (1, 'hResInfo'))

#def LoadResource(hModule, hResInfo):
#    return LoadResource.ctypes_function(hModule, hResInfo)
LoadResourcePrototype = WINFUNCTYPE(HGLOBAL, HMODULE, HRSRC)
LoadResourceParams = ((1, 'hModule'), (1, 'hResInfo'))

#def LockResource(hResData):
#    return LockResource.ctypes_function(hResData)
LockResourcePrototype = WINFUNCTYPE(LPVOID, HGLOBAL)
LockResourceParams = ((1, 'hResData'),)

#def GetVersionExA(lpVersionInformation):
#    return GetVersionExA.ctypes_function(lpVersionInformation)
GetVersionExAPrototype = WINFUNCTYPE(BOOL, LPOSVERSIONINFOA)
GetVersionExAParams = ((1, 'lpVersionInformation'),)

#def GetVersionExW(lpVersionInformation):
#    return GetVersionExW.ctypes_function(lpVersionInformation)
GetVersionExWPrototype = WINFUNCTYPE(BOOL, LPOSVERSIONINFOW)
GetVersionExWParams = ((1, 'lpVersionInformation'),)

#def GetVersion():
#    return GetVersion.ctypes_function()
GetVersionPrototype = WINFUNCTYPE(DWORD)
GetVersionParams = ()

#def GetCurrentThread():
#    return GetCurrentThread.ctypes_function()
GetCurrentThreadPrototype = WINFUNCTYPE(HANDLE)
GetCurrentThreadParams = ()

#def GetCurrentThreadId():
#    return GetCurrentThreadId.ctypes_function()
GetCurrentThreadIdPrototype = WINFUNCTYPE(DWORD)
GetCurrentThreadIdParams = ()

#def GetCurrentProcessorNumber():
#    return GetCurrentProcessorNumber.ctypes_function()
GetCurrentProcessorNumberPrototype = WINFUNCTYPE(DWORD)
GetCurrentProcessorNumberParams = ()

#def AllocConsole():
#    return AllocConsole.ctypes_function()
AllocConsolePrototype = WINFUNCTYPE(BOOL)
AllocConsoleParams = ()

#def FreeConsole():
#    return FreeConsole.ctypes_function()
FreeConsolePrototype = WINFUNCTYPE(BOOL)
FreeConsoleParams = ()

#def GetStdHandle(nStdHandle):
#    return GetStdHandle.ctypes_function(nStdHandle)
GetStdHandlePrototype = WINFUNCTYPE(HANDLE, DWORD)
GetStdHandleParams = ((1, 'nStdHandle'),)

#def SetStdHandle(nStdHandle, hHandle):
#    return SetStdHandle.ctypes_function(nStdHandle, hHandle)
SetStdHandlePrototype = WINFUNCTYPE(BOOL, DWORD, HANDLE)
SetStdHandleParams = ((1, 'nStdHandle'), (1, 'hHandle'))

#def SetThreadAffinityMask(hThread, dwThreadAffinityMask):
#    return SetThreadAffinityMask.ctypes_function(hThread, dwThreadAffinityMask)
SetThreadAffinityMaskPrototype = WINFUNCTYPE(DWORD, HANDLE, DWORD)
SetThreadAffinityMaskParams = ((1, 'hThread'), (1, 'dwThreadAffinityMask'))

#def ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):
#    return ReadFile.ctypes_function(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
ReadFilePrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
ReadFileParams = ((1, 'hFile'), (1, 'lpBuffer'), (1, 'nNumberOfBytesToRead'), (1, 'lpNumberOfBytesRead'), (1, 'lpOverlapped'))

#def WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
#    return WriteFile.ctypes_function(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)
WriteFilePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)
WriteFileParams = ((1, 'hFile'), (1, 'lpBuffer'), (1, 'nNumberOfBytesToWrite'), (1, 'lpNumberOfBytesWritten'), (1, 'lpOverlapped'))

#def GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved):
#    return GetExtendedTcpTable.ctypes_function(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)
GetExtendedTcpTablePrototype = WINFUNCTYPE(DWORD, PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG)
GetExtendedTcpTableParams = ((1, 'pTcpTable'), (1, 'pdwSize'), (1, 'bOrder'), (1, 'ulAf'), (1, 'TableClass'), (1, 'Reserved'))

#def GetExtendedUdpTable(pUdpTable, pdwSize, bOrder, ulAf, TableClass, Reserved):
#    return GetExtendedUdpTable.ctypes_function(pUdpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)
GetExtendedUdpTablePrototype = WINFUNCTYPE(DWORD, PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG)
GetExtendedUdpTableParams = ((1, 'pUdpTable'), (1, 'pdwSize'), (1, 'bOrder'), (1, 'ulAf'), (1, 'TableClass'), (1, 'Reserved'))

#def SetTcpEntry(pTcpRow):
#    return SetTcpEntry.ctypes_function(pTcpRow)
SetTcpEntryPrototype = WINFUNCTYPE(DWORD, PMIB_TCPROW)
SetTcpEntryParams = ((1, 'pTcpRow'),)

#def AddVectoredContinueHandler(FirstHandler, VectoredHandler):
#    return AddVectoredContinueHandler.ctypes_function(FirstHandler, VectoredHandler)
AddVectoredContinueHandlerPrototype = WINFUNCTYPE(PVOID, ULONG, PVECTORED_EXCEPTION_HANDLER)
AddVectoredContinueHandlerParams = ((1, 'FirstHandler'), (1, 'VectoredHandler'))

#def AddVectoredExceptionHandler(FirstHandler, VectoredHandler):
#    return AddVectoredExceptionHandler.ctypes_function(FirstHandler, VectoredHandler)
AddVectoredExceptionHandlerPrototype = WINFUNCTYPE(PVOID, ULONG, PVECTORED_EXCEPTION_HANDLER)
AddVectoredExceptionHandlerParams = ((1, 'FirstHandler'), (1, 'VectoredHandler'))

#def TerminateThread(hThread, dwExitCode):
#    return TerminateThread.ctypes_function(hThread, dwExitCode)
TerminateThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD)
TerminateThreadParams = ((1, 'hThread'), (1, 'dwExitCode'))

#def ExitThread(dwExitCode):
#    return ExitThread.ctypes_function(dwExitCode)
ExitThreadPrototype = WINFUNCTYPE(VOID, DWORD)
ExitThreadParams = ((1, 'dwExitCode'),)

#def RemoveVectoredExceptionHandler(Handler):
#    return RemoveVectoredExceptionHandler.ctypes_function(Handler)
RemoveVectoredExceptionHandlerPrototype = WINFUNCTYPE(ULONG, PVOID)
RemoveVectoredExceptionHandlerParams = ((1, 'Handler'),)

#def ResumeThread(hThread):
#    return ResumeThread.ctypes_function(hThread)
ResumeThreadPrototype = WINFUNCTYPE(DWORD, HANDLE)
ResumeThreadParams = ((1, 'hThread'),)

#def SuspendThread(hThread):
#    return SuspendThread.ctypes_function(hThread)
SuspendThreadPrototype = WINFUNCTYPE(DWORD, HANDLE)
SuspendThreadParams = ((1, 'hThread'),)

#def WaitForSingleObject(hHandle, dwMilliseconds):
#    return WaitForSingleObject.ctypes_function(hHandle, dwMilliseconds)
WaitForSingleObjectPrototype = WINFUNCTYPE(DWORD, HANDLE, DWORD)
WaitForSingleObjectParams = ((1, 'hHandle'), (1, 'dwMilliseconds'))

#def GetThreadId(Thread):
#    return GetThreadId.ctypes_function(Thread)
GetThreadIdPrototype = WINFUNCTYPE(DWORD, HANDLE)
GetThreadIdParams = ((1, 'Thread'),)

#def LoadLibraryExA(lpFileName, hFile, dwFlags):
#    return LoadLibraryExA.ctypes_function(lpFileName, hFile, dwFlags)
LoadLibraryExAPrototype = WINFUNCTYPE(HMODULE, LPCSTR, HANDLE, DWORD)
LoadLibraryExAParams = ((1, 'lpFileName'), (1, 'hFile'), (1, 'dwFlags'))

#def LoadLibraryExW(lpFileName, hFile, dwFlags):
#    return LoadLibraryExW.ctypes_function(lpFileName, hFile, dwFlags)
LoadLibraryExWPrototype = WINFUNCTYPE(HMODULE, LPCWSTR, HANDLE, DWORD)
LoadLibraryExWParams = ((1, 'lpFileName'), (1, 'hFile'), (1, 'dwFlags'))

#def SymInitialize(hProcess, UserSearchPath, fInvadeProcess):
#    return SymInitialize.ctypes_function(hProcess, UserSearchPath, fInvadeProcess)
SymInitializePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCSTR, BOOL)
SymInitializeParams = ((1, 'hProcess'), (1, 'UserSearchPath'), (1, 'fInvadeProcess'))

#def SymFromName(hProcess, Name, Symbol):
#    return SymFromName.ctypes_function(hProcess, Name, Symbol)
SymFromNamePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCSTR, PSYMBOL_INFO)
SymFromNameParams = ((1, 'hProcess'), (1, 'Name'), (1, 'Symbol'))

#def SymLoadModuleEx(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
#    return SymLoadModuleEx.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)
SymLoadModuleExPrototype = WINFUNCTYPE(DWORD64, HANDLE, HANDLE, LPCSTR, LPCSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD)
SymLoadModuleExParams = ((1, 'hProcess'), (1, 'hFile'), (1, 'ImageName'), (1, 'ModuleName'), (1, 'BaseOfDll'), (1, 'DllSize'), (1, 'Data'), (1, 'Flags'))

#def SymSetOptions(SymOptions):
#    return SymSetOptions.ctypes_function(SymOptions)
SymSetOptionsPrototype = WINFUNCTYPE(DWORD, DWORD)
SymSetOptionsParams = ((1, 'SymOptions'),)

#def SymGetTypeInfo(hProcess, ModBase, TypeId, GetType, pInfo):
#    return SymGetTypeInfo.ctypes_function(hProcess, ModBase, TypeId, GetType, pInfo)
SymGetTypeInfoPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64, ULONG, IMAGEHLP_SYMBOL_TYPE_INFO, PVOID)
SymGetTypeInfoParams = ((1, 'hProcess'), (1, 'ModBase'), (1, 'TypeId'), (1, 'GetType'), (1, 'pInfo'))

#def DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped):
#    return DeviceIoControl.ctypes_function(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)
DeviceIoControlPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
DeviceIoControlParams = ((1, 'hDevice'), (1, 'dwIoControlCode'), (1, 'lpInBuffer'), (1, 'nInBufferSize'), (1, 'lpOutBuffer'), (1, 'nOutBufferSize'), (1, 'lpBytesReturned'), (1, 'lpOverlapped'))

#def GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength):
#    return GetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength)
GetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD)
GetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'), (1, 'ReturnLength'))

#def RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult):
#    return RegOpenKeyExA.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)
RegOpenKeyExAPrototype = WINFUNCTYPE(LONG, HKEY, LPCSTR, DWORD, REGSAM, PHKEY)
RegOpenKeyExAParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'ulOptions'), (1, 'samDesired'), (1, 'phkResult'))

#def RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult):
#    return RegOpenKeyExW.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)
RegOpenKeyExWPrototype = WINFUNCTYPE(LONG, HKEY, LPWSTR, DWORD, REGSAM, PHKEY)
RegOpenKeyExWParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'ulOptions'), (1, 'samDesired'), (1, 'phkResult'))

#def RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
#    return RegGetValueA.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
RegGetValueAPrototype = WINFUNCTYPE(LONG, HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD)
RegGetValueAParams = ((1, 'hkey'), (1, 'lpSubKey'), (1, 'lpValue'), (1, 'dwFlags'), (1, 'pdwType'), (1, 'pvData'), (1, 'pcbData'))

#def RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
#    return RegGetValueW.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
RegGetValueWPrototype = WINFUNCTYPE(LONG, HKEY, LPWSTR, LPWSTR, DWORD, LPDWORD, PVOID, LPDWORD)
RegGetValueWParams = ((1, 'hkey'), (1, 'lpSubKey'), (1, 'lpValue'), (1, 'dwFlags'), (1, 'pdwType'), (1, 'pvData'), (1, 'pcbData'))

#def RegCloseKey(hKey):
#    return RegCloseKey.ctypes_function(hKey)
RegCloseKeyPrototype = WINFUNCTYPE(LONG, HKEY)
RegCloseKeyParams = ((1, 'hKey'),)

#def Wow64DisableWow64FsRedirection(OldValue):
#    return Wow64DisableWow64FsRedirection.ctypes_function(OldValue)
Wow64DisableWow64FsRedirectionPrototype = WINFUNCTYPE(BOOL, POINTER(PVOID))
Wow64DisableWow64FsRedirectionParams = ((1, 'OldValue'),)

#def Wow64RevertWow64FsRedirection(OldValue):
#    return Wow64RevertWow64FsRedirection.ctypes_function(OldValue)
Wow64RevertWow64FsRedirectionPrototype = WINFUNCTYPE(BOOL, PVOID)
Wow64RevertWow64FsRedirectionParams = ((1, 'OldValue'),)

#def Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection):
#    return Wow64EnableWow64FsRedirection.ctypes_function(Wow64FsEnableRedirection)
Wow64EnableWow64FsRedirectionPrototype = WINFUNCTYPE(BOOLEAN, BOOLEAN)
Wow64EnableWow64FsRedirectionParams = ((1, 'Wow64FsEnableRedirection'),)

#def Wow64GetThreadContext(hThread, lpContext):
#    return Wow64GetThreadContext.ctypes_function(hThread, lpContext)
Wow64GetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, PWOW64_CONTEXT)
Wow64GetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

#def SetConsoleCtrlHandler(HandlerRoutine, Add):
#    return SetConsoleCtrlHandler.ctypes_function(HandlerRoutine, Add)
SetConsoleCtrlHandlerPrototype = WINFUNCTYPE(BOOL, PHANDLER_ROUTINE, BOOL)
SetConsoleCtrlHandlerParams = ((1, 'HandlerRoutine'), (1, 'Add'))

#def WinVerifyTrust(hwnd, pgActionID, pWVTData):
#    return WinVerifyTrust.ctypes_function(hwnd, pgActionID, pWVTData)
WinVerifyTrustPrototype = WINFUNCTYPE(LONG, HWND, POINTER(GUID), LPVOID)
WinVerifyTrustParams = ((1, 'hwnd'), (1, 'pgActionID'), (1, 'pWVTData'))

#def GlobalAlloc(uFlags, dwBytes):
#    return GlobalAlloc.ctypes_function(uFlags, dwBytes)
GlobalAllocPrototype = WINFUNCTYPE(HGLOBAL, UINT, SIZE_T)
GlobalAllocParams = ((1, 'uFlags'), (1, 'dwBytes'))

#def GlobalFree(hMem):
#    return GlobalFree.ctypes_function(hMem)
GlobalFreePrototype = WINFUNCTYPE(HGLOBAL, HGLOBAL)
GlobalFreeParams = ((1, 'hMem'),)

#def GlobalUnlock(hMem):
#    return GlobalUnlock.ctypes_function(hMem)
GlobalUnlockPrototype = WINFUNCTYPE(BOOL, HGLOBAL)
GlobalUnlockParams = ((1, 'hMem'),)

#def GlobalLock(hMem):
#    return GlobalLock.ctypes_function(hMem)
GlobalLockPrototype = WINFUNCTYPE(LPVOID, HGLOBAL)
GlobalLockParams = ((1, 'hMem'),)

#def OpenClipboard(hWndNewOwner):
#    return OpenClipboard.ctypes_function(hWndNewOwner)
OpenClipboardPrototype = WINFUNCTYPE(BOOL, HWND)
OpenClipboardParams = ((1, 'hWndNewOwner'),)

#def EmptyClipboard():
#    return EmptyClipboard.ctypes_function()
EmptyClipboardPrototype = WINFUNCTYPE(BOOL)
EmptyClipboardParams = ()

#def CloseClipboard():
#    return CloseClipboard.ctypes_function()
CloseClipboardPrototype = WINFUNCTYPE(BOOL)
CloseClipboardParams = ()

#def SetClipboardData(uFormat, hMem):
#    return SetClipboardData.ctypes_function(uFormat, hMem)
SetClipboardDataPrototype = WINFUNCTYPE(HANDLE, UINT, HANDLE)
SetClipboardDataParams = ((1, 'uFormat'), (1, 'hMem'))

#def GetClipboardData(uFormat):
#    return GetClipboardData.ctypes_function(uFormat)
GetClipboardDataPrototype = WINFUNCTYPE(HANDLE, UINT)
GetClipboardDataParams = ((1, 'uFormat'),)

#def EnumClipboardFormats(format):
#    return EnumClipboardFormats.ctypes_function(format)
EnumClipboardFormatsPrototype = WINFUNCTYPE(UINT, UINT)
EnumClipboardFormatsParams = ((1, 'format'),)

#def GetClipboardFormatNameA(format, lpszFormatName, cchMaxCount):
#    return GetClipboardFormatNameA.ctypes_function(format, lpszFormatName, cchMaxCount)
GetClipboardFormatNameAPrototype = WINFUNCTYPE(INT, UINT, LPCSTR, INT)
GetClipboardFormatNameAParams = ((1, 'format'), (1, 'lpszFormatName'), (1, 'cchMaxCount'))

#def GetClipboardFormatNameW(format, lpszFormatName, cchMaxCount):
#    return GetClipboardFormatNameW.ctypes_function(format, lpszFormatName, cchMaxCount)
GetClipboardFormatNameWPrototype = WINFUNCTYPE(INT, UINT, LPCWSTR, INT)
GetClipboardFormatNameWParams = ((1, 'format'), (1, 'lpszFormatName'), (1, 'cchMaxCount'))

#def WinVerifyTrust(hWnd, pgActionID, pWVTData):
#    return WinVerifyTrust.ctypes_function(hWnd, pgActionID, pWVTData)
WinVerifyTrustPrototype = WINFUNCTYPE(LONG, HWND, POINTER(GUID), LPVOID)
WinVerifyTrustParams = ((1, 'hWnd'), (1, 'pgActionID'), (1, 'pWVTData'))

#def OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle):
#    return OpenProcessToken.ctypes_function(ProcessHandle, DesiredAccess, TokenHandle)
OpenProcessTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, PHANDLE)
OpenProcessTokenParams = ((1, 'ProcessHandle'), (1, 'DesiredAccess'), (1, 'TokenHandle'))

#def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle):
#    return OpenThreadToken.ctypes_function(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle)
OpenThreadTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, BOOL, PHANDLE)
OpenThreadTokenParams = ((1, 'ThreadHandle'), (1, 'DesiredAccess'), (1, 'OpenAsSelf'), (1, 'TokenHandle'))

#def GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength):
#    return GetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength)
GetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD)
GetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'), (1, 'ReturnLength'))

#def SetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength):
#    return SetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength)
SetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD)
SetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'))

#def GetSidIdentifierAuthority(pSid):
#    return GetSidIdentifierAuthority.ctypes_function(pSid)
GetSidIdentifierAuthorityPrototype = WINFUNCTYPE(PSID_IDENTIFIER_AUTHORITY, PSID)
GetSidIdentifierAuthorityParams = ((1, 'pSid'),)

#def GetSidSubAuthority(pSid, nSubAuthority):
#    return GetSidSubAuthority.ctypes_function(pSid, nSubAuthority)
GetSidSubAuthorityPrototype = WINFUNCTYPE(PDWORD, PSID, DWORD)
GetSidSubAuthorityParams = ((1, 'pSid'), (1, 'nSubAuthority'))

#def GetSidSubAuthorityCount(pSid):
#    return GetSidSubAuthorityCount.ctypes_function(pSid)
GetSidSubAuthorityCountPrototype = WINFUNCTYPE(PUCHAR, PSID)
GetSidSubAuthorityCountParams = ((1, 'pSid'),)

#def DebugBreak():
#    return DebugBreak.ctypes_function()
DebugBreakPrototype = WINFUNCTYPE(VOID)
DebugBreakParams = ()

#def WaitForDebugEvent(lpDebugEvent, dwMilliseconds):
#    return WaitForDebugEvent.ctypes_function(lpDebugEvent, dwMilliseconds)
WaitForDebugEventPrototype = WINFUNCTYPE(BOOL, LPDEBUG_EVENT, DWORD)
WaitForDebugEventParams = ((1, 'lpDebugEvent'), (1, 'dwMilliseconds'))

#def ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus):
#    return ContinueDebugEvent.ctypes_function(dwProcessId, dwThreadId, dwContinueStatus)
ContinueDebugEventPrototype = WINFUNCTYPE(BOOL, DWORD, DWORD, DWORD)
ContinueDebugEventParams = ((1, 'dwProcessId'), (1, 'dwThreadId'), (1, 'dwContinueStatus'))

#def DebugActiveProcess(dwProcessId):
#    return DebugActiveProcess.ctypes_function(dwProcessId)
DebugActiveProcessPrototype = WINFUNCTYPE(BOOL, DWORD)
DebugActiveProcessParams = ((1, 'dwProcessId'),)

#def DebugActiveProcessStop(dwProcessId):
#    return DebugActiveProcessStop.ctypes_function(dwProcessId)
DebugActiveProcessStopPrototype = WINFUNCTYPE(BOOL, DWORD)
DebugActiveProcessStopParams = ((1, 'dwProcessId'),)

#def DebugSetProcessKillOnExit(KillOnExit):
#    return DebugSetProcessKillOnExit.ctypes_function(KillOnExit)
DebugSetProcessKillOnExitPrototype = WINFUNCTYPE(BOOL, BOOL)
DebugSetProcessKillOnExitParams = ((1, 'KillOnExit'),)

#def DebugBreakProcess(Process):
#    return DebugBreakProcess.ctypes_function(Process)
DebugBreakProcessPrototype = WINFUNCTYPE(BOOL, HANDLE)
DebugBreakProcessParams = ((1, 'Process'),)

#def GetProcessId(Process):
#    return GetProcessId.ctypes_function(Process)
GetProcessIdPrototype = WINFUNCTYPE(DWORD, HANDLE)
GetProcessIdParams = ((1, 'Process'),)

#def Wow64SetThreadContext(hThread, lpContext):
#    return Wow64SetThreadContext.ctypes_function(hThread, lpContext)
Wow64SetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, POINTER(WOW64_CONTEXT))
Wow64SetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

#def GetMappedFileNameW(hProcess, lpv, lpFilename, nSize):
#    return GetMappedFileNameW.ctypes_function(hProcess, lpv, lpFilename, nSize)
GetMappedFileNameWPrototype = WINFUNCTYPE(DWORD, HANDLE, LPVOID, PVOID, DWORD)
GetMappedFileNameWParams = ((1, 'hProcess'), (1, 'lpv'), (1, 'lpFilename'), (1, 'nSize'))

#def GetMappedFileNameA(hProcess, lpv, lpFilename, nSize):
#    return GetMappedFileNameA.ctypes_function(hProcess, lpv, lpFilename, nSize)
GetMappedFileNameAPrototype = WINFUNCTYPE(DWORD, HANDLE, LPVOID, PVOID, DWORD)
GetMappedFileNameAParams = ((1, 'hProcess'), (1, 'lpv'), (1, 'lpFilename'), (1, 'nSize'))

#def RtlInitString(DestinationString, SourceString):
#    return RtlInitString.ctypes_function(DestinationString, SourceString)
RtlInitStringPrototype = WINFUNCTYPE(VOID, PSTRING, LPCSTR)
RtlInitStringParams = ((1, 'DestinationString'), (1, 'SourceString'))

#def RtlInitUnicodeString(DestinationString, SourceString):
#    return RtlInitUnicodeString.ctypes_function(DestinationString, SourceString)
RtlInitUnicodeStringPrototype = WINFUNCTYPE(VOID, PUNICODE_STRING, LPCWSTR)
RtlInitUnicodeStringParams = ((1, 'DestinationString'), (1, 'SourceString'))

#def RtlAnsiStringToUnicodeString(DestinationString, SourceString, AllocateDestinationString):
#    return RtlAnsiStringToUnicodeString.ctypes_function(DestinationString, SourceString, AllocateDestinationString)
RtlAnsiStringToUnicodeStringPrototype = WINFUNCTYPE(NTSTATUS, PUNICODE_STRING, PCANSI_STRING, BOOLEAN)
RtlAnsiStringToUnicodeStringParams = ((1, 'DestinationString'), (1, 'SourceString'), (1, 'AllocateDestinationString'))

#def OpenEventA(dwDesiredAccess, bInheritHandle, lpName):
#    return OpenEventA.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)
OpenEventAPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCSTR)
OpenEventAParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

#def OpenEventW(dwDesiredAccess, bInheritHandle, lpName):
#    return OpenEventW.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)
OpenEventWPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCWSTR)
OpenEventWParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

#def NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes):
#    return NtOpenEvent.ctypes_function(EventHandle, DesiredAccess, ObjectAttributes)
NtOpenEventPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenEventParams = ((1, 'EventHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

#def NtAlpcCreatePort(PortHandle, ObjectAttributes, PortAttributes):
#    return NtAlpcCreatePort.ctypes_function(PortHandle, ObjectAttributes, PortAttributes)
NtAlpcCreatePortPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES)
NtAlpcCreatePortParams = ((1, 'PortHandle'), (1, 'ObjectAttributes'), (1, 'PortAttributes'))

#def NtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout):
#    return NtAlpcConnectPort.ctypes_function(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)
NtAlpcConnectPortPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, ULONG, PSID, PPORT_MESSAGE, PULONG, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER)
NtAlpcConnectPortParams = ((1, 'PortHandle'), (1, 'PortName'), (1, 'ObjectAttributes'), (1, 'PortAttributes'), (1, 'Flags'), (1, 'RequiredServerSid'), (1, 'ConnectionMessage'), (1, 'BufferLength'), (1, 'OutMessageAttributes'), (1, 'InMessageAttributes'), (1, 'Timeout'))

#def NtAlpcConnectPortEx(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout):
#    return NtAlpcConnectPortEx.ctypes_function(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)
NtAlpcConnectPortExPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, ULONG, PSECURITY_DESCRIPTOR, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER)
NtAlpcConnectPortExParams = ((1, 'PortHandle'), (1, 'ConnectionPortObjectAttributes'), (1, 'ClientPortObjectAttributes'), (1, 'PortAttributes'), (1, 'Flags'), (1, 'ServerSecurityRequirements'), (1, 'ConnectionMessage'), (1, 'BufferLength'), (1, 'OutMessageAttributes'), (1, 'InMessageAttributes'), (1, 'Timeout'))

#def NtAlpcAcceptConnectPort(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection):
#    return NtAlpcAcceptConnectPort.ctypes_function(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection)
NtAlpcAcceptConnectPortPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, HANDLE, ULONG, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, PVOID, PPORT_MESSAGE, PALPC_MESSAGE_ATTRIBUTES, BOOLEAN)
NtAlpcAcceptConnectPortParams = ((1, 'PortHandle'), (1, 'ConnectionPortHandle'), (1, 'Flags'), (1, 'ObjectAttributes'), (1, 'PortAttributes'), (1, 'PortContext'), (1, 'ConnectionRequest'), (1, 'ConnectionMessageAttributes'), (1, 'AcceptConnection'))

#def AlpcInitializeMessageAttribute(AttributeFlags, Buffer, BufferSize, RequiredBufferSize):
#    return AlpcInitializeMessageAttribute.ctypes_function(AttributeFlags, Buffer, BufferSize, RequiredBufferSize)
AlpcInitializeMessageAttributePrototype = WINFUNCTYPE(NTSTATUS, ULONG, PALPC_MESSAGE_ATTRIBUTES, ULONG, PULONG)
AlpcInitializeMessageAttributeParams = ((1, 'AttributeFlags'), (1, 'Buffer'), (1, 'BufferSize'), (1, 'RequiredBufferSize'))

#def AlpcGetMessageAttribute(Buffer, AttributeFlag):
#    return AlpcGetMessageAttribute.ctypes_function(Buffer, AttributeFlag)
AlpcGetMessageAttributePrototype = WINFUNCTYPE(PVOID, PALPC_MESSAGE_ATTRIBUTES, ULONG)
AlpcGetMessageAttributeParams = ((1, 'Buffer'), (1, 'AttributeFlag'))

#def NtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout):
#    return NtAlpcSendWaitReceivePort.ctypes_function(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout)
NtAlpcSendWaitReceivePortPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, PPORT_MESSAGE, PALPC_MESSAGE_ATTRIBUTES, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER)
NtAlpcSendWaitReceivePortParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'SendMessage'), (1, 'SendMessageAttributes'), (1, 'ReceiveMessage'), (1, 'BufferLength'), (1, 'ReceiveMessageAttributes'), (1, 'Timeout'))

#def lstrcmpA(lpString1, lpString2):
#    return lstrcmpA.ctypes_function(lpString1, lpString2)
lstrcmpAPrototype = WINFUNCTYPE(INT, LPCSTR, LPCSTR)
lstrcmpAParams = ((1, 'lpString1'), (1, 'lpString2'))

#def lstrcmpW(lpString1, lpString2):
#    return lstrcmpW.ctypes_function(lpString1, lpString2)
lstrcmpWPrototype = WINFUNCTYPE(INT, LPCWSTR, LPCWSTR)
lstrcmpWParams = ((1, 'lpString1'), (1, 'lpString2'))

#def CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
#    return CreateFileMappingA.ctypes_function(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
CreateFileMappingAPrototype = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR)
CreateFileMappingAParams = ((1, 'hFile'), (1, 'lpFileMappingAttributes'), (1, 'flProtect'), (1, 'dwMaximumSizeHigh'), (1, 'dwMaximumSizeLow'), (1, 'lpName'))

#def CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
#    return CreateFileMappingW.ctypes_function(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
CreateFileMappingWPrototype = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR)
CreateFileMappingWParams = ((1, 'hFile'), (1, 'lpFileMappingAttributes'), (1, 'flProtect'), (1, 'dwMaximumSizeHigh'), (1, 'dwMaximumSizeLow'), (1, 'lpName'))

#def MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap):
#    return MapViewOfFile.ctypes_function(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)
MapViewOfFilePrototype = WINFUNCTYPE(LPVOID, HANDLE, DWORD, DWORD, DWORD, SIZE_T)
MapViewOfFileParams = ((1, 'hFileMappingObject'), (1, 'dwDesiredAccess'), (1, 'dwFileOffsetHigh'), (1, 'dwFileOffsetLow'), (1, 'dwNumberOfBytesToMap'))

#def OpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess):
#    return OpenSCManagerA.ctypes_function(lpMachineName, lpDatabaseName, dwDesiredAccess)
OpenSCManagerAPrototype = WINFUNCTYPE(SC_HANDLE, LPCSTR, LPCSTR, DWORD)
OpenSCManagerAParams = ((1, 'lpMachineName'), (1, 'lpDatabaseName'), (1, 'dwDesiredAccess'))

#def OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess):
#    return OpenSCManagerW.ctypes_function(lpMachineName, lpDatabaseName, dwDesiredAccess)
OpenSCManagerWPrototype = WINFUNCTYPE(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD)
OpenSCManagerWParams = ((1, 'lpMachineName'), (1, 'lpDatabaseName'), (1, 'dwDesiredAccess'))

#def EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
#    return EnumServicesStatusExA.ctypes_function(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)
EnumServicesStatusExAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR)
EnumServicesStatusExAParams = ((1, 'hSCManager'), (1, 'InfoLevel'), (1, 'dwServiceType'), (1, 'dwServiceState'), (1, 'lpServices'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'), (1, 'lpServicesReturned'), (1, 'lpResumeHandle'), (1, 'pszGroupName'))

#def EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
#    return EnumServicesStatusExW.ctypes_function(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)
EnumServicesStatusExWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR)
EnumServicesStatusExWParams = ((1, 'hSCManager'), (1, 'InfoLevel'), (1, 'dwServiceType'), (1, 'dwServiceState'), (1, 'lpServices'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'), (1, 'lpServicesReturned'), (1, 'lpResumeHandle'), (1, 'pszGroupName'))

#def EnumWindows(lpEnumFunc, lParam):
#    return EnumWindows.ctypes_function(lpEnumFunc, lParam)
EnumWindowsPrototype = WINFUNCTYPE(BOOL, WNDENUMPROC, LPARAM)
EnumWindowsParams = ((1, 'lpEnumFunc'), (1, 'lParam'))

#def GetWindowTextA(hWnd, lpString, nMaxCount):
#    return GetWindowTextA.ctypes_function(hWnd, lpString, nMaxCount)
GetWindowTextAPrototype = WINFUNCTYPE(INT, HWND, LPSTR, INT)
GetWindowTextAParams = ((1, 'hWnd'), (1, 'lpString'), (1, 'nMaxCount'))

#def GetWindowTextW(hWnd, lpString, nMaxCount):
#    return GetWindowTextW.ctypes_function(hWnd, lpString, nMaxCount)
GetWindowTextWPrototype = WINFUNCTYPE(INT, HWND, LPWSTR, INT)
GetWindowTextWParams = ((1, 'hWnd'), (1, 'lpString'), (1, 'nMaxCount'))

#def GetWindowModuleFileNameA(hwnd, pszFileName, cchFileNameMax):
#    return GetWindowModuleFileNameA.ctypes_function(hwnd, pszFileName, cchFileNameMax)
GetWindowModuleFileNameAPrototype = WINFUNCTYPE(UINT, HWND, LPSTR, UINT)
GetWindowModuleFileNameAParams = ((1, 'hwnd'), (1, 'pszFileName'), (1, 'cchFileNameMax'))

#def GetWindowModuleFileNameW(hwnd, pszFileName, cchFileNameMax):
#    return GetWindowModuleFileNameW.ctypes_function(hwnd, pszFileName, cchFileNameMax)
GetWindowModuleFileNameWPrototype = WINFUNCTYPE(UINT, HWND, LPWSTR, UINT)
GetWindowModuleFileNameWParams = ((1, 'hwnd'), (1, 'pszFileName'), (1, 'cchFileNameMax'))

#def CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags):
#    return CryptCATAdminCalcHashFromFileHandle.ctypes_function(hFile, pcbHash, pbHash, dwFlags)
CryptCATAdminCalcHashFromFileHandlePrototype = WINFUNCTYPE(BOOL, HANDLE, POINTER(DWORD), POINTER(BYTE), DWORD)
CryptCATAdminCalcHashFromFileHandleParams = ((1, 'hFile'), (1, 'pcbHash'), (1, 'pbHash'), (1, 'dwFlags'))

#def CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo):
#    return CryptCATAdminEnumCatalogFromHash.ctypes_function(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo)
CryptCATAdminEnumCatalogFromHashPrototype = WINFUNCTYPE(HCATINFO, HCATADMIN, POINTER(BYTE), DWORD, DWORD, POINTER(HCATINFO))
CryptCATAdminEnumCatalogFromHashParams = ((1, 'hCatAdmin'), (1, 'pbHash'), (1, 'cbHash'), (1, 'dwFlags'), (1, 'phPrevCatInfo'))

#def CryptCATAdminAcquireContext(phCatAdmin, pgSubsystem, dwFlags):
#    return CryptCATAdminAcquireContext.ctypes_function(phCatAdmin, pgSubsystem, dwFlags)
CryptCATAdminAcquireContextPrototype = WINFUNCTYPE(BOOL, POINTER(HCATADMIN), POINTER(GUID), DWORD)
CryptCATAdminAcquireContextParams = ((1, 'phCatAdmin'), (1, 'pgSubsystem'), (1, 'dwFlags'))

#def CryptCATCatalogInfoFromContext(hCatInfo, psCatInfo, dwFlags):
#    return CryptCATCatalogInfoFromContext.ctypes_function(hCatInfo, psCatInfo, dwFlags)
CryptCATCatalogInfoFromContextPrototype = WINFUNCTYPE(BOOL, HCATINFO, POINTER(CATALOG_INFO), DWORD)
CryptCATCatalogInfoFromContextParams = ((1, 'hCatInfo'), (1, 'psCatInfo'), (1, 'dwFlags'))

#def CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwFlags):
#    return CryptCATAdminReleaseCatalogContext.ctypes_function(hCatAdmin, hCatInfo, dwFlags)
CryptCATAdminReleaseCatalogContextPrototype = WINFUNCTYPE(BOOL, HCATADMIN, HCATINFO, DWORD)
CryptCATAdminReleaseCatalogContextParams = ((1, 'hCatAdmin'), (1, 'hCatInfo'), (1, 'dwFlags'))

#def CryptCATAdminReleaseContext(hCatAdmin, dwFlags):
#    return CryptCATAdminReleaseContext.ctypes_function(hCatAdmin, dwFlags)
CryptCATAdminReleaseContextPrototype = WINFUNCTYPE(BOOL, HCATADMIN, DWORD)
CryptCATAdminReleaseContextParams = ((1, 'hCatAdmin'), (1, 'dwFlags'))

#def GetLogicalDriveStringsA(nBufferLength, lpBuffer):
#    return GetLogicalDriveStringsA.ctypes_function(nBufferLength, lpBuffer)
GetLogicalDriveStringsAPrototype = WINFUNCTYPE(DWORD, DWORD, LPCSTR)
GetLogicalDriveStringsAParams = ((1, 'nBufferLength'), (1, 'lpBuffer'))

#def GetLogicalDriveStringsW(nBufferLength, lpBuffer):
#    return GetLogicalDriveStringsW.ctypes_function(nBufferLength, lpBuffer)
GetLogicalDriveStringsWPrototype = WINFUNCTYPE(DWORD, DWORD, LPWSTR)
GetLogicalDriveStringsWParams = ((1, 'nBufferLength'), (1, 'lpBuffer'))

#def GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize):
#    return GetVolumeInformationA.ctypes_function(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)
GetVolumeInformationAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPSTR, DWORD)
GetVolumeInformationAParams = ((1, 'lpRootPathName'), (1, 'lpVolumeNameBuffer'), (1, 'nVolumeNameSize'), (1, 'lpVolumeSerialNumber'), (1, 'lpMaximumComponentLength'), (1, 'lpFileSystemFlags'), (1, 'lpFileSystemNameBuffer'), (1, 'nFileSystemNameSize'))

#def GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize):
#    return GetVolumeInformationW.ctypes_function(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)
GetVolumeInformationWPrototype = WINFUNCTYPE(BOOL, LPWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD)
GetVolumeInformationWParams = ((1, 'lpRootPathName'), (1, 'lpVolumeNameBuffer'), (1, 'nVolumeNameSize'), (1, 'lpVolumeSerialNumber'), (1, 'lpMaximumComponentLength'), (1, 'lpFileSystemFlags'), (1, 'lpFileSystemNameBuffer'), (1, 'nFileSystemNameSize'))

#def GetVolumeNameForVolumeMountPointA(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength):
#    return GetVolumeNameForVolumeMountPointA.ctypes_function(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)
GetVolumeNameForVolumeMountPointAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPCSTR, DWORD)
GetVolumeNameForVolumeMountPointAParams = ((1, 'lpszVolumeMountPoint'), (1, 'lpszVolumeName'), (1, 'cchBufferLength'))

#def GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength):
#    return GetVolumeNameForVolumeMountPointW.ctypes_function(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)
GetVolumeNameForVolumeMountPointWPrototype = WINFUNCTYPE(BOOL, LPWSTR, LPWSTR, DWORD)
GetVolumeNameForVolumeMountPointWParams = ((1, 'lpszVolumeMountPoint'), (1, 'lpszVolumeName'), (1, 'cchBufferLength'))

#def GetDriveTypeA(lpRootPathName):
#    return GetDriveTypeA.ctypes_function(lpRootPathName)
GetDriveTypeAPrototype = WINFUNCTYPE(UINT, LPCSTR)
GetDriveTypeAParams = ((1, 'lpRootPathName'),)

#def GetDriveTypeW(lpRootPathName):
#    return GetDriveTypeW.ctypes_function(lpRootPathName)
GetDriveTypeWPrototype = WINFUNCTYPE(UINT, LPWSTR)
GetDriveTypeWParams = ((1, 'lpRootPathName'),)

#def QueryDosDeviceA(lpDeviceName, lpTargetPath, ucchMax):
#    return QueryDosDeviceA.ctypes_function(lpDeviceName, lpTargetPath, ucchMax)
QueryDosDeviceAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPCSTR, DWORD)
QueryDosDeviceAParams = ((1, 'lpDeviceName'), (1, 'lpTargetPath'), (1, 'ucchMax'))

#def QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax):
#    return QueryDosDeviceW.ctypes_function(lpDeviceName, lpTargetPath, ucchMax)
QueryDosDeviceWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPWSTR, DWORD)
QueryDosDeviceWParams = ((1, 'lpDeviceName'), (1, 'lpTargetPath'), (1, 'ucchMax'))

#def NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength):
#    return NtQueryObject.ctypes_function(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength)
NtQueryObjectPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQueryObjectParams = ((1, 'Handle'), (1, 'ObjectInformationClass'), (1, 'ObjectInformation'), (1, 'ObjectInformationLength'), (1, 'ReturnLength'))

#def DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions):
#    return DuplicateHandle.ctypes_function(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions)
DuplicateHandlePrototype = WINFUNCTYPE(BOOL, HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD)
DuplicateHandleParams = ((1, 'hSourceProcessHandle'), (1, 'hSourceHandle'), (1, 'hTargetProcessHandle'), (1, 'lpTargetHandle'), (1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'dwOptions'))

#def GetModuleBaseNameA(hProcess, hModule, lpBaseName, nSize):
#    return GetModuleBaseNameA.ctypes_function(hProcess, hModule, lpBaseName, nSize)
GetModuleBaseNameAPrototype = WINFUNCTYPE(DWORD, HANDLE, HMODULE, LPCSTR, DWORD)
GetModuleBaseNameAParams = ((1, 'hProcess'), (1, 'hModule'), (1, 'lpBaseName'), (1, 'nSize'))

#def GetModuleBaseNameW(hProcess, hModule, lpBaseName, nSize):
#    return GetModuleBaseNameW.ctypes_function(hProcess, hModule, lpBaseName, nSize)
GetModuleBaseNameWPrototype = WINFUNCTYPE(DWORD, HANDLE, HMODULE, LPWSTR, DWORD)
GetModuleBaseNameWParams = ((1, 'hProcess'), (1, 'hModule'), (1, 'lpBaseName'), (1, 'nSize'))

#def GetProcessImageFileNameA(hProcess, lpImageFileName, nSize):
#    return GetProcessImageFileNameA.ctypes_function(hProcess, lpImageFileName, nSize)
GetProcessImageFileNameAPrototype = WINFUNCTYPE(DWORD, HANDLE, LPCSTR, DWORD)
GetProcessImageFileNameAParams = ((1, 'hProcess'), (1, 'lpImageFileName'), (1, 'nSize'))

#def GetProcessImageFileNameW(hProcess, lpImageFileName, nSize):
#    return GetProcessImageFileNameW.ctypes_function(hProcess, lpImageFileName, nSize)
GetProcessImageFileNameWPrototype = WINFUNCTYPE(DWORD, HANDLE, LPWSTR, DWORD)
GetProcessImageFileNameWParams = ((1, 'hProcess'), (1, 'lpImageFileName'), (1, 'nSize'))

#def GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData):
#    return GetFileVersionInfoA.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)
GetFileVersionInfoAPrototype = WINFUNCTYPE(BOOL, LPCSTR, DWORD, DWORD, LPVOID)
GetFileVersionInfoAParams = ((1, 'lptstrFilename'), (1, 'dwHandle'), (1, 'dwLen'), (1, 'lpData'))

#def GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData):
#    return GetFileVersionInfoW.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)
GetFileVersionInfoWPrototype = WINFUNCTYPE(BOOL, LPWSTR, DWORD, DWORD, LPVOID)
GetFileVersionInfoWParams = ((1, 'lptstrFilename'), (1, 'dwHandle'), (1, 'dwLen'), (1, 'lpData'))

#def GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle):
#    return GetFileVersionInfoSizeA.ctypes_function(lptstrFilename, lpdwHandle)
GetFileVersionInfoSizeAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPDWORD)
GetFileVersionInfoSizeAParams = ((1, 'lptstrFilename'), (1, 'lpdwHandle'))

#def GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle):
#    return GetFileVersionInfoSizeW.ctypes_function(lptstrFilename, lpdwHandle)
GetFileVersionInfoSizeWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPDWORD)
GetFileVersionInfoSizeWParams = ((1, 'lptstrFilename'), (1, 'lpdwHandle'))

#def VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen):
#    return VerQueryValueA.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)
VerQueryValueAPrototype = WINFUNCTYPE(BOOL, LPCVOID, LPCSTR, POINTER(LPVOID), PUINT)
VerQueryValueAParams = ((1, 'pBlock'), (1, 'lpSubBlock'), (1, 'lplpBuffer'), (1, 'puLen'))

#def VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen):
#    return VerQueryValueW.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)
VerQueryValueWPrototype = WINFUNCTYPE(BOOL, LPCVOID, LPWSTR, POINTER(LPVOID), PUINT)
VerQueryValueWParams = ((1, 'pBlock'), (1, 'lpSubBlock'), (1, 'lplpBuffer'), (1, 'puLen'))

#def GetSystemMetrics(nIndex):
#    return GetSystemMetrics.ctypes_function(nIndex)
GetSystemMetricsPrototype = WINFUNCTYPE(INT, INT)
GetSystemMetricsParams = ((1, 'nIndex'),)

#def GetComputerNameA(lpBuffer, lpnSize):
#    return GetComputerNameA.ctypes_function(lpBuffer, lpnSize)
GetComputerNameAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPDWORD)
GetComputerNameAParams = ((1, 'lpBuffer'), (1, 'lpnSize'))

#def GetComputerNameW(lpBuffer, lpnSize):
#    return GetComputerNameW.ctypes_function(lpBuffer, lpnSize)
GetComputerNameWPrototype = WINFUNCTYPE(BOOL, LPWSTR, LPDWORD)
GetComputerNameWParams = ((1, 'lpBuffer'), (1, 'lpnSize'))

#def LookupAccountSidA(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
#    return LookupAccountSidA.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)
LookupAccountSidAPrototype = WINFUNCTYPE(BOOL, LPCSTR, PSID, LPCSTR, LPDWORD, LPCSTR, LPDWORD, PSID_NAME_USE)
LookupAccountSidAParams = ((1, 'lpSystemName'), (1, 'lpSid'), (1, 'lpName'), (1, 'cchName'), (1, 'lpReferencedDomainName'), (1, 'cchReferencedDomainName'), (1, 'peUse'))

#def LookupAccountSidW(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
#    return LookupAccountSidW.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)
LookupAccountSidWPrototype = WINFUNCTYPE(BOOL, LPWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE)
LookupAccountSidWParams = ((1, 'lpSystemName'), (1, 'lpSid'), (1, 'lpName'), (1, 'cchName'), (1, 'lpReferencedDomainName'), (1, 'cchReferencedDomainName'), (1, 'peUse'))

#def CoInitializeEx(pvReserved, dwCoInit):
#    return CoInitializeEx.ctypes_function(pvReserved, dwCoInit)
CoInitializeExPrototype = WINFUNCTYPE(HRESULT, LPVOID, DWORD)
CoInitializeExParams = ((1, 'pvReserved'), (1, 'dwCoInit'))

#def CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3):
#    return CoInitializeSecurity.ctypes_function(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3)
CoInitializeSecurityPrototype = WINFUNCTYPE(HRESULT, PSECURITY_DESCRIPTOR, LONG, POINTER(SOLE_AUTHENTICATION_SERVICE), PVOID, DWORD, DWORD, PVOID, DWORD, PVOID)
CoInitializeSecurityParams = ((1, 'pSecDesc'), (1, 'cAuthSvc'), (1, 'asAuthSvc'), (1, 'pReserved1'), (1, 'dwAuthnLevel'), (1, 'dwImpLevel'), (1, 'pAuthList'), (1, 'dwCapabilities'), (1, 'pReserved3'))

#def CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv):
#    return CoCreateInstance.ctypes_function(rclsid, pUnkOuter, dwClsContext, riid, ppv)
CoCreateInstancePrototype = WINFUNCTYPE(HRESULT, REFCLSID, LPUNKNOWN, DWORD, REFIID, POINTER(LPVOID))
CoCreateInstanceParams = ((1, 'rclsid'), (1, 'pUnkOuter'), (1, 'dwClsContext'), (1, 'riid'), (1, 'ppv'))

#def GetInterfaceInfo(pIfTable, dwOutBufLen):
#    return GetInterfaceInfo.ctypes_function(pIfTable, dwOutBufLen)
GetInterfaceInfoPrototype = WINFUNCTYPE(DWORD, PIP_INTERFACE_INFO, PULONG)
GetInterfaceInfoParams = ((1, 'pIfTable'), (1, 'dwOutBufLen'))

#def GetIfTable(pIfTable, pdwSize, bOrder):
#    return GetIfTable.ctypes_function(pIfTable, pdwSize, bOrder)
GetIfTablePrototype = WINFUNCTYPE(DWORD, PMIB_IFTABLE, PULONG, BOOL)
GetIfTableParams = ((1, 'pIfTable'), (1, 'pdwSize'), (1, 'bOrder'))

#def GetIpAddrTable(pIpAddrTable, pdwSize, bOrder):
#    return GetIpAddrTable.ctypes_function(pIpAddrTable, pdwSize, bOrder)
GetIpAddrTablePrototype = WINFUNCTYPE(DWORD, PMIB_IPADDRTABLE, PULONG, BOOL)
GetIpAddrTableParams = ((1, 'pIpAddrTable'), (1, 'pdwSize'), (1, 'bOrder'))

#def NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes):
#    return NtOpenDirectoryObject.ctypes_function(DirectoryHandle, DesiredAccess, ObjectAttributes)
NtOpenDirectoryObjectPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenDirectoryObjectParams = ((1, 'DirectoryHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

#def NtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength):
#    return NtQueryDirectoryObject.ctypes_function(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength)
NtQueryDirectoryObjectPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG)
NtQueryDirectoryObjectParams = ((1, 'DirectoryHandle'), (1, 'Buffer'), (1, 'Length'), (1, 'ReturnSingleEntry'), (1, 'RestartScan'), (1, 'Context'), (1, 'ReturnLength'))

#def NtQuerySymbolicLinkObject(LinkHandle, LinkTarget, ReturnedLength):
#    return NtQuerySymbolicLinkObject.ctypes_function(LinkHandle, LinkTarget, ReturnedLength)
NtQuerySymbolicLinkObjectPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PUNICODE_STRING, PULONG)
NtQuerySymbolicLinkObjectParams = ((1, 'LinkHandle'), (1, 'LinkTarget'), (1, 'ReturnedLength'))

#def NtOpenSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes):
#    return NtOpenSymbolicLinkObject.ctypes_function(LinkHandle, DesiredAccess, ObjectAttributes)
NtOpenSymbolicLinkObjectPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenSymbolicLinkObjectParams = ((1, 'LinkHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

#def GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime):
#    return GetProcessTimes.ctypes_function(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime)
GetProcessTimesPrototype = WINFUNCTYPE(BOOL, HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME)
GetProcessTimesParams = ((1, 'hProcess'), (1, 'lpCreationTime'), (1, 'lpExitTime'), (1, 'lpKernelTime'), (1, 'lpUserTime'))

#def GetShortPathNameA(lpszLongPath, lpszShortPath, cchBuffer):
#    return GetShortPathNameA.ctypes_function(lpszLongPath, lpszShortPath, cchBuffer)
GetShortPathNameAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPCSTR, DWORD)
GetShortPathNameAParams = ((1, 'lpszLongPath'), (1, 'lpszShortPath'), (1, 'cchBuffer'))

#def GetShortPathNameW(lpszLongPath, lpszShortPath, cchBuffer):
#    return GetShortPathNameW.ctypes_function(lpszLongPath, lpszShortPath, cchBuffer)
GetShortPathNameWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPWSTR, DWORD)
GetShortPathNameWParams = ((1, 'lpszLongPath'), (1, 'lpszShortPath'), (1, 'cchBuffer'))

#def GetLongPathNameA(lpszShortPath, lpszLongPath, cchBuffer):
#    return GetLongPathNameA.ctypes_function(lpszShortPath, lpszLongPath, cchBuffer)
GetLongPathNameAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPCSTR, DWORD)
GetLongPathNameAParams = ((1, 'lpszShortPath'), (1, 'lpszLongPath'), (1, 'cchBuffer'))

#def GetLongPathNameW(lpszShortPath, lpszLongPath, cchBuffer):
#    return GetLongPathNameW.ctypes_function(lpszShortPath, lpszLongPath, cchBuffer)
GetLongPathNameWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPWSTR, DWORD)
GetLongPathNameWParams = ((1, 'lpszShortPath'), (1, 'lpszLongPath'), (1, 'cchBuffer'))

#def GetProcessDEPPolicy(hProcess, lpFlags, lpPermanent):
#    return GetProcessDEPPolicy.ctypes_function(hProcess, lpFlags, lpPermanent)
GetProcessDEPPolicyPrototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD, PBOOL)
GetProcessDEPPolicyParams = ((1, 'hProcess'), (1, 'lpFlags'), (1, 'lpPermanent'))

#def GetCursorPos(lpPoint):
#    return GetCursorPos.ctypes_function(lpPoint)
GetCursorPosPrototype = WINFUNCTYPE(BOOL, LPPOINT)
GetCursorPosParams = ((1, 'lpPoint'),)

#def WindowFromPoint(Point):
#    return WindowFromPoint.ctypes_function(Point)
WindowFromPointPrototype = WINFUNCTYPE(HWND, POINT)
WindowFromPointParams = ((1, 'Point'),)

#def GetWindowRect(hWnd, lpRect):
#    return GetWindowRect.ctypes_function(hWnd, lpRect)
GetWindowRectPrototype = WINFUNCTYPE(BOOL, HWND, LPRECT)
GetWindowRectParams = ((1, 'hWnd'), (1, 'lpRect'))

#def CryptQueryObject(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext):
#    return CryptQueryObject.ctypes_function(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext)
CryptQueryObjectPrototype = WINFUNCTYPE(BOOL, DWORD, PVOID, DWORD, DWORD, DWORD, POINTER(DWORD), POINTER(DWORD), POINTER(DWORD), POINTER(HCERTSTORE), POINTER(HCRYPTMSG), POINTER(PVOID))
CryptQueryObjectParams = ((1, 'dwObjectType'), (1, 'pvObject'), (1, 'dwExpectedContentTypeFlags'), (1, 'dwExpectedFormatTypeFlags'), (1, 'dwFlags'), (1, 'pdwMsgAndCertEncodingType'), (1, 'pdwContentType'), (1, 'pdwFormatType'), (1, 'phCertStore'), (1, 'phMsg'), (1, 'ppvContext'))

#def CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, pvData, pcbData):
#    return CryptMsgGetParam.ctypes_function(hCryptMsg, dwParamType, dwIndex, pvData, pcbData)
CryptMsgGetParamPrototype = WINFUNCTYPE(BOOL, HCRYPTMSG, DWORD, DWORD, PVOID, POINTER(DWORD))
CryptMsgGetParamParams = ((1, 'hCryptMsg'), (1, 'dwParamType'), (1, 'dwIndex'), (1, 'pvData'), (1, 'pcbData'))

#def CryptDecodeObject(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo):
#    return CryptDecodeObject.ctypes_function(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo)
CryptDecodeObjectPrototype = WINFUNCTYPE(BOOL, DWORD, LPCSTR, POINTER(BYTE), DWORD, DWORD, PVOID, POINTER(DWORD))
CryptDecodeObjectParams = ((1, 'dwCertEncodingType'), (1, 'lpszStructType'), (1, 'pbEncoded'), (1, 'cbEncoded'), (1, 'dwFlags'), (1, 'pvStructInfo'), (1, 'pcbStructInfo'))

#def CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext):
#    return CertFindCertificateInStore.ctypes_function(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext)
CertFindCertificateInStorePrototype = WINFUNCTYPE(PCCERT_CONTEXT, HCERTSTORE, DWORD, DWORD, DWORD, PVOID, PCCERT_CONTEXT)
CertFindCertificateInStoreParams = ((1, 'hCertStore'), (1, 'dwCertEncodingType'), (1, 'dwFindFlags'), (1, 'dwFindType'), (1, 'pvFindPara'), (1, 'pPrevCertContext'))

#def CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString):
#    return CertGetNameStringA.ctypes_function(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)
CertGetNameStringAPrototype = WINFUNCTYPE(DWORD, PCCERT_CONTEXT, DWORD, DWORD, PVOID, LPCSTR, DWORD)
CertGetNameStringAParams = ((1, 'pCertContext'), (1, 'dwType'), (1, 'dwFlags'), (1, 'pvTypePara'), (1, 'pszNameString'), (1, 'cchNameString'))

#def CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString):
#    return CertGetNameStringW.ctypes_function(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)
CertGetNameStringWPrototype = WINFUNCTYPE(DWORD, PCCERT_CONTEXT, DWORD, DWORD, PVOID, LPWSTR, DWORD)
CertGetNameStringWParams = ((1, 'pCertContext'), (1, 'dwType'), (1, 'dwFlags'), (1, 'pvTypePara'), (1, 'pszNameString'), (1, 'cchNameString'))

#def CertGetCertificateChain(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext):
#    return CertGetCertificateChain.ctypes_function(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext)
CertGetCertificateChainPrototype = WINFUNCTYPE(BOOL, HCERTCHAINENGINE, PCCERT_CONTEXT, LPFILETIME, HCERTSTORE, PCERT_CHAIN_PARA, DWORD, LPVOID, POINTER(PCCERT_CHAIN_CONTEXT))
CertGetCertificateChainParams = ((1, 'hChainEngine'), (1, 'pCertContext'), (1, 'pTime'), (1, 'hAdditionalStore'), (1, 'pChainPara'), (1, 'dwFlags'), (1, 'pvReserved'), (1, 'ppChainContext'))

#def CertCreateSelfSignCertificate(hCryptProvOrNCryptKey, pSubjectIssuerBlob, dwFlags, pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions):
#    return CertCreateSelfSignCertificate.ctypes_function(hCryptProvOrNCryptKey, pSubjectIssuerBlob, dwFlags, pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions)
CertCreateSelfSignCertificatePrototype = WINFUNCTYPE(PCCERT_CONTEXT, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, PCERT_NAME_BLOB, DWORD, PCRYPT_KEY_PROV_INFO, PCRYPT_ALGORITHM_IDENTIFIER, PSYSTEMTIME, PSYSTEMTIME, PCERT_EXTENSIONS)
CertCreateSelfSignCertificateParams = ((1, 'hCryptProvOrNCryptKey'), (1, 'pSubjectIssuerBlob'), (1, 'dwFlags'), (1, 'pKeyProvInfo'), (1, 'pSignatureAlgorithm'), (1, 'pStartTime'), (1, 'pEndTime'), (1, 'pExtensions'))

#def CertStrToNameA(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError):
#    return CertStrToNameA.ctypes_function(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)
CertStrToNameAPrototype = WINFUNCTYPE(BOOL, DWORD, LPCSTR, DWORD, PVOID, POINTER(BYTE), POINTER(DWORD), POINTER(LPCSTR))
CertStrToNameAParams = ((1, 'dwCertEncodingType'), (1, 'pszX500'), (1, 'dwStrType'), (1, 'pvReserved'), (1, 'pbEncoded'), (1, 'pcbEncoded'), (1, 'ppszError'))

#def CertStrToNameW(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError):
#    return CertStrToNameW.ctypes_function(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)
CertStrToNameWPrototype = WINFUNCTYPE(BOOL, DWORD, LPWSTR, DWORD, PVOID, POINTER(BYTE), POINTER(DWORD), POINTER(LPWSTR))
CertStrToNameWParams = ((1, 'dwCertEncodingType'), (1, 'pszX500'), (1, 'dwStrType'), (1, 'pvReserved'), (1, 'pbEncoded'), (1, 'pcbEncoded'), (1, 'ppszError'))

#def CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara):
#    return CertOpenStore.ctypes_function(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara)
CertOpenStorePrototype = WINFUNCTYPE(HCERTSTORE, LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, PVOID)
CertOpenStoreParams = ((1, 'lpszStoreProvider'), (1, 'dwMsgAndCertEncodingType'), (1, 'hCryptProv'), (1, 'dwFlags'), (1, 'pvPara'))

#def CertAddCertificateContextToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext):
#    return CertAddCertificateContextToStore.ctypes_function(hCertStore, pCertContext, dwAddDisposition, ppStoreContext)
CertAddCertificateContextToStorePrototype = WINFUNCTYPE(BOOL, HCERTSTORE, PCCERT_CONTEXT, DWORD, POINTER(PCCERT_CONTEXT))
CertAddCertificateContextToStoreParams = ((1, 'hCertStore'), (1, 'pCertContext'), (1, 'dwAddDisposition'), (1, 'ppStoreContext'))

#def PFXExportCertStoreEx(hStore, pPFX, szPassword, pvPara, dwFlags):
#    return PFXExportCertStoreEx.ctypes_function(hStore, pPFX, szPassword, pvPara, dwFlags)
PFXExportCertStoreExPrototype = WINFUNCTYPE(BOOL, HCERTSTORE, POINTER(CRYPT_DATA_BLOB), LPCWSTR, PVOID, DWORD)
PFXExportCertStoreExParams = ((1, 'hStore'), (1, 'pPFX'), (1, 'szPassword'), (1, 'pvPara'), (1, 'dwFlags'))

#def PFXImportCertStore(pPFX, szPassword, dwFlags):
#    return PFXImportCertStore.ctypes_function(pPFX, szPassword, dwFlags)
PFXImportCertStorePrototype = WINFUNCTYPE(HCERTSTORE, POINTER(CRYPT_DATA_BLOB), LPCWSTR, DWORD)
PFXImportCertStoreParams = ((1, 'pPFX'), (1, 'szPassword'), (1, 'dwFlags'))

#def CryptGenKey(hProv, Algid, dwFlags, phKey):
#    return CryptGenKey.ctypes_function(hProv, Algid, dwFlags, phKey)
CryptGenKeyPrototype = WINFUNCTYPE(BOOL, HCRYPTPROV, ALG_ID, DWORD, POINTER(HCRYPTKEY))
CryptGenKeyParams = ((1, 'hProv'), (1, 'Algid'), (1, 'dwFlags'), (1, 'phKey'))

#def CryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags):
#    return CryptAcquireContextA.ctypes_function(phProv, pszContainer, pszProvider, dwProvType, dwFlags)
CryptAcquireContextAPrototype = WINFUNCTYPE(BOOL, POINTER(HCRYPTPROV), LPCSTR, LPCSTR, DWORD, DWORD)
CryptAcquireContextAParams = ((1, 'phProv'), (1, 'pszContainer'), (1, 'pszProvider'), (1, 'dwProvType'), (1, 'dwFlags'))

#def CryptAcquireContextW(phProv, pszContainer, pszProvider, dwProvType, dwFlags):
#    return CryptAcquireContextW.ctypes_function(phProv, pszContainer, pszProvider, dwProvType, dwFlags)
CryptAcquireContextWPrototype = WINFUNCTYPE(BOOL, POINTER(HCRYPTPROV), LPWSTR, LPWSTR, DWORD, DWORD)
CryptAcquireContextWParams = ((1, 'phProv'), (1, 'pszContainer'), (1, 'pszProvider'), (1, 'dwProvType'), (1, 'dwFlags'))

#def CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen):
#    return CryptExportKey.ctypes_function(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen)
CryptExportKeyPrototype = WINFUNCTYPE(BOOL, HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, POINTER(BYTE), POINTER(DWORD))
CryptExportKeyParams = ((1, 'hKey'), (1, 'hExpKey'), (1, 'dwBlobType'), (1, 'dwFlags'), (1, 'pbData'), (1, 'pdwDataLen'))

#def CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, pcbData):
#    return CertGetCertificateContextProperty.ctypes_function(pCertContext, dwPropId, pvData, pcbData)
CertGetCertificateContextPropertyPrototype = WINFUNCTYPE(BOOL, PCCERT_CONTEXT, DWORD, PVOID, POINTER(DWORD))
CertGetCertificateContextPropertyParams = ((1, 'pCertContext'), (1, 'dwPropId'), (1, 'pvData'), (1, 'pcbData'))

#def CertEnumCertificateContextProperties(pCertContext, dwPropId):
#    return CertEnumCertificateContextProperties.ctypes_function(pCertContext, dwPropId)
CertEnumCertificateContextPropertiesPrototype = WINFUNCTYPE(DWORD, PCCERT_CONTEXT, DWORD)
CertEnumCertificateContextPropertiesParams = ((1, 'pCertContext'), (1, 'dwPropId'))

#def CryptEncryptMessage(pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob, pcbEncryptedBlob):
#    return CryptEncryptMessage.ctypes_function(pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob, pcbEncryptedBlob)
CryptEncryptMessagePrototype = WINFUNCTYPE(BOOL, PCRYPT_ENCRYPT_MESSAGE_PARA, DWORD, POINTER(PCCERT_CONTEXT), POINTER(BYTE), DWORD, POINTER(BYTE), POINTER(DWORD))
CryptEncryptMessageParams = ((1, 'pEncryptPara'), (1, 'cRecipientCert'), (1, 'rgpRecipientCert'), (1, 'pbToBeEncrypted'), (1, 'cbToBeEncrypted'), (1, 'pbEncryptedBlob'), (1, 'pcbEncryptedBlob'))

#def CryptDecryptMessage(pDecryptPara, pbEncryptedBlob, cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert):
#    return CryptDecryptMessage.ctypes_function(pDecryptPara, pbEncryptedBlob, cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert)
CryptDecryptMessagePrototype = WINFUNCTYPE(BOOL, PCRYPT_DECRYPT_MESSAGE_PARA, POINTER(BYTE), DWORD, POINTER(BYTE), POINTER(DWORD), POINTER(PCCERT_CONTEXT))
CryptDecryptMessageParams = ((1, 'pDecryptPara'), (1, 'pbEncryptedBlob'), (1, 'cbEncryptedBlob'), (1, 'pbDecrypted'), (1, 'pcbDecrypted'), (1, 'ppXchgCert'))

#def CryptAcquireCertificatePrivateKey(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey):
#    return CryptAcquireCertificatePrivateKey.ctypes_function(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey)
CryptAcquireCertificatePrivateKeyPrototype = WINFUNCTYPE(BOOL, PCCERT_CONTEXT, DWORD, PVOID, POINTER(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE), POINTER(DWORD), POINTER(BOOL))
CryptAcquireCertificatePrivateKeyParams = ((1, 'pCert'), (1, 'dwFlags'), (1, 'pvParameters'), (1, 'phCryptProvOrNCryptKey'), (1, 'pdwKeySpec'), (1, 'pfCallerFreeProvOrNCryptKey'))

#def CertDuplicateCertificateContext(pCertContext):
#    return CertDuplicateCertificateContext.ctypes_function(pCertContext)
CertDuplicateCertificateContextPrototype = WINFUNCTYPE(PCCERT_CONTEXT, PCCERT_CONTEXT)
CertDuplicateCertificateContextParams = ((1, 'pCertContext'),)

#def CertEnumCertificatesInStore(hCertStore, pPrevCertContext):
#    return CertEnumCertificatesInStore.ctypes_function(hCertStore, pPrevCertContext)
CertEnumCertificatesInStorePrototype = WINFUNCTYPE(PCCERT_CONTEXT, HCERTSTORE, PCCERT_CONTEXT)
CertEnumCertificatesInStoreParams = ((1, 'hCertStore'), (1, 'pPrevCertContext'))

#def CryptEncodeObjectEx(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded):
#    return CryptEncodeObjectEx.ctypes_function(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded)
CryptEncodeObjectExPrototype = WINFUNCTYPE(BOOL, DWORD, LPCSTR, PVOID, DWORD, PCRYPT_ENCODE_PARA, PVOID, POINTER(DWORD))
CryptEncodeObjectExParams = ((1, 'dwCertEncodingType'), (1, 'lpszStructType'), (1, 'pvStructInfo'), (1, 'dwFlags'), (1, 'pEncodePara'), (1, 'pvEncoded'), (1, 'pcbEncoded'))

#def CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded):
#    return CertCreateCertificateContext.ctypes_function(dwCertEncodingType, pbCertEncoded, cbCertEncoded)
CertCreateCertificateContextPrototype = WINFUNCTYPE(PCCERT_CONTEXT, DWORD, POINTER(BYTE), DWORD)
CertCreateCertificateContextParams = ((1, 'dwCertEncodingType'), (1, 'pbCertEncoded'), (1, 'cbCertEncoded'))
