#Generated file
from ctypes import *
from ctypes.wintypes import *
from .winstructs import *

functions = ['ExitProcess', 'TerminateProcess', 'GetLastError', 'GetCurrentProcess', 'CreateFileA', 'CreateFileW', 'LdrLoadDll', 'NtQuerySystemInformation', 'NtQueryInformationProcess', 'NtQueryVirtualMemory', 'NtCreateThreadEx', 'NtQueryInformationThread', 'GetExitCodeThread', 'GetExitCodeProcess', 'VirtualAlloc', 'VirtualAllocEx', 'VirtualFree', 'VirtualFreeEx', 'VirtualProtect', 'VirtualQuery', 'VirtualQueryEx', 'GetModuleFileNameA', 'GetModuleFileNameW', 'CreateThread', 'CreateRemoteThread', 'VirtualProtect', 'CreateProcessA', 'CreateProcessW', 'GetThreadContext', 'NtGetContextThread', 'SetThreadContext', 'NtSetContextThread', 'OpenThread', 'OpenProcess', 'CloseHandle', 'ReadProcessMemory', 'NtWow64ReadVirtualMemory64', 'WriteProcessMemory', 'CreateToolhelp32Snapshot', 'Thread32First', 'Thread32Next', 'Process32First', 'Process32Next', 'Process32FirstW', 'Process32NextW', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'OpenProcessToken', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 'AdjustTokenPrivileges', 'FindResourceA', 'FindResourceW', 'SizeofResource', 'LoadResource', 'LockResource', 'GetVersionExA', 'GetVersionExW', 'GetVersion', 'GetCurrentThread', 'GetCurrentThreadId', 'GetCurrentProcessorNumber', 'AllocConsole', 'FreeConsole', 'GetStdHandle', 'SetStdHandle', 'SetThreadAffinityMask', 'WriteFile', 'GetExtendedTcpTable', 'GetExtendedUdpTable', 'SetTcpEntry', 'AddVectoredContinueHandler', 'AddVectoredExceptionHandler', 'TerminateThread', 'ExitThread', 'RemoveVectoredExceptionHandler', 'ResumeThread', 'SuspendThread', 'WaitForSingleObject', 'GetThreadId', 'LoadLibraryExA', 'LoadLibraryExW', 'SymInitialize', 'SymFromName', 'SymLoadModuleEx', 'SymSetOptions', 'SymGetTypeInfo', 'DeviceIoControl', 'GetTokenInformation', 'RegOpenKeyExA', 'RegOpenKeyExW', 'RegGetValueA', 'RegGetValueW', 'RegCloseKey', 'Wow64DisableWow64FsRedirection', 'Wow64RevertWow64FsRedirection', 'Wow64EnableWow64FsRedirection', 'Wow64GetThreadContext', 'SetConsoleCtrlHandler', 'WinVerifyTrust', 'GlobalAlloc', 'GlobalFree', 'GlobalUnlock', 'GlobalLock', 'OpenClipboard', 'EmptyClipboard', 'CloseClipboard', 'SetClipboardData', 'GetClipboardData', 'EnumClipboardFormats', 'GetClipboardFormatNameA', 'GetClipboardFormatNameW', 'WinVerifyTrust', 'OpenProcessToken', 'OpenThreadToken', 'GetTokenInformation', 'SetTokenInformation', 'GetSidIdentifierAuthority', 'GetSidSubAuthority', 'GetSidSubAuthorityCount', 'DebugBreak', 'WaitForDebugEvent', 'ContinueDebugEvent', 'DebugActiveProcess', 'DebugActiveProcessStop', 'DebugSetProcessKillOnExit', 'DebugBreakProcess', 'GetProcessId', 'Wow64SetThreadContext', 'GetMappedFileNameW', 'GetMappedFileNameA', 'RtlInitString', 'RtlInitUnicodeString', 'RtlAnsiStringToUnicodeString', 'OpenEventA', 'OpenEventW', 'NtOpenEvent', 'NtAlpcConnectPort', 'NtAlpcSendWaitReceivePort', 'lstrcmpA', 'lstrcmpW', 'CreateFileMappingA', 'CreateFileMappingW', 'MapViewOfFile', 'OpenSCManagerA', 'OpenSCManagerW', 'EnumServicesStatusExA', 'EnumServicesStatusExW', 'EnumWindows', 'GetWindowTextA', 'GetWindowTextW', 'GetWindowModuleFileNameA', 'GetWindowModuleFileNameW', 'CryptCATAdminCalcHashFromFileHandle', 'CryptCATAdminEnumCatalogFromHash', 'CryptCATAdminAcquireContext', 'CryptCATCatalogInfoFromContext', 'CryptCATAdminReleaseCatalogContext', 'CryptCATAdminReleaseContext', 'GetLogicalDriveStringsA', 'GetLogicalDriveStringsW', 'GetVolumeInformationA', 'GetVolumeInformationW', 'GetVolumeNameForVolumeMountPointA', 'GetVolumeNameForVolumeMountPointW', 'GetDriveTypeA', 'GetDriveTypeW', 'QueryDosDeviceA', 'QueryDosDeviceW']

# ExitProcess(uExitCode):
ExitProcessPrototype = WINFUNCTYPE(VOID, UINT)
ExitProcessParams = ((1, 'uExitCode'),)

# TerminateProcess(hProcess, uExitCode):
TerminateProcessPrototype = WINFUNCTYPE(BOOL, HANDLE, UINT)
TerminateProcessParams = ((1, 'hProcess'), (1, 'uExitCode'))

# GetLastError():
GetLastErrorPrototype = WINFUNCTYPE(DWORD)
GetLastErrorParams = ()

# GetCurrentProcess():
GetCurrentProcessPrototype = WINFUNCTYPE(HANDLE)
GetCurrentProcessParams = ()

# CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):
CreateFileAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
CreateFileAParams = ((1, 'lpFileName'), (1, 'dwDesiredAccess'), (1, 'dwShareMode'), (1, 'lpSecurityAttributes'), (1, 'dwCreationDisposition'), (1, 'dwFlagsAndAttributes'), (1, 'hTemplateFile'))

# CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):
CreateFileWPrototype = WINFUNCTYPE(HANDLE, LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
CreateFileWParams = ((1, 'lpFileName'), (1, 'dwDesiredAccess'), (1, 'dwShareMode'), (1, 'lpSecurityAttributes'), (1, 'dwCreationDisposition'), (1, 'dwFlagsAndAttributes'), (1, 'hTemplateFile'))

# LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle):
LdrLoadDllPrototype = WINFUNCTYPE(NTSTATUS, LPCWSTR, ULONG, PUNICODE_STRING, PHANDLE)
LdrLoadDllParams = ((1, 'PathToFile'), (1, 'Flags'), (1, 'ModuleFileName'), (1, 'ModuleHandle'))

# NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength):
NtQuerySystemInformationPrototype = WINFUNCTYPE(NTSTATUS, SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQuerySystemInformationParams = ((1, 'SystemInformationClass'), (1, 'SystemInformation'), (1, 'SystemInformationLength'), (1, 'ReturnLength'))

# NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength):
NtQueryInformationProcessPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)
NtQueryInformationProcessParams = ((1, 'ProcessHandle'), (1, 'ProcessInformationClass'), (1, 'ProcessInformation'), (1, 'ProcessInformationLength'), (1, 'ReturnLength'))

# NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength):
NtQueryVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T)
NtQueryVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'MemoryInformationClass'), (1, 'MemoryInformation'), (1, 'MemoryInformationLength'), (1, 'ReturnLength'))

# NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3):
NtCreateThreadExPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, DWORD, DWORD, DWORD, LPVOID)
NtCreateThreadExParams = ((1, 'ThreadHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'ProcessHandle'), (1, 'lpStartAddress'), (1, 'lpParameter'), (1, 'CreateSuspended'), (1, 'dwStackSize'), (1, 'Unknown1'), (1, 'Unknown2'), (1, 'Unknown3'))

# NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength):
NtQueryInformationThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQueryInformationThreadParams = ((1, 'ThreadHandle'), (1, 'ThreadInformationClass'), (1, 'ThreadInformation'), (1, 'ThreadInformationLength'), (1, 'ReturnLength'))

# GetExitCodeThread(hThread, lpExitCode):
GetExitCodeThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD)
GetExitCodeThreadParams = ((1, 'hThread'), (1, 'lpExitCode'))

# GetExitCodeProcess(hProcess, lpExitCode):
GetExitCodeProcessPrototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD)
GetExitCodeProcessParams = ((1, 'hProcess'), (1, 'lpExitCode'))

# VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect):
VirtualAllocPrototype = WINFUNCTYPE(LPVOID, LPVOID, SIZE_T, DWORD, DWORD)
VirtualAllocParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flAllocationType'), (1, 'flProtect'))

# VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect):
VirtualAllocExPrototype = WINFUNCTYPE(LPVOID, HANDLE, LPVOID, SIZE_T, DWORD, DWORD)
VirtualAllocExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'flAllocationType'), (1, 'flProtect'))

# VirtualFree(lpAddress, dwSize, dwFreeType):
VirtualFreePrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD)
VirtualFreeParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'dwFreeType'))

# VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType):
VirtualFreeExPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, SIZE_T, DWORD)
VirtualFreeExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'dwFreeType'))

# VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect):
VirtualProtectPrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD, PDWORD)
VirtualProtectParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flNewProtect'), (1, 'lpflOldProtect'))

# VirtualQuery(lpAddress, lpBuffer, dwLength):
VirtualQueryPrototype = WINFUNCTYPE(DWORD, LPCVOID, PMEMORY_BASIC_INFORMATION, DWORD)
VirtualQueryParams = ((1, 'lpAddress'), (1, 'lpBuffer'), (1, 'dwLength'))

# VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength):
VirtualQueryExPrototype = WINFUNCTYPE(SIZE_T, HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T)
VirtualQueryExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'lpBuffer'), (1, 'dwLength'))

# GetModuleFileNameA(hModule, lpFilename, nSize):
GetModuleFileNameAPrototype = WINFUNCTYPE(DWORD, HMODULE, LPSTR, DWORD)
GetModuleFileNameAParams = ((1, 'hModule'), (1, 'lpFilename'), (1, 'nSize'))

# GetModuleFileNameW(hModule, lpFilename, nSize):
GetModuleFileNameWPrototype = WINFUNCTYPE(DWORD, HMODULE, LPWSTR, DWORD)
GetModuleFileNameWParams = ((1, 'hModule'), (1, 'lpFilename'), (1, 'nSize'))

# CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
CreateThreadPrototype = WINFUNCTYPE(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)
CreateThreadParams = ((1, 'lpThreadAttributes'), (1, 'dwStackSize'), (1, 'lpStartAddress'), (1, 'lpParameter'), (1, 'dwCreationFlags'), (1, 'lpThreadId'))

# CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
CreateRemoteThreadPrototype = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)
CreateRemoteThreadParams = ((1, 'hProcess'), (1, 'lpThreadAttributes'), (1, 'dwStackSize'), (1, 'lpStartAddress'), (1, 'lpParameter'), (1, 'dwCreationFlags'), (1, 'lpThreadId'))

# VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect):
VirtualProtectPrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD, PDWORD)
VirtualProtectParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flNewProtect'), (1, 'lpflOldProtect'))

# CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
CreateProcessAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)
CreateProcessAParams = ((1, 'lpApplicationName'), (1, 'lpCommandLine'), (1, 'lpProcessAttributes'), (1, 'lpThreadAttributes'), (1, 'bInheritHandles'), (1, 'dwCreationFlags'), (1, 'lpEnvironment'), (1, 'lpCurrentDirectory'), (1, 'lpStartupInfo'), (1, 'lpProcessInformation'))

# CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
CreateProcessWPrototype = WINFUNCTYPE(BOOL, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION)
CreateProcessWParams = ((1, 'lpApplicationName'), (1, 'lpCommandLine'), (1, 'lpProcessAttributes'), (1, 'lpThreadAttributes'), (1, 'bInheritHandles'), (1, 'dwCreationFlags'), (1, 'lpEnvironment'), (1, 'lpCurrentDirectory'), (1, 'lpStartupInfo'), (1, 'lpProcessInformation'))

# GetThreadContext(hThread, lpContext):
GetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
GetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

# NtGetContextThread(hThread, lpContext):
NtGetContextThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
NtGetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

# SetThreadContext(hThread, lpContext):
SetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
SetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

# NtSetContextThread(hThread, lpContext):
NtSetContextThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
NtSetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

# OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
OpenThreadPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, DWORD)
OpenThreadParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'dwThreadId'))

# OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
OpenProcessPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, DWORD)
OpenProcessParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'dwProcessId'))

# CloseHandle(hObject):
CloseHandlePrototype = WINFUNCTYPE(BOOL, HANDLE)
CloseHandleParams = ((1, 'hObject'),)

# ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
ReadProcessMemoryPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCVOID, LPVOID, SIZE_T, POINTER(SIZE_T))
ReadProcessMemoryParams = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesRead'))

# NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
NtWow64ReadVirtualMemory64Prototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, LPVOID, ULONG64, POINTER(PULONG64))
NtWow64ReadVirtualMemory64Params = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesRead'))

# WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten):
WriteProcessMemoryPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemoryParams = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesWritten'))

# CreateToolhelp32Snapshot(dwFlags, th32ProcessID):
CreateToolhelp32SnapshotPrototype = WINFUNCTYPE(HANDLE, DWORD, DWORD)
CreateToolhelp32SnapshotParams = ((1, 'dwFlags'), (1, 'th32ProcessID'))

# Thread32First(hSnapshot, lpte):
Thread32FirstPrototype = WINFUNCTYPE(BOOL, HANDLE, LPTHREADENTRY32)
Thread32FirstParams = ((1, 'hSnapshot'), (1, 'lpte'))

# Thread32Next(hSnapshot, lpte):
Thread32NextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPTHREADENTRY32)
Thread32NextParams = ((1, 'hSnapshot'), (1, 'lpte'))

# Process32First(hSnapshot, lppe):
Process32FirstPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32)
Process32FirstParams = ((1, 'hSnapshot'), (1, 'lppe'))

# Process32Next(hSnapshot, lppe):
Process32NextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32)
Process32NextParams = ((1, 'hSnapshot'), (1, 'lppe'))

# Process32FirstW(hSnapshot, lppe):
Process32FirstWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32W)
Process32FirstWParams = ((1, 'hSnapshot'), (1, 'lppe'))

# Process32NextW(hSnapshot, lppe):
Process32NextWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32W)
Process32NextWParams = ((1, 'hSnapshot'), (1, 'lppe'))

# GetProcAddress(hModule, lpProcName):
GetProcAddressPrototype = WINFUNCTYPE(FARPROC, HMODULE, LPCSTR)
GetProcAddressParams = ((1, 'hModule'), (1, 'lpProcName'))

# LoadLibraryA(lpFileName):
LoadLibraryAPrototype = WINFUNCTYPE(HMODULE, LPCSTR)
LoadLibraryAParams = ((1, 'lpFileName'),)

# LoadLibraryW(lpFileName):
LoadLibraryWPrototype = WINFUNCTYPE(HMODULE, LPCWSTR)
LoadLibraryWParams = ((1, 'lpFileName'),)

# OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle):
OpenProcessTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, PHANDLE)
OpenProcessTokenParams = ((1, 'ProcessHandle'), (1, 'DesiredAccess'), (1, 'TokenHandle'))

# LookupPrivilegeValueA(lpSystemName, lpName, lpLuid):
LookupPrivilegeValueAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPCSTR, PLUID)
LookupPrivilegeValueAParams = ((1, 'lpSystemName'), (1, 'lpName'), (1, 'lpLuid'))

# LookupPrivilegeValueW(lpSystemName, lpName, lpLuid):
LookupPrivilegeValueWPrototype = WINFUNCTYPE(BOOL, LPCWSTR, LPCWSTR, PLUID)
LookupPrivilegeValueWParams = ((1, 'lpSystemName'), (1, 'lpName'), (1, 'lpLuid'))

# AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength):
AdjustTokenPrivilegesPrototype = WINFUNCTYPE(BOOL, HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD)
AdjustTokenPrivilegesParams = ((1, 'TokenHandle'), (1, 'DisableAllPrivileges'), (1, 'NewState'), (1, 'BufferLength'), (1, 'PreviousState'), (1, 'ReturnLength'))

# FindResourceA(hModule, lpName, lpType):
FindResourceAPrototype = WINFUNCTYPE(HRSRC, HMODULE, LPCSTR, LPCSTR)
FindResourceAParams = ((1, 'hModule'), (1, 'lpName'), (1, 'lpType'))

# FindResourceW(hModule, lpName, lpType):
FindResourceWPrototype = WINFUNCTYPE(HRSRC, HMODULE, LPCWSTR, LPCWSTR)
FindResourceWParams = ((1, 'hModule'), (1, 'lpName'), (1, 'lpType'))

# SizeofResource(hModule, hResInfo):
SizeofResourcePrototype = WINFUNCTYPE(DWORD, HMODULE, HRSRC)
SizeofResourceParams = ((1, 'hModule'), (1, 'hResInfo'))

# LoadResource(hModule, hResInfo):
LoadResourcePrototype = WINFUNCTYPE(HGLOBAL, HMODULE, HRSRC)
LoadResourceParams = ((1, 'hModule'), (1, 'hResInfo'))

# LockResource(hResData):
LockResourcePrototype = WINFUNCTYPE(LPVOID, HGLOBAL)
LockResourceParams = ((1, 'hResData'),)

# GetVersionExA(lpVersionInformation):
GetVersionExAPrototype = WINFUNCTYPE(BOOL, LPOSVERSIONINFOA)
GetVersionExAParams = ((1, 'lpVersionInformation'),)

# GetVersionExW(lpVersionInformation):
GetVersionExWPrototype = WINFUNCTYPE(BOOL, LPOSVERSIONINFOW)
GetVersionExWParams = ((1, 'lpVersionInformation'),)

# GetVersion():
GetVersionPrototype = WINFUNCTYPE(DWORD)
GetVersionParams = ()

# GetCurrentThread():
GetCurrentThreadPrototype = WINFUNCTYPE(HANDLE)
GetCurrentThreadParams = ()

# GetCurrentThreadId():
GetCurrentThreadIdPrototype = WINFUNCTYPE(DWORD)
GetCurrentThreadIdParams = ()

# GetCurrentProcessorNumber():
GetCurrentProcessorNumberPrototype = WINFUNCTYPE(DWORD)
GetCurrentProcessorNumberParams = ()

# AllocConsole():
AllocConsolePrototype = WINFUNCTYPE(BOOL)
AllocConsoleParams = ()

# FreeConsole():
FreeConsolePrototype = WINFUNCTYPE(BOOL)
FreeConsoleParams = ()

# GetStdHandle(nStdHandle):
GetStdHandlePrototype = WINFUNCTYPE(HANDLE, DWORD)
GetStdHandleParams = ((1, 'nStdHandle'),)

# SetStdHandle(nStdHandle, hHandle):
SetStdHandlePrototype = WINFUNCTYPE(BOOL, DWORD, HANDLE)
SetStdHandleParams = ((1, 'nStdHandle'), (1, 'hHandle'))

# SetThreadAffinityMask(hThread, dwThreadAffinityMask):
SetThreadAffinityMaskPrototype = WINFUNCTYPE(DWORD, HANDLE, DWORD)
SetThreadAffinityMaskParams = ((1, 'hThread'), (1, 'dwThreadAffinityMask'))

# WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
WriteFilePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)
WriteFileParams = ((1, 'hFile'), (1, 'lpBuffer'), (1, 'nNumberOfBytesToWrite'), (1, 'lpNumberOfBytesWritten'), (1, 'lpOverlapped'))

# GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved):
GetExtendedTcpTablePrototype = WINFUNCTYPE(DWORD, PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG)
GetExtendedTcpTableParams = ((1, 'pTcpTable'), (1, 'pdwSize'), (1, 'bOrder'), (1, 'ulAf'), (1, 'TableClass'), (1, 'Reserved'))

# GetExtendedUdpTable(pUdpTable, pdwSize, bOrder, ulAf, TableClass, Reserved):
GetExtendedUdpTablePrototype = WINFUNCTYPE(DWORD, PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG)
GetExtendedUdpTableParams = ((1, 'pUdpTable'), (1, 'pdwSize'), (1, 'bOrder'), (1, 'ulAf'), (1, 'TableClass'), (1, 'Reserved'))

# SetTcpEntry(pTcpRow):
SetTcpEntryPrototype = WINFUNCTYPE(DWORD, PMIB_TCPROW)
SetTcpEntryParams = ((1, 'pTcpRow'),)

# AddVectoredContinueHandler(FirstHandler, VectoredHandler):
AddVectoredContinueHandlerPrototype = WINFUNCTYPE(PVOID, ULONG, PVECTORED_EXCEPTION_HANDLER)
AddVectoredContinueHandlerParams = ((1, 'FirstHandler'), (1, 'VectoredHandler'))

# AddVectoredExceptionHandler(FirstHandler, VectoredHandler):
AddVectoredExceptionHandlerPrototype = WINFUNCTYPE(PVOID, ULONG, PVECTORED_EXCEPTION_HANDLER)
AddVectoredExceptionHandlerParams = ((1, 'FirstHandler'), (1, 'VectoredHandler'))

# TerminateThread(hThread, dwExitCode):
TerminateThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD)
TerminateThreadParams = ((1, 'hThread'), (1, 'dwExitCode'))

# ExitThread(dwExitCode):
ExitThreadPrototype = WINFUNCTYPE(VOID, DWORD)
ExitThreadParams = ((1, 'dwExitCode'),)

# RemoveVectoredExceptionHandler(Handler):
RemoveVectoredExceptionHandlerPrototype = WINFUNCTYPE(ULONG, PVOID)
RemoveVectoredExceptionHandlerParams = ((1, 'Handler'),)

# ResumeThread(hThread):
ResumeThreadPrototype = WINFUNCTYPE(DWORD, HANDLE)
ResumeThreadParams = ((1, 'hThread'),)

# SuspendThread(hThread):
SuspendThreadPrototype = WINFUNCTYPE(DWORD, HANDLE)
SuspendThreadParams = ((1, 'hThread'),)

# WaitForSingleObject(hHandle, dwMilliseconds):
WaitForSingleObjectPrototype = WINFUNCTYPE(DWORD, HANDLE, DWORD)
WaitForSingleObjectParams = ((1, 'hHandle'), (1, 'dwMilliseconds'))

# GetThreadId(Thread):
GetThreadIdPrototype = WINFUNCTYPE(DWORD, HANDLE)
GetThreadIdParams = ((1, 'Thread'),)

# LoadLibraryExA(lpFileName, hFile, dwFlags):
LoadLibraryExAPrototype = WINFUNCTYPE(HMODULE, LPCSTR, HANDLE, DWORD)
LoadLibraryExAParams = ((1, 'lpFileName'), (1, 'hFile'), (1, 'dwFlags'))

# LoadLibraryExW(lpFileName, hFile, dwFlags):
LoadLibraryExWPrototype = WINFUNCTYPE(HMODULE, LPCWSTR, HANDLE, DWORD)
LoadLibraryExWParams = ((1, 'lpFileName'), (1, 'hFile'), (1, 'dwFlags'))

# SymInitialize(hProcess, UserSearchPath, fInvadeProcess):
SymInitializePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCSTR, BOOL)
SymInitializeParams = ((1, 'hProcess'), (1, 'UserSearchPath'), (1, 'fInvadeProcess'))

# SymFromName(hProcess, Name, Symbol):
SymFromNamePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCSTR, PSYMBOL_INFO)
SymFromNameParams = ((1, 'hProcess'), (1, 'Name'), (1, 'Symbol'))

# SymLoadModuleEx(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
SymLoadModuleExPrototype = WINFUNCTYPE(DWORD64, HANDLE, HANDLE, LPCSTR, LPCSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD)
SymLoadModuleExParams = ((1, 'hProcess'), (1, 'hFile'), (1, 'ImageName'), (1, 'ModuleName'), (1, 'BaseOfDll'), (1, 'DllSize'), (1, 'Data'), (1, 'Flags'))

# SymSetOptions(SymOptions):
SymSetOptionsPrototype = WINFUNCTYPE(DWORD, DWORD)
SymSetOptionsParams = ((1, 'SymOptions'),)

# SymGetTypeInfo(hProcess, ModBase, TypeId, GetType, pInfo):
SymGetTypeInfoPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64, ULONG, IMAGEHLP_SYMBOL_TYPE_INFO, PVOID)
SymGetTypeInfoParams = ((1, 'hProcess'), (1, 'ModBase'), (1, 'TypeId'), (1, 'GetType'), (1, 'pInfo'))

# DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped):
DeviceIoControlPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
DeviceIoControlParams = ((1, 'hDevice'), (1, 'dwIoControlCode'), (1, 'lpInBuffer'), (1, 'nInBufferSize'), (1, 'lpOutBuffer'), (1, 'nOutBufferSize'), (1, 'lpBytesReturned'), (1, 'lpOverlapped'))

# GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength):
GetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD)
GetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'), (1, 'ReturnLength'))

# RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult):
RegOpenKeyExAPrototype = WINFUNCTYPE(LONG, HKEY, LPCSTR, DWORD, REGSAM, PHKEY)
RegOpenKeyExAParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'ulOptions'), (1, 'samDesired'), (1, 'phkResult'))

# RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult):
RegOpenKeyExWPrototype = WINFUNCTYPE(LONG, HKEY, LPWSTR, DWORD, REGSAM, PHKEY)
RegOpenKeyExWParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'ulOptions'), (1, 'samDesired'), (1, 'phkResult'))

# RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
RegGetValueAPrototype = WINFUNCTYPE(LONG, HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD)
RegGetValueAParams = ((1, 'hkey'), (1, 'lpSubKey'), (1, 'lpValue'), (1, 'dwFlags'), (1, 'pdwType'), (1, 'pvData'), (1, 'pcbData'))

# RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
RegGetValueWPrototype = WINFUNCTYPE(LONG, HKEY, LPWSTR, LPWSTR, DWORD, LPDWORD, PVOID, LPDWORD)
RegGetValueWParams = ((1, 'hkey'), (1, 'lpSubKey'), (1, 'lpValue'), (1, 'dwFlags'), (1, 'pdwType'), (1, 'pvData'), (1, 'pcbData'))

# RegCloseKey(hKey):
RegCloseKeyPrototype = WINFUNCTYPE(LONG, HKEY)
RegCloseKeyParams = ((1, 'hKey'),)

# Wow64DisableWow64FsRedirection(OldValue):
Wow64DisableWow64FsRedirectionPrototype = WINFUNCTYPE(BOOL, POINTER(PVOID))
Wow64DisableWow64FsRedirectionParams = ((1, 'OldValue'),)

# Wow64RevertWow64FsRedirection(OldValue):
Wow64RevertWow64FsRedirectionPrototype = WINFUNCTYPE(BOOL, PVOID)
Wow64RevertWow64FsRedirectionParams = ((1, 'OldValue'),)

# Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection):
Wow64EnableWow64FsRedirectionPrototype = WINFUNCTYPE(BOOLEAN, BOOLEAN)
Wow64EnableWow64FsRedirectionParams = ((1, 'Wow64FsEnableRedirection'),)

# Wow64GetThreadContext(hThread, lpContext):
Wow64GetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, PWOW64_CONTEXT)
Wow64GetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

# SetConsoleCtrlHandler(HandlerRoutine, Add):
SetConsoleCtrlHandlerPrototype = WINFUNCTYPE(BOOL, PHANDLER_ROUTINE, BOOL)
SetConsoleCtrlHandlerParams = ((1, 'HandlerRoutine'), (1, 'Add'))

# WinVerifyTrust(hwnd, pgActionID, pWVTData):
WinVerifyTrustPrototype = WINFUNCTYPE(LONG, HWND, POINTER(GUID), LPVOID)
WinVerifyTrustParams = ((1, 'hwnd'), (1, 'pgActionID'), (1, 'pWVTData'))

# GlobalAlloc(uFlags, dwBytes):
GlobalAllocPrototype = WINFUNCTYPE(HGLOBAL, UINT, SIZE_T)
GlobalAllocParams = ((1, 'uFlags'), (1, 'dwBytes'))

# GlobalFree(hMem):
GlobalFreePrototype = WINFUNCTYPE(HGLOBAL, HGLOBAL)
GlobalFreeParams = ((1, 'hMem'),)

# GlobalUnlock(hMem):
GlobalUnlockPrototype = WINFUNCTYPE(BOOL, HGLOBAL)
GlobalUnlockParams = ((1, 'hMem'),)

# GlobalLock(hMem):
GlobalLockPrototype = WINFUNCTYPE(LPVOID, HGLOBAL)
GlobalLockParams = ((1, 'hMem'),)

# OpenClipboard(hWndNewOwner):
OpenClipboardPrototype = WINFUNCTYPE(BOOL, HWND)
OpenClipboardParams = ((1, 'hWndNewOwner'),)

# EmptyClipboard():
EmptyClipboardPrototype = WINFUNCTYPE(BOOL)
EmptyClipboardParams = ()

# CloseClipboard():
CloseClipboardPrototype = WINFUNCTYPE(BOOL)
CloseClipboardParams = ()

# SetClipboardData(uFormat, hMem):
SetClipboardDataPrototype = WINFUNCTYPE(HANDLE, UINT, HANDLE)
SetClipboardDataParams = ((1, 'uFormat'), (1, 'hMem'))

# GetClipboardData(uFormat):
GetClipboardDataPrototype = WINFUNCTYPE(HANDLE, UINT)
GetClipboardDataParams = ((1, 'uFormat'),)

# EnumClipboardFormats(format):
EnumClipboardFormatsPrototype = WINFUNCTYPE(UINT, UINT)
EnumClipboardFormatsParams = ((1, 'format'),)

# GetClipboardFormatNameA(format, lpszFormatName, cchMaxCount):
GetClipboardFormatNameAPrototype = WINFUNCTYPE(INT, UINT, LPCSTR, INT)
GetClipboardFormatNameAParams = ((1, 'format'), (1, 'lpszFormatName'), (1, 'cchMaxCount'))

# GetClipboardFormatNameW(format, lpszFormatName, cchMaxCount):
GetClipboardFormatNameWPrototype = WINFUNCTYPE(INT, UINT, LPCWSTR, INT)
GetClipboardFormatNameWParams = ((1, 'format'), (1, 'lpszFormatName'), (1, 'cchMaxCount'))

# WinVerifyTrust(hWnd, pgActionID, pWVTData):
WinVerifyTrustPrototype = WINFUNCTYPE(LONG, HWND, POINTER(GUID), LPVOID)
WinVerifyTrustParams = ((1, 'hWnd'), (1, 'pgActionID'), (1, 'pWVTData'))

# OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle):
OpenProcessTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, PHANDLE)
OpenProcessTokenParams = ((1, 'ProcessHandle'), (1, 'DesiredAccess'), (1, 'TokenHandle'))

# OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle):
OpenThreadTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, BOOL, PHANDLE)
OpenThreadTokenParams = ((1, 'ThreadHandle'), (1, 'DesiredAccess'), (1, 'OpenAsSelf'), (1, 'TokenHandle'))

# GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength):
GetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD)
GetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'), (1, 'ReturnLength'))

# SetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength):
SetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD)
SetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'))

# GetSidIdentifierAuthority(pSid):
GetSidIdentifierAuthorityPrototype = WINFUNCTYPE(PSID_IDENTIFIER_AUTHORITY, PSID)
GetSidIdentifierAuthorityParams = ((1, 'pSid'),)

# GetSidSubAuthority(pSid, nSubAuthority):
GetSidSubAuthorityPrototype = WINFUNCTYPE(PDWORD, PSID, DWORD)
GetSidSubAuthorityParams = ((1, 'pSid'), (1, 'nSubAuthority'))

# GetSidSubAuthorityCount(pSid):
GetSidSubAuthorityCountPrototype = WINFUNCTYPE(PUCHAR, PSID)
GetSidSubAuthorityCountParams = ((1, 'pSid'),)

# DebugBreak():
DebugBreakPrototype = WINFUNCTYPE(VOID)
DebugBreakParams = ()

# WaitForDebugEvent(lpDebugEvent, dwMilliseconds):
WaitForDebugEventPrototype = WINFUNCTYPE(BOOL, LPDEBUG_EVENT, DWORD)
WaitForDebugEventParams = ((1, 'lpDebugEvent'), (1, 'dwMilliseconds'))

# ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus):
ContinueDebugEventPrototype = WINFUNCTYPE(BOOL, DWORD, DWORD, DWORD)
ContinueDebugEventParams = ((1, 'dwProcessId'), (1, 'dwThreadId'), (1, 'dwContinueStatus'))

# DebugActiveProcess(dwProcessId):
DebugActiveProcessPrototype = WINFUNCTYPE(BOOL, DWORD)
DebugActiveProcessParams = ((1, 'dwProcessId'),)

# DebugActiveProcessStop(dwProcessId):
DebugActiveProcessStopPrototype = WINFUNCTYPE(BOOL, DWORD)
DebugActiveProcessStopParams = ((1, 'dwProcessId'),)

# DebugSetProcessKillOnExit(KillOnExit):
DebugSetProcessKillOnExitPrototype = WINFUNCTYPE(BOOL, BOOL)
DebugSetProcessKillOnExitParams = ((1, 'KillOnExit'),)

# DebugBreakProcess(Process):
DebugBreakProcessPrototype = WINFUNCTYPE(BOOL, HANDLE)
DebugBreakProcessParams = ((1, 'Process'),)

# GetProcessId(Process):
GetProcessIdPrototype = WINFUNCTYPE(DWORD, HANDLE)
GetProcessIdParams = ((1, 'Process'),)

# Wow64SetThreadContext(hThread, lpContext):
Wow64SetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, POINTER(WOW64_CONTEXT))
Wow64SetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

# GetMappedFileNameW(hProcess, lpv, lpFilename, nSize):
GetMappedFileNameWPrototype = WINFUNCTYPE(DWORD, HANDLE, LPVOID, PVOID, DWORD)
GetMappedFileNameWParams = ((1, 'hProcess'), (1, 'lpv'), (1, 'lpFilename'), (1, 'nSize'))

# GetMappedFileNameA(hProcess, lpv, lpFilename, nSize):
GetMappedFileNameAPrototype = WINFUNCTYPE(DWORD, HANDLE, LPVOID, PVOID, DWORD)
GetMappedFileNameAParams = ((1, 'hProcess'), (1, 'lpv'), (1, 'lpFilename'), (1, 'nSize'))

# RtlInitString(DestinationString, SourceString):
RtlInitStringPrototype = WINFUNCTYPE(VOID, PSTRING, LPCSTR)
RtlInitStringParams = ((1, 'DestinationString'), (1, 'SourceString'))

# RtlInitUnicodeString(DestinationString, SourceString):
RtlInitUnicodeStringPrototype = WINFUNCTYPE(VOID, PUNICODE_STRING, LPCWSTR)
RtlInitUnicodeStringParams = ((1, 'DestinationString'), (1, 'SourceString'))

# RtlAnsiStringToUnicodeString(DestinationString, SourceString, AllocateDestinationString):
RtlAnsiStringToUnicodeStringPrototype = WINFUNCTYPE(NTSTATUS, PUNICODE_STRING, PCANSI_STRING, BOOLEAN)
RtlAnsiStringToUnicodeStringParams = ((1, 'DestinationString'), (1, 'SourceString'), (1, 'AllocateDestinationString'))

# OpenEventA(dwDesiredAccess, bInheritHandle, lpName):
OpenEventAPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCSTR)
OpenEventAParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

# OpenEventW(dwDesiredAccess, bInheritHandle, lpName):
OpenEventWPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCWSTR)
OpenEventWParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

# NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes):
NtOpenEventPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenEventParams = ((1, 'EventHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

# NtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout):
NtAlpcConnectPortPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, ULONG, PSID, PPORT_MESSAGE, PULONG, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER)
NtAlpcConnectPortParams = ((1, 'PortHandle'), (1, 'PortName'), (1, 'ObjectAttributes'), (1, 'PortAttributes'), (1, 'Flags'), (1, 'RequiredServerSid'), (1, 'ConnectionMessage'), (1, 'BufferLength'), (1, 'OutMessageAttributes'), (1, 'InMessageAttributes'), (1, 'Timeout'))

# NtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout):
NtAlpcSendWaitReceivePortPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, PPORT_MESSAGE, PALPC_MESSAGE_ATTRIBUTES, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER)
NtAlpcSendWaitReceivePortParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'SendMessage'), (1, 'SendMessageAttributes'), (1, 'ReceiveMessage'), (1, 'BufferLength'), (1, 'ReceiveMessageAttributes'), (1, 'Timeout'))

# lstrcmpA(lpString1, lpString2):
lstrcmpAPrototype = WINFUNCTYPE(INT, LPCSTR, LPCSTR)
lstrcmpAParams = ((1, 'lpString1'), (1, 'lpString2'))

# lstrcmpW(lpString1, lpString2):
lstrcmpWPrototype = WINFUNCTYPE(INT, LPCWSTR, LPCWSTR)
lstrcmpWParams = ((1, 'lpString1'), (1, 'lpString2'))

# CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
CreateFileMappingAPrototype = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR)
CreateFileMappingAParams = ((1, 'hFile'), (1, 'lpFileMappingAttributes'), (1, 'flProtect'), (1, 'dwMaximumSizeHigh'), (1, 'dwMaximumSizeLow'), (1, 'lpName'))

# CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
CreateFileMappingWPrototype = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR)
CreateFileMappingWParams = ((1, 'hFile'), (1, 'lpFileMappingAttributes'), (1, 'flProtect'), (1, 'dwMaximumSizeHigh'), (1, 'dwMaximumSizeLow'), (1, 'lpName'))

# MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap):
MapViewOfFilePrototype = WINFUNCTYPE(LPVOID, HANDLE, DWORD, DWORD, DWORD, SIZE_T)
MapViewOfFileParams = ((1, 'hFileMappingObject'), (1, 'dwDesiredAccess'), (1, 'dwFileOffsetHigh'), (1, 'dwFileOffsetLow'), (1, 'dwNumberOfBytesToMap'))

# OpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess):
OpenSCManagerAPrototype = WINFUNCTYPE(SC_HANDLE, LPCSTR, LPCSTR, DWORD)
OpenSCManagerAParams = ((1, 'lpMachineName'), (1, 'lpDatabaseName'), (1, 'dwDesiredAccess'))

# OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess):
OpenSCManagerWPrototype = WINFUNCTYPE(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD)
OpenSCManagerWParams = ((1, 'lpMachineName'), (1, 'lpDatabaseName'), (1, 'dwDesiredAccess'))

# EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
EnumServicesStatusExAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR)
EnumServicesStatusExAParams = ((1, 'hSCManager'), (1, 'InfoLevel'), (1, 'dwServiceType'), (1, 'dwServiceState'), (1, 'lpServices'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'), (1, 'lpServicesReturned'), (1, 'lpResumeHandle'), (1, 'pszGroupName'))

# EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
EnumServicesStatusExWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR)
EnumServicesStatusExWParams = ((1, 'hSCManager'), (1, 'InfoLevel'), (1, 'dwServiceType'), (1, 'dwServiceState'), (1, 'lpServices'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'), (1, 'lpServicesReturned'), (1, 'lpResumeHandle'), (1, 'pszGroupName'))

# EnumWindows(lpEnumFunc, lParam):
EnumWindowsPrototype = WINFUNCTYPE(BOOL, WNDENUMPROC, LPARAM)
EnumWindowsParams = ((1, 'lpEnumFunc'), (1, 'lParam'))

# GetWindowTextA(hWnd, lpString, nMaxCount):
GetWindowTextAPrototype = WINFUNCTYPE(INT, HWND, LPSTR, INT)
GetWindowTextAParams = ((1, 'hWnd'), (1, 'lpString'), (1, 'nMaxCount'))

# GetWindowTextW(hWnd, lpString, nMaxCount):
GetWindowTextWPrototype = WINFUNCTYPE(INT, HWND, LPWSTR, INT)
GetWindowTextWParams = ((1, 'hWnd'), (1, 'lpString'), (1, 'nMaxCount'))

# GetWindowModuleFileNameA(hwnd, pszFileName, cchFileNameMax):
GetWindowModuleFileNameAPrototype = WINFUNCTYPE(UINT, HWND, LPSTR, UINT)
GetWindowModuleFileNameAParams = ((1, 'hwnd'), (1, 'pszFileName'), (1, 'cchFileNameMax'))

# GetWindowModuleFileNameW(hwnd, pszFileName, cchFileNameMax):
GetWindowModuleFileNameWPrototype = WINFUNCTYPE(UINT, HWND, LPWSTR, UINT)
GetWindowModuleFileNameWParams = ((1, 'hwnd'), (1, 'pszFileName'), (1, 'cchFileNameMax'))

# CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags):
CryptCATAdminCalcHashFromFileHandlePrototype = WINFUNCTYPE(BOOL, HANDLE, POINTER(DWORD), POINTER(BYTE), DWORD)
CryptCATAdminCalcHashFromFileHandleParams = ((1, 'hFile'), (1, 'pcbHash'), (1, 'pbHash'), (1, 'dwFlags'))

# CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo):
CryptCATAdminEnumCatalogFromHashPrototype = WINFUNCTYPE(HCATINFO, HCATADMIN, POINTER(BYTE), DWORD, DWORD, POINTER(HCATINFO))
CryptCATAdminEnumCatalogFromHashParams = ((1, 'hCatAdmin'), (1, 'pbHash'), (1, 'cbHash'), (1, 'dwFlags'), (1, 'phPrevCatInfo'))

# CryptCATAdminAcquireContext(phCatAdmin, pgSubsystem, dwFlags):
CryptCATAdminAcquireContextPrototype = WINFUNCTYPE(BOOL, POINTER(HCATADMIN), POINTER(GUID), DWORD)
CryptCATAdminAcquireContextParams = ((1, 'phCatAdmin'), (1, 'pgSubsystem'), (1, 'dwFlags'))

# CryptCATCatalogInfoFromContext(hCatInfo, psCatInfo, dwFlags):
CryptCATCatalogInfoFromContextPrototype = WINFUNCTYPE(BOOL, HCATINFO, POINTER(CATALOG_INFO), DWORD)
CryptCATCatalogInfoFromContextParams = ((1, 'hCatInfo'), (1, 'psCatInfo'), (1, 'dwFlags'))

# CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwFlags):
CryptCATAdminReleaseCatalogContextPrototype = WINFUNCTYPE(BOOL, HCATADMIN, HCATINFO, DWORD)
CryptCATAdminReleaseCatalogContextParams = ((1, 'hCatAdmin'), (1, 'hCatInfo'), (1, 'dwFlags'))

# CryptCATAdminReleaseContext(hCatAdmin, dwFlags):
CryptCATAdminReleaseContextPrototype = WINFUNCTYPE(BOOL, HCATADMIN, DWORD)
CryptCATAdminReleaseContextParams = ((1, 'hCatAdmin'), (1, 'dwFlags'))

# GetLogicalDriveStringsA(nBufferLength, lpBuffer):
GetLogicalDriveStringsAPrototype = WINFUNCTYPE(DWORD, DWORD, LPCSTR)
GetLogicalDriveStringsAParams = ((1, 'nBufferLength'), (1, 'lpBuffer'))

# GetLogicalDriveStringsW(nBufferLength, lpBuffer):
GetLogicalDriveStringsWPrototype = WINFUNCTYPE(DWORD, DWORD, LPWSTR)
GetLogicalDriveStringsWParams = ((1, 'nBufferLength'), (1, 'lpBuffer'))

# GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize):
GetVolumeInformationAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPSTR, DWORD)
GetVolumeInformationAParams = ((1, 'lpRootPathName'), (1, 'lpVolumeNameBuffer'), (1, 'nVolumeNameSize'), (1, 'lpVolumeSerialNumber'), (1, 'lpMaximumComponentLength'), (1, 'lpFileSystemFlags'), (1, 'lpFileSystemNameBuffer'), (1, 'nFileSystemNameSize'))

# GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize):
GetVolumeInformationWPrototype = WINFUNCTYPE(BOOL, LPWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD)
GetVolumeInformationWParams = ((1, 'lpRootPathName'), (1, 'lpVolumeNameBuffer'), (1, 'nVolumeNameSize'), (1, 'lpVolumeSerialNumber'), (1, 'lpMaximumComponentLength'), (1, 'lpFileSystemFlags'), (1, 'lpFileSystemNameBuffer'), (1, 'nFileSystemNameSize'))

# GetVolumeNameForVolumeMountPointA(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength):
GetVolumeNameForVolumeMountPointAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPCSTR, DWORD)
GetVolumeNameForVolumeMountPointAParams = ((1, 'lpszVolumeMountPoint'), (1, 'lpszVolumeName'), (1, 'cchBufferLength'))

# GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength):
GetVolumeNameForVolumeMountPointWPrototype = WINFUNCTYPE(BOOL, LPWSTR, LPWSTR, DWORD)
GetVolumeNameForVolumeMountPointWParams = ((1, 'lpszVolumeMountPoint'), (1, 'lpszVolumeName'), (1, 'cchBufferLength'))

# GetDriveTypeA(lpRootPathName):
GetDriveTypeAPrototype = WINFUNCTYPE(UINT, LPCSTR)
GetDriveTypeAParams = ((1, 'lpRootPathName'),)

# GetDriveTypeW(lpRootPathName):
GetDriveTypeWPrototype = WINFUNCTYPE(UINT, LPWSTR)
GetDriveTypeWParams = ((1, 'lpRootPathName'),)

# QueryDosDeviceA(lpDeviceName, lpTargetPath, ucchMax):
QueryDosDeviceAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPCSTR, DWORD)
QueryDosDeviceAParams = ((1, 'lpDeviceName'), (1, 'lpTargetPath'), (1, 'ucchMax'))

# QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax):
QueryDosDeviceWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPWSTR, DWORD)
QueryDosDeviceWParams = ((1, 'lpDeviceName'), (1, 'lpTargetPath'), (1, 'ucchMax'))

