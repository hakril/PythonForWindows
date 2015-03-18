#Generated file
from ctypes import *
from ctypes.wintypes import *
from winstructs import *

functions = ['ExitProcess', 'GetLastError', 'GetCurrentProcess', 'CreateFileA', 'CreateFileW', 'NtQuerySystemInformation', 'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualQuery', 'GetModuleFileNameA', 'GetModuleFileNameW', 'CreateRemoteThread', 'VirtualProtect', 'CreateProcessA', 'CreateProcessW', 'GetThreadContext', 'SetThreadContext', 'OpenThread', 'OpenProcess', 'CloseHandle', 'ReadProcessMemory', 'WriteProcessMemory', 'CreateToolhelp32Snapshot', 'Thread32First', 'Thread32Next', 'Process32First', 'Process32Next', 'Process32FirstW', 'Process32NextW', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'OpenProcessToken', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 'AdjustTokenPrivileges', 'FindResourceA', 'FindResourceW', 'SizeofResource', 'LoadResource', 'LockResource', 'GetVersionExA', 'GetVersionExW', 'GetVersion', 'GetCurrentThread', 'GetCurrentProcessorNumber', 'AllocConsole', 'GetStdHandle', 'SetStdHandle', 'SetThreadAffinityMask', 'WriteFile']

# ExitProcess(uExitCode):
ExitProcessPrototype = WINFUNCTYPE(VOID, UINT)
ExitProcessParams = ((1, 'uExitCode'),)

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

# NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength):
NtQuerySystemInformationPrototype = WINFUNCTYPE(NTSTATUS, SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQuerySystemInformationParams = ((1, 'SystemInformationClass'), (1, 'SystemInformation'), (1, 'SystemInformationLength'), (1, 'ReturnLength'))

# VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect):
VirtualAllocPrototype = WINFUNCTYPE(LPVOID, LPVOID, SIZE_T, DWORD, DWORD)
VirtualAllocParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flAllocationType'), (1, 'flProtect'))

# VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect):
VirtualAllocExPrototype = WINFUNCTYPE(LPVOID, HANDLE, LPVOID, SIZE_T, DWORD, DWORD)
VirtualAllocExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'flAllocationType'), (1, 'flProtect'))

# VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect):
VirtualProtectPrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD, PDWORD)
VirtualProtectParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flNewProtect'), (1, 'lpflOldProtect'))

# VirtualQuery(lpAddress, lpBuffer, dwLength):
VirtualQueryPrototype = WINFUNCTYPE(DWORD, LPCVOID, PMEMORY_BASIC_INFORMATION, DWORD)
VirtualQueryParams = ((1, 'lpAddress'), (1, 'lpBuffer'), (1, 'dwLength'))

# GetModuleFileNameA(hModule, lpFilename, nSize):
GetModuleFileNameAPrototype = WINFUNCTYPE(DWORD, HMODULE, LPSTR, DWORD)
GetModuleFileNameAParams = ((1, 'hModule'), (1, 'lpFilename'), (1, 'nSize'))

# GetModuleFileNameW(hModule, lpFilename, nSize):
GetModuleFileNameWPrototype = WINFUNCTYPE(DWORD, HMODULE, LPWSTR, DWORD)
GetModuleFileNameWParams = ((1, 'hModule'), (1, 'lpFilename'), (1, 'nSize'))

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

# SetThreadContext(hThread, lpContext):
SetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, POINTER(CONTEXT))
SetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

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

# GetCurrentProcessorNumber():
GetCurrentProcessorNumberPrototype = WINFUNCTYPE(DWORD)
GetCurrentProcessorNumberParams = ()

# AllocConsole():
AllocConsolePrototype = WINFUNCTYPE(BOOL)
AllocConsoleParams = ()

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

