#Generated file
from ctypes import *
from ctypes.wintypes import *
from windef import *

PWSTR = LPWSTR
SIZE_T = c_ulong
PVOID = c_void_p
PPS_POST_PROCESS_INIT_ROUTINE = PVOID
NTSTATUS = DWORD
PULONG = POINTER(ULONG)
PDWORD = POINTER(DWORD)
LPDWORD = POINTER(DWORD)
LPTHREAD_START_ROUTINE = PVOID
LPBYTE = POINTER(BYTE)
ULONG_PTR = PULONG
CHAR = c_char
FARPROC = PVOID
HGLOBAL = PVOID
ULONGLONG = c_ulonglong
ULONG64 = c_ulonglong
PULONG64 = POINTER(ULONG64)
PHANDLE = POINTER(HANDLE)
VOID = DWORD

structs = ['_LIST_ENTRY', '_PEB_LDR_DATA', '_LSA_UNICODE_STRING', '_RTL_USER_PROCESS_PARAMETERS', '_PEB', '_SECURITY_ATTRIBUTES', '_SYSTEM_VERIFIER_INFORMATION', '_LDR_DATA_TABLE_ENTRY', '_PEB_LDR_DATA', '_IMAGE_FILE_HEADER', '_IMAGE_DATA_DIRECTORY', '_IMAGE_SECTION_HEADER', '_IMAGE_OPTIONAL_HEADER64', '_IMAGE_OPTIONAL_HEADER', '_IMAGE_NT_HEADERS64', '_IMAGE_NT_HEADERS', '_IMAGE_IMPORT_DESCRIPTOR', '_IMAGE_IMPORT_BY_NAME', '_MEMORY_BASIC_INFORMATION', '_STARTUPINFOA', '_STARTUPINFOW', '_PROCESS_INFORMATION', '_FLOATING_SAVE_AREA', '_CONTEXT', 'tagPROCESSENTRY32W', 'tagPROCESSENTRY32', 'tagTHREADENTRY32', '_LUID', '_LUID_AND_ATTRIBUTES', '_TOKEN_PRIVILEGES', '_OSVERSIONINFOA', '_OSVERSIONINFOW', '_OSVERSIONINFOEXA', '_OSVERSIONINFOEXW', '_OVERLAPPED']

enums = ['_SYSTEM_INFORMATION_CLASS']

# Enum _SYSTEM_INFORMATION_CLASS definitions
_SYSTEM_INFORMATION_CLASS = DWORD
SYSTEM_INFORMATION_CLASS = _SYSTEM_INFORMATION_CLASS

SystemBasicInformation = 0x0
SystemProcessorInformation = 0x1
SystemPerformanceInformation = 0x2
SystemTimeOfDayInformation = 0x3
SystemPathInformation = 0x4
SystemProcessInformation = 0x5
SystemCallCountInformation = 0x6
SystemDeviceInformation = 0x7
SystemProcessorPerformanceInformation = 0x8
SystemFlagsInformation = 0x9
SystemCallTimeInformation = 0xa
SystemModuleInformation = 0xb
SystemLocksInformation = 0xc
SystemStackTraceInformation = 0xd
SystemPagedPoolInformation = 0xe
SystemNonPagedPoolInformation = 0xf
SystemHandleInformation = 0x10
SystemObjectInformation = 0x11
SystemPageFileInformation = 0x12
SystemVdmInstemulInformation = 0x13
SystemVdmBopInformation = 0x14
SystemFileCacheInformation = 0x15
SystemPoolTagInformation = 0x16
SystemInterruptInformation = 0x17
SystemDpcBehaviorInformation = 0x18
SystemFullMemoryInformation = 0x19
SystemLoadGdiDriverInformation = 0x1a
SystemUnloadGdiDriverInformation = 0x1b
SystemTimeAdjustmentInformation = 0x1c
SystemSummaryMemoryInformation = 0x1d
SystemMirrorMemoryInformation = 0x1e
SystemPerformanceTraceInformation = 0x1f
SystemObsolete0 = 0x20
SystemExceptionInformation = 0x21
SystemCrashDumpStateInformation = 0x22
SystemKernelDebuggerInformation = 0x23
SystemContextSwitchInformation = 0x24
SystemRegistryQuotaInformation = 0x25
SystemExtendServiceTableInformation = 0x26
SystemPrioritySeperation = 0x27
SystemVerifierAddDriverInformation = 0x28
SystemVerifierRemoveDriverInformation = 0x29
SystemProcessorIdleInformation = 0x2a
SystemLegacyDriverInformation = 0x2b
SystemCurrentTimeZoneInformation = 0x2c
SystemLookasideInformation = 0x2d
SystemTimeSlipNotification = 0x2e
SystemSessionCreate = 0x2f
SystemSessionDetach = 0x30
SystemSessionInformation = 0x31
SystemRangeStartInformation = 0x32
SystemVerifierInformation = 0x33
SystemVerifierThunkExtend = 0x34
SystemSessionProcessInformation = 0x35
SystemLoadGdiDriverInSystemSpace = 0x36
SystemNumaProcessorMap = 0x37
SystemPrefetcherInformation = 0x38
SystemExtendedProcessInformation = 0x39
SystemRecommendedSharedDataAlignment = 0x3a
SystemComPlusPackage = 0x3b
SystemNumaAvailableMemory = 0x3c
SystemProcessorPowerInformation = 0x3d
SystemEmulationBasicInformation = 0x3e
SystemEmulationProcessorInformation = 0x3f
SystemExtendedHandleInformation = 0x40
SystemLostDelayedWriteInformation = 0x41
SystemBigPoolInformation = 0x42
SystemSessionPoolTagInformation = 0x43
SystemSessionMappedViewInformation = 0x44
SystemHotpatchInformation = 0x45
SystemObjectSecurityMode = 0x46
SystemWatchdogTimerHandler = 0x47
SystemWatchdogTimerInformation = 0x48
SystemLogicalProcessorInformation = 0x49
SystemWow64SharedInformation = 0x4a
SystemRegisterFirmwareTableInformationHandler = 0x4b
SystemFirmwareTableInformation = 0x4c
SystemModuleInformationEx = 0x4d
SystemVerifierTriageInformation = 0x4e
SystemSuperfetchInformation = 0x4f
SystemMemoryListInformation = 0x50
SystemFileCacheInformationEx = 0x51
MaxSystemInfoClass = 0x52
# Struct _LIST_ENTRY definitions
# Self referencing struct tricks
class _LIST_ENTRY(Structure): pass
_LIST_ENTRY._fields_ = [
    ("Flink", POINTER(_LIST_ENTRY)),
    ("Blink", POINTER(_LIST_ENTRY)),
]
PLIST_ENTRY = POINTER(_LIST_ENTRY)
LIST_ENTRY = _LIST_ENTRY
PRLIST_ENTRY = POINTER(_LIST_ENTRY)

# Struct _PEB_LDR_DATA definitions
class _PEB_LDR_DATA(Structure):
        _fields_ = [
        ("Reserved1", BYTE * 8),
        ("Reserved2", PVOID * 3),
        ("InMemoryOrderModuleList", LIST_ENTRY),
    ]
PPEB_LDR_DATA = POINTER(_PEB_LDR_DATA)
PEB_LDR_DATA = _PEB_LDR_DATA

# Struct _LSA_UNICODE_STRING definitions
class _LSA_UNICODE_STRING(Structure):
        _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", PWSTR),
    ]
PUNICODE_STRING = POINTER(_LSA_UNICODE_STRING)
UNICODE_STRING = _LSA_UNICODE_STRING
LSA_UNICODE_STRING = _LSA_UNICODE_STRING
PLSA_UNICODE_STRING = POINTER(_LSA_UNICODE_STRING)

# Struct _RTL_USER_PROCESS_PARAMETERS definitions
class _RTL_USER_PROCESS_PARAMETERS(Structure):
        _fields_ = [
        ("Reserved1", BYTE * 16),
        ("Reserved2", PVOID * 10),
        ("ImagePathName", UNICODE_STRING),
        ("CommandLine", UNICODE_STRING),
    ]
PRTL_USER_PROCESS_PARAMETERS = POINTER(_RTL_USER_PROCESS_PARAMETERS)
RTL_USER_PROCESS_PARAMETERS = _RTL_USER_PROCESS_PARAMETERS

# Struct _PEB definitions
class _PEB(Structure):
        _fields_ = [
        ("Reserved1", BYTE * 2),
        ("BeingDebugged", BYTE),
        ("Reserved2", BYTE * 1),
        ("Reserved3", PVOID * 2),
        ("Ldr", PPEB_LDR_DATA),
        ("ProcessParameters", PRTL_USER_PROCESS_PARAMETERS),
        ("Reserved4", BYTE * 104),
        ("Reserved5", PVOID * 52),
        ("PostProcessInitRoutine", PPS_POST_PROCESS_INIT_ROUTINE),
        ("Reserved6", BYTE * 128),
        ("Reserved7", PVOID * 1),
        ("SessionId", ULONG),
    ]
PPEB = POINTER(_PEB)
PEB = _PEB

# Struct _SECURITY_ATTRIBUTES definitions
class _SECURITY_ATTRIBUTES(Structure):
        _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL),
    ]
SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
PSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)

# Struct _SYSTEM_VERIFIER_INFORMATION definitions
class _SYSTEM_VERIFIER_INFORMATION(Structure):
        _fields_ = [
        ("NextEntryOffset", ULONG),
        ("Level", ULONG),
        ("DriverName", UNICODE_STRING),
        ("RaiseIrqls", ULONG),
        ("AcquireSpinLocks", ULONG),
        ("SynchronizeExecutions", ULONG),
        ("AllocationsAttempted", ULONG),
        ("AllocationsSucceeded", ULONG),
        ("AllocationsSucceededSpecialPool", ULONG),
        ("AllocationsWithNoTag", ULONG),
        ("TrimRequests", ULONG),
        ("Trims", ULONG),
        ("AllocationsFailed", ULONG),
        ("AllocationsFailedDeliberately", ULONG),
        ("Loads", ULONG),
        ("Unloads", ULONG),
        ("UnTrackedPool", ULONG),
        ("CurrentPagedPoolAllocations", ULONG),
        ("CurrentNonPagedPoolAllocations", ULONG),
        ("PeakPagedPoolAllocations", ULONG),
        ("PeakNonPagedPoolAllocations", ULONG),
        ("PagedPoolUsageInBytes", SIZE_T),
        ("NonPagedPoolUsageInBytes", SIZE_T),
        ("PeakPagedPoolUsageInBytes", SIZE_T),
        ("PeakNonPagedPoolUsageInBytes", SIZE_T),
    ]
PSYSTEM_VERIFIER_INFORMATION = POINTER(_SYSTEM_VERIFIER_INFORMATION)
SYSTEM_VERIFIER_INFORMATION = _SYSTEM_VERIFIER_INFORMATION

# Struct _LDR_DATA_TABLE_ENTRY definitions
class _LDR_DATA_TABLE_ENTRY(Structure):
        _fields_ = [
        ("Reserved1", PVOID * 2),
        ("InMemoryOrderLinks", LIST_ENTRY),
        ("Reserved2", PVOID * 2),
        ("DllBase", PVOID),
        ("EntryPoint", PVOID),
        ("Reserved3", PVOID),
        ("FullDllName", UNICODE_STRING),
        ("BaseDllName", UNICODE_STRING),
        ("Reserved5", PVOID * 3),
        ("CheckSum", ULONG),
        ("TimeDateStamp", ULONG),
    ]
PLDR_DATA_TABLE_ENTRY = POINTER(_LDR_DATA_TABLE_ENTRY)
LDR_DATA_TABLE_ENTRY = _LDR_DATA_TABLE_ENTRY

# Struct _PEB_LDR_DATA definitions
class _PEB_LDR_DATA(Structure):
        _fields_ = [
        ("Reserved1", BYTE * 8),
        ("Reserved2", PVOID * 3),
        ("InMemoryOrderModuleList", LIST_ENTRY),
    ]
PPEB_LDR_DATA = POINTER(_PEB_LDR_DATA)
PEB_LDR_DATA = _PEB_LDR_DATA

# Struct _IMAGE_FILE_HEADER definitions
class _IMAGE_FILE_HEADER(Structure):
        _fields_ = [
        ("Machine", WORD),
        ("NumberOfSections", WORD),
        ("TimeDateStamp", DWORD),
        ("PointerToSymbolTable", DWORD),
        ("NumberOfSymbols", DWORD),
        ("SizeOfOptionalHeader", WORD),
        ("Characteristics", WORD),
    ]
IMAGE_FILE_HEADER = _IMAGE_FILE_HEADER
PIMAGE_FILE_HEADER = POINTER(_IMAGE_FILE_HEADER)

# Struct _IMAGE_DATA_DIRECTORY definitions
class _IMAGE_DATA_DIRECTORY(Structure):
        _fields_ = [
        ("VirtualAddress", DWORD),
        ("Size", DWORD),
    ]
IMAGE_DATA_DIRECTORY = _IMAGE_DATA_DIRECTORY
PIMAGE_DATA_DIRECTORY = POINTER(_IMAGE_DATA_DIRECTORY)

# Struct _IMAGE_SECTION_HEADER definitions
class _IMAGE_SECTION_HEADER(Structure):
        _fields_ = [
        ("Name", BYTE * IMAGE_SIZEOF_SHORT_NAME),
        ("VirtualSize", DWORD),
        ("VirtualAddress", DWORD),
        ("SizeOfRawData", DWORD),
        ("PointerToRawData", DWORD),
        ("PointerToRelocations", DWORD),
        ("PointerToLinenumbers", DWORD),
        ("NumberOfRelocations", WORD),
        ("NumberOfLinenumbers", WORD),
        ("Characteristics", DWORD),
    ]
PIMAGE_SECTION_HEADER = POINTER(_IMAGE_SECTION_HEADER)
IMAGE_SECTION_HEADER = _IMAGE_SECTION_HEADER

# Struct _IMAGE_OPTIONAL_HEADER64 definitions
class _IMAGE_OPTIONAL_HEADER64(Structure):
        _fields_ = [
        ("Magic", WORD),
        ("MajorLinkerVersion", BYTE),
        ("MinorLinkerVersion", BYTE),
        ("SizeOfCode", DWORD),
        ("SizeOfInitializedData", DWORD),
        ("SizeOfUninitializedData", DWORD),
        ("AddressOfEntryPoint", DWORD),
        ("BaseOfCode", DWORD),
        ("ImageBase", ULONGLONG),
        ("SectionAlignment", DWORD),
        ("FileAlignment", DWORD),
        ("MajorOperatingSystemVersion", WORD),
        ("MinorOperatingSystemVersion", WORD),
        ("MajorImageVersion", WORD),
        ("MinorImageVersion", WORD),
        ("MajorSubsystemVersion", WORD),
        ("MinorSubsystemVersion", WORD),
        ("Win32VersionValue", DWORD),
        ("SizeOfImage", DWORD),
        ("SizeOfHeaders", DWORD),
        ("CheckSum", DWORD),
        ("Subsystem", WORD),
        ("DllCharacteristics", WORD),
        ("SizeOfStackReserve", ULONGLONG),
        ("SizeOfStackCommit", ULONGLONG),
        ("SizeOfHeapReserve", ULONGLONG),
        ("SizeOfHeapCommit", ULONGLONG),
        ("LoaderFlags", DWORD),
        ("NumberOfRvaAndSizes", DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]
PIMAGE_OPTIONAL_HEADER64 = POINTER(_IMAGE_OPTIONAL_HEADER64)
IMAGE_OPTIONAL_HEADER64 = _IMAGE_OPTIONAL_HEADER64

# Struct _IMAGE_OPTIONAL_HEADER definitions
class _IMAGE_OPTIONAL_HEADER(Structure):
        _fields_ = [
        ("Magic", WORD),
        ("MajorLinkerVersion", BYTE),
        ("MinorLinkerVersion", BYTE),
        ("SizeOfCode", DWORD),
        ("SizeOfInitializedData", DWORD),
        ("SizeOfUninitializedData", DWORD),
        ("AddressOfEntryPoint", DWORD),
        ("BaseOfCode", DWORD),
        ("BaseOfData", DWORD),
        ("ImageBase", DWORD),
        ("SectionAlignment", DWORD),
        ("FileAlignment", DWORD),
        ("MajorOperatingSystemVersion", WORD),
        ("MinorOperatingSystemVersion", WORD),
        ("MajorImageVersion", WORD),
        ("MinorImageVersion", WORD),
        ("MajorSubsystemVersion", WORD),
        ("MinorSubsystemVersion", WORD),
        ("Win32VersionValue", DWORD),
        ("SizeOfImage", DWORD),
        ("SizeOfHeaders", DWORD),
        ("CheckSum", DWORD),
        ("Subsystem", WORD),
        ("DllCharacteristics", WORD),
        ("SizeOfStackReserve", DWORD),
        ("SizeOfStackCommit", DWORD),
        ("SizeOfHeapReserve", DWORD),
        ("SizeOfHeapCommit", DWORD),
        ("LoaderFlags", DWORD),
        ("NumberOfRvaAndSizes", DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]
PIMAGE_OPTIONAL_HEADER32 = POINTER(_IMAGE_OPTIONAL_HEADER)
IMAGE_OPTIONAL_HEADER32 = _IMAGE_OPTIONAL_HEADER

# Struct _IMAGE_NT_HEADERS64 definitions
class _IMAGE_NT_HEADERS64(Structure):
        _fields_ = [
        ("Signature", DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER64),
    ]
PIMAGE_NT_HEADERS64 = POINTER(_IMAGE_NT_HEADERS64)
IMAGE_NT_HEADERS64 = _IMAGE_NT_HEADERS64

# Struct _IMAGE_NT_HEADERS definitions
class _IMAGE_NT_HEADERS(Structure):
        _fields_ = [
        ("Signature", DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER32),
    ]
IMAGE_NT_HEADERS32 = _IMAGE_NT_HEADERS
PIMAGE_NT_HEADERS32 = POINTER(_IMAGE_NT_HEADERS)

# Struct _IMAGE_IMPORT_DESCRIPTOR definitions
class _IMAGE_IMPORT_DESCRIPTOR(Structure):
        _fields_ = [
        ("OriginalFirstThunk", DWORD),
        ("TimeDateStamp", DWORD),
        ("ForwarderChain", DWORD),
        ("Name", DWORD),
        ("FirstThunk", DWORD),
    ]
IMAGE_IMPORT_DESCRIPTOR = _IMAGE_IMPORT_DESCRIPTOR
PIMAGE_IMPORT_DESCRIPTOR = POINTER(_IMAGE_IMPORT_DESCRIPTOR)

# Struct _IMAGE_IMPORT_BY_NAME definitions
class _IMAGE_IMPORT_BY_NAME(Structure):
        _fields_ = [
        ("Hint", WORD),
        ("Name", BYTE * 1),
    ]
PIMAGE_IMPORT_BY_NAME = POINTER(_IMAGE_IMPORT_BY_NAME)
IMAGE_IMPORT_BY_NAME = _IMAGE_IMPORT_BY_NAME

# Struct _MEMORY_BASIC_INFORMATION definitions
class _MEMORY_BASIC_INFORMATION(Structure):
        _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]
PMEMORY_BASIC_INFORMATION = POINTER(_MEMORY_BASIC_INFORMATION)
MEMORY_BASIC_INFORMATION = _MEMORY_BASIC_INFORMATION

# Struct _STARTUPINFOA definitions
class _STARTUPINFOA(Structure):
        _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPSTR),
        ("lpDesktop", LPSTR),
        ("lpTitle", LPSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]
LPSTARTUPINFOA = POINTER(_STARTUPINFOA)
STARTUPINFOA = _STARTUPINFOA

# Struct _STARTUPINFOW definitions
class _STARTUPINFOW(Structure):
        _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPWSTR),
        ("lpDesktop", LPWSTR),
        ("lpTitle", LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]
STARTUPINFOW = _STARTUPINFOW
LPSTARTUPINFOW = POINTER(_STARTUPINFOW)

# Struct _PROCESS_INFORMATION definitions
class _PROCESS_INFORMATION(Structure):
        _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]
LPPROCESS_INFORMATION = POINTER(_PROCESS_INFORMATION)
PROCESS_INFORMATION = _PROCESS_INFORMATION
PPROCESS_INFORMATION = POINTER(_PROCESS_INFORMATION)

# Struct _FLOATING_SAVE_AREA definitions
class _FLOATING_SAVE_AREA(Structure):
        _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]
FLOATING_SAVE_AREA = _FLOATING_SAVE_AREA

# Struct _CONTEXT definitions
class _CONTEXT(Structure):
        _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
    ]
PCONTEXT = POINTER(_CONTEXT)
LPCONTEXT = POINTER(_CONTEXT)
CONTEXT = _CONTEXT

# Struct tagPROCESSENTRY32W definitions
class tagPROCESSENTRY32W(Structure):
        _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", WCHAR * MAX_PATH),
    ]
PPROCESSENTRY32W = POINTER(tagPROCESSENTRY32W)
LPPROCESSENTRY32W = POINTER(tagPROCESSENTRY32W)
PROCESSENTRY32W = tagPROCESSENTRY32W

# Struct tagPROCESSENTRY32 definitions
class tagPROCESSENTRY32(Structure):
        _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", CHAR * MAX_PATH),
    ]
PROCESSENTRY32 = tagPROCESSENTRY32
PPROCESSENTRY32 = POINTER(tagPROCESSENTRY32)
LPPROCESSENTRY32 = POINTER(tagPROCESSENTRY32)

# Struct tagTHREADENTRY32 definitions
class tagTHREADENTRY32(Structure):
        _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", LONG),
        ("tpDeltaPri", LONG),
        ("dwFlags", DWORD),
    ]
PTHREADENTRY32 = POINTER(tagTHREADENTRY32)
THREADENTRY32 = tagTHREADENTRY32
LPTHREADENTRY32 = POINTER(tagTHREADENTRY32)

# Struct _LUID definitions
class _LUID(Structure):
        _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]
LUID = _LUID
PLUID = POINTER(_LUID)

# Struct _LUID_AND_ATTRIBUTES definitions
class _LUID_AND_ATTRIBUTES(Structure):
        _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]
LUID_AND_ATTRIBUTES = _LUID_AND_ATTRIBUTES
PLUID_AND_ATTRIBUTES = POINTER(_LUID_AND_ATTRIBUTES)

# Struct _TOKEN_PRIVILEGES definitions
class _TOKEN_PRIVILEGES(Structure):
        _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * ANYSIZE_ARRAY),
    ]
TOKEN_PRIVILEGES = _TOKEN_PRIVILEGES
PTOKEN_PRIVILEGES = POINTER(_TOKEN_PRIVILEGES)

# Struct _OSVERSIONINFOA definitions
class _OSVERSIONINFOA(Structure):
        _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", CHAR * 128),
    ]
POSVERSIONINFOA = POINTER(_OSVERSIONINFOA)
OSVERSIONINFOA = _OSVERSIONINFOA
LPOSVERSIONINFOA = POINTER(_OSVERSIONINFOA)

# Struct _OSVERSIONINFOW definitions
class _OSVERSIONINFOW(Structure):
        _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", WCHAR * 128),
    ]
RTL_OSVERSIONINFOW = _OSVERSIONINFOW
PRTL_OSVERSIONINFOW = POINTER(_OSVERSIONINFOW)
LPOSVERSIONINFOW = POINTER(_OSVERSIONINFOW)
POSVERSIONINFOW = POINTER(_OSVERSIONINFOW)
OSVERSIONINFOW = _OSVERSIONINFOW

# Struct _OSVERSIONINFOEXA definitions
class _OSVERSIONINFOEXA(Structure):
        _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", CHAR * 128),
        ("wServicePackMajor", WORD),
        ("wServicePackMinor", WORD),
        ("wSuiteMask", WORD),
        ("wProductType", BYTE),
        ("wReserved", BYTE),
    ]
OSVERSIONINFOEXA = _OSVERSIONINFOEXA
POSVERSIONINFOEXA = POINTER(_OSVERSIONINFOEXA)
LPOSVERSIONINFOEXA = POINTER(_OSVERSIONINFOEXA)

# Struct _OSVERSIONINFOEXW definitions
class _OSVERSIONINFOEXW(Structure):
        _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", WCHAR * 128),
        ("wServicePackMajor", WORD),
        ("wServicePackMinor", WORD),
        ("wSuiteMask", WORD),
        ("wProductType", BYTE),
        ("wReserved", BYTE),
    ]
PRTL_OSVERSIONINFOEXW = POINTER(_OSVERSIONINFOEXW)
LPOSVERSIONINFOEXW = POINTER(_OSVERSIONINFOEXW)
OSVERSIONINFOEXW = _OSVERSIONINFOEXW
POSVERSIONINFOEXW = POINTER(_OSVERSIONINFOEXW)
RTL_OSVERSIONINFOEXW = _OSVERSIONINFOEXW

# Struct _OVERLAPPED definitions
class _OVERLAPPED(Structure):
        _fields_ = [
        ("Internal", ULONG_PTR),
        ("InternalHigh", ULONG_PTR),
        ("Pointer", PVOID),
        ("hEvent", HANDLE),
    ]
LPOVERLAPPED = POINTER(_OVERLAPPED)
OVERLAPPED = _OVERLAPPED

