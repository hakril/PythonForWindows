#Generated file
from ctypes import *
from ctypes.wintypes import *
from .windef import *

PWSTR = LPWSTR
SIZE_T = c_ulong
PSIZE_T = POINTER(SIZE_T)
PVOID = c_void_p
PPS_POST_PROCESS_INIT_ROUTINE = PVOID
NTSTATUS = DWORD
PULONG = POINTER(ULONG)
PDWORD = POINTER(DWORD)
LPDWORD = POINTER(DWORD)
LPTHREAD_START_ROUTINE = PVOID
PHANDLER_ROUTINE = PVOID
LPBYTE = POINTER(BYTE)
ULONG_PTR = PULONG
CHAR = c_char
UCHAR = c_char
PUCHAR = POINTER(UCHAR)
FARPROC = PVOID
HGLOBAL = PVOID
PSID = PVOID
PVECTORED_EXCEPTION_HANDLER = PVOID
ULONGLONG = c_ulonglong
LONGLONG = c_longlong
ULONG64 = c_ulonglong
DWORD64 = ULONG64
PULONG64 = POINTER(ULONG64)
PHANDLE = POINTER(HANDLE)
HKEY = HANDLE
PHKEY = POINTER(HKEY)
ACCESS_MASK = DWORD
REGSAM = ACCESS_MASK
LPCONTEXT = PVOID
HCERTSTORE = PVOID
HCRYPTMSG = PVOID
VOID = DWORD

structs = ['_LIST_ENTRY', '_PEB_LDR_DATA', '_LSA_UNICODE_STRING', '_RTL_USER_PROCESS_PARAMETERS', '_PEB', '_SECURITY_ATTRIBUTES', '_SYSTEM_VERIFIER_INFORMATION', '_LDR_DATA_TABLE_ENTRY', '_IMAGE_FILE_HEADER', '_IMAGE_DATA_DIRECTORY', '_IMAGE_SECTION_HEADER', '_IMAGE_OPTIONAL_HEADER64', '_IMAGE_OPTIONAL_HEADER', '_IMAGE_NT_HEADERS64', '_IMAGE_NT_HEADERS', '_IMAGE_IMPORT_DESCRIPTOR', '_IMAGE_IMPORT_BY_NAME', '_IMAGE_EXPORT_DIRECTORY', '_MEMORY_BASIC_INFORMATION', '_MEMORY_BASIC_INFORMATION32', '_MEMORY_BASIC_INFORMATION64', '_STARTUPINFOA', '_STARTUPINFOW', '_PROCESS_INFORMATION', '_FLOATING_SAVE_AREA', '_CONTEXT32', '_WOW64_FLOATING_SAVE_AREA', '_WOW64_CONTEXT', '_M128A', '_CONTEXT64', 'tagPROCESSENTRY32W', 'tagPROCESSENTRY32', 'tagTHREADENTRY32', '_LUID', '_LUID_AND_ATTRIBUTES', '_TOKEN_PRIVILEGES', '_TOKEN_ELEVATION', '_SID_AND_ATTRIBUTES', '_TOKEN_MANDATORY_LABEL', '_OSVERSIONINFOA', '_OSVERSIONINFOW', '_OSVERSIONINFOEXA', '_OSVERSIONINFOEXW', '_OVERLAPPED', '_MIB_TCPROW_OWNER_PID', '_MIB_TCPTABLE_OWNER_PID', '_MIB_UDPROW_OWNER_PID', '_MIB_UDPTABLE_OWNER_PID', '_MIB_UDP6ROW_OWNER_PID', '_MIB_UDP6TABLE_OWNER_PID', '_MIB_TCP6ROW_OWNER_PID', '_MIB_TCP6TABLE_OWNER_PID', '_MIB_TCPROW', '_EXCEPTION_RECORD', '_EXCEPTION_RECORD32', '_EXCEPTION_RECORD64', '_EXCEPTION_POINTERS64', '_EXCEPTION_POINTERS32', '_DEBUG_PROCESSOR_IDENTIFICATION_ALPHA', '_DEBUG_PROCESSOR_IDENTIFICATION_AMD64', '_DEBUG_PROCESSOR_IDENTIFICATION_IA64', '_DEBUG_PROCESSOR_IDENTIFICATION_X86', '_DEBUG_PROCESSOR_IDENTIFICATION_ARM', '_DEBUG_PROCESSOR_IDENTIFICATION_ALL', '_SYMBOL_INFO', '_MODLOAD_DATA', '_SYSTEM_MODULE32', '_SYSTEM_MODULE64', '_SYSTEM_MODULE_INFORMATION32', '_SYSTEM_MODULE_INFORMATION64', 'tagSAFEARRAYBOUND', 'tagSAFEARRAY', '_DEBUG_BREAKPOINT_PARAMETERS', '_DEBUG_REGISTER_DESCRIPTION', '_DEBUG_STACK_FRAME', '_DEBUG_LAST_EVENT_INFO_BREAKPOINT', '_DEBUG_LAST_EVENT_INFO_EXCEPTION', '_DEBUG_LAST_EVENT_INFO_EXIT_THREAD', '_DEBUG_LAST_EVENT_INFO_EXIT_PROCESS', '_DEBUG_LAST_EVENT_INFO_LOAD_MODULE', '_DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE', '_DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR', '_DEBUG_SPECIFIC_FILTER_PARAMETERS', '_DEBUG_EXCEPTION_FILTER_PARAMETERS', '_GUID', '_CRYPTOAPI_BLOB', 'WINTRUST_FILE_INFO_', '_CRYPT_ATTRIBUTE', '_CTL_ENTRY', '_CRYPT_ATTRIBUTE', '_CRYPT_ATTRIBUTES', '_CRYPT_ALGORITHM_IDENTIFIER', '_CMSG_SIGNER_INFO', '_CERT_EXTENSION', '_CTL_USAGE', '_CTL_INFO', '_CTL_CONTEXT', 'WINTRUST_CATALOG_INFO_', 'WINTRUST_BLOB_INFO_', '_CRYPT_BIT_BLOB', '_CERT_PUBLIC_KEY_INFO', '_CERT_INFO', '_CERT_CONTEXT', 'WINTRUST_SGNR_INFO_', '_FILETIME', 'WINTRUST_CERT_INFO_', '_TMP_WINTRUST_UNION_TYPE', '_WINTRUST_DATA', '_PROCESS_BASIC_INFORMATION', '_JIT_DEBUG_INFO', '_SID_IDENTIFIER_AUTHORITY', '_EXCEPTION_DEBUG_INFO', '_CREATE_THREAD_DEBUG_INFO', '_CREATE_PROCESS_DEBUG_INFO', '_EXIT_THREAD_DEBUG_INFO', '_EXIT_PROCESS_DEBUG_INFO', '_LOAD_DLL_DEBUG_INFO', '_UNLOAD_DLL_DEBUG_INFO', '_OUTPUT_DEBUG_STRING_INFO', '_RIP_INFO', '_TMP_UNION_DEBUG_INFO', '_DEBUG_EVENT']

enums = ['_SYSTEM_INFORMATION_CLASS', '_MEMORY_INFORMATION_CLASS', '_THREAD_INFORMATION_CLASS', '_TCP_TABLE_CLASS', '_VARENUM', '_UDP_TABLE_CLASS', '_MIB_TCP_STATE', '_TOKEN_INFORMATION_CLASS', '_IMAGEHLP_SYMBOL_TYPE_INFO', '_PROCESSINFOCLASS']

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

# Enum _MEMORY_INFORMATION_CLASS definitions
_MEMORY_INFORMATION_CLASS = DWORD
MEMORY_INFORMATION_CLASS = _MEMORY_INFORMATION_CLASS

MemoryBasicInformation = 0x0

# Enum _THREAD_INFORMATION_CLASS definitions
_THREAD_INFORMATION_CLASS = DWORD
THREAD_INFORMATION_CLASS = _THREAD_INFORMATION_CLASS
PTHREAD_INFORMATION_CLASS = POINTER(_THREAD_INFORMATION_CLASS)

ThreadBasicInformation = 0x0
ThreadTimes = 0x1
ThreadPriority = 0x2
ThreadBasePriority = 0x3
ThreadAffinityMask = 0x4
ThreadImpersonationToken = 0x5
ThreadDescriptorTableEntry = 0x6
ThreadEnableAlignmentFaultFixup = 0x7
ThreadEventPair = 0x8
ThreadQuerySetWin32StartAddress = 0x9
ThreadZeroTlsCell = 0xa
ThreadPerformanceCount = 0xb
ThreadAmILastThread = 0xc
ThreadIdealProcessor = 0xd
ThreadPriorityBoost = 0xe
ThreadSetTlsArrayAddress = 0xf
ThreadIsIoPending = 0x10
ThreadHideFromDebugger = 0x11

# Enum _TCP_TABLE_CLASS definitions
_TCP_TABLE_CLASS = DWORD
TCP_TABLE_CLASS = _TCP_TABLE_CLASS

TCP_TABLE_BASIC_LISTENER = 0x0
TCP_TABLE_BASIC_CONNECTIONS = 0x1
TCP_TABLE_BASIC_ALL = 0x2
TCP_TABLE_OWNER_PID_LISTENER = 0x3
TCP_TABLE_OWNER_PID_CONNECTIONS = 0x4
TCP_TABLE_OWNER_PID_ALL = 0x5
TCP_TABLE_OWNER_MODULE_LISTENER = 0x6
TCP_TABLE_OWNER_MODULE_CONNECTIONS = 0x7
TCP_TABLE_OWNER_MODULE_ALL = 0x8

# Enum _VARENUM definitions
_VARENUM = DWORD
VARENUM = _VARENUM

VT_EMPTY = 0x0
VT_NULL = 0x1
VT_I2 = 0x2
VT_I4 = 0x3
VT_R4 = 0x4
VT_R8 = 0x5
VT_CY = 0x6
VT_DATE = 0x7
VT_BSTR = 0x8
VT_DISPATCH = 0x9
VT_ERROR = 0xa
VT_BOOL = 0xb
VT_VARIANT = 0xc
VT_UNKNOWN = 0xd
VT_DECIMAL = 0xe
VT_I1 = 0x10
VT_UI1 = 0x11
VT_UI2 = 0x12
VT_UI4 = 0x13
VT_I8 = 0x14
VT_UI8 = 0x15
VT_INT = 0x16
VT_UINT = 0x17
VT_VOID = 0x18
VT_HRESULT = 0x19
VT_PTR = 0x1a
VT_SAFEARRAY = 0x1b
VT_CARRAY = 0x1c
VT_USERDEFINED = 0x1d
VT_LPSTR = 0x1e
VT_LPWSTR = 0x1f
VT_RECORD = 0x24
VT_INT_PTR = 0x25
VT_UINT_PTR = 0x26
VT_FILETIME = 0x40
VT_BLOB = 0x41
VT_STREAM = 0x42
VT_STORAGE = 0x43
VT_STREAMED_OBJECT = 0x44
VT_STORED_OBJECT = 0x45
VT_BLOB_OBJECT = 0x46
VT_CF = 0x47
VT_CLSID = 0x48
VT_VERSIONED_STREAM = 0x49
VT_BSTR_BLOB = 0xfff
VT_VECTOR = 0x1000
VT_ARRAY = 0x2000
VT_BYREF = 0x4000
VT_RESERVED = 0x8000
VT_ILLEGAL = 0xffff
VT_ILLEGALMASKED = 0xfff
VT_TYPEMASK = 0xfff

# Enum _UDP_TABLE_CLASS definitions
_UDP_TABLE_CLASS = DWORD
UDP_TABLE_CLASS = _UDP_TABLE_CLASS

UDP_TABLE_BASIC = 0x0
UDP_TABLE_OWNER_PID = 0x1
UDP_TABLE_OWNER_MODULE = 0x2

# Enum _MIB_TCP_STATE definitions
_MIB_TCP_STATE = DWORD
MIB_TCP_STATE = _MIB_TCP_STATE

MIB_TCP_STATE_CLOSED = 0x1
MIB_TCP_STATE_LISTEN = 0x2
MIB_TCP_STATE_SYN_SENT = 0x3
MIB_TCP_STATE_SYN_RCVD = 0x4
MIB_TCP_STATE_ESTAB = 0x5
MIB_TCP_STATE_FIN_WAIT1 = 0x6
MIB_TCP_STATE_FIN_WAIT2 = 0x7
MIB_TCP_STATE_CLOSE_WAIT = 0x8
MIB_TCP_STATE_CLOSING = 0x9
MIB_TCP_STATE_LAST_ACK = 0xa
MIB_TCP_STATE_TIME_WAIT = 0xb
MIB_TCP_STATE_DELETE_TCB = 0xc

# Enum _TOKEN_INFORMATION_CLASS definitions
_TOKEN_INFORMATION_CLASS = DWORD
TOKEN_INFORMATION_CLASS = _TOKEN_INFORMATION_CLASS
PTOKEN_INFORMATION_CLASS = POINTER(_TOKEN_INFORMATION_CLASS)

TokenInvalid = 0x0
TokenUser = 0x1
TokenGroups = 0x2
TokenPrivileges = 0x3
TokenOwner = 0x4
TokenPrimaryGroup = 0x5
TokenDefaultDacl = 0x6
TokenSource = 0x7
TokenType = 0x8
TokenImpersonationLevel = 0x9
TokenStatistics = 0xa
TokenRestrictedSids = 0xb
TokenSessionId = 0xc
TokenGroupsAndPrivileges = 0xd
TokenSessionReference = 0xe
TokenSandBoxInert = 0xf
TokenAuditPolicy = 0x10
TokenOrigin = 0x11
TokenElevationType = 0x12
TokenLinkedToken = 0x13
TokenElevation = 0x14
TokenHasRestrictions = 0x15
TokenAccessInformation = 0x16
TokenVirtualizationAllowed = 0x17
TokenVirtualizationEnabled = 0x18
TokenIntegrityLevel = 0x19
TokenUIAccess = 0x1a
TokenMandatoryPolicy = 0x1b
TokenLogonSid = 0x1c
TokenIsAppContainer = 0x1d
TokenCapabilities = 0x1e
TokenAppContainerSid = 0x1f
TokenAppContainerNumber = 0x20
TokenUserClaimAttributes = 0x21
TokenDeviceClaimAttributes = 0x22
TokenRestrictedUserClaimAttributes = 0x23
TokenRestrictedDeviceClaimAttributes = 0x24
TokenDeviceGroups = 0x25
TokenRestrictedDeviceGroups = 0x26
TokenSecurityAttributes = 0x27
TokenIsRestricted = 0x28
MaxTokenInfoClass = 0x29

# Enum _IMAGEHLP_SYMBOL_TYPE_INFO definitions
_IMAGEHLP_SYMBOL_TYPE_INFO = DWORD
IMAGEHLP_SYMBOL_TYPE_INFO = _IMAGEHLP_SYMBOL_TYPE_INFO

TI_GET_SYMTAG = 0x0
TI_GET_SYMNAME = 0x1
TI_GET_LENGTH = 0x2
TI_GET_TYPE = 0x3
TI_GET_TYPEID = 0x4
TI_GET_BASETYPE = 0x5
TI_GET_ARRAYINDEXTYPEID = 0x6
TI_FINDCHILDREN = 0x7
TI_GET_DATAKIND = 0x8
TI_GET_ADDRESSOFFSET = 0x9
TI_GET_OFFSET = 0xa
TI_GET_VALUE = 0xb
TI_GET_COUNT = 0xc
TI_GET_CHILDRENCOUNT = 0xd
TI_GET_BITPOSITION = 0xe
TI_GET_VIRTUALBASECLASS = 0xf
TI_GET_VIRTUALTABLESHAPEID = 0x10
TI_GET_VIRTUALBASEPOINTEROFFSET = 0x11
TI_GET_CLASSPARENTID = 0x12
TI_GET_NESTED = 0x13
TI_GET_SYMINDEX = 0x14
TI_GET_LEXICALPARENT = 0x15
TI_GET_ADDRESS = 0x16
TI_GET_THISADJUST = 0x17
TI_GET_UDTKIND = 0x18
TI_IS_EQUIV_TO = 0x19
TI_GET_CALLING_CONVENTION = 0x1a
TI_IS_CLOSE_EQUIV_TO = 0x1b
TI_GTIEX_REQS_VALID = 0x1c
TI_GET_VIRTUALBASEOFFSET = 0x1d
TI_GET_VIRTUALBASEDISPINDEX = 0x1e
TI_GET_IS_REFERENCE = 0x1f
TI_GET_INDIRECTVIRTUALBASECLASS = 0x20
IMAGEHLP_SYMBOL_TYPE_INFO_MAX = 0x21

# Enum _PROCESSINFOCLASS definitions
_PROCESSINFOCLASS = DWORD
PROCESSINFOCLASS = _PROCESSINFOCLASS

ProcessBasicInformation = 0x0
ProcessWow64Information = 0x1a

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

# Struct _IMAGE_EXPORT_DIRECTORY definitions
class _IMAGE_EXPORT_DIRECTORY(Structure):
        _fields_ = [
        ("Characteristics", DWORD),
        ("TimeDateStamp", DWORD),
        ("MajorVersion", WORD),
        ("MinorVersion", WORD),
        ("Name", DWORD),
        ("Base", DWORD),
        ("NumberOfFunctions", DWORD),
        ("NumberOfNames", DWORD),
        ("AddressOfFunctions", DWORD),
        ("AddressOfNames", DWORD),
        ("AddressOfNameOrdinals", DWORD),
    ]
IMAGE_EXPORT_DIRECTORY = _IMAGE_EXPORT_DIRECTORY
PIMAGE_EXPORT_DIRECTORY = POINTER(_IMAGE_EXPORT_DIRECTORY)

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

# Struct _MEMORY_BASIC_INFORMATION32 definitions
class _MEMORY_BASIC_INFORMATION32(Structure):
        _fields_ = [
        ("BaseAddress", DWORD),
        ("AllocationBase", DWORD),
        ("AllocationProtect", DWORD),
        ("RegionSize", DWORD),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]
MEMORY_BASIC_INFORMATION32 = _MEMORY_BASIC_INFORMATION32
PMEMORY_BASIC_INFORMATION32 = POINTER(_MEMORY_BASIC_INFORMATION32)

# Struct _MEMORY_BASIC_INFORMATION64 definitions
class _MEMORY_BASIC_INFORMATION64(Structure):
        _fields_ = [
        ("BaseAddress", ULONGLONG),
        ("AllocationBase", ULONGLONG),
        ("AllocationProtect", DWORD),
        ("__alignment1", DWORD),
        ("RegionSize", ULONGLONG),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
        ("__alignment2", DWORD),
    ]
PMEMORY_BASIC_INFORMATION64 = POINTER(_MEMORY_BASIC_INFORMATION64)
MEMORY_BASIC_INFORMATION64 = _MEMORY_BASIC_INFORMATION64

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

# Struct _CONTEXT32 definitions
class _CONTEXT32(Structure):
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
PCONTEXT32 = POINTER(_CONTEXT32)
CONTEXT32 = _CONTEXT32
LPCONTEXT32 = POINTER(_CONTEXT32)

# Struct _WOW64_FLOATING_SAVE_AREA definitions
class _WOW64_FLOATING_SAVE_AREA(Structure):
        _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * WOW64_SIZE_OF_80387_REGISTERS),
        ("Cr0NpxState", DWORD),
    ]
WOW64_FLOATING_SAVE_AREA = _WOW64_FLOATING_SAVE_AREA

# Struct _WOW64_CONTEXT definitions
class _WOW64_CONTEXT(Structure):
        _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
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
        ("ExtendedRegisters", BYTE * WOW64_MAXIMUM_SUPPORTED_EXTENSION),
    ]
PWOW64_CONTEXT = POINTER(_WOW64_CONTEXT)
WOW64_CONTEXT = _WOW64_CONTEXT

# Struct _M128A definitions
class _M128A(Structure):
        _fields_ = [
        ("Low", ULONGLONG),
        ("High", LONGLONG),
    ]
M128A = _M128A
PM128A = POINTER(_M128A)

# Struct _CONTEXT64 definitions
class _CONTEXT64(Structure):
        _fields_ = [
        ("P1Home", DWORD64),
        ("P2Home", DWORD64),
        ("P3Home", DWORD64),
        ("P4Home", DWORD64),
        ("P5Home", DWORD64),
        ("P6Home", DWORD64),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegFs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("EFlags", DWORD),
        ("Dr0", DWORD64),
        ("Dr1", DWORD64),
        ("Dr2", DWORD64),
        ("Dr3", DWORD64),
        ("Dr6", DWORD64),
        ("Dr7", DWORD64),
        ("Rax", DWORD64),
        ("Rcx", DWORD64),
        ("Rdx", DWORD64),
        ("Rbx", DWORD64),
        ("Rsp", DWORD64),
        ("Rbp", DWORD64),
        ("Rsi", DWORD64),
        ("Rdi", DWORD64),
        ("R8", DWORD64),
        ("R9", DWORD64),
        ("R10", DWORD64),
        ("R11", DWORD64),
        ("R12", DWORD64),
        ("R13", DWORD64),
        ("R14", DWORD64),
        ("R15", DWORD64),
        ("Rip", DWORD64),
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
        ("VectorRegister", M128A * 26),
        ("VectorControl", DWORD64),
        ("DebugControl", DWORD64),
        ("LastBranchToRip", DWORD64),
        ("LastBranchFromRip", DWORD64),
        ("LastExceptionToRip", DWORD64),
        ("LastExceptionFromRip", DWORD64),
    ]
PCONTEXT64 = POINTER(_CONTEXT64)
CONTEXT64 = _CONTEXT64
LPCONTEXT64 = POINTER(_CONTEXT64)

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

# Struct _TOKEN_ELEVATION definitions
class _TOKEN_ELEVATION(Structure):
        _fields_ = [
        ("TokenIsElevated", DWORD),
    ]
TOKEN_ELEVATION = _TOKEN_ELEVATION
PTOKEN_ELEVATION = POINTER(_TOKEN_ELEVATION)

# Struct _SID_AND_ATTRIBUTES definitions
class _SID_AND_ATTRIBUTES(Structure):
        _fields_ = [
        ("Sid", PSID),
        ("Attributes", DWORD),
    ]
SID_AND_ATTRIBUTES = _SID_AND_ATTRIBUTES
PSID_AND_ATTRIBUTES = POINTER(_SID_AND_ATTRIBUTES)

# Struct _TOKEN_MANDATORY_LABEL definitions
class _TOKEN_MANDATORY_LABEL(Structure):
        _fields_ = [
        ("Label", SID_AND_ATTRIBUTES),
    ]
TOKEN_MANDATORY_LABEL = _TOKEN_MANDATORY_LABEL
PTOKEN_MANDATORY_LABEL = POINTER(_TOKEN_MANDATORY_LABEL)

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

# Struct _MIB_TCPROW_OWNER_PID definitions
class _MIB_TCPROW_OWNER_PID(Structure):
        _fields_ = [
        ("dwState", DWORD),
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_TCPROW_OWNER_PID = _MIB_TCPROW_OWNER_PID
PMIB_TCPROW_OWNER_PID = POINTER(_MIB_TCPROW_OWNER_PID)

# Struct _MIB_TCPTABLE_OWNER_PID definitions
class _MIB_TCPTABLE_OWNER_PID(Structure):
        _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCPROW_OWNER_PID * ANY_SIZE),
    ]
MIB_TCPTABLE_OWNER_PID = _MIB_TCPTABLE_OWNER_PID
PMIB_TCPTABLE_OWNER_PID = POINTER(_MIB_TCPTABLE_OWNER_PID)

# Struct _MIB_UDPROW_OWNER_PID definitions
class _MIB_UDPROW_OWNER_PID(Structure):
        _fields_ = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_UDPROW_OWNER_PID = _MIB_UDPROW_OWNER_PID
PMIB_UDPROW_OWNER_PID = POINTER(_MIB_UDPROW_OWNER_PID)

# Struct _MIB_UDPTABLE_OWNER_PID definitions
class _MIB_UDPTABLE_OWNER_PID(Structure):
        _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_UDPROW_OWNER_PID * ANY_SIZE),
    ]
MIB_UDPTABLE_OWNER_PID = _MIB_UDPTABLE_OWNER_PID
PMIB_UDPTABLE_OWNER_PID = POINTER(_MIB_UDPTABLE_OWNER_PID)

# Struct _MIB_UDP6ROW_OWNER_PID definitions
class _MIB_UDP6ROW_OWNER_PID(Structure):
        _fields_ = [
        ("ucLocalAddr", UCHAR * 16),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_UDP6ROW_OWNER_PID = _MIB_UDP6ROW_OWNER_PID
PMIB_UDP6ROW_OWNER_PID = POINTER(_MIB_UDP6ROW_OWNER_PID)

# Struct _MIB_UDP6TABLE_OWNER_PID definitions
class _MIB_UDP6TABLE_OWNER_PID(Structure):
        _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_UDP6ROW_OWNER_PID * ANY_SIZE),
    ]
PMIB_UDP6TABLE_OWNER_PID = POINTER(_MIB_UDP6TABLE_OWNER_PID)
MIB_UDP6TABLE_OWNER_PID = _MIB_UDP6TABLE_OWNER_PID

# Struct _MIB_TCP6ROW_OWNER_PID definitions
class _MIB_TCP6ROW_OWNER_PID(Structure):
        _fields_ = [
        ("ucLocalAddr", UCHAR * 16),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("ucRemoteAddr", UCHAR * 16),
        ("dwRemoteScopeId", DWORD),
        ("dwRemotePort", DWORD),
        ("dwState", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_TCP6ROW_OWNER_PID = _MIB_TCP6ROW_OWNER_PID
PMIB_TCP6ROW_OWNER_PID = POINTER(_MIB_TCP6ROW_OWNER_PID)

# Struct _MIB_TCP6TABLE_OWNER_PID definitions
class _MIB_TCP6TABLE_OWNER_PID(Structure):
        _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCP6ROW_OWNER_PID * ANY_SIZE),
    ]
MIB_TCP6TABLE_OWNER_PID = _MIB_TCP6TABLE_OWNER_PID
PMIB_TCP6TABLE_OWNER_PID = POINTER(_MIB_TCP6TABLE_OWNER_PID)

# Struct _MIB_TCPROW definitions
class _MIB_TCPROW(Structure):
        _fields_ = [
        ("dwState", DWORD),
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
    ]
MIB_TCPROW = _MIB_TCPROW
PMIB_TCPROW = POINTER(_MIB_TCPROW)

# Struct _EXCEPTION_RECORD definitions
# Self referencing struct tricks
class _EXCEPTION_RECORD(Structure): pass
_EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", POINTER(_EXCEPTION_RECORD)),
    ("ExceptionAddress", PVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", ULONG_PTR * EXCEPTION_MAXIMUM_PARAMETERS),
]
PEXCEPTION_RECORD = POINTER(_EXCEPTION_RECORD)
EXCEPTION_RECORD = _EXCEPTION_RECORD

# Struct _EXCEPTION_RECORD32 definitions
class _EXCEPTION_RECORD32(Structure):
        _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", DWORD),
        ("ExceptionAddress", DWORD),
        ("NumberParameters", DWORD),
        ("ExceptionInformation", DWORD * EXCEPTION_MAXIMUM_PARAMETERS),
    ]
EXCEPTION_RECORD32 = _EXCEPTION_RECORD32
PEXCEPTION_RECORD32 = POINTER(_EXCEPTION_RECORD32)

# Struct _EXCEPTION_RECORD64 definitions
class _EXCEPTION_RECORD64(Structure):
        _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", DWORD64),
        ("ExceptionAddress", DWORD64),
        ("NumberParameters", DWORD),
        ("__unusedAlignment", DWORD),
        ("ExceptionInformation", DWORD64 * EXCEPTION_MAXIMUM_PARAMETERS),
    ]
PEXCEPTION_RECORD64 = POINTER(_EXCEPTION_RECORD64)
EXCEPTION_RECORD64 = _EXCEPTION_RECORD64

# Struct _EXCEPTION_POINTERS64 definitions
class _EXCEPTION_POINTERS64(Structure):
        _fields_ = [
        ("ExceptionRecord", PEXCEPTION_RECORD),
        ("ContextRecord", PCONTEXT64),
    ]
EXCEPTION_POINTERS64 = _EXCEPTION_POINTERS64
PEXCEPTION_POINTERS64 = POINTER(_EXCEPTION_POINTERS64)

# Struct _EXCEPTION_POINTERS32 definitions
class _EXCEPTION_POINTERS32(Structure):
        _fields_ = [
        ("ExceptionRecord", PEXCEPTION_RECORD),
        ("ContextRecord", PCONTEXT32),
    ]
PEXCEPTION_POINTERS32 = POINTER(_EXCEPTION_POINTERS32)
EXCEPTION_POINTERS32 = _EXCEPTION_POINTERS32

# Struct _DEBUG_PROCESSOR_IDENTIFICATION_ALPHA definitions
class _DEBUG_PROCESSOR_IDENTIFICATION_ALPHA(Structure):
        _fields_ = [
        ("Type", ULONG),
        ("Revision", ULONG),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_ALPHA = _DEBUG_PROCESSOR_IDENTIFICATION_ALPHA
PDEBUG_PROCESSOR_IDENTIFICATION_ALPHA = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_ALPHA)

# Struct _DEBUG_PROCESSOR_IDENTIFICATION_AMD64 definitions
class _DEBUG_PROCESSOR_IDENTIFICATION_AMD64(Structure):
        _fields_ = [
        ("Family", ULONG),
        ("Model", ULONG),
        ("Stepping", ULONG),
        ("VendorString", CHAR * 16),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_AMD64 = _DEBUG_PROCESSOR_IDENTIFICATION_AMD64
PDEBUG_PROCESSOR_IDENTIFICATION_AMD64 = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_AMD64)

# Struct _DEBUG_PROCESSOR_IDENTIFICATION_IA64 definitions
class _DEBUG_PROCESSOR_IDENTIFICATION_IA64(Structure):
        _fields_ = [
        ("Model", ULONG),
        ("Revision", ULONG),
        ("Family", ULONG),
        ("ArchRev", ULONG),
        ("VendorString", CHAR * 16),
    ]
PDEBUG_PROCESSOR_IDENTIFICATION_IA64 = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_IA64)
DEBUG_PROCESSOR_IDENTIFICATION_IA64 = _DEBUG_PROCESSOR_IDENTIFICATION_IA64

# Struct _DEBUG_PROCESSOR_IDENTIFICATION_X86 definitions
class _DEBUG_PROCESSOR_IDENTIFICATION_X86(Structure):
        _fields_ = [
        ("Family", ULONG),
        ("Model", ULONG),
        ("Stepping", ULONG),
        ("VendorString", CHAR * 16),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_X86 = _DEBUG_PROCESSOR_IDENTIFICATION_X86
PDEBUG_PROCESSOR_IDENTIFICATION_X86 = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_X86)

# Struct _DEBUG_PROCESSOR_IDENTIFICATION_ARM definitions
class _DEBUG_PROCESSOR_IDENTIFICATION_ARM(Structure):
        _fields_ = [
        ("Type", ULONG),
        ("Revision", ULONG),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_ARM = _DEBUG_PROCESSOR_IDENTIFICATION_ARM
PDEBUG_PROCESSOR_IDENTIFICATION_ARM = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_ARM)

# Struct _DEBUG_PROCESSOR_IDENTIFICATION_ALL definitions
class _DEBUG_PROCESSOR_IDENTIFICATION_ALL(Union):
        _fields_ = [
        ("Alpha", DEBUG_PROCESSOR_IDENTIFICATION_ALPHA),
        ("Amd64", DEBUG_PROCESSOR_IDENTIFICATION_AMD64),
        ("Ia64", DEBUG_PROCESSOR_IDENTIFICATION_IA64),
        ("X86", DEBUG_PROCESSOR_IDENTIFICATION_X86),
        ("Arm", DEBUG_PROCESSOR_IDENTIFICATION_ARM),
    ]
PDEBUG_PROCESSOR_IDENTIFICATION_ALL = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_ALL)
DEBUG_PROCESSOR_IDENTIFICATION_ALL = _DEBUG_PROCESSOR_IDENTIFICATION_ALL

# Struct _SYMBOL_INFO definitions
class _SYMBOL_INFO(Structure):
        _fields_ = [
        ("SizeOfStruct", ULONG),
        ("TypeIndex", ULONG),
        ("Reserved", ULONG64 * 2),
        ("Index", ULONG),
        ("Size", ULONG),
        ("ModBase", ULONG64),
        ("Flags", ULONG),
        ("Value", ULONG64),
        ("Address", ULONG64),
        ("Register", ULONG),
        ("Scope", ULONG),
        ("Tag", ULONG),
        ("NameLen", ULONG),
        ("MaxNameLen", ULONG),
        ("Name", CHAR * 1),
    ]
SYMBOL_INFO = _SYMBOL_INFO
PSYMBOL_INFO = POINTER(_SYMBOL_INFO)

# Struct _MODLOAD_DATA definitions
class _MODLOAD_DATA(Structure):
        _fields_ = [
        ("ssize", DWORD),
        ("ssig", DWORD),
        ("data", PVOID),
        ("size", DWORD),
        ("flags", DWORD),
    ]
PMODLOAD_DATA = POINTER(_MODLOAD_DATA)
MODLOAD_DATA = _MODLOAD_DATA

# Struct _SYSTEM_MODULE32 definitions
class _SYSTEM_MODULE32(Structure):
        _fields_ = [
        ("Reserved", ULONG * 2),
        ("Base", ULONG),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Index", USHORT),
        ("Unknown", USHORT),
        ("LoadCount", USHORT),
        ("ModuleNameOffset", USHORT),
        ("ImageName", CHAR * 256),
    ]
SYSTEM_MODULE32 = _SYSTEM_MODULE32
PSYSTEM_MODULE32 = POINTER(_SYSTEM_MODULE32)

# Struct _SYSTEM_MODULE64 definitions
class _SYSTEM_MODULE64(Structure):
        _fields_ = [
        ("Reserved", ULONG * 4),
        ("Base", ULONG64),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Index", USHORT),
        ("Unknown", USHORT),
        ("LoadCount", USHORT),
        ("ModuleNameOffset", USHORT),
        ("ImageName", CHAR * 256),
    ]
SYSTEM_MODULE64 = _SYSTEM_MODULE64
PSYSTEM_MODULE64 = POINTER(_SYSTEM_MODULE64)

# Struct _SYSTEM_MODULE_INFORMATION32 definitions
class _SYSTEM_MODULE_INFORMATION32(Structure):
        _fields_ = [
        ("ModulesCount", ULONG),
        ("Modules", SYSTEM_MODULE32 * 0),
    ]
PSYSTEM_MODULE_INFORMATION32 = POINTER(_SYSTEM_MODULE_INFORMATION32)
SYSTEM_MODULE_INFORMATION32 = _SYSTEM_MODULE_INFORMATION32

# Struct _SYSTEM_MODULE_INFORMATION64 definitions
class _SYSTEM_MODULE_INFORMATION64(Structure):
        _fields_ = [
        ("ModulesCount", ULONG),
        ("Modules", SYSTEM_MODULE64 * 0),
    ]
PSYSTEM_MODULE_INFORMATION64 = POINTER(_SYSTEM_MODULE_INFORMATION64)
SYSTEM_MODULE_INFORMATION64 = _SYSTEM_MODULE_INFORMATION64

# Struct tagSAFEARRAYBOUND definitions
class tagSAFEARRAYBOUND(Structure):
        _fields_ = [
        ("cElements", ULONG),
        ("lLbound", LONG),
    ]
SAFEARRAYBOUND = tagSAFEARRAYBOUND
LPSAFEARRAYBOUND = POINTER(tagSAFEARRAYBOUND)

# Struct tagSAFEARRAY definitions
class tagSAFEARRAY(Structure):
        _fields_ = [
        ("cDims", USHORT),
        ("fFeatures", USHORT),
        ("cbElements", ULONG),
        ("cLocks", ULONG),
        ("pvData", PVOID),
        ("rgsabound", SAFEARRAYBOUND * 1),
    ]
SAFEARRAY = tagSAFEARRAY

# Struct _DEBUG_BREAKPOINT_PARAMETERS definitions
class _DEBUG_BREAKPOINT_PARAMETERS(Structure):
        _fields_ = [
        ("Offset", ULONG64),
        ("Id", ULONG),
        ("BreakType", ULONG),
        ("ProcType", ULONG),
        ("Flags", ULONG),
        ("DataSize", ULONG),
        ("DataAccessType", ULONG),
        ("PassCount", ULONG),
        ("CurrentPassCount", ULONG),
        ("MatchThread", ULONG),
        ("CommandSize", ULONG),
        ("OffsetExpressionSize", ULONG),
    ]
PDEBUG_BREAKPOINT_PARAMETERS = POINTER(_DEBUG_BREAKPOINT_PARAMETERS)
DEBUG_BREAKPOINT_PARAMETERS = _DEBUG_BREAKPOINT_PARAMETERS

# Struct _DEBUG_REGISTER_DESCRIPTION definitions
class _DEBUG_REGISTER_DESCRIPTION(Structure):
        _fields_ = [
        ("Type", ULONG),
        ("Flags", ULONG),
        ("SubregMaster", ULONG),
        ("SubregLength", ULONG),
        ("SubregMask", ULONG64),
        ("SubregShift", ULONG),
        ("Reserved0", ULONG),
    ]
DEBUG_REGISTER_DESCRIPTION = _DEBUG_REGISTER_DESCRIPTION
PDEBUG_REGISTER_DESCRIPTION = POINTER(_DEBUG_REGISTER_DESCRIPTION)

# Struct _DEBUG_STACK_FRAME definitions
class _DEBUG_STACK_FRAME(Structure):
        _fields_ = [
        ("InstructionOffset", ULONG64),
        ("ReturnOffset", ULONG64),
        ("FrameOffset", ULONG64),
        ("StackOffset", ULONG64),
        ("FuncTableEntry", ULONG64),
        ("Params", ULONG64 * 4),
        ("Reserved", ULONG64 * 6),
        ("Virtual", BOOL),
        ("FrameNumber", ULONG),
    ]
PDEBUG_STACK_FRAME = POINTER(_DEBUG_STACK_FRAME)
DEBUG_STACK_FRAME = _DEBUG_STACK_FRAME

# Struct _DEBUG_LAST_EVENT_INFO_BREAKPOINT definitions
class _DEBUG_LAST_EVENT_INFO_BREAKPOINT(Structure):
        _fields_ = [
        ("Id", ULONG),
    ]
DEBUG_LAST_EVENT_INFO_BREAKPOINT = _DEBUG_LAST_EVENT_INFO_BREAKPOINT
PDEBUG_LAST_EVENT_INFO_BREAKPOINT = POINTER(_DEBUG_LAST_EVENT_INFO_BREAKPOINT)

# Struct _DEBUG_LAST_EVENT_INFO_EXCEPTION definitions
class _DEBUG_LAST_EVENT_INFO_EXCEPTION(Structure):
        _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD64),
        ("FirstChance", ULONG),
    ]
DEBUG_LAST_EVENT_INFO_EXCEPTION = _DEBUG_LAST_EVENT_INFO_EXCEPTION
PDEBUG_LAST_EVENT_INFO_EXCEPTION = POINTER(_DEBUG_LAST_EVENT_INFO_EXCEPTION)

# Struct _DEBUG_LAST_EVENT_INFO_EXIT_THREAD definitions
class _DEBUG_LAST_EVENT_INFO_EXIT_THREAD(Structure):
        _fields_ = [
        ("ExitCode", ULONG),
    ]
PDEBUG_LAST_EVENT_INFO_EXIT_THREAD = POINTER(_DEBUG_LAST_EVENT_INFO_EXIT_THREAD)
DEBUG_LAST_EVENT_INFO_EXIT_THREAD = _DEBUG_LAST_EVENT_INFO_EXIT_THREAD

# Struct _DEBUG_LAST_EVENT_INFO_EXIT_PROCESS definitions
class _DEBUG_LAST_EVENT_INFO_EXIT_PROCESS(Structure):
        _fields_ = [
        ("ExitCode", ULONG),
    ]
PDEBUG_LAST_EVENT_INFO_EXIT_PROCESS = POINTER(_DEBUG_LAST_EVENT_INFO_EXIT_PROCESS)
DEBUG_LAST_EVENT_INFO_EXIT_PROCESS = _DEBUG_LAST_EVENT_INFO_EXIT_PROCESS

# Struct _DEBUG_LAST_EVENT_INFO_LOAD_MODULE definitions
class _DEBUG_LAST_EVENT_INFO_LOAD_MODULE(Structure):
        _fields_ = [
        ("Base", ULONG64),
    ]
PDEBUG_LAST_EVENT_INFO_LOAD_MODULE = POINTER(_DEBUG_LAST_EVENT_INFO_LOAD_MODULE)
DEBUG_LAST_EVENT_INFO_LOAD_MODULE = _DEBUG_LAST_EVENT_INFO_LOAD_MODULE

# Struct _DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE definitions
class _DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE(Structure):
        _fields_ = [
        ("Base", ULONG64),
    ]
PDEBUG_LAST_EVENT_INFO_UNLOAD_MODULE = POINTER(_DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE)
DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE = _DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE

# Struct _DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR definitions
class _DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR(Structure):
        _fields_ = [
        ("Error", ULONG),
        ("Level", ULONG),
    ]
PDEBUG_LAST_EVENT_INFO_SYSTEM_ERROR = POINTER(_DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR)
DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR = _DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR

# Struct _DEBUG_SPECIFIC_FILTER_PARAMETERS definitions
class _DEBUG_SPECIFIC_FILTER_PARAMETERS(Structure):
        _fields_ = [
        ("ExecutionOption", ULONG),
        ("ContinueOption", ULONG),
        ("TextSize", ULONG),
        ("CommandSize", ULONG),
        ("ArgumentSize", ULONG),
    ]
DEBUG_SPECIFIC_FILTER_PARAMETERS = _DEBUG_SPECIFIC_FILTER_PARAMETERS
PDEBUG_SPECIFIC_FILTER_PARAMETERS = POINTER(_DEBUG_SPECIFIC_FILTER_PARAMETERS)

# Struct _DEBUG_EXCEPTION_FILTER_PARAMETERS definitions
class _DEBUG_EXCEPTION_FILTER_PARAMETERS(Structure):
        _fields_ = [
        ("ExecutionOption", ULONG),
        ("ContinueOption", ULONG),
        ("TextSize", ULONG),
        ("CommandSize", ULONG),
        ("SecondCommandSize", ULONG),
        ("ExceptionCode", ULONG),
    ]
PDEBUG_EXCEPTION_FILTER_PARAMETERS = POINTER(_DEBUG_EXCEPTION_FILTER_PARAMETERS)
DEBUG_EXCEPTION_FILTER_PARAMETERS = _DEBUG_EXCEPTION_FILTER_PARAMETERS

# Struct _GUID definitions
class _GUID(Structure):
        _fields_ = [
        ("Data1", ULONG),
        ("Data2", USHORT),
        ("Data3", USHORT),
        ("Data4", UCHAR * 8),
    ]
GUID = _GUID

# Struct _CRYPTOAPI_BLOB definitions
class _CRYPTOAPI_BLOB(Structure):
        _fields_ = [
        ("cbData", DWORD),
        ("pbData", POINTER(BYTE)),
    ]
CRYPT_INTEGER_BLOB = _CRYPTOAPI_BLOB
PCRYPT_DATA_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_OBJID_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_DER_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRL_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_UINT_BLOB = POINTER(_CRYPTOAPI_BLOB)
CERT_NAME_BLOB = _CRYPTOAPI_BLOB
PCRYPT_DIGEST_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_INTEGER_BLOB = POINTER(_CRYPTOAPI_BLOB)
CERT_RDN_VALUE_BLOB = _CRYPTOAPI_BLOB
PCERT_NAME_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_HASH_BLOB = POINTER(_CRYPTOAPI_BLOB)
CRYPT_DATA_BLOB = _CRYPTOAPI_BLOB
DATA_BLOB = _CRYPTOAPI_BLOB
CRYPT_UINT_BLOB = _CRYPTOAPI_BLOB
PCERT_RDN_VALUE_BLOB = POINTER(_CRYPTOAPI_BLOB)
CRYPT_HASH_BLOB = _CRYPTOAPI_BLOB
CRL_BLOB = _CRYPTOAPI_BLOB
PCERT_BLOB = POINTER(_CRYPTOAPI_BLOB)
CRYPT_DIGEST_BLOB = _CRYPTOAPI_BLOB
CRYPT_OBJID_BLOB = _CRYPTOAPI_BLOB
CERT_BLOB = _CRYPTOAPI_BLOB
CRYPT_DER_BLOB = _CRYPTOAPI_BLOB
PDATA_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_ATTR_BLOB = POINTER(_CRYPTOAPI_BLOB)
CRYPT_ATTR_BLOB = _CRYPTOAPI_BLOB

# Struct WINTRUST_FILE_INFO_ definitions
class WINTRUST_FILE_INFO_(Structure):
        _fields_ = [
        ("cbStruct", DWORD),
        ("pcwszFilePath", LPCWSTR),
        ("hFile", HANDLE),
        ("pgKnownSubject", POINTER(GUID)),
    ]
WINTRUST_FILE_INFO = WINTRUST_FILE_INFO_
PWINTRUST_FILE_INFO = POINTER(WINTRUST_FILE_INFO_)

# Struct _CRYPT_ATTRIBUTE definitions
class _CRYPT_ATTRIBUTE(Structure):
        _fields_ = [
        ("pszObjId", LPSTR),
        ("cValue", DWORD),
        ("rgValue", PCRYPT_ATTR_BLOB),
    ]
PCRYPT_ATTRIBUTE = POINTER(_CRYPT_ATTRIBUTE)
CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE

# Struct _CTL_ENTRY definitions
class _CTL_ENTRY(Structure):
        _fields_ = [
        ("SubjectIdentifier", CRYPT_DATA_BLOB),
        ("cAttribute", DWORD),
        ("rgAttribute", PCRYPT_ATTRIBUTE),
    ]
PCTL_ENTRY = POINTER(_CTL_ENTRY)
CTL_ENTRY = _CTL_ENTRY

# Struct _CRYPT_ATTRIBUTE definitions
class _CRYPT_ATTRIBUTE(Structure):
        _fields_ = [
        ("pszObjId", LPSTR),
        ("cValue", DWORD),
        ("rgValue", PCRYPT_ATTR_BLOB),
    ]
PCRYPT_ATTRIBUTE = POINTER(_CRYPT_ATTRIBUTE)
CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE

# Struct _CRYPT_ATTRIBUTES definitions
class _CRYPT_ATTRIBUTES(Structure):
        _fields_ = [
        ("cAttr", DWORD),
        ("rgAttr", PCRYPT_ATTRIBUTE),
    ]
CRYPT_ATTRIBUTES = _CRYPT_ATTRIBUTES
PCRYPT_ATTRIBUTES = POINTER(_CRYPT_ATTRIBUTES)

# Struct _CRYPT_ALGORITHM_IDENTIFIER definitions
class _CRYPT_ALGORITHM_IDENTIFIER(Structure):
        _fields_ = [
        ("pszObjId", LPSTR),
        ("Parameters", CRYPT_OBJID_BLOB),
    ]
CRYPT_ALGORITHM_IDENTIFIER = _CRYPT_ALGORITHM_IDENTIFIER
PCRYPT_ALGORITHM_IDENTIFIER = POINTER(_CRYPT_ALGORITHM_IDENTIFIER)

# Struct _CMSG_SIGNER_INFO definitions
class _CMSG_SIGNER_INFO(Structure):
        _fields_ = [
        ("dwVersion", DWORD),
        ("Issuer", CERT_NAME_BLOB),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("HashAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("HashEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("EncryptedHash", CRYPT_DATA_BLOB),
        ("AuthAttrs", CRYPT_ATTRIBUTES),
        ("UnauthAttrs", CRYPT_ATTRIBUTES),
    ]
CMSG_SIGNER_INFO = _CMSG_SIGNER_INFO
PCMSG_SIGNER_INFO = POINTER(_CMSG_SIGNER_INFO)

# Struct _CERT_EXTENSION definitions
class _CERT_EXTENSION(Structure):
        _fields_ = [
        ("pszObjId", LPSTR),
        ("fCritical", BOOL),
        ("Value", CRYPT_OBJID_BLOB),
    ]
CERT_EXTENSION = _CERT_EXTENSION
PCERT_EXTENSION = POINTER(_CERT_EXTENSION)

# Struct _CTL_USAGE definitions
class _CTL_USAGE(Structure):
        _fields_ = [
        ("cUsageIdentifier", DWORD),
        ("rgpszUsageIdentifier", POINTER(LPSTR)),
    ]
CERT_ENHKEY_USAGE = _CTL_USAGE
PCTL_USAGE = POINTER(_CTL_USAGE)
CTL_USAGE = _CTL_USAGE
PCERT_ENHKEY_USAGE = POINTER(_CTL_USAGE)

# Struct _CTL_INFO definitions
class _CTL_INFO(Structure):
        _fields_ = [
        ("dwVersion", DWORD),
        ("SubjectUsage", CTL_USAGE),
        ("ListIdentifier", CRYPT_DATA_BLOB),
        ("SequenceNumber", CRYPT_INTEGER_BLOB),
        ("ThisUpdate", FILETIME),
        ("NextUpdate", FILETIME),
        ("SubjectAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("cCTLEntry", DWORD),
        ("rgCTLEntry", PCTL_ENTRY),
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
CTL_INFO = _CTL_INFO
PCTL_INFO = POINTER(_CTL_INFO)

# Struct _CTL_CONTEXT definitions
class _CTL_CONTEXT(Structure):
        _fields_ = [
        ("dwMsgAndCertEncodingType", DWORD),
        ("pbCtlEncoded", POINTER(BYTE)),
        ("cbCtlEncoded", DWORD),
        ("pCtlInfo", PCTL_INFO),
        ("hCertStore", HCERTSTORE),
        ("hCryptMsg", HCRYPTMSG),
        ("pbCtlContent", POINTER(BYTE)),
        ("cbCtlContent", DWORD),
    ]
PCTL_CONTEXT = POINTER(_CTL_CONTEXT)
CTL_CONTEXT = _CTL_CONTEXT
PCCTL_CONTEXT = POINTER(_CTL_CONTEXT)

# Struct WINTRUST_CATALOG_INFO_ definitions
class WINTRUST_CATALOG_INFO_(Structure):
        _fields_ = [
        ("cbStruct", DWORD),
        ("dwCatalogVersion", DWORD),
        ("pcwszCatalogFilePath", LPCWSTR),
        ("pcwszMemberTag", LPCWSTR),
        ("pcwszMemberFilePath", LPCWSTR),
        ("hMemberFile", HANDLE),
        ("pbCalculatedFileHash", POINTER(BYTE)),
        ("cbCalculatedFileHash", DWORD),
        ("pcCatalogContext", PCCTL_CONTEXT),
    ]
PWINTRUST_CATALOG_INFO = POINTER(WINTRUST_CATALOG_INFO_)
WINTRUST_CATALOG_INFO = WINTRUST_CATALOG_INFO_

# Struct WINTRUST_BLOB_INFO_ definitions
class WINTRUST_BLOB_INFO_(Structure):
        _fields_ = [
        ("cbStruct", DWORD),
        ("gSubject", GUID),
        ("pcwszDisplayName", LPCWSTR),
        ("cbMemObject", DWORD),
        ("pbMemObject", POINTER(BYTE)),
        ("cbMemSignedMsg", DWORD),
        ("pbMemSignedMsg", POINTER(BYTE)),
    ]
PWINTRUST_BLOB_INFO = POINTER(WINTRUST_BLOB_INFO_)
WINTRUST_BLOB_INFO = WINTRUST_BLOB_INFO_

# Struct _CRYPT_BIT_BLOB definitions
class _CRYPT_BIT_BLOB(Structure):
        _fields_ = [
        ("cbData", DWORD),
        ("pbData", POINTER(BYTE)),
        ("cUnusedBits", DWORD),
    ]
CRYPT_BIT_BLOB = _CRYPT_BIT_BLOB
PCRYPT_BIT_BLOB = POINTER(_CRYPT_BIT_BLOB)

# Struct _CERT_PUBLIC_KEY_INFO definitions
class _CERT_PUBLIC_KEY_INFO(Structure):
        _fields_ = [
        ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("PublicKey", CRYPT_BIT_BLOB),
    ]
PCERT_PUBLIC_KEY_INFO = POINTER(_CERT_PUBLIC_KEY_INFO)
CERT_PUBLIC_KEY_INFO = _CERT_PUBLIC_KEY_INFO

# Struct _CERT_INFO definitions
class _CERT_INFO(Structure):
        _fields_ = [
        ("dwVersion", DWORD),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Issuer", CERT_NAME_BLOB),
        ("NotBefore", FILETIME),
        ("NotAfter", FILETIME),
        ("Subject", CERT_NAME_BLOB),
        ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
        ("IssuerUniqueId", CRYPT_BIT_BLOB),
        ("SubjectUniqueId", CRYPT_BIT_BLOB),
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
CERT_INFO = _CERT_INFO
PCERT_INFO = POINTER(_CERT_INFO)

# Struct _CERT_CONTEXT definitions
class _CERT_CONTEXT(Structure):
        _fields_ = [
        ("dwCertEncodingType", DWORD),
        ("pbCertEncoded", POINTER(BYTE)),
        ("cbCertEncoded", DWORD),
        ("pCertInfo", PCERT_INFO),
        ("hCertStore", HCERTSTORE),
    ]
CERT_CONTEXT = _CERT_CONTEXT
PCERT_CONTEXT = POINTER(_CERT_CONTEXT)

# Struct WINTRUST_SGNR_INFO_ definitions
class WINTRUST_SGNR_INFO_(Structure):
        _fields_ = [
        ("cbStruct", DWORD),
        ("pcwszDisplayName", LPCWSTR),
        ("psSignerInfo", POINTER(CMSG_SIGNER_INFO)),
        ("chStores", DWORD),
        ("pahStores", POINTER(HCERTSTORE)),
    ]
WINTRUST_SGNR_INFO = WINTRUST_SGNR_INFO_
PWINTRUST_SGNR_INFO = POINTER(WINTRUST_SGNR_INFO_)

# Struct _FILETIME definitions
class _FILETIME(Structure):
        _fields_ = [
        ("dwLowDateTime", DWORD),
        ("dwHighDateTime", DWORD),
    ]
LPFILETIME = POINTER(_FILETIME)
PFILETIME = POINTER(_FILETIME)
FILETIME = _FILETIME

# Struct WINTRUST_CERT_INFO_ definitions
class WINTRUST_CERT_INFO_(Structure):
        _fields_ = [
        ("cbStruct", DWORD),
        ("pcwszDisplayName", LPCWSTR),
        ("psCertContext", POINTER(CERT_CONTEXT)),
        ("chStores", DWORD),
        ("pahStores", POINTER(HCERTSTORE)),
        ("dwFlags", DWORD),
        ("psftVerifyAsOf", POINTER(FILETIME)),
    ]
WINTRUST_CERT_INFO = WINTRUST_CERT_INFO_
PWINTRUST_CERT_INFO = POINTER(WINTRUST_CERT_INFO_)

# Struct _TMP_WINTRUST_UNION_TYPE definitions
class _TMP_WINTRUST_UNION_TYPE(Union):
        _fields_ = [
        ("pFile", POINTER(WINTRUST_FILE_INFO_)),
        ("pCatalog", POINTER(WINTRUST_CATALOG_INFO_)),
        ("pBlob", POINTER(WINTRUST_BLOB_INFO_)),
        ("pSgnr", POINTER(WINTRUST_SGNR_INFO_)),
        ("pCert", POINTER(WINTRUST_CERT_INFO_)),
    ]
TMP_WINTRUST_UNION_TYPE = _TMP_WINTRUST_UNION_TYPE

# Struct _WINTRUST_DATA definitions
class _WINTRUST_DATA(Structure):
        _fields_ = [
        ("cbStruct", DWORD),
        ("pPolicyCallbackData", LPVOID),
        ("pSIPClientData", LPVOID),
        ("dwUIChoice", DWORD),
        ("fdwRevocationChecks", DWORD),
        ("dwUnionChoice", DWORD),
        ("tmp_union", TMP_WINTRUST_UNION_TYPE),
        ("dwStateAction", DWORD),
        ("hWVTStateData", HANDLE),
        ("pwszURLReference", POINTER(WCHAR)),
        ("dwProvFlags", DWORD),
        ("dwUIContext", DWORD),
    ]
PWINTRUST_DATA = POINTER(_WINTRUST_DATA)
WINTRUST_DATA = _WINTRUST_DATA

# Struct _PROCESS_BASIC_INFORMATION definitions
class _PROCESS_BASIC_INFORMATION(Structure):
        _fields_ = [
        ("Reserved1", PVOID),
        ("PebBaseAddress", PPEB),
        ("Reserved2", PVOID * 2),
        ("UniqueProcessId", ULONG_PTR),
        ("Reserved3", PVOID),
    ]
PPROCESS_BASIC_INFORMATION = POINTER(_PROCESS_BASIC_INFORMATION)
PROCESS_BASIC_INFORMATION = _PROCESS_BASIC_INFORMATION

# Struct _JIT_DEBUG_INFO definitions
class _JIT_DEBUG_INFO(Structure):
        _fields_ = [
        ("dwSize", DWORD),
        ("dwProcessorArchitecture", DWORD),
        ("dwThreadID", DWORD),
        ("dwReserved0", DWORD),
        ("lpExceptionAddress", ULONG64),
        ("lpExceptionRecord", ULONG64),
        ("lpContextRecord", ULONG64),
    ]
LPJIT_DEBUG_INFO = POINTER(_JIT_DEBUG_INFO)
JIT_DEBUG_INFO = _JIT_DEBUG_INFO

# Struct _SID_IDENTIFIER_AUTHORITY definitions
class _SID_IDENTIFIER_AUTHORITY(Structure):
        _fields_ = [
        ("Value", BYTE * 6),
    ]
SID_IDENTIFIER_AUTHORITY = _SID_IDENTIFIER_AUTHORITY
PSID_IDENTIFIER_AUTHORITY = POINTER(_SID_IDENTIFIER_AUTHORITY)

# Struct _EXCEPTION_DEBUG_INFO definitions
class _EXCEPTION_DEBUG_INFO(Structure):
        _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD),
    ]
LPEXCEPTION_DEBUG_INFO = POINTER(_EXCEPTION_DEBUG_INFO)
EXCEPTION_DEBUG_INFO = _EXCEPTION_DEBUG_INFO

# Struct _CREATE_THREAD_DEBUG_INFO definitions
class _CREATE_THREAD_DEBUG_INFO(Structure):
        _fields_ = [
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPTHREAD_START_ROUTINE),
    ]
LPCREATE_THREAD_DEBUG_INFO = POINTER(_CREATE_THREAD_DEBUG_INFO)
CREATE_THREAD_DEBUG_INFO = _CREATE_THREAD_DEBUG_INFO

# Struct _CREATE_PROCESS_DEBUG_INFO definitions
class _CREATE_PROCESS_DEBUG_INFO(Structure):
        _fields_ = [
        ("hFile", HANDLE),
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("lpBaseOfImage", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPTHREAD_START_ROUTINE),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]
CREATE_PROCESS_DEBUG_INFO = _CREATE_PROCESS_DEBUG_INFO
LPCREATE_PROCESS_DEBUG_INFO = POINTER(_CREATE_PROCESS_DEBUG_INFO)

# Struct _EXIT_THREAD_DEBUG_INFO definitions
class _EXIT_THREAD_DEBUG_INFO(Structure):
        _fields_ = [
        ("dwExitCode", DWORD),
    ]
EXIT_THREAD_DEBUG_INFO = _EXIT_THREAD_DEBUG_INFO
LPEXIT_THREAD_DEBUG_INFO = POINTER(_EXIT_THREAD_DEBUG_INFO)

# Struct _EXIT_PROCESS_DEBUG_INFO definitions
class _EXIT_PROCESS_DEBUG_INFO(Structure):
        _fields_ = [
        ("dwExitCode", DWORD),
    ]
LPEXIT_PROCESS_DEBUG_INFO = POINTER(_EXIT_PROCESS_DEBUG_INFO)
EXIT_PROCESS_DEBUG_INFO = _EXIT_PROCESS_DEBUG_INFO

# Struct _LOAD_DLL_DEBUG_INFO definitions
class _LOAD_DLL_DEBUG_INFO(Structure):
        _fields_ = [
        ("hFile", HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]
LPLOAD_DLL_DEBUG_INFO = POINTER(_LOAD_DLL_DEBUG_INFO)
LOAD_DLL_DEBUG_INFO = _LOAD_DLL_DEBUG_INFO

# Struct _UNLOAD_DLL_DEBUG_INFO definitions
class _UNLOAD_DLL_DEBUG_INFO(Structure):
        _fields_ = [
        ("lpBaseOfDll", LPVOID),
    ]
UNLOAD_DLL_DEBUG_INFO = _UNLOAD_DLL_DEBUG_INFO
LPUNLOAD_DLL_DEBUG_INFO = POINTER(_UNLOAD_DLL_DEBUG_INFO)

# Struct _OUTPUT_DEBUG_STRING_INFO definitions
class _OUTPUT_DEBUG_STRING_INFO(Structure):
        _fields_ = [
        ("lpDebugStringData", LPSTR),
        ("fUnicode", WORD),
        ("nDebugStringLength", WORD),
    ]
OUTPUT_DEBUG_STRING_INFO = _OUTPUT_DEBUG_STRING_INFO
LPOUTPUT_DEBUG_STRING_INFO = POINTER(_OUTPUT_DEBUG_STRING_INFO)

# Struct _RIP_INFO definitions
class _RIP_INFO(Structure):
        _fields_ = [
        ("dwError", DWORD),
        ("dwType", DWORD),
    ]
LPRIP_INFO = POINTER(_RIP_INFO)
RIP_INFO = _RIP_INFO

# Struct _TMP_UNION_DEBUG_INFO definitions
class _TMP_UNION_DEBUG_INFO(Union):
        _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]
TMP_UNION_DEBUG_INFO = _TMP_UNION_DEBUG_INFO

# Struct _DEBUG_EVENT definitions
class _DEBUG_EVENT(Structure):
        _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", _TMP_UNION_DEBUG_INFO),
    ]
LPDEBUG_EVENT = POINTER(_DEBUG_EVENT)
DEBUG_EVENT = _DEBUG_EVENT

