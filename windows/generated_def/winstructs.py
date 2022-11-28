from .windef import *
import windows # Allow extended-struct to use windows/winproxy/...
from ctypes import *
from ctypes.wintypes import *

from .flag import Flag, FlagMapper, FlagExatractor

class EnumValue(Flag):
    def __new__(cls, enum_name, name, value):
        return super(EnumValue, cls).__new__(cls, name, value)

    def __init__(self, enum_name, name, value):
        self.enum_name = enum_name
        self.name = name

    def __repr__(self):
        return "{0}.{1}({2})".format(self.enum_name, self.name, hex(self))

    # Fix pickling with protocol 2
    def __getnewargs__(self, *args):
        return self.enum_name, self.name, int(self)

# Bypass bug https://bugs.python.org/issue29270

super_noissue = super

class EnumType(DWORD):
    values = ()
    mapper = {}

    @property
    def value(self):
        raw_value = super_noissue(EnumType, self).value
        return self.mapper.get(raw_value, raw_value)

    def __repr__(self):
        raw_value = super_noissue(EnumType, self).value
        if raw_value in self.values:
            value = self.value
            return "<{0} {1}({2})>".format(type(self).__name__, value.name, hex(raw_value))
        return "<{0}({1})>".format(type(self).__name__, hex(self.value))

# Sale: windef is hardcoded
from . import windef
SZOID_MAPPER = FlagMapper(*(getattr(windef, x) for x in dir(windef) if x.startswith("szOID")))
class _CRYPTPROTECT_PROMPTSTRUCT(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwPromptFlags", DWORD),
        ("hwndApp", HWND),
        ("szPrompt", LPCWSTR),
    ]
CRYPTPROTECT_PROMPTSTRUCT = _CRYPTPROTECT_PROMPTSTRUCT
PCRYPTPROTECT_PROMPTSTRUCT = POINTER(_CRYPTPROTECT_PROMPTSTRUCT)

VOID = DWORD
BYTE = c_ubyte
PWSTR = LPWSTR
PCWSTR = LPWSTR
SIZE_T = c_size_t
PSIZE_T = POINTER(SIZE_T)
PVOID = c_void_p
NTSTATUS = DWORD
TDHSTATUS = ULONG
DNS_STATUS = ULONG
LSTATUS = LONG#Registryfunctionsreturnvalue|typedef_Return_type_success_(return==ERROR_SUCCESS)LONGLSTATUS;
SECURITY_INFORMATION = DWORD
PSECURITY_INFORMATION = POINTER(SECURITY_INFORMATION)
PULONG = POINTER(ULONG)
PDWORD = POINTER(DWORD)
LPDWORD = POINTER(DWORD)
LPBYTE = POINTER(BYTE)
ULONG_PTR = PVOID
LONG_PTR = PVOID
DWORD_PTR = ULONG_PTR
PDWORD_PTR = POINTER(DWORD_PTR)
KAFFINITY = ULONG_PTR
KPRIORITY = LONG
INTERNET_PORT = WORD
CHAR = c_char
PCHAR = POINTER(CHAR)
UCHAR = c_char
CSHORT = c_short
VARTYPE = c_ushort
PUSHORT = POINTER(USHORT)
PBOOL = POINTER(BOOL)
LPBOOL = PBOOL
PSTR = LPSTR
PCSTR = LPSTR
va_list = c_char_p
LPCH = c_char_p
LPWCH = c_wchar
BSTR = c_wchar_p
OLECHAR = c_wchar
POLECHAR = c_wchar_p
PZZWSTR = c_wchar_p
PUCHAR = POINTER(UCHAR)
double = c_double
DATE = double
ULONGLONG = c_ulonglong
PULONGLONG = POINTER(ULONGLONG)
LONGLONG = c_longlong
ULONG64 = c_ulonglong
UINT64 = ULONG64
LONG64 = c_longlong
PLARGE_INTEGER = POINTER(LARGE_INTEGER)
DWORD64 = ULONG64
PDWORD64 = POINTER(DWORD64)
DWORDLONG = ULONGLONG
SCODE = LONG
CIMTYPE = LONG
NET_IFINDEX = ULONG
IF_INDEX = NET_IFINDEX
IFTYPE = ULONG
PLONG64 = POINTER(LONG64)
PULONG64 = POINTER(ULONG64)
PBYTE = POINTER(BYTE)
PUINT = POINTER(UINT)
PHKEY = POINTER(HKEY)
ACCESS_MASK = DWORD
REGSAM = ACCESS_MASK
PBOOLEAN = POINTER(BOOLEAN)
SECURITY_CONTEXT_TRACKING_MODE = BOOLEAN
HCRYPTPROV_LEGACY = PULONG
HCRYPTKEY = PULONG
HCRYPTPROV = PULONG
HCRYPTHASH = PULONG
ALG_ID = UINT
DISPID = LONG
MEMBERID = DISPID
LRESULT = LONG_PTR
LPUNKNOWN = POINTER(PVOID)
LPPOINT = POINTER(POINT)
LPRECT = POINTER(RECT)
SPC_UUID = BYTE*16
DEVICE_TYPE = DWORD
PWINDBG_EXTENSION_APIS32 = PVOID
PWINDBG_EXTENSION_APIS64 = PVOID
FILEOP_FLAGS = WORD
NET_API_STATUS = DWORD
NCRYPT_HANDLE = ULONG_PTR
NCRYPT_PROV_HANDLE = ULONG_PTR
NCRYPT_KEY_HANDLE = ULONG_PTR
NCRYPT_HASH_HANDLE = ULONG_PTR
NCRYPT_SECRET_HANDLE = ULONG_PTR
TRACEHANDLE = ULONG64
PTRACEHANDLE = POINTER(TRACEHANDLE)
PIMAGEHLP_CONTEXT = PVOID
INT8 = c_byte
INT16 = SHORT
INT32 = INT
INT64 = LONGLONG
UINT8 = BYTE
UINT16 = USHORT
UINT32 = UINT
UINT64 = ULONGLONG
ULONG32 = UINT32
LONG32 = INT32
PHANDLE = POINTER(HANDLE)
HCATADMIN = HANDLE
HCATINFO = HANDLE
HCERTCHAINENGINE = HANDLE
LPHANDLE = POINTER(HANDLE)
ALPC_HANDLE = HANDLE
PALPC_HANDLE = POINTER(ALPC_HANDLE)
HCURSOR = HANDLE
HBRUSH = HANDLE
HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = PULONG
EVT_HANDLE = HANDLE
EVT_OBJECT_ARRAY_PROPERTY_HANDLE = HANDLE
LSA_HANDLE = HANDLE
PLSA_HANDLE = POINTER(LSA_HANDLE)
HDSKSPC = HANDLE
HDEVINFO = HANDLE
HINTERNET = PVOID
IP4_ADDRESS = DWORD
PSECURITY_DESCRIPTOR = PVOID
SECURITY_DESCRIPTOR_CONTROL = WORD
PSECURITY_DESCRIPTOR_CONTROL = POINTER(SECURITY_DESCRIPTOR_CONTROL)
ACCESS_MASK = DWORD
PACCESS_MASK = POINTER(ACCESS_MASK)
SECURITY_INFORMATION = DWORD
PSECURITY_INFORMATION = POINTER(SECURITY_INFORMATION)
PSECURITY_ATTRIBUTES_OPAQUE = PVOID
SID_HASH_ENTRY = ULONG_PTR
PSID_HASH_ENTRY = POINTER(SID_HASH_ENTRY)
PSID = PVOID
_INITIAL_PSID = PSID
class PSID(_INITIAL_PSID): # _INITIAL_PSID -> PVOID

    def __eq__(self, other):
        return bool(windows.winproxy.EqualSid(self, other))

    def __ne__(self, other):
        return not windows.winproxy.EqualSid(self, other)

    @property
    def size(self):
        return windows.winproxy.GetLengthSid(self)

    def duplicate(self):
        size = self.size
        buffer = ctypes.c_buffer(size)
        windows.winproxy.CopySid(size, buffer, self)
        return ctypes.cast(buffer, type(self))

    @classmethod
    def from_string(cls, strsid):
        self = cls()
        if not isinstance(strsid, bytes):
            strsid = strsid.encode("ascii")
        # Pass to ConvertStringSidToSidW ?
        windows.winproxy.ConvertStringSidToSidA(strsid, self)
        return self

    def to_string(self):
       sid_str  = LPCSTR()
       windows.winproxy.ConvertSidToStringSidA(self, sid_str)
       result = sid_str.value.decode("ascii") # ConvertSidToStringSidW ?
       windows.winproxy.LocalFree(sid_str)
       return result

    __str__ = to_string

    def __repr__(self):
        try:
            return """<{0} "{1}">""".format(type(self).__name__, self.to_string())
        except WindowsError: # Case of PSID is not valide
            if not self:
                return """<{0} (NULL) at {1:#x}>""".format(type(self).__name__, id(self))
            return """<{0} "<conversion-failed>" at {1:#x}>""".format(type(self).__name__, id(self))

    __sprint__ = __repr__

CONFIGRET = DWORD
DEVNODE = DWORD
DEVINST = DWORD
PDEVNODE = POINTER(DEVNODE)
PDEVINST = POINTER(DEVINST)
PRIORITY = ULONG
PPRIORITY = POINTER(PRIORITY)
RES_DES = DWORD_PTR
PRES_DES = POINTER(RES_DES)
HMACHINE = HANDLE
PHMACHINE = POINTER(HMACHINE)
LOG_CONF = DWORD_PTR
PLOG_CONF = POINTER(LOG_CONF)
RESOURCEID = ULONG
PRESOURCEID = POINTER(RESOURCEID)
DEVNODEID_A = PCSTR
DEVINSTID_A = PCSTR
DEVNODEID_W = LPWSTR
DEVINSTID_W = LPWSTR
RPCOLEDATAREP = ULONG
HREFTYPE = DWORD
SFGAOF = ULONG
GROUP = UINT
SOCKET = HANDLE
WNDPROC = PVOID
LPPROC_THREAD_ATTRIBUTE_LIST = PVOID
PPS_POST_PROCESS_INIT_ROUTINE = PVOID
LPTHREAD_START_ROUTINE = PVOID
WNDENUMPROC = PVOID
PHANDLER_ROUTINE = PVOID
FARPROC = PVOID
PIO_APC_ROUTINE = PVOID
PVECTORED_EXCEPTION_HANDLER = PVOID
PFN_CRYPT_GET_SIGNER_CERTIFICATE = PVOID
PSYM_ENUMERATESYMBOLS_CALLBACK = PVOID
PSYM_ENUMERATESYMBOLS_CALLBACKW = PVOID
PEVENT_CALLBACK = PVOID
PEVENT_TRACE_BUFFER_CALLBACKA = PVOID
PEVENT_TRACE_BUFFER_CALLBACKW = PVOID
PEVENT_RECORD_CALLBACK = PVOID
PFN_CRYPT_ENUM_OID_FUNC = PVOID
PGET_MODULE_BASE_ROUTINE64 = PVOID#StackWalk
PGET_MODULE_BASE_ROUTINE = PVOID#StackWalk
PREAD_PROCESS_MEMORY_ROUTINE = PVOID#StackWalk
PREAD_PROCESS_MEMORY_ROUTINE64 = PVOID#StackWalk
PFUNCTION_TABLE_ACCESS_ROUTINE = PVOID#StackWalk
PFUNCTION_TABLE_ACCESS_ROUTINE64 = PVOID#StackWalk
PTRANSLATE_ADDRESS_ROUTINE = PVOID#StackWalk
PTRANSLATE_ADDRESS_ROUTINE64 = PVOID#StackWalk
PSYMBOL_REGISTERED_CALLBACK64 = PVOID#Symbols
PSYMBOL_REGISTERED_CALLBACK = PVOID#Symbols
PSYM_ENUMPROCESSES_CALLBACK = PVOID#Symbols
ENUMRESNAMEPROCA = PVOID#Resources
ENUMRESNAMEPROCW = PVOID#Resources
ENUMRESTYPEPROCA = PVOID#Resources
ENUMRESTYPEPROCW = PVOID#Resources
LPSERVICE_MAIN_FUNCTIONA = PVOID
LPSERVICE_MAIN_FUNCTIONW = PVOID
LPOVERLAPPED_COMPLETION_ROUTINE = PVOID
PDNS_QUERY_COMPLETION_ROUTINE = PVOID
LPCONTEXT = PVOID
HCERTSTORE = PVOID
HCRYPTMSG = PVOID
PALPC_PORT_ATTRIBUTES = PVOID
PPORT_MESSAGE = PVOID
LPWSADATA = PVOID
FC_ZERO = EnumValue("NDR_FORMAT_CHARACTER", "FC_ZERO", 0x0)
FC_BYTE = EnumValue("NDR_FORMAT_CHARACTER", "FC_BYTE", 0x1)
FC_CHAR = EnumValue("NDR_FORMAT_CHARACTER", "FC_CHAR", 0x2)
FC_SMALL = EnumValue("NDR_FORMAT_CHARACTER", "FC_SMALL", 0x3)
FC_USMALL = EnumValue("NDR_FORMAT_CHARACTER", "FC_USMALL", 0x4)
FC_WCHAR = EnumValue("NDR_FORMAT_CHARACTER", "FC_WCHAR", 0x5)
FC_SHORT = EnumValue("NDR_FORMAT_CHARACTER", "FC_SHORT", 0x6)
FC_USHORT = EnumValue("NDR_FORMAT_CHARACTER", "FC_USHORT", 0x7)
FC_LONG = EnumValue("NDR_FORMAT_CHARACTER", "FC_LONG", 0x8)
FC_ULONG = EnumValue("NDR_FORMAT_CHARACTER", "FC_ULONG", 0x9)
FC_FLOAT = EnumValue("NDR_FORMAT_CHARACTER", "FC_FLOAT", 0xa)
FC_HYPER = EnumValue("NDR_FORMAT_CHARACTER", "FC_HYPER", 0xb)
FC_DOUBLE = EnumValue("NDR_FORMAT_CHARACTER", "FC_DOUBLE", 0xc)
FC_ENUM16 = EnumValue("NDR_FORMAT_CHARACTER", "FC_ENUM16", 0xd)
FC_ENUM32 = EnumValue("NDR_FORMAT_CHARACTER", "FC_ENUM32", 0xe)
FC_IGNORE = EnumValue("NDR_FORMAT_CHARACTER", "FC_IGNORE", 0xf)
FC_ERROR_STATUS_T = EnumValue("NDR_FORMAT_CHARACTER", "FC_ERROR_STATUS_T", 0x10)
FC_RP = EnumValue("NDR_FORMAT_CHARACTER", "FC_RP", 0x11)
FC_UP = EnumValue("NDR_FORMAT_CHARACTER", "FC_UP", 0x12)
FC_OP = EnumValue("NDR_FORMAT_CHARACTER", "FC_OP", 0x13)
FC_FP = EnumValue("NDR_FORMAT_CHARACTER", "FC_FP", 0x14)
FC_STRUCT = EnumValue("NDR_FORMAT_CHARACTER", "FC_STRUCT", 0x15)
FC_PSTRUCT = EnumValue("NDR_FORMAT_CHARACTER", "FC_PSTRUCT", 0x16)
FC_CSTRUCT = EnumValue("NDR_FORMAT_CHARACTER", "FC_CSTRUCT", 0x17)
FC_CPSTRUCT = EnumValue("NDR_FORMAT_CHARACTER", "FC_CPSTRUCT", 0x18)
FC_CVSTRUCT = EnumValue("NDR_FORMAT_CHARACTER", "FC_CVSTRUCT", 0x19)
FC_BOGUS_STRUCT = EnumValue("NDR_FORMAT_CHARACTER", "FC_BOGUS_STRUCT", 0x1a)
FC_CARRAY = EnumValue("NDR_FORMAT_CHARACTER", "FC_CARRAY", 0x1b)
FC_CVARRAY = EnumValue("NDR_FORMAT_CHARACTER", "FC_CVARRAY", 0x1c)
FC_SMFARRAY = EnumValue("NDR_FORMAT_CHARACTER", "FC_SMFARRAY", 0x1d)
FC_LGFARRAY = EnumValue("NDR_FORMAT_CHARACTER", "FC_LGFARRAY", 0x1e)
FC_SMVARRAY = EnumValue("NDR_FORMAT_CHARACTER", "FC_SMVARRAY", 0x1f)
FC_LGVARRAY = EnumValue("NDR_FORMAT_CHARACTER", "FC_LGVARRAY", 0x20)
FC_BOGUS_ARRAY = EnumValue("NDR_FORMAT_CHARACTER", "FC_BOGUS_ARRAY", 0x21)
FC_C_CSTRING = EnumValue("NDR_FORMAT_CHARACTER", "FC_C_CSTRING", 0x22)
FC_C_BSTRING = EnumValue("NDR_FORMAT_CHARACTER", "FC_C_BSTRING", 0x23)
FC_C_SSTRING = EnumValue("NDR_FORMAT_CHARACTER", "FC_C_SSTRING", 0x24)
FC_C_WSTRING = EnumValue("NDR_FORMAT_CHARACTER", "FC_C_WSTRING", 0x25)
FC_CSTRING = EnumValue("NDR_FORMAT_CHARACTER", "FC_CSTRING", 0x26)
FC_BSTRING = EnumValue("NDR_FORMAT_CHARACTER", "FC_BSTRING", 0x27)
FC_SSTRING = EnumValue("NDR_FORMAT_CHARACTER", "FC_SSTRING", 0x28)
FC_WSTRING = EnumValue("NDR_FORMAT_CHARACTER", "FC_WSTRING", 0x29)
FC_ENCAPSULATED_UNION = EnumValue("NDR_FORMAT_CHARACTER", "FC_ENCAPSULATED_UNION", 0x2a)
FC_NON_ENCAPSULATED_UNION = EnumValue("NDR_FORMAT_CHARACTER", "FC_NON_ENCAPSULATED_UNION", 0x2b)
FC_BYTE_COUNT_POINTER = EnumValue("NDR_FORMAT_CHARACTER", "FC_BYTE_COUNT_POINTER", 0x2c)
FC_TRANSMIT_AS = EnumValue("NDR_FORMAT_CHARACTER", "FC_TRANSMIT_AS", 0x2d)
FC_REPRESENT_AS = EnumValue("NDR_FORMAT_CHARACTER", "FC_REPRESENT_AS", 0x2e)
FC_IP = EnumValue("NDR_FORMAT_CHARACTER", "FC_IP", 0x2f)
FC_BIND_CONTEXT = EnumValue("NDR_FORMAT_CHARACTER", "FC_BIND_CONTEXT", 0x30)
FC_BIND_GENERIC = EnumValue("NDR_FORMAT_CHARACTER", "FC_BIND_GENERIC", 0x31)
FC_BIND_PRIMITIVE = EnumValue("NDR_FORMAT_CHARACTER", "FC_BIND_PRIMITIVE", 0x32)
FC_AUTO_HANDLE = EnumValue("NDR_FORMAT_CHARACTER", "FC_AUTO_HANDLE", 0x33)
FC_CALLBACK_HANDLE = EnumValue("NDR_FORMAT_CHARACTER", "FC_CALLBACK_HANDLE", 0x34)
FC_UNUSED1 = EnumValue("NDR_FORMAT_CHARACTER", "FC_UNUSED1", 0x35)
FC_POINTER = EnumValue("NDR_FORMAT_CHARACTER", "FC_POINTER", 0x36)
FC_ALIGNM2 = EnumValue("NDR_FORMAT_CHARACTER", "FC_ALIGNM2", 0x37)
FC_ALIGNM4 = EnumValue("NDR_FORMAT_CHARACTER", "FC_ALIGNM4", 0x38)
FC_ALIGNM8 = EnumValue("NDR_FORMAT_CHARACTER", "FC_ALIGNM8", 0x39)
FC_UNUSED2 = EnumValue("NDR_FORMAT_CHARACTER", "FC_UNUSED2", 0x3a)
FC_UNUSED3 = EnumValue("NDR_FORMAT_CHARACTER", "FC_UNUSED3", 0x3b)
FC_UNUSED4 = EnumValue("NDR_FORMAT_CHARACTER", "FC_UNUSED4", 0x3c)
FC_STRUCTPAD1 = EnumValue("NDR_FORMAT_CHARACTER", "FC_STRUCTPAD1", 0x3d)
FC_STRUCTPAD2 = EnumValue("NDR_FORMAT_CHARACTER", "FC_STRUCTPAD2", 0x3e)
FC_STRUCTPAD3 = EnumValue("NDR_FORMAT_CHARACTER", "FC_STRUCTPAD3", 0x3f)
FC_STRUCTPAD4 = EnumValue("NDR_FORMAT_CHARACTER", "FC_STRUCTPAD4", 0x40)
FC_STRUCTPAD5 = EnumValue("NDR_FORMAT_CHARACTER", "FC_STRUCTPAD5", 0x41)
FC_STRUCTPAD6 = EnumValue("NDR_FORMAT_CHARACTER", "FC_STRUCTPAD6", 0x42)
FC_STRUCTPAD7 = EnumValue("NDR_FORMAT_CHARACTER", "FC_STRUCTPAD7", 0x43)
FC_STRING_SIZED = EnumValue("NDR_FORMAT_CHARACTER", "FC_STRING_SIZED", 0x44)
FC_UNUSED5 = EnumValue("NDR_FORMAT_CHARACTER", "FC_UNUSED5", 0x45)
FC_NO_REPEAT = EnumValue("NDR_FORMAT_CHARACTER", "FC_NO_REPEAT", 0x46)
FC_FIXED_REPEAT = EnumValue("NDR_FORMAT_CHARACTER", "FC_FIXED_REPEAT", 0x47)
FC_VARIABLE_REPEAT = EnumValue("NDR_FORMAT_CHARACTER", "FC_VARIABLE_REPEAT", 0x48)
FC_FIXED_OFFSET = EnumValue("NDR_FORMAT_CHARACTER", "FC_FIXED_OFFSET", 0x49)
FC_VARIABLE_OFFSET = EnumValue("NDR_FORMAT_CHARACTER", "FC_VARIABLE_OFFSET", 0x4a)
FC_PP = EnumValue("NDR_FORMAT_CHARACTER", "FC_PP", 0x4b)
FC_EMBEDDED_COMPLEX = EnumValue("NDR_FORMAT_CHARACTER", "FC_EMBEDDED_COMPLEX", 0x4c)
FC_IN_PARAM = EnumValue("NDR_FORMAT_CHARACTER", "FC_IN_PARAM", 0x4d)
FC_IN_PARAM_BASETYPE = EnumValue("NDR_FORMAT_CHARACTER", "FC_IN_PARAM_BASETYPE", 0x4e)
FC_IN_PARAM_NO_FREE_INST = EnumValue("NDR_FORMAT_CHARACTER", "FC_IN_PARAM_NO_FREE_INST", 0x4f)
FC_IN_OUT_PARAM = EnumValue("NDR_FORMAT_CHARACTER", "FC_IN_OUT_PARAM", 0x50)
FC_OUT_PARAM = EnumValue("NDR_FORMAT_CHARACTER", "FC_OUT_PARAM", 0x51)
FC_RETURN_PARAM = EnumValue("NDR_FORMAT_CHARACTER", "FC_RETURN_PARAM", 0x52)
FC_RETURN_PARAM_BASETYPE = EnumValue("NDR_FORMAT_CHARACTER", "FC_RETURN_PARAM_BASETYPE", 0x53)
FC_DEREFERENCE = EnumValue("NDR_FORMAT_CHARACTER", "FC_DEREFERENCE", 0x54)
FC_DIV_2 = EnumValue("NDR_FORMAT_CHARACTER", "FC_DIV_2", 0x55)
FC_MULT_2 = EnumValue("NDR_FORMAT_CHARACTER", "FC_MULT_2", 0x56)
FC_ADD_1 = EnumValue("NDR_FORMAT_CHARACTER", "FC_ADD_1", 0x57)
FC_SUB_1 = EnumValue("NDR_FORMAT_CHARACTER", "FC_SUB_1", 0x58)
FC_CALLBACK = EnumValue("NDR_FORMAT_CHARACTER", "FC_CALLBACK", 0x59)
FC_CONSTANT_IID = EnumValue("NDR_FORMAT_CHARACTER", "FC_CONSTANT_IID", 0x5a)
FC_END = EnumValue("NDR_FORMAT_CHARACTER", "FC_END", 0x5b)
FC_PAD = EnumValue("NDR_FORMAT_CHARACTER", "FC_PAD", 0x5c)
FC_SPLIT_DEREFERENCE = EnumValue("NDR_FORMAT_CHARACTER", "FC_SPLIT_DEREFERENCE", 0x74)
FC_SPLIT_DIV_2 = EnumValue("NDR_FORMAT_CHARACTER", "FC_SPLIT_DIV_2", 0x75)
FC_SPLIT_MULT_2 = EnumValue("NDR_FORMAT_CHARACTER", "FC_SPLIT_MULT_2", 0x76)
FC_SPLIT_ADD_1 = EnumValue("NDR_FORMAT_CHARACTER", "FC_SPLIT_ADD_1", 0x77)
FC_SPLIT_SUB_1 = EnumValue("NDR_FORMAT_CHARACTER", "FC_SPLIT_SUB_1", 0x78)
FC_SPLIT_CALLBACK = EnumValue("NDR_FORMAT_CHARACTER", "FC_SPLIT_CALLBACK", 0x79)
FC_HARD_STRUCT = EnumValue("NDR_FORMAT_CHARACTER", "FC_HARD_STRUCT", 0xb1)
FC_TRANSMIT_AS_PTR = EnumValue("NDR_FORMAT_CHARACTER", "FC_TRANSMIT_AS_PTR", 0xb2)
FC_REPRESENT_AS_PTR = EnumValue("NDR_FORMAT_CHARACTER", "FC_REPRESENT_AS_PTR", 0xb3)
FC_USER_MARSHAL = EnumValue("NDR_FORMAT_CHARACTER", "FC_USER_MARSHAL", 0xb4)
FC_PIPE = EnumValue("NDR_FORMAT_CHARACTER", "FC_PIPE", 0xb5)
FC_BLKHOLE = EnumValue("NDR_FORMAT_CHARACTER", "FC_BLKHOLE", 0xb6)
FC_RANGE = EnumValue("NDR_FORMAT_CHARACTER", "FC_RANGE", 0xb7)
FC_INT3264 = EnumValue("NDR_FORMAT_CHARACTER", "FC_INT3264", 0xb8)
FC_UINT3264 = EnumValue("NDR_FORMAT_CHARACTER", "FC_UINT3264", 0xb9)
FC_END_OF_UNIVERSE = EnumValue("NDR_FORMAT_CHARACTER", "FC_END_OF_UNIVERSE", 0xba)
class NDR_FORMAT_CHARACTER(EnumType):
    values = [FC_ZERO, FC_BYTE, FC_CHAR, FC_SMALL, FC_USMALL, FC_WCHAR, FC_SHORT, FC_USHORT, FC_LONG, FC_ULONG, FC_FLOAT, FC_HYPER, FC_DOUBLE, FC_ENUM16, FC_ENUM32, FC_IGNORE, FC_ERROR_STATUS_T, FC_RP, FC_UP, FC_OP, FC_FP, FC_STRUCT, FC_PSTRUCT, FC_CSTRUCT, FC_CPSTRUCT, FC_CVSTRUCT, FC_BOGUS_STRUCT, FC_CARRAY, FC_CVARRAY, FC_SMFARRAY, FC_LGFARRAY, FC_SMVARRAY, FC_LGVARRAY, FC_BOGUS_ARRAY, FC_C_CSTRING, FC_C_BSTRING, FC_C_SSTRING, FC_C_WSTRING, FC_CSTRING, FC_BSTRING, FC_SSTRING, FC_WSTRING, FC_ENCAPSULATED_UNION, FC_NON_ENCAPSULATED_UNION, FC_BYTE_COUNT_POINTER, FC_TRANSMIT_AS, FC_REPRESENT_AS, FC_IP, FC_BIND_CONTEXT, FC_BIND_GENERIC, FC_BIND_PRIMITIVE, FC_AUTO_HANDLE, FC_CALLBACK_HANDLE, FC_UNUSED1, FC_POINTER, FC_ALIGNM2, FC_ALIGNM4, FC_ALIGNM8, FC_UNUSED2, FC_UNUSED3, FC_UNUSED4, FC_STRUCTPAD1, FC_STRUCTPAD2, FC_STRUCTPAD3, FC_STRUCTPAD4, FC_STRUCTPAD5, FC_STRUCTPAD6, FC_STRUCTPAD7, FC_STRING_SIZED, FC_UNUSED5, FC_NO_REPEAT, FC_FIXED_REPEAT, FC_VARIABLE_REPEAT, FC_FIXED_OFFSET, FC_VARIABLE_OFFSET, FC_PP, FC_EMBEDDED_COMPLEX, FC_IN_PARAM, FC_IN_PARAM_BASETYPE, FC_IN_PARAM_NO_FREE_INST, FC_IN_OUT_PARAM, FC_OUT_PARAM, FC_RETURN_PARAM, FC_RETURN_PARAM_BASETYPE, FC_DEREFERENCE, FC_DIV_2, FC_MULT_2, FC_ADD_1, FC_SUB_1, FC_CALLBACK, FC_CONSTANT_IID, FC_END, FC_PAD, FC_SPLIT_DEREFERENCE, FC_SPLIT_DIV_2, FC_SPLIT_MULT_2, FC_SPLIT_ADD_1, FC_SPLIT_SUB_1, FC_SPLIT_CALLBACK, FC_HARD_STRUCT, FC_TRANSMIT_AS_PTR, FC_REPRESENT_AS_PTR, FC_USER_MARSHAL, FC_PIPE, FC_BLKHOLE, FC_RANGE, FC_INT3264, FC_UINT3264, FC_END_OF_UNIVERSE]
    mapper = FlagMapper(*values)


BG_AUTH_SCHEME_BASIC = EnumValue("__MIDL_IBackgroundCopyJob2_0002", "BG_AUTH_SCHEME_BASIC", 0x0)
BG_AUTH_SCHEME_DIGEST = EnumValue("__MIDL_IBackgroundCopyJob2_0002", "BG_AUTH_SCHEME_DIGEST", 0x1)
BG_AUTH_SCHEME_NTLM = EnumValue("__MIDL_IBackgroundCopyJob2_0002", "BG_AUTH_SCHEME_NTLM", 0x2)
BG_AUTH_SCHEME_NEGOTIATE = EnumValue("__MIDL_IBackgroundCopyJob2_0002", "BG_AUTH_SCHEME_NEGOTIATE", 0x3)
BG_AUTH_SCHEME_PASSPORT = EnumValue("__MIDL_IBackgroundCopyJob2_0002", "BG_AUTH_SCHEME_PASSPORT", 0x4)
class __MIDL_IBackgroundCopyJob2_0002(EnumType):
    values = [BG_AUTH_SCHEME_BASIC, BG_AUTH_SCHEME_DIGEST, BG_AUTH_SCHEME_NTLM, BG_AUTH_SCHEME_NEGOTIATE, BG_AUTH_SCHEME_PASSPORT]
    mapper = FlagMapper(*values)
BG_AUTH_SCHEME = __MIDL_IBackgroundCopyJob2_0002


BG_AUTH_TARGET_SERVER = EnumValue("__MIDL_IBackgroundCopyJob2_0001", "BG_AUTH_TARGET_SERVER", 0x0)
BG_AUTH_TARGET_PROXY = EnumValue("__MIDL_IBackgroundCopyJob2_0001", "BG_AUTH_TARGET_PROXY", 0x1)
class __MIDL_IBackgroundCopyJob2_0001(EnumType):
    values = [BG_AUTH_TARGET_SERVER, BG_AUTH_TARGET_PROXY]
    mapper = FlagMapper(*values)
BG_AUTH_TARGET = __MIDL_IBackgroundCopyJob2_0001


class __MIDL_IBackgroundCopyJob2_0003(Structure):
    _fields_ = [
        ("UserName", LPWSTR),
        ("Password", LPWSTR),
    ]
BG_BASIC_CREDENTIALS = __MIDL_IBackgroundCopyJob2_0003

class __MIDL_IBackgroundCopyJob2_0004(Union):
    _fields_ = [
        ("Basic", BG_BASIC_CREDENTIALS),
    ]
BG_AUTH_CREDENTIALS_UNION = __MIDL_IBackgroundCopyJob2_0004

class BG_AUTH_CREDENTIALS(Structure):
    _fields_ = [
        ("Target", BG_AUTH_TARGET),
        ("Scheme", BG_AUTH_SCHEME),
        ("Credentials", BG_AUTH_CREDENTIALS_UNION),
    ]


class _BG_JOB_REPLY_PROGRESS(Structure):
    _fields_ = [
        ("BytesTotal", UINT64),
        ("BytesTransferred", UINT64),
    ]
BG_JOB_REPLY_PROGRESS = _BG_JOB_REPLY_PROGRESS

class _BG_FILE_RANGE(Structure):
    _fields_ = [
        ("InitialOffset", UINT64),
        ("Length", UINT64),
    ]
BG_FILE_RANGE = _BG_FILE_RANGE

class _GUID(Structure):
    _fields_ = [
        ("Data1", ULONG),
        ("Data2", USHORT),
        ("Data3", USHORT),
        ("Data4", BYTE * (8)),
    ]
REFCLSID = POINTER(_GUID)
LPCGUID = POINTER(_GUID)
REFGUID = POINTER(_GUID)
LPGUID = POINTER(_GUID)
IID = _GUID
CLSID = _GUID
LPCLSID = POINTER(_GUID)
GUID = _GUID
REFIID = POINTER(_GUID)

INITIAL_GUID = _GUID
class _GUID(INITIAL_GUID):
    def __init__(self, Data1=None, Data2=None, Data3=None, Data4=None, name=None, strid=None):
        data_tuple = (Data1, Data2, Data3, Data4)
        self.name = name
        self.strid = strid
        if all(data is None for data in data_tuple):
            return super(_GUID, self).__init__()
        if any(data is None for data in data_tuple):
            raise ValueError("All or none of (Data1, Data2, Data3, Data4) should be None")
        super(_GUID, self).__init__(Data1, Data2, Data3, Data4)

    def __repr__(self):
        notpresent = object()
        # Handle IID created without '__init__' (like ctypes-ptr deref)
        if getattr(self, "strid", notpresent) is notpresent:
            self.strid = self.to_string()
        if self.strid is None:
            return super(_GUID, self).__repr__()

        if getattr(self, "name", notpresent) is notpresent:
            self.name = None
        if self.name is None:
            return '<GUID "{0}">'.format(self.strid.upper())
        return '<GUID "{0}({1})">'.format(self.strid.upper(), self.name)

    __sprint__ = __repr__


    def to_string(self):
        data4_format = "{0:02X}{1:02X}-" + "".join("{{{i}:02X}}".format(i=i + 2) for i in range(6))
        data4_str = data4_format.format(*self.Data4)
        return "{0:08X}-{1:04X}-{2:04X}-".format(self.Data1, self.Data2, self.Data3) + data4_str

    __str__ = to_string

    def update_strid(self):
       new_strid = self.to_string()
       self.strid = new_strid

    @classmethod
    def from_string(cls, iid):
        part_iid = iid.split("-")
        datas = [int(x, 16) for x in part_iid[:3]]
        datas.append(int(part_iid[3][:2], 16))
        datas.append(int(part_iid[3][2:], 16))
        for i in range(6):
            datas.append(int(part_iid[4][i * 2:(i + 1) * 2], 16))
        return cls.from_raw(*datas, strid=iid)


    @classmethod
    def from_raw(cls, Data1, Data2, Data3, Data41, Data42, Data43, Data44, Data45, Data46, Data47, Data48, **kwargs):
        return cls(Data1, Data2, Data3,  (BYTE*8)(Data41, Data42, Data43, Data44, Data45, Data46, Data47, Data48), **kwargs)

    def __eq__(self, other):
        if not isinstance(other, (_GUID, INITIAL_GUID)):
            return NotImplemented
        return (self.Data1, self.Data2, self.Data3, self.Data4[:]) == (other.Data1, other.Data2, other.Data3, other.Data4[:])

REFCLSID = POINTER(_GUID)
LPCGUID = POINTER(_GUID)
REFGUID = POINTER(_GUID)
LPGUID = POINTER(_GUID)
IID = _GUID
CLSID = _GUID
LPCLSID = POINTER(_GUID)
GUID = _GUID
REFIID = POINTER(_GUID)
class IO_Des_s(Structure):
    _fields_ = [
        ("IOD_Count", DWORD),
        ("IOD_Type", DWORD),
        ("IOD_Alloc_Base", DWORDLONG),
        ("IOD_Alloc_End", DWORDLONG),
        ("IOD_DesFlags", DWORD),
    ]
PIO_DES = POINTER(IO_Des_s)
IO_DES = IO_Des_s

class IO_Range_s(Structure):
    _fields_ = [
        ("IOR_Align", DWORDLONG),
        ("IOR_nPorts", DWORD),
        ("IOR_Min", DWORDLONG),
        ("IOR_Max", DWORDLONG),
        ("IOR_RangeFlags", DWORD),
        ("IOR_Alias", DWORDLONG),
    ]
IO_RANGE = IO_Range_s
PIO_RANGE = POINTER(IO_Range_s)

class Mem_Des_s(Structure):
    _fields_ = [
        ("MD_Count", DWORD),
        ("MD_Type", DWORD),
        ("MD_Alloc_Base", DWORDLONG),
        ("MD_Alloc_End", DWORDLONG),
        ("MD_Flags", DWORD),
        ("MD_Reserved", DWORD),
    ]
MEM_DES = Mem_Des_s
PMEM_DES = POINTER(Mem_Des_s)

class Mem_Range_s(Structure):
    _fields_ = [
        ("MR_Align", DWORDLONG),
        ("MR_nBytes", ULONG),
        ("MR_Min", DWORDLONG),
        ("MR_Max", DWORDLONG),
        ("MR_Flags", DWORD),
        ("MR_Reserved", DWORD),
    ]
MEM_RANGE = Mem_Range_s
PMEM_RANGE = POINTER(Mem_Range_s)

class DMA_Des_s(Structure):
    _fields_ = [
        ("DD_Count", DWORD),
        ("DD_Type", DWORD),
        ("DD_Flags", DWORD),
        ("DD_Alloc_Chan", ULONG),
    ]
PDMA_DES = POINTER(DMA_Des_s)
DMA_DES = DMA_Des_s

class DMA_Range_s(Structure):
    _fields_ = [
        ("DR_Min", ULONG),
        ("DR_Max", ULONG),
        ("DR_Flags", ULONG),
    ]
DMA_RANGE = DMA_Range_s
PDMA_RANGE = POINTER(DMA_Range_s)

class IRQ_Des_64_s(Structure):
    _fields_ = [
        ("IRQD_Count", DWORD),
        ("IRQD_Type", DWORD),
        ("IRQD_Flags", DWORD),
        ("IRQD_Alloc_Num", ULONG),
        ("IRQD_Affinity", ULONG64),
    ]
IRQ_DES_64 = IRQ_Des_64_s
PIRQ_DES_64 = POINTER(IRQ_Des_64_s)

class IRQ_Des_32_s(Structure):
    _fields_ = [
        ("IRQD_Count", DWORD),
        ("IRQD_Type", DWORD),
        ("IRQD_Flags", DWORD),
        ("IRQD_Alloc_Num", ULONG),
        ("IRQD_Affinity", ULONG32),
    ]
PIRQ_DES_32 = POINTER(IRQ_Des_32_s)
IRQ_DES_32 = IRQ_Des_32_s

class IRQ_Range_s(Structure):
    _fields_ = [
        ("IRQR_Min", ULONG),
        ("IRQR_Max", ULONG),
        ("IRQR_Flags", ULONG),
    ]
IRQ_RANGE = IRQ_Range_s
PIRQ_RANGE = POINTER(IRQ_Range_s)

class BusNumber_Des_s(Structure):
    _fields_ = [
        ("BUSD_Count", DWORD),
        ("BUSD_Type", DWORD),
        ("BUSD_Flags", DWORD),
        ("BUSD_Alloc_Base", ULONG),
        ("BUSD_Alloc_End", ULONG),
    ]
BUSNUMBER_DES = BusNumber_Des_s
PBUSNUMBER_DES = POINTER(BusNumber_Des_s)

class BusNumber_Range_s(Structure):
    _fields_ = [
        ("BUSR_Min", ULONG),
        ("BUSR_Max", ULONG),
        ("BUSR_nBusNumbers", ULONG),
        ("BUSR_Flags", ULONG),
    ]
PBUSNUMBER_RANGE = POINTER(BusNumber_Range_s)
BUSNUMBER_RANGE = BusNumber_Range_s

class BusNumber_Resource_s(Structure):
    _fields_ = [
        ("BusNumber_Header", BUSNUMBER_DES),
        ("BusNumber_Data", BUSNUMBER_RANGE * (ANYSIZE_ARRAY)),
    ]
BUSNUMBER_RESOURCE = BusNumber_Resource_s
PBUSNUMBER_RESOURCE = POINTER(BusNumber_Resource_s)

class CS_Des_s(Structure):
    _fields_ = [
        ("CSD_SignatureLength", DWORD),
        ("CSD_LegacyDataOffset", DWORD),
        ("CSD_LegacyDataSize", DWORD),
        ("CSD_Flags", DWORD),
        ("CSD_ClassGuid", GUID),
        ("CSD_Signature", BYTE * (ANYSIZE_ARRAY)),
    ]
PCS_DES = POINTER(CS_Des_s)
CS_DES = CS_Des_s

class CS_Resource_s(Structure):
    _fields_ = [
        ("CS_Header", CS_DES),
    ]
PCS_RESOURCE = POINTER(CS_Resource_s)
CS_RESOURCE = CS_Resource_s

class DMA_Des_s(Structure):
    _fields_ = [
        ("DD_Count", DWORD),
        ("DD_Type", DWORD),
        ("DD_Flags", DWORD),
        ("DD_Alloc_Chan", ULONG),
    ]
PDMA_DES = POINTER(DMA_Des_s)
DMA_DES = DMA_Des_s

class DMA_Resource_s(Structure):
    _fields_ = [
        ("DMA_Header", DMA_DES),
        ("DMA_Data", DMA_RANGE * (ANYSIZE_ARRAY)),
    ]
PDMA_RESOURCE = POINTER(DMA_Resource_s)
DMA_RESOURCE = DMA_Resource_s

class IO_Des_s(Structure):
    _fields_ = [
        ("IOD_Count", DWORD),
        ("IOD_Type", DWORD),
        ("IOD_Alloc_Base", DWORDLONG),
        ("IOD_Alloc_End", DWORDLONG),
        ("IOD_DesFlags", DWORD),
    ]
PIO_DES = POINTER(IO_Des_s)
IO_DES = IO_Des_s

class IO_Resource_s(Structure):
    _fields_ = [
        ("IO_Header", IO_DES),
        ("IO_Data", IO_RANGE * (ANYSIZE_ARRAY)),
    ]
IO_RESOURCE = IO_Resource_s
PIO_RESOURCE = POINTER(IO_Resource_s)

class IRQ_Resource_32_s(Structure):
    _fields_ = [
        ("IRQ_Header", IRQ_DES_32),
        ("IRQ_Data", IRQ_RANGE * (ANYSIZE_ARRAY)),
    ]
PIRQ_RESOURCE_32 = POINTER(IRQ_Resource_32_s)
IRQ_RESOURCE_32 = IRQ_Resource_32_s

class IRQ_Resource_64_s(Structure):
    _fields_ = [
        ("IRQ_Header", IRQ_DES_64),
        ("IRQ_Data", IRQ_RANGE * (ANYSIZE_ARRAY)),
    ]
IRQ_RESOURCE_64 = IRQ_Resource_64_s
PIRQ_RESOURCE_64 = POINTER(IRQ_Resource_64_s)

class Mem_Resource_s(Structure):
    _fields_ = [
        ("MEM_Header", MEM_DES),
        ("MEM_Data", MEM_RANGE * (ANYSIZE_ARRAY)),
    ]
MEM_RESOURCE = Mem_Resource_s
PMEM_RESOURCE = POINTER(Mem_Resource_s)

class MfCard_Des_s(Structure):
    _fields_ = [
        ("PMF_Count", DWORD),
        ("PMF_Type", DWORD),
        ("PMF_Flags", DWORD),
        ("PMF_ConfigOptions", BYTE),
        ("PMF_IoResourceIndex", BYTE),
        ("PMF_Reserved", BYTE * (2)),
        ("PMF_ConfigRegisterBase", DWORD),
    ]
MFCARD_DES = MfCard_Des_s
PMFCARD_DES = POINTER(MfCard_Des_s)

class MfCard_Resource_s(Structure):
    _fields_ = [
        ("MfCard_Header", MFCARD_DES),
    ]
PMFCARD_RESOURCE = POINTER(MfCard_Resource_s)
MFCARD_RESOURCE = MfCard_Resource_s

class PcCard_Des_s(Structure):
    _fields_ = [
        ("PCD_Count", DWORD),
        ("PCD_Type", DWORD),
        ("PCD_Flags", DWORD),
        ("PCD_ConfigIndex", BYTE),
        ("PCD_Reserved", BYTE * (3)),
        ("PCD_MemoryCardBase1", DWORD),
        ("PCD_MemoryCardBase2", DWORD),
        ("PCD_MemoryCardBase", DWORD * (PCD_MAX_MEMORY)),
        ("PCD_MemoryFlags", WORD * (PCD_MAX_MEMORY)),
        ("PCD_IoFlags", BYTE * (PCD_MAX_IO)),
    ]
PCCARD_DES = PcCard_Des_s
PPCCARD_DES = POINTER(PcCard_Des_s)

class PcCard_Resource_s(Structure):
    _fields_ = [
        ("PcCard_Header", PCCARD_DES),
    ]
PPCCARD_RESOURCE = POINTER(PcCard_Resource_s)
PCCARD_RESOURCE = PcCard_Resource_s

class Mem_Large_Range_s(Structure):
    _fields_ = [
        ("MLR_Align", DWORDLONG),
        ("MLR_nBytes", ULONGLONG),
        ("MLR_Min", DWORDLONG),
        ("MLR_Max", DWORDLONG),
        ("MLR_Flags", DWORD),
        ("MLR_Reserved", DWORD),
    ]
PMEM_LARGE_RANGE = POINTER(Mem_Large_Range_s)
MEM_LARGE_RANGE = Mem_Large_Range_s

class Mem_Large_Des_s(Structure):
    _fields_ = [
        ("MLD_Count", DWORD),
        ("MLD_Type", DWORD),
        ("MLD_Alloc_Base", DWORDLONG),
        ("MLD_Alloc_End", DWORDLONG),
        ("MLD_Flags", DWORD),
        ("MLD_Reserved", DWORD),
    ]
PMEM_LARGE_DES = POINTER(Mem_Large_Des_s)
MEM_LARGE_DES = Mem_Large_Des_s

class Mem_Large_Resource_s(Structure):
    _fields_ = [
        ("MEM_LARGE_Header", MEM_LARGE_DES),
        ("MEM_LARGE_Data", MEM_LARGE_RANGE * (ANYSIZE_ARRAY)),
    ]
MEM_LARGE_RESOURCE = Mem_Large_Resource_s
PMEM_LARGE_RESOURCE = POINTER(Mem_Large_Resource_s)

CALLFRAME_COPY_NESTED = EnumValue("_CALLFRAME_COPY", "CALLFRAME_COPY_NESTED", 0x1)
CALLFRAME_COPY_INDEPENDENT = EnumValue("_CALLFRAME_COPY", "CALLFRAME_COPY_INDEPENDENT", 0x2)
class _CALLFRAME_COPY(EnumType):
    values = [CALLFRAME_COPY_NESTED, CALLFRAME_COPY_INDEPENDENT]
    mapper = FlagMapper(*values)
CALLFRAME_COPY = _CALLFRAME_COPY


MSHLFLAGS_NORMAL = EnumValue("tagMSHLFLAGS", "MSHLFLAGS_NORMAL", 0x0)
MSHLFLAGS_TABLESTRONG = EnumValue("tagMSHLFLAGS", "MSHLFLAGS_TABLESTRONG", 0x1)
MSHLFLAGS_TABLEWEAK = EnumValue("tagMSHLFLAGS", "MSHLFLAGS_TABLEWEAK", 0x2)
MSHLFLAGS_NOPING = EnumValue("tagMSHLFLAGS", "MSHLFLAGS_NOPING", 0x4)
class tagMSHLFLAGS(EnumType):
    values = [MSHLFLAGS_NORMAL, MSHLFLAGS_TABLESTRONG, MSHLFLAGS_TABLEWEAK, MSHLFLAGS_NOPING]
    mapper = FlagMapper(*values)
MSHLFLAGS = tagMSHLFLAGS


CALLFRAME_WALK_IN = EnumValue("tagCALLFRAME_WALK", "CALLFRAME_WALK_IN", 0x1)
CALLFRAME_WALK_INOUT = EnumValue("tagCALLFRAME_WALK", "CALLFRAME_WALK_INOUT", 0x2)
CALLFRAME_WALK_OUT = EnumValue("tagCALLFRAME_WALK", "CALLFRAME_WALK_OUT", 0x4)
class tagCALLFRAME_WALK(EnumType):
    values = [CALLFRAME_WALK_IN, CALLFRAME_WALK_INOUT, CALLFRAME_WALK_OUT]
    mapper = FlagMapper(*values)
CALLFRAME_WALK = tagCALLFRAME_WALK


SD_LAUNCHPERMISSIONS = EnumValue("tagCOMSD", "SD_LAUNCHPERMISSIONS", 0x0)
SD_ACCESSPERMISSIONS = EnumValue("tagCOMSD", "SD_ACCESSPERMISSIONS", 0x1)
SD_LAUNCHRESTRICTIONS = EnumValue("tagCOMSD", "SD_LAUNCHRESTRICTIONS", 0x2)
SD_ACCESSRESTRICTIONS = EnumValue("tagCOMSD", "SD_ACCESSRESTRICTIONS", 0x3)
class tagCOMSD(EnumType):
    values = [SD_LAUNCHPERMISSIONS, SD_ACCESSPERMISSIONS, SD_LAUNCHRESTRICTIONS, SD_ACCESSRESTRICTIONS]
    mapper = FlagMapper(*values)
COMSD = tagCOMSD


class tagMULTI_QI(Structure):
    _fields_ = [
        ("pIID", POINTER(IID)),
        ("pItf", POINTER(PVOID)),
        ("hr", HRESULT),
    ]
MULTI_QI = tagMULTI_QI

class _COAUTHIDENTITY(Structure):
    _fields_ = [
        ("User", POINTER(USHORT)),
        ("UserLength", ULONG),
        ("Domain", POINTER(USHORT)),
        ("DomainLength", ULONG),
        ("Password", POINTER(USHORT)),
        ("PasswordLength", ULONG),
        ("Flags", ULONG),
    ]
COAUTHIDENTITY = _COAUTHIDENTITY

class _COAUTHINFO(Structure):
    _fields_ = [
        ("dwAuthnSvc", DWORD),
        ("dwAuthzSvc", DWORD),
        ("pwszServerPrincName", LPWSTR),
        ("dwAuthnLevel", DWORD),
        ("dwImpersonationLevel", DWORD),
        ("pAuthIdentityData", POINTER(COAUTHIDENTITY)),
        ("dwCapabilities", DWORD),
    ]
COAUTHINFO = _COAUTHINFO

class _COSERVERINFO(Structure):
    _fields_ = [
        ("dwReserved1", DWORD),
        ("pwszName", LPWSTR),
        ("pAuthInfo", POINTER(COAUTHINFO)),
        ("dwReserved2", DWORD),
    ]
COSERVERINFO = _COSERVERINFO

class _CALLFRAMEPARAMINFO(Structure):
    _fields_ = [
        ("fIn", BOOLEAN),
        ("fOut", BOOLEAN),
        ("stackOffset", ULONG),
        ("cbParam", ULONG),
    ]
CALLFRAMEPARAMINFO = _CALLFRAMEPARAMINFO

class _CALLFRAMEINFO(Structure):
    _fields_ = [
        ("iMethod", ULONG),
        ("fHasInValues", BOOL),
        ("fHasInOutValues", BOOL),
        ("fHasOutValues", BOOL),
        ("fDerivesFromIDispatch", BOOL),
        ("cInInterfacesMax", LONG),
        ("cInOutInterfacesMax", LONG),
        ("cOutInterfacesMax", LONG),
        ("cTopLevelInInterfaces", LONG),
        ("iid", IID),
        ("cMethod", ULONG),
        ("cParams", ULONG),
    ]
CALLFRAMEINFO = _CALLFRAMEINFO

class _CALLFRAME_MARSHALCONTEXT(Structure):
    _fields_ = [
        ("fIn", BOOLEAN),
        ("dwDestContext", DWORD),
        ("pvDestContext", LPVOID),
        ("mshlmgr", POINTER(PVOID)),
        ("guidTransferSyntax", GUID),
    ]
CALLFRAME_MARSHALCONTEXT = _CALLFRAME_MARSHALCONTEXT

class tagSAFEARRAYBOUND(Structure):
    _fields_ = [
        ("cElements", ULONG),
        ("lLbound", LONG),
    ]
SAFEARRAYBOUND = tagSAFEARRAYBOUND
LPSAFEARRAYBOUND = POINTER(tagSAFEARRAYBOUND)

class tagSAFEARRAY(Structure):
    _fields_ = [
        ("cDims", USHORT),
        ("fFeatures", USHORT),
        ("cbElements", ULONG),
        ("cLocks", ULONG),
        ("pvData", PVOID),
        ("rgsabound", SAFEARRAYBOUND * (1)),
    ]
SAFEARRAY = tagSAFEARRAY
LPSAFEARRAY = POINTER(tagSAFEARRAY)

class __tagBRECORD(Structure):
    _fields_ = [
        ("pvRecord", PVOID),
        ("pRecInfo", PVOID),
    ]
_tagBRECORD = __tagBRECORD

class _ANON_TMP_variant_sub_union(Union):
    _fields_ = [
        ("llVal", LONGLONG),
        ("lVal", LONG),
        ("bVal", BYTE),
        ("iVal", SHORT),
        ("fltVal", FLOAT),
        ("dblVal", DOUBLE),
        ("boolVal", VARIANT_BOOL),
        ("scode", SCODE),
        ("bstrVal", BSTR),
        ("punkVal", PVOID),
        ("pdispVal", PVOID),
        ("parray", POINTER(SAFEARRAY)),
        ("pbVal", POINTER(BYTE)),
        ("piVal", POINTER(SHORT)),
        ("plVal", POINTER(LONG)),
        ("pllVal", POINTER(LONGLONG)),
        ("pfltVal", POINTER(FLOAT)),
        ("pdblVal", POINTER(DOUBLE)),
        ("pboolVal", POINTER(VARIANT_BOOL)),
        ("pscode", POINTER(SCODE)),
        ("pbstrVal", POINTER(BSTR)),
        ("byref", PVOID),
        ("cVal", CHAR),
        ("uiVal", USHORT),
        ("ulVal", ULONG),
        ("ullVal", ULONGLONG),
        ("intVal", INT),
        ("uintVal", UINT),
        ("pcVal", POINTER(CHAR)),
        ("puiVal", POINTER(USHORT)),
        ("pulVal", POINTER(ULONG)),
        ("pullVal", POINTER(ULONGLONG)),
        ("pintVal", POINTER(INT)),
        ("puintVal", POINTER(UINT)),
        ("_VARIANT_NAME_4", _tagBRECORD),
    ]


class __tagVARIANT(Structure):
    _anonymous_ = ("_VARIANT_NAME_3",)
    _fields_ = [
        ("vt", VARTYPE),
        ("wReserved1", WORD),
        ("wReserved2", WORD),
        ("wReserved3", WORD),
        ("_VARIANT_NAME_3", _ANON_TMP_variant_sub_union),
    ]
LPVARIANTARG = POINTER(__tagVARIANT)
VARIANTARG = __tagVARIANT
VARIANT = __tagVARIANT
LPVARIANT = POINTER(__tagVARIANT)
_tagVARIANT = __tagVARIANT

VIRTUAL_DISK_ACCESS_NONE = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_NONE", 0x0)
VIRTUAL_DISK_ACCESS_ATTACH_RO = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_ATTACH_RO", 0x1)
VIRTUAL_DISK_ACCESS_ATTACH_RW = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_ATTACH_RW", 0x2)
VIRTUAL_DISK_ACCESS_DETACH = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_DETACH", 0x3)
VIRTUAL_DISK_ACCESS_GET_INFO = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_GET_INFO", 0x4)
VIRTUAL_DISK_ACCESS_CREATE = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_CREATE", 0x5)
VIRTUAL_DISK_ACCESS_METAOPS = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_METAOPS", 0x6)
VIRTUAL_DISK_ACCESS_READ = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_READ", 0x7)
VIRTUAL_DISK_ACCESS_ALL = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_ALL", 0x8)
VIRTUAL_DISK_ACCESS_WRITABLE = EnumValue("_VIRTUAL_DISK_ACCESS_MASK", "VIRTUAL_DISK_ACCESS_WRITABLE", 0x9)
class _VIRTUAL_DISK_ACCESS_MASK(EnumType):
    values = [VIRTUAL_DISK_ACCESS_NONE, VIRTUAL_DISK_ACCESS_ATTACH_RO, VIRTUAL_DISK_ACCESS_ATTACH_RW, VIRTUAL_DISK_ACCESS_DETACH, VIRTUAL_DISK_ACCESS_GET_INFO, VIRTUAL_DISK_ACCESS_CREATE, VIRTUAL_DISK_ACCESS_METAOPS, VIRTUAL_DISK_ACCESS_READ, VIRTUAL_DISK_ACCESS_ALL, VIRTUAL_DISK_ACCESS_WRITABLE]
    mapper = FlagMapper(*values)
VIRTUAL_DISK_ACCESS_MASK = _VIRTUAL_DISK_ACCESS_MASK


OPEN_VIRTUAL_DISK_FLAG_NONE = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_NONE", 0x0)
OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS", 0x1)
OPEN_VIRTUAL_DISK_FLAG_BLANK_FILE = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_BLANK_FILE", 0x2)
OPEN_VIRTUAL_DISK_FLAG_BOOT_DRIVE = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_BOOT_DRIVE", 0x3)
OPEN_VIRTUAL_DISK_FLAG_CACHED_IO = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_CACHED_IO", 0x4)
OPEN_VIRTUAL_DISK_FLAG_CUSTOM_DIFF_CHAIN = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_CUSTOM_DIFF_CHAIN", 0x5)
OPEN_VIRTUAL_DISK_FLAG_PARENT_CACHED_IO = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_PARENT_CACHED_IO", 0x6)
OPEN_VIRTUAL_DISK_FLAG_VHDSET_FILE_ONLY = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_VHDSET_FILE_ONLY", 0x7)
OPEN_VIRTUAL_DISK_FLAG_IGNORE_RELATIVE_PARENT_LOCATOR = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_IGNORE_RELATIVE_PARENT_LOCATOR", 0x8)
OPEN_VIRTUAL_DISK_FLAG_NO_WRITE_HARDENING = EnumValue("_OPEN_VIRTUAL_DISK_FLAG", "OPEN_VIRTUAL_DISK_FLAG_NO_WRITE_HARDENING", 0x9)
class _OPEN_VIRTUAL_DISK_FLAG(EnumType):
    values = [OPEN_VIRTUAL_DISK_FLAG_NONE, OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS, OPEN_VIRTUAL_DISK_FLAG_BLANK_FILE, OPEN_VIRTUAL_DISK_FLAG_BOOT_DRIVE, OPEN_VIRTUAL_DISK_FLAG_CACHED_IO, OPEN_VIRTUAL_DISK_FLAG_CUSTOM_DIFF_CHAIN, OPEN_VIRTUAL_DISK_FLAG_PARENT_CACHED_IO, OPEN_VIRTUAL_DISK_FLAG_VHDSET_FILE_ONLY, OPEN_VIRTUAL_DISK_FLAG_IGNORE_RELATIVE_PARENT_LOCATOR, OPEN_VIRTUAL_DISK_FLAG_NO_WRITE_HARDENING]
    mapper = FlagMapper(*values)
OPEN_VIRTUAL_DISK_FLAG = _OPEN_VIRTUAL_DISK_FLAG


ATTACH_VIRTUAL_DISK_FLAG_NONE = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_NONE", 0x0)
ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY", 0x1)
ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER", 0x2)
ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME", 0x3)
ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST", 0x4)
ATTACH_VIRTUAL_DISK_FLAG_NO_SECURITY_DESCRIPTOR = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_NO_SECURITY_DESCRIPTOR", 0x5)
ATTACH_VIRTUAL_DISK_FLAG_BYPASS_DEFAULT_ENCRYPTION_POLICY = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_BYPASS_DEFAULT_ENCRYPTION_POLICY", 0x6)
ATTACH_VIRTUAL_DISK_FLAG_NON_PNP = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_NON_PNP", 0x7)
ATTACH_VIRTUAL_DISK_FLAG_RESTRICTED_RANGE = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_RESTRICTED_RANGE", 0x8)
ATTACH_VIRTUAL_DISK_FLAG_SINGLE_PARTITION = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_SINGLE_PARTITION", 0x9)
ATTACH_VIRTUAL_DISK_FLAG_REGISTER_VOLUME = EnumValue("_ATTACH_VIRTUAL_DISK_FLAG", "ATTACH_VIRTUAL_DISK_FLAG_REGISTER_VOLUME", 0xa)
class _ATTACH_VIRTUAL_DISK_FLAG(EnumType):
    values = [ATTACH_VIRTUAL_DISK_FLAG_NONE, ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY, ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME, ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST, ATTACH_VIRTUAL_DISK_FLAG_NO_SECURITY_DESCRIPTOR, ATTACH_VIRTUAL_DISK_FLAG_BYPASS_DEFAULT_ENCRYPTION_POLICY, ATTACH_VIRTUAL_DISK_FLAG_NON_PNP, ATTACH_VIRTUAL_DISK_FLAG_RESTRICTED_RANGE, ATTACH_VIRTUAL_DISK_FLAG_SINGLE_PARTITION, ATTACH_VIRTUAL_DISK_FLAG_REGISTER_VOLUME]
    mapper = FlagMapper(*values)
ATTACH_VIRTUAL_DISK_FLAG = _ATTACH_VIRTUAL_DISK_FLAG


OPEN_VIRTUAL_DISK_VERSION_UNSPECIFIED = EnumValue("_OPEN_VIRTUAL_DISK_VERSION", "OPEN_VIRTUAL_DISK_VERSION_UNSPECIFIED", 0x0)
OPEN_VIRTUAL_DISK_VERSION_1 = EnumValue("_OPEN_VIRTUAL_DISK_VERSION", "OPEN_VIRTUAL_DISK_VERSION_1", 0x1)
OPEN_VIRTUAL_DISK_VERSION_2 = EnumValue("_OPEN_VIRTUAL_DISK_VERSION", "OPEN_VIRTUAL_DISK_VERSION_2", 0x2)
OPEN_VIRTUAL_DISK_VERSION_3 = EnumValue("_OPEN_VIRTUAL_DISK_VERSION", "OPEN_VIRTUAL_DISK_VERSION_3", 0x3)
class _OPEN_VIRTUAL_DISK_VERSION(EnumType):
    values = [OPEN_VIRTUAL_DISK_VERSION_UNSPECIFIED, OPEN_VIRTUAL_DISK_VERSION_1, OPEN_VIRTUAL_DISK_VERSION_2, OPEN_VIRTUAL_DISK_VERSION_3]
    mapper = FlagMapper(*values)
OPEN_VIRTUAL_DISK_VERSION = _OPEN_VIRTUAL_DISK_VERSION


ATTACH_VIRTUAL_DISK_VERSION_UNSPECIFIED = EnumValue("_ATTACH_VIRTUAL_DISK_VERSION", "ATTACH_VIRTUAL_DISK_VERSION_UNSPECIFIED", 0x0)
ATTACH_VIRTUAL_DISK_VERSION_1 = EnumValue("_ATTACH_VIRTUAL_DISK_VERSION", "ATTACH_VIRTUAL_DISK_VERSION_1", 0x1)
ATTACH_VIRTUAL_DISK_VERSION_2 = EnumValue("_ATTACH_VIRTUAL_DISK_VERSION", "ATTACH_VIRTUAL_DISK_VERSION_2", 0x2)
class _ATTACH_VIRTUAL_DISK_VERSION(EnumType):
    values = [ATTACH_VIRTUAL_DISK_VERSION_UNSPECIFIED, ATTACH_VIRTUAL_DISK_VERSION_1, ATTACH_VIRTUAL_DISK_VERSION_2]
    mapper = FlagMapper(*values)
ATTACH_VIRTUAL_DISK_VERSION = _ATTACH_VIRTUAL_DISK_VERSION


class _VIRTUAL_STORAGE_TYPE(Structure):
    _fields_ = [
        ("DeviceId", ULONG),
        ("VendorId", GUID),
    ]
VIRTUAL_STORAGE_TYPE = _VIRTUAL_STORAGE_TYPE
PVIRTUAL_STORAGE_TYPE = POINTER(_VIRTUAL_STORAGE_TYPE)

class _ANON__ANON__OPEN_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("RWDepth", ULONG),
    ]


class _ANON__ANON__OPEN_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_2(Structure):
    _fields_ = [
        ("GetInfoOnly", BOOL),
        ("ReadOnly", BOOL),
        ("ResiliencyGuid", GUID),
    ]


class _ANON__ANON__OPEN_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_3(Structure):
    _fields_ = [
        ("GetInfoOnly", BOOL),
        ("ReadOnly", BOOL),
        ("ResiliencyGuid", GUID),
        ("SnapshotId", GUID),
    ]

class _ANON__OPEN_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1(Union):
    _anonymous_ = ("Version1","Version2","Version3")
    _fields_ = [
        ("Version1", _ANON__ANON__OPEN_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_1),
        ("Version2", _ANON__ANON__OPEN_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_2),
        ("Version3", _ANON__ANON__OPEN_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_3),
    ]

class _OPEN_VIRTUAL_DISK_PARAMETERS(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Version", OPEN_VIRTUAL_DISK_VERSION),
        ("anon_01", _ANON__OPEN_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1),
    ]
POPEN_VIRTUAL_DISK_PARAMETERS = POINTER(_OPEN_VIRTUAL_DISK_PARAMETERS)
OPEN_VIRTUAL_DISK_PARAMETERS = _OPEN_VIRTUAL_DISK_PARAMETERS

class _ANON__ANON__ATTACH_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("Reserved", ULONG),
    ]


class _ANON__ANON__ATTACH_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_2(Structure):
    _fields_ = [
        ("RestrictedOffset", ULONGLONG),
        ("RestrictedLength", ULONGLONG),
    ]

class _ANON__ATTACH_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1(Union):
    _anonymous_ = ("Version1","Version2")
    _fields_ = [
        ("Version1", _ANON__ANON__ATTACH_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_1),
        ("Version2", _ANON__ANON__ATTACH_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1_SUB_STRUCTURE_2),
    ]

class _ATTACH_VIRTUAL_DISK_PARAMETERS(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Version", ATTACH_VIRTUAL_DISK_VERSION),
        ("anon_01", _ANON__ATTACH_VIRTUAL_DISK_PARAMETERS_SUB_UNION_1),
    ]
ATTACH_VIRTUAL_DISK_PARAMETERS = _ATTACH_VIRTUAL_DISK_PARAMETERS
PATTACH_VIRTUAL_DISK_PARAMETERS = POINTER(_ATTACH_VIRTUAL_DISK_PARAMETERS)

# Self referencing struct tricks
class _INTERNET_BUFFERSA(Structure): pass
INTERNET_BUFFERSA = _INTERNET_BUFFERSA
LPINTERNET_BUFFERSA = POINTER(_INTERNET_BUFFERSA)
_INTERNET_BUFFERSA._fields_ = [
    ("dwStructSize", DWORD),
    ("Next", POINTER(_INTERNET_BUFFERSA)),
    ("lpcszHeader", LPCSTR),
    ("dwHeadersLength", DWORD),
    ("dwHeadersTotal", DWORD),
    ("lpvBuffer", LPVOID),
    ("dwBufferLength", DWORD),
    ("dwBufferTotal", DWORD),
    ("dwOffsetLow", DWORD),
    ("dwOffsetHigh", DWORD),
]

# Self referencing struct tricks
class _INTERNET_BUFFERSW(Structure): pass
LPINTERNET_BUFFERSW = POINTER(_INTERNET_BUFFERSW)
INTERNET_BUFFERSW = _INTERNET_BUFFERSW
_INTERNET_BUFFERSW._fields_ = [
    ("dwStructSize", DWORD),
    ("Next", POINTER(_INTERNET_BUFFERSW)),
    ("lpcszHeader", LPCWSTR),
    ("dwHeadersLength", DWORD),
    ("dwHeadersTotal", DWORD),
    ("lpvBuffer", LPVOID),
    ("dwBufferLength", DWORD),
    ("dwBufferTotal", DWORD),
    ("dwOffsetLow", DWORD),
    ("dwOffsetHigh", DWORD),
]

ProcessDEPPolicy = EnumValue("_PROCESS_MITIGATION_POLICY", "ProcessDEPPolicy", 0x0)
ProcessASLRPolicy = EnumValue("_PROCESS_MITIGATION_POLICY", "ProcessASLRPolicy", 0x1)
ProcessDynamicCodePolicy = EnumValue("_PROCESS_MITIGATION_POLICY", "ProcessDynamicCodePolicy", 0x2)
ProcessStrictHandleCheckPolicy = EnumValue("_PROCESS_MITIGATION_POLICY", "ProcessStrictHandleCheckPolicy", 0x3)
ProcessSystemCallDisablePolicy = EnumValue("_PROCESS_MITIGATION_POLICY", "ProcessSystemCallDisablePolicy", 0x4)
ProcessMitigationOptionsMask = EnumValue("_PROCESS_MITIGATION_POLICY", "ProcessMitigationOptionsMask", 0x5)
ProcessExtensionPointDisablePolicy = EnumValue("_PROCESS_MITIGATION_POLICY", "ProcessExtensionPointDisablePolicy", 0x6)
ProcessReserved1Policy = EnumValue("_PROCESS_MITIGATION_POLICY", "ProcessReserved1Policy", 0x7)
ProcessSignaturePolicy = EnumValue("_PROCESS_MITIGATION_POLICY", "ProcessSignaturePolicy", 0x8)
MaxProcessMitigationPolicy = EnumValue("_PROCESS_MITIGATION_POLICY", "MaxProcessMitigationPolicy", 0x9)
class _PROCESS_MITIGATION_POLICY(EnumType):
    values = [ProcessDEPPolicy, ProcessASLRPolicy, ProcessDynamicCodePolicy, ProcessStrictHandleCheckPolicy, ProcessSystemCallDisablePolicy, ProcessMitigationOptionsMask, ProcessExtensionPointDisablePolicy, ProcessReserved1Policy, ProcessSignaturePolicy, MaxProcessMitigationPolicy]
    mapper = FlagMapper(*values)
PROCESS_MITIGATION_POLICY = _PROCESS_MITIGATION_POLICY
PPROCESS_MITIGATION_POLICY = POINTER(_PROCESS_MITIGATION_POLICY)


class _ANON__ANON__PROCESS_MITIGATION_DEP_POLICY_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("Enable", DWORD, 1),
    ("DisableAtlThunkEmulation", DWORD, 1),
    ("ReservedFlags", DWORD, 30),
    ]

class _ANON__PROCESS_MITIGATION_DEP_POLICY_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Flags", DWORD),
        ("anon_01", _ANON__ANON__PROCESS_MITIGATION_DEP_POLICY_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _PROCESS_MITIGATION_DEP_POLICY(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__PROCESS_MITIGATION_DEP_POLICY_SUB_UNION_1),
        ("Permanent", BOOLEAN),
    ]
PPROCESS_MITIGATION_DEP_POLICY = POINTER(_PROCESS_MITIGATION_DEP_POLICY)
PROCESS_MITIGATION_DEP_POLICY = _PROCESS_MITIGATION_DEP_POLICY

class _ANON__ANON__PROCESS_MITIGATION_ASLR_POLICY_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("EnableBottomUpRandomization", DWORD, 1),
    ("EnableForceRelocateImages", DWORD, 1),
    ("EnableHighEntropy", DWORD, 1),
    ("DisallowStrippedImages", DWORD, 1),
    ("ReservedFlags", DWORD, 28),
    ]

class _ANON__PROCESS_MITIGATION_ASLR_POLICY_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Flags", DWORD),
        ("anon_01", _ANON__ANON__PROCESS_MITIGATION_ASLR_POLICY_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _PROCESS_MITIGATION_ASLR_POLICY(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__PROCESS_MITIGATION_ASLR_POLICY_SUB_UNION_1),
    ]
PPROCESS_MITIGATION_ASLR_POLICY = POINTER(_PROCESS_MITIGATION_ASLR_POLICY)
PROCESS_MITIGATION_ASLR_POLICY = _PROCESS_MITIGATION_ASLR_POLICY

class _ANON__ANON__PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("ProhibitDynamicCode", DWORD, 1),
    ("AllowThreadOptOut", DWORD, 1),
    ("AllowRemoteDowngrade", DWORD, 1),
    ("AuditProhibitDynamicCode", DWORD, 1),
    ("ReservedFlags", DWORD, 28),
    ]

class _ANON__PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Flags", DWORD),
        ("anon_01", _ANON__ANON__PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_SUB_UNION_1),
    ]
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY = POINTER(_PROCESS_MITIGATION_DYNAMIC_CODE_POLICY)

class _ANON__ANON__PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("RaiseExceptionOnInvalidHandleReference", DWORD, 1),
    ("HandleExceptionsPermanentlyEnabled", DWORD, 1),
    ("ReservedFlags", DWORD, 30),
    ]

class _ANON__PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Flags", DWORD),
        ("anon_01", _ANON__ANON__PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY_SUB_UNION_1),
    ]
PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY = _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
PPROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY = POINTER(_PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY)

class _ANON__ANON__PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("DisallowWin32kSystemCalls", DWORD, 1),
    ("AuditDisallowWin32kSystemCalls", DWORD, 1),
    ("ReservedFlags", DWORD, 30),
    ]

class _ANON__PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Flags", DWORD),
        ("anon_01", _ANON__ANON__PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_SUB_UNION_1),
    ]
PPROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = POINTER(_PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY)
PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY

class _ANON__ANON__PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("DisableExtensionPoints", DWORD, 1),
    ("ReservedFlags", DWORD, 31),
    ]

class _ANON__PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Flags", DWORD),
        ("anon_01", _ANON__ANON__PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY_SUB_UNION_1),
    ]
PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY = _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
PPROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY = POINTER(_PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY)

class _ANON__ANON__PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("EnableControlFlowGuard", DWORD, 1),
    ("EnableExportSuppression", DWORD, 1),
    ("StrictMode", DWORD, 1),
    ("ReservedFlags", DWORD, 29),
    ]

class _ANON__PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Flags", DWORD),
        ("anon_01", _ANON__ANON__PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_SUB_UNION_1),
    ]
PPROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = POINTER(_PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY)
PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY

class _ANON__ANON__PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("MicrosoftSignedOnly", DWORD, 1),
    ("StoreSignedOnly", DWORD, 1),
    ("MitigationOptIn", DWORD, 1),
    ("AuditMicrosoftSignedOnly", DWORD, 1),
    ("AuditStoreSignedOnly", DWORD, 1),
    ("ReservedFlags", DWORD, 27),
    ]

class _ANON__PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Flags", DWORD),
        ("anon_01", _ANON__ANON__PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_SUB_UNION_1),
    ]
PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = POINTER(_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY)
PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY

class _ANON__ANON__PROCESS_MITIGATION_IMAGE_LOAD_POLICY_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("NoRemoteImages", DWORD, 1),
    ("NoLowMandatoryLabelImages", DWORD, 1),
    ("PreferSystem32Images", DWORD, 1),
    ("AuditNoRemoteImages", DWORD, 1),
    ("AuditNoLowMandatoryLabelImages", DWORD, 1),
    ("ReservedFlags", DWORD, 27),
    ]

class _ANON__PROCESS_MITIGATION_IMAGE_LOAD_POLICY_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Flags", DWORD),
        ("anon_01", _ANON__ANON__PROCESS_MITIGATION_IMAGE_LOAD_POLICY_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _PROCESS_MITIGATION_IMAGE_LOAD_POLICY(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__PROCESS_MITIGATION_IMAGE_LOAD_POLICY_SUB_UNION_1),
    ]
PPROCESS_MITIGATION_IMAGE_LOAD_POLICY = POINTER(_PROCESS_MITIGATION_IMAGE_LOAD_POLICY)
PROCESS_MITIGATION_IMAGE_LOAD_POLICY = _PROCESS_MITIGATION_IMAGE_LOAD_POLICY

class _ANON__MIB_IPNETROW_LH_SUB_UNION_1(Union):
    _fields_ = [
        ("dwType", DWORD),
    ]

class _MIB_IPNETROW_LH(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("dwIndex", IF_INDEX),
        ("dwPhysAddrLen", DWORD),
        ("bPhysAddr", UCHAR * (8)),
        ("dwAddr", DWORD),
        ("anon_01", _ANON__MIB_IPNETROW_LH_SUB_UNION_1),
    ]
PMIB_IPNETROW = POINTER(_MIB_IPNETROW_LH)
MIB_IPNETROW = _MIB_IPNETROW_LH

class _MIB_IPNETTABLE(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_IPNETROW * (ANY_SIZE)),
    ]
PMIB_IPNETTABLE = POINTER(_MIB_IPNETTABLE)
MIB_IPNETTABLE = _MIB_IPNETTABLE

TCP_TABLE_BASIC_LISTENER = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_BASIC_LISTENER", 0x0)
TCP_TABLE_BASIC_CONNECTIONS = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_BASIC_CONNECTIONS", 0x1)
TCP_TABLE_BASIC_ALL = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_BASIC_ALL", 0x2)
TCP_TABLE_OWNER_PID_LISTENER = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_PID_LISTENER", 0x3)
TCP_TABLE_OWNER_PID_CONNECTIONS = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_PID_CONNECTIONS", 0x4)
TCP_TABLE_OWNER_PID_ALL = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_PID_ALL", 0x5)
TCP_TABLE_OWNER_MODULE_LISTENER = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_MODULE_LISTENER", 0x6)
TCP_TABLE_OWNER_MODULE_CONNECTIONS = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_MODULE_CONNECTIONS", 0x7)
TCP_TABLE_OWNER_MODULE_ALL = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_MODULE_ALL", 0x8)
class _TCP_TABLE_CLASS(EnumType):
    values = [TCP_TABLE_BASIC_LISTENER, TCP_TABLE_BASIC_CONNECTIONS, TCP_TABLE_BASIC_ALL, TCP_TABLE_OWNER_PID_LISTENER, TCP_TABLE_OWNER_PID_CONNECTIONS, TCP_TABLE_OWNER_PID_ALL, TCP_TABLE_OWNER_MODULE_LISTENER, TCP_TABLE_OWNER_MODULE_CONNECTIONS, TCP_TABLE_OWNER_MODULE_ALL]
    mapper = FlagMapper(*values)
TCP_TABLE_CLASS = _TCP_TABLE_CLASS


MIB_TCP_STATE_CLOSED = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_CLOSED", 0x1)
MIB_TCP_STATE_LISTEN = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_LISTEN", 0x2)
MIB_TCP_STATE_SYN_SENT = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_SYN_SENT", 0x3)
MIB_TCP_STATE_SYN_RCVD = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_SYN_RCVD", 0x4)
MIB_TCP_STATE_ESTAB = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_ESTAB", 0x5)
MIB_TCP_STATE_FIN_WAIT1 = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_FIN_WAIT1", 0x6)
MIB_TCP_STATE_FIN_WAIT2 = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_FIN_WAIT2", 0x7)
MIB_TCP_STATE_CLOSE_WAIT = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_CLOSE_WAIT", 0x8)
MIB_TCP_STATE_CLOSING = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_CLOSING", 0x9)
MIB_TCP_STATE_LAST_ACK = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_LAST_ACK", 0xa)
MIB_TCP_STATE_TIME_WAIT = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_TIME_WAIT", 0xb)
MIB_TCP_STATE_DELETE_TCB = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_DELETE_TCB", 0xc)
class _MIB_TCP_STATE(EnumType):
    values = [MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1, MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_TIME_WAIT, MIB_TCP_STATE_DELETE_TCB]
    mapper = FlagMapper(*values)
MIB_TCP_STATE = _MIB_TCP_STATE


NET_FW_IP_PROTOCOL_TCP = EnumValue("NET_FW_IP_PROTOCOL_", "NET_FW_IP_PROTOCOL_TCP", 0x6)
NET_FW_IP_PROTOCOL_UDP = EnumValue("NET_FW_IP_PROTOCOL_", "NET_FW_IP_PROTOCOL_UDP", 0x11)
NET_FW_IP_PROTOCOL_ANY = EnumValue("NET_FW_IP_PROTOCOL_", "NET_FW_IP_PROTOCOL_ANY", 0x100)
class NET_FW_IP_PROTOCOL_(EnumType):
    values = [NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_IP_PROTOCOL_ANY]
    mapper = FlagMapper(*values)
NET_FW_IP_PROTOCOL = NET_FW_IP_PROTOCOL_


IF_OPER_STATUS_NON_OPERATIONAL = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_NON_OPERATIONAL", 0x0)
IF_OPER_STATUS_UNREACHABLE = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_UNREACHABLE", 0x1)
IF_OPER_STATUS_DISCONNECTED = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_DISCONNECTED", 0x2)
IF_OPER_STATUS_CONNECTING = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_CONNECTING", 0x3)
IF_OPER_STATUS_CONNECTED = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_CONNECTED", 0x4)
IF_OPER_STATUS_OPERATIONAL = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_OPERATIONAL", 0x5)
class _INTERNAL_IF_OPER_STATUS(EnumType):
    values = [IF_OPER_STATUS_NON_OPERATIONAL, IF_OPER_STATUS_UNREACHABLE, IF_OPER_STATUS_DISCONNECTED, IF_OPER_STATUS_CONNECTING, IF_OPER_STATUS_CONNECTED, IF_OPER_STATUS_OPERATIONAL]
    mapper = FlagMapper(*values)
INTERNAL_IF_OPER_STATUS = _INTERNAL_IF_OPER_STATUS


DnsFreeFlat = EnumValue("DNS_FREE_TYPE", "DnsFreeFlat", 0x0)
DnsFreeRecordList = EnumValue("DNS_FREE_TYPE", "DnsFreeRecordList", 0x1)
DnsFreeParsedMessageFields = EnumValue("DNS_FREE_TYPE", "DnsFreeParsedMessageFields", 0x2)
class DNS_FREE_TYPE(EnumType):
    values = [DnsFreeFlat, DnsFreeRecordList, DnsFreeParsedMessageFields]
    mapper = FlagMapper(*values)


class IP6_ADDRESS(Structure):
    _fields_ = [
        ("IP6Qword", ULONGLONG * (2)),
    ]
PIP6_ADDRESS = POINTER(IP6_ADDRESS)

class _MIB_IPADDRROW_XP(Structure):
    _fields_ = [
        ("dwAddr", DWORD),
        ("dwIndex", IF_INDEX),
        ("dwMask", DWORD),
        ("dwBCastAddr", DWORD),
        ("dwReasmSize", DWORD),
        ("unused1", USHORT),
        ("wType", USHORT),
    ]
MIB_IPADDRROW = _MIB_IPADDRROW_XP
PMIB_IPADDRROW_XP = POINTER(_MIB_IPADDRROW_XP)
MIB_IPADDRROW_XP = _MIB_IPADDRROW_XP

class _MIB_IPADDRTABLE(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_IPADDRROW * (ANY_SIZE)),
    ]
PMIB_IPADDRTABLE = POINTER(_MIB_IPADDRTABLE)
MIB_IPADDRTABLE = _MIB_IPADDRTABLE

class _MIB_IFROW(Structure):
    _fields_ = [
        ("wszName", WCHAR * (MAX_INTERFACE_NAME_LEN)),
        ("dwIndex", IF_INDEX),
        ("dwType", IFTYPE),
        ("dwMtu", DWORD),
        ("dwSpeed", DWORD),
        ("dwPhysAddrLen", DWORD),
        ("bPhysAddr", BYTE * (MAXLEN_PHYSADDR)),
        ("dwAdminStatus", DWORD),
        ("dwOperStatus", INTERNAL_IF_OPER_STATUS),
        ("dwLastChange", DWORD),
        ("dwInOctets", DWORD),
        ("dwInUcastPkts", DWORD),
        ("dwInNUcastPkts", DWORD),
        ("dwInDiscards", DWORD),
        ("dwInErrors", DWORD),
        ("dwInUnknownProtos", DWORD),
        ("dwOutOctets", DWORD),
        ("dwOutUcastPkts", DWORD),
        ("dwOutNUcastPkts", DWORD),
        ("dwOutDiscards", DWORD),
        ("dwOutErrors", DWORD),
        ("dwOutQLen", DWORD),
        ("dwDescrLen", DWORD),
        ("bDescr", UCHAR * (MAXLEN_IFDESCR)),
    ]
PMIB_IFROW = POINTER(_MIB_IFROW)
MIB_IFROW = _MIB_IFROW

class _MIB_IFTABLE(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_IFROW * (ANY_SIZE)),
    ]
PMIB_IFTABLE = POINTER(_MIB_IFTABLE)
MIB_IFTABLE = _MIB_IFTABLE

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

class _MIB_TCPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCPROW_OWNER_PID * (ANY_SIZE)),
    ]
MIB_TCPTABLE_OWNER_PID = _MIB_TCPTABLE_OWNER_PID
PMIB_TCPTABLE_OWNER_PID = POINTER(_MIB_TCPTABLE_OWNER_PID)

class _MIB_UDPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_UDPROW_OWNER_PID = _MIB_UDPROW_OWNER_PID
PMIB_UDPROW_OWNER_PID = POINTER(_MIB_UDPROW_OWNER_PID)

class _MIB_UDPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_UDPROW_OWNER_PID * (ANY_SIZE)),
    ]
MIB_UDPTABLE_OWNER_PID = _MIB_UDPTABLE_OWNER_PID
PMIB_UDPTABLE_OWNER_PID = POINTER(_MIB_UDPTABLE_OWNER_PID)

class _MIB_UDP6ROW_OWNER_PID(Structure):
    _fields_ = [
        ("ucLocalAddr", UCHAR * (16)),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_UDP6ROW_OWNER_PID = _MIB_UDP6ROW_OWNER_PID
PMIB_UDP6ROW_OWNER_PID = POINTER(_MIB_UDP6ROW_OWNER_PID)

class _MIB_UDP6TABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_UDP6ROW_OWNER_PID * (ANY_SIZE)),
    ]
PMIB_UDP6TABLE_OWNER_PID = POINTER(_MIB_UDP6TABLE_OWNER_PID)
MIB_UDP6TABLE_OWNER_PID = _MIB_UDP6TABLE_OWNER_PID

class _MIB_TCP6ROW_OWNER_PID(Structure):
    _fields_ = [
        ("ucLocalAddr", UCHAR * (16)),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("ucRemoteAddr", UCHAR * (16)),
        ("dwRemoteScopeId", DWORD),
        ("dwRemotePort", DWORD),
        ("dwState", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_TCP6ROW_OWNER_PID = _MIB_TCP6ROW_OWNER_PID
PMIB_TCP6ROW_OWNER_PID = POINTER(_MIB_TCP6ROW_OWNER_PID)

class _MIB_TCP6TABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCP6ROW_OWNER_PID * (ANY_SIZE)),
    ]
MIB_TCP6TABLE_OWNER_PID = _MIB_TCP6TABLE_OWNER_PID
PMIB_TCP6TABLE_OWNER_PID = POINTER(_MIB_TCP6TABLE_OWNER_PID)

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

class _IP_ADAPTER_INDEX_MAP(Structure):
    _fields_ = [
        ("Index", ULONG),
        ("Name", WCHAR * (MAX_ADAPTER_NAME)),
    ]
PIP_ADAPTER_INDEX_MAP = POINTER(_IP_ADAPTER_INDEX_MAP)
IP_ADAPTER_INDEX_MAP = _IP_ADAPTER_INDEX_MAP

class _IP_INTERFACE_INFO(Structure):
    _fields_ = [
        ("NumAdapters", LONG),
        ("Adapter", IP_ADAPTER_INDEX_MAP * (1)),
    ]
PIP_INTERFACE_INFO = POINTER(_IP_INTERFACE_INFO)
IP_INTERFACE_INFO = _IP_INTERFACE_INFO

# Self referencing struct tricks
class _DNS_CACHE_ENTRY(Structure): pass
PDNS_CACHE_ENTRY = POINTER(_DNS_CACHE_ENTRY)
DNS_CACHE_ENTRY = _DNS_CACHE_ENTRY
_DNS_CACHE_ENTRY._fields_ = [
    ("pNext", POINTER(_DNS_CACHE_ENTRY)),
    ("pszName", PCWSTR),
    ("wType", USHORT),
    ("wDataLength", USHORT),
    ("dwFlags", ULONG),
]

class DNS_A_DATA(Structure):
    _fields_ = [
        ("IpAddress", IP4_ADDRESS),
    ]
PDNS_A_DATA = POINTER(DNS_A_DATA)

class DNS_PTR_DATAW(Structure):
    _fields_ = [
        ("pNameHost", PWSTR),
    ]
PDNS_PTR_DATAW = POINTER(DNS_PTR_DATAW)

class DNS_PTR_DATAA(Structure):
    _fields_ = [
        ("pNameHost", PSTR),
    ]
PDNS_PTR_DATAA = POINTER(DNS_PTR_DATAA)

class DNS_SOA_DATAW(Structure):
    _fields_ = [
        ("pNamePrimaryServer", PWSTR),
        ("pNameAdministrator", PWSTR),
        ("dwSerialNo", DWORD),
        ("dwRefresh", DWORD),
        ("dwRetry", DWORD),
        ("dwExpire", DWORD),
        ("dwDefaultTtl", DWORD),
    ]
PDNS_SOA_DATAW = POINTER(DNS_SOA_DATAW)

class DNS_SOA_DATAA(Structure):
    _fields_ = [
        ("pNamePrimaryServer", PSTR),
        ("pNameAdministrator", PSTR),
        ("dwSerialNo", DWORD),
        ("dwRefresh", DWORD),
        ("dwRetry", DWORD),
        ("dwExpire", DWORD),
        ("dwDefaultTtl", DWORD),
    ]
PDNS_SOA_DATAA = POINTER(DNS_SOA_DATAA)

class DNS_MINFO_DATAW(Structure):
    _fields_ = [
        ("pNameMailbox", PWSTR),
        ("pNameErrorsMailbox", PWSTR),
    ]
PDNS_MINFO_DATAW = POINTER(DNS_MINFO_DATAW)

class DNS_MINFO_DATAA(Structure):
    _fields_ = [
        ("pNameMailbox", PSTR),
        ("pNameErrorsMailbox", PSTR),
    ]
PDNS_MINFO_DATAA = POINTER(DNS_MINFO_DATAA)

class DNS_MX_DATAW(Structure):
    _fields_ = [
        ("pNameExchange", PWSTR),
        ("wPreference", WORD),
        ("Pad", WORD),
    ]
PDNS_MX_DATAW = POINTER(DNS_MX_DATAW)

class DNS_MX_DATAA(Structure):
    _fields_ = [
        ("pNameExchange", PSTR),
        ("wPreference", WORD),
        ("Pad", WORD),
    ]
PDNS_MX_DATAA = POINTER(DNS_MX_DATAA)

class DNS_TXT_DATAW(Structure):
    _fields_ = [
        ("dwStringCount", DWORD),
        ("pStringArray", PWSTR * (1)),
    ]
PDNS_TXT_DATAW = POINTER(DNS_TXT_DATAW)

class DNS_TXT_DATAA(Structure):
    _fields_ = [
        ("dwStringCount", DWORD),
        ("pStringArray", PSTR * (1)),
    ]
PDNS_TXT_DATAA = POINTER(DNS_TXT_DATAA)

class DNS_NULL_DATA(Structure):
    _fields_ = [
        ("dwByteCount", DWORD),
        ("Data", BYTE * (1)),
    ]
PDNS_NULL_DATA = POINTER(DNS_NULL_DATA)

class DNS_WKS_DATA(Structure):
    _fields_ = [
        ("IpAddress", IP4_ADDRESS),
        ("chProtocol", UCHAR),
        ("BitMask", BYTE * (1)),
    ]
PDNS_WKS_DATA = POINTER(DNS_WKS_DATA)

class DNS_AAAA_DATA(Structure):
    _fields_ = [
        ("Ip6Address", IP6_ADDRESS),
    ]
PDNS_AAAA_DATA = POINTER(DNS_AAAA_DATA)

class DNS_SIG_DATAW(Structure):
    _fields_ = [
        ("wTypeCovered", WORD),
        ("chAlgorithm", BYTE),
        ("chLabelCount", BYTE),
        ("dwOriginalTtl", DWORD),
        ("dwExpiration", DWORD),
        ("dwTimeSigned", DWORD),
        ("wKeyTag", WORD),
        ("wSignatureLength", WORD),
        ("pNameSigner", PWSTR),
        ("Signature", BYTE * (1)),
    ]
DNS_RRSIG_DATAW = DNS_SIG_DATAW
PDNS_RRSIG_DATAW = POINTER(DNS_SIG_DATAW)
PDNS_SIG_DATAW = POINTER(DNS_SIG_DATAW)

class DNS_SIG_DATAA(Structure):
    _fields_ = [
        ("wTypeCovered", WORD),
        ("chAlgorithm", BYTE),
        ("chLabelCount", BYTE),
        ("dwOriginalTtl", DWORD),
        ("dwExpiration", DWORD),
        ("dwTimeSigned", DWORD),
        ("wKeyTag", WORD),
        ("wSignatureLength", WORD),
        ("pNameSigner", PSTR),
        ("Signature", BYTE * (1)),
    ]
PDNS_SIG_DATAA = POINTER(DNS_SIG_DATAA)
PDNS_RRSIG_DATAA = POINTER(DNS_SIG_DATAA)
DNS_RRSIG_DATAA = DNS_SIG_DATAA

class DNS_KEY_DATA(Structure):
    _fields_ = [
        ("wFlags", WORD),
        ("chProtocol", BYTE),
        ("chAlgorithm", BYTE),
        ("wKeyLength", WORD),
        ("wPad", WORD),
        ("Key", BYTE * (1)),
    ]
PDNS_DNSKEY_DATA = POINTER(DNS_KEY_DATA)
PDNS_KEY_DATA = POINTER(DNS_KEY_DATA)
DNS_DNSKEY_DATA = DNS_KEY_DATA

class DNS_DHCID_DATA(Structure):
    _fields_ = [
        ("dwByteCount", DWORD),
        ("DHCID", BYTE * (1)),
    ]
PDNS_DHCID_DATA = POINTER(DNS_DHCID_DATA)

class DNS_NSEC_DATAW(Structure):
    _fields_ = [
        ("pNextDomainName", PWSTR),
        ("wTypeBitMapsLength", WORD),
        ("wPad", WORD),
        ("TypeBitMaps", BYTE * (1)),
    ]
PDNS_NSEC_DATAW = POINTER(DNS_NSEC_DATAW)

class DNS_NSEC_DATAA(Structure):
    _fields_ = [
        ("pNextDomainName", PSTR),
        ("wTypeBitMapsLength", WORD),
        ("wPad", WORD),
        ("TypeBitMaps", BYTE * (1)),
    ]
PDNS_NSEC_DATAA = POINTER(DNS_NSEC_DATAA)

class DNS_NSEC3_DATA(Structure):
    _fields_ = [
        ("chAlgorithm", BYTE),
        ("bFlags", BYTE),
        ("wIterations", WORD),
        ("bSaltLength", BYTE),
        ("bHashLength", BYTE),
        ("wTypeBitMapsLength", WORD),
        ("chData", BYTE * (1)),
    ]
PDNS_NSEC3_DATA = POINTER(DNS_NSEC3_DATA)

class DNS_NSEC3PARAM_DATA(Structure):
    _fields_ = [
        ("chAlgorithm", BYTE),
        ("bFlags", BYTE),
        ("wIterations", WORD),
        ("bSaltLength", BYTE),
        ("bPad", BYTE * (3)),
        ("pbSalt", BYTE * (1)),
    ]
PDNS_NSEC3PARAM_DATA = POINTER(DNS_NSEC3PARAM_DATA)

class DNS_DS_DATA(Structure):
    _fields_ = [
        ("wKeyTag", WORD),
        ("chAlgorithm", BYTE),
        ("chDigestType", BYTE),
        ("wDigestLength", WORD),
        ("wPad", WORD),
        ("Digest", BYTE * (1)),
    ]
PDNS_DS_DATA = POINTER(DNS_DS_DATA)

class DNS_OPT_DATA(Structure):
    _fields_ = [
        ("wDataLength", WORD),
        ("wPad", WORD),
        ("Data", BYTE * (1)),
    ]
PDNS_OPT_DATA = POINTER(DNS_OPT_DATA)

class DNS_LOC_DATA(Structure):
    _fields_ = [
        ("wVersion", WORD),
        ("wSize", WORD),
        ("wHorPrec", WORD),
        ("wVerPrec", WORD),
        ("dwLatitude", DWORD),
        ("dwLongitude", DWORD),
        ("dwAltitude", DWORD),
    ]
PDNS_LOC_DATA = POINTER(DNS_LOC_DATA)

class DNS_NXT_DATAW(Structure):
    _fields_ = [
        ("pNameNext", PWSTR),
        ("wNumTypes", WORD),
        ("wTypes", WORD * (1)),
    ]
PDNS_NXT_DATAW = POINTER(DNS_NXT_DATAW)

class DNS_NXT_DATAA(Structure):
    _fields_ = [
        ("pNameNext", PSTR),
        ("wNumTypes", WORD),
        ("wTypes", WORD * (1)),
    ]
PDNS_NXT_DATAA = POINTER(DNS_NXT_DATAA)

class DNS_SRV_DATAW(Structure):
    _fields_ = [
        ("pNameTarget", PWSTR),
        ("wPriority", WORD),
        ("wWeight", WORD),
        ("wPort", WORD),
        ("Pad", WORD),
    ]
PDNS_SRV_DATAW = POINTER(DNS_SRV_DATAW)

class DNS_SRV_DATAA(Structure):
    _fields_ = [
        ("pNameTarget", PSTR),
        ("wPriority", WORD),
        ("wWeight", WORD),
        ("wPort", WORD),
        ("Pad", WORD),
    ]
PDNS_SRV_DATAA = POINTER(DNS_SRV_DATAA)

class DNS_NAPTR_DATAW(Structure):
    _fields_ = [
        ("wOrder", WORD),
        ("wPreference", WORD),
        ("pFlags", PWSTR),
        ("pService", PWSTR),
        ("pRegularExpression", PWSTR),
        ("pReplacement", PWSTR),
    ]
PDNS_NAPTR_DATAW = POINTER(DNS_NAPTR_DATAW)

class DNS_NAPTR_DATAA(Structure):
    _fields_ = [
        ("wOrder", WORD),
        ("wPreference", WORD),
        ("pFlags", PSTR),
        ("pService", PSTR),
        ("pRegularExpression", PSTR),
        ("pReplacement", PSTR),
    ]
PDNS_NAPTR_DATAA = POINTER(DNS_NAPTR_DATAA)

class DNS_ATMA_DATA(Structure):
    _fields_ = [
        ("AddressType", BYTE),
        ("Address", BYTE * (DNS_ATMA_MAX_ADDR_LENGTH)),
    ]
PDNS_ATMA_DATA = POINTER(DNS_ATMA_DATA)

class DNS_TKEY_DATAW(Structure):
    _fields_ = [
        ("pNameAlgorithm", PWSTR),
        ("pAlgorithmPacket", PBYTE),
        ("pKey", PBYTE),
        ("pOtherData", PBYTE),
        ("dwCreateTime", DWORD),
        ("dwExpireTime", DWORD),
        ("wMode", WORD),
        ("wError", WORD),
        ("wKeyLength", WORD),
        ("wOtherLength", WORD),
        ("cAlgNameLength", UCHAR),
        ("bPacketPointers", BOOL),
    ]
PDNS_TKEY_DATAW = POINTER(DNS_TKEY_DATAW)

class DNS_TKEY_DATAA(Structure):
    _fields_ = [
        ("pNameAlgorithm", PSTR),
        ("pAlgorithmPacket", PBYTE),
        ("pKey", PBYTE),
        ("pOtherData", PBYTE),
        ("dwCreateTime", DWORD),
        ("dwExpireTime", DWORD),
        ("wMode", WORD),
        ("wError", WORD),
        ("wKeyLength", WORD),
        ("wOtherLength", WORD),
        ("cAlgNameLength", UCHAR),
        ("bPacketPointers", BOOL),
    ]
PDNS_TKEY_DATAA = POINTER(DNS_TKEY_DATAA)

class DNS_TSIG_DATAW(Structure):
    _fields_ = [
        ("pNameAlgorithm", PWSTR),
        ("pAlgorithmPacket", PBYTE),
        ("pSignature", PBYTE),
        ("pOtherData", PBYTE),
        ("i64CreateTime", LONGLONG),
        ("wFudgeTime", WORD),
        ("wOriginalXid", WORD),
        ("wError", WORD),
        ("wSigLength", WORD),
        ("wOtherLength", WORD),
        ("cAlgNameLength", UCHAR),
        ("bPacketPointers", BOOL),
    ]
PDNS_TSIG_DATAW = POINTER(DNS_TSIG_DATAW)

class DNS_TSIG_DATAA(Structure):
    _fields_ = [
        ("pNameAlgorithm", PSTR),
        ("pAlgorithmPacket", PBYTE),
        ("pSignature", PBYTE),
        ("pOtherData", PBYTE),
        ("i64CreateTime", LONGLONG),
        ("wFudgeTime", WORD),
        ("wOriginalXid", WORD),
        ("wError", WORD),
        ("wSigLength", WORD),
        ("wOtherLength", WORD),
        ("cAlgNameLength", UCHAR),
        ("bPacketPointers", BOOL),
    ]
PDNS_TSIG_DATAA = POINTER(DNS_TSIG_DATAA)

class DNS_WINS_DATA(Structure):
    _fields_ = [
        ("dwMappingFlag", DWORD),
        ("dwLookupTimeout", DWORD),
        ("dwCacheTimeout", DWORD),
        ("cWinsServerCount", DWORD),
        ("WinsServers", IP4_ADDRESS * (1)),
    ]
PDNS_WINS_DATA = POINTER(DNS_WINS_DATA)

class DNS_WINSR_DATAW(Structure):
    _fields_ = [
        ("dwMappingFlag", DWORD),
        ("dwLookupTimeout", DWORD),
        ("dwCacheTimeout", DWORD),
        ("pNameResultDomain", PWSTR),
    ]
PDNS_WINSR_DATAW = POINTER(DNS_WINSR_DATAW)

class DNS_WINSR_DATAA(Structure):
    _fields_ = [
        ("dwMappingFlag", DWORD),
        ("dwLookupTimeout", DWORD),
        ("dwCacheTimeout", DWORD),
        ("pNameResultDomain", PSTR),
    ]
PDNS_WINSR_DATAA = POINTER(DNS_WINSR_DATAA)

class DNS_TLSA_DATA(Structure):
    _fields_ = [
        ("bCertUsage", BYTE),
        ("bSelector", BYTE),
        ("bMatchingType", BYTE),
        ("bCertificateAssociationDataLength", WORD),
        ("bPad", BYTE * (3)),
        ("bCertificateAssociationData", BYTE * (1)),
    ]
PDNS_TLSA_DATA = POINTER(DNS_TLSA_DATA)

class DNS_UNKNOWN_DATA(Structure):
    _fields_ = [
        ("dwByteCount", DWORD),
        ("bData", BYTE * (1)),
    ]
PDNS_UNKNOWN_DATA = POINTER(DNS_UNKNOWN_DATA)

class _DnsRecordFlags(Structure):
    _fields_ = [
    ("Section", DWORD, 2),
    ("Delete", DWORD, 1),
    ("CharSet", DWORD, 2),
    ("Unused", DWORD, 3),
    ("Reserved", DWORD, 24),
    ]
DNS_RECORD_FLAGS = _DnsRecordFlags

class _ANON__DNSRECORDA_SUB_UNION_1(Union):
    _fields_ = [
        ("DW", DWORD),
        ("S", DNS_RECORD_FLAGS),
    ]


class _ANON__DNSRECORDA_SUB_UNION_2(Union):
    _fields_ = [
        ("A", DNS_A_DATA),
        ("SOA", DNS_SOA_DATAA),
        ("Soa", DNS_SOA_DATAA),
        ("PTR", DNS_PTR_DATAA),
        ("Ptr", DNS_PTR_DATAA),
        ("NS", DNS_PTR_DATAA),
        ("Ns", DNS_PTR_DATAA),
        ("CNAME", DNS_PTR_DATAA),
        ("Cname", DNS_PTR_DATAA),
        ("DNAME", DNS_PTR_DATAA),
        ("Dname", DNS_PTR_DATAA),
        ("MB", DNS_PTR_DATAA),
        ("Mb", DNS_PTR_DATAA),
        ("MD", DNS_PTR_DATAA),
        ("Md", DNS_PTR_DATAA),
        ("MF", DNS_PTR_DATAA),
        ("Mf", DNS_PTR_DATAA),
        ("MG", DNS_PTR_DATAA),
        ("Mg", DNS_PTR_DATAA),
        ("MR", DNS_PTR_DATAA),
        ("Mr", DNS_PTR_DATAA),
        ("MINFO", DNS_MINFO_DATAA),
        ("Minfo", DNS_MINFO_DATAA),
        ("RP", DNS_MINFO_DATAA),
        ("Rp", DNS_MINFO_DATAA),
        ("MX", DNS_MX_DATAA),
        ("Mx", DNS_MX_DATAA),
        ("AFSDB", DNS_MX_DATAA),
        ("Afsdb", DNS_MX_DATAA),
        ("RT", DNS_MX_DATAA),
        ("Rt", DNS_MX_DATAA),
        ("HINFO", DNS_TXT_DATAA),
        ("Hinfo", DNS_TXT_DATAA),
        ("ISDN", DNS_TXT_DATAA),
        ("Isdn", DNS_TXT_DATAA),
        ("TXT", DNS_TXT_DATAA),
        ("Txt", DNS_TXT_DATAA),
        ("X25", DNS_TXT_DATAA),
        ("Null", DNS_NULL_DATA),
        ("WKS", DNS_WKS_DATA),
        ("Wks", DNS_WKS_DATA),
        ("AAAA", DNS_AAAA_DATA),
        ("KEY", DNS_KEY_DATA),
        ("Key", DNS_KEY_DATA),
        ("SIG", DNS_SIG_DATAA),
        ("Sig", DNS_SIG_DATAA),
        ("ATMA", DNS_ATMA_DATA),
        ("Atma", DNS_ATMA_DATA),
        ("NXT", DNS_NXT_DATAA),
        ("Nxt", DNS_NXT_DATAA),
        ("SRV", DNS_SRV_DATAA),
        ("Srv", DNS_SRV_DATAA),
        ("NAPTR", DNS_NAPTR_DATAA),
        ("Naptr", DNS_NAPTR_DATAA),
        ("OPT", DNS_OPT_DATA),
        ("Opt", DNS_OPT_DATA),
        ("DS", DNS_DS_DATA),
        ("Ds", DNS_DS_DATA),
        ("RRSIG", DNS_RRSIG_DATAA),
        ("Rrsig", DNS_RRSIG_DATAA),
        ("NSEC", DNS_NSEC_DATAA),
        ("Nsec", DNS_NSEC_DATAA),
        ("DNSKEY", DNS_DNSKEY_DATA),
        ("Dnskey", DNS_DNSKEY_DATA),
        ("TKEY", DNS_TKEY_DATAA),
        ("Tkey", DNS_TKEY_DATAA),
        ("TSIG", DNS_TSIG_DATAA),
        ("Tsig", DNS_TSIG_DATAA),
        ("WINS", DNS_WINS_DATA),
        ("Wins", DNS_WINS_DATA),
        ("WINSR", DNS_WINSR_DATAA),
        ("WinsR", DNS_WINSR_DATAA),
        ("NBSTAT", DNS_WINSR_DATAA),
        ("Nbstat", DNS_WINSR_DATAA),
        ("DHCID", DNS_DHCID_DATA),
        ("NSEC3", DNS_NSEC3_DATA),
        ("Nsec3", DNS_NSEC3_DATA),
        ("NSEC3PARAM", DNS_NSEC3PARAM_DATA),
        ("Nsec3Param", DNS_NSEC3PARAM_DATA),
        ("TLSA", DNS_TLSA_DATA),
        ("Tlsa", DNS_TLSA_DATA),
        ("UNKNOWN", DNS_UNKNOWN_DATA),
        ("Unknown", DNS_UNKNOWN_DATA),
        ("pDataPtr", PBYTE),
    ]

# Self referencing struct tricks
class _DnsRecordA(Structure): pass
PDNS_RECORDA = POINTER(_DnsRecordA)
DNS_RECORDA = _DnsRecordA
_DnsRecordA._fields_ = [
    ("pNext", POINTER(_DnsRecordA)),
    ("pName", PSTR),
    ("wType", WORD),
    ("wDataLength", WORD),
    ("Flags", _ANON__DNSRECORDA_SUB_UNION_1),
    ("dwTtl", DWORD),
    ("dwReserved", DWORD),
    ("Data", _ANON__DNSRECORDA_SUB_UNION_2),
]

class _ANON__DNSRECORDW_SUB_UNION_1(Union):
    _fields_ = [
        ("DW", DWORD),
        ("S", DNS_RECORD_FLAGS),
    ]


class _ANON__DNSRECORDW_SUB_UNION_2(Union):
    _fields_ = [
        ("A", DNS_A_DATA),
        ("SOA", DNS_SOA_DATAW),
        ("Soa", DNS_SOA_DATAW),
        ("PTR", DNS_PTR_DATAW),
        ("Ptr", DNS_PTR_DATAW),
        ("NS", DNS_PTR_DATAW),
        ("Ns", DNS_PTR_DATAW),
        ("CNAME", DNS_PTR_DATAW),
        ("Cname", DNS_PTR_DATAW),
        ("DNAME", DNS_PTR_DATAW),
        ("Dname", DNS_PTR_DATAW),
        ("MB", DNS_PTR_DATAW),
        ("Mb", DNS_PTR_DATAW),
        ("MD", DNS_PTR_DATAW),
        ("Md", DNS_PTR_DATAW),
        ("MF", DNS_PTR_DATAW),
        ("Mf", DNS_PTR_DATAW),
        ("MG", DNS_PTR_DATAW),
        ("Mg", DNS_PTR_DATAW),
        ("MR", DNS_PTR_DATAW),
        ("Mr", DNS_PTR_DATAW),
        ("MINFO", DNS_MINFO_DATAW),
        ("Minfo", DNS_MINFO_DATAW),
        ("RP", DNS_MINFO_DATAW),
        ("Rp", DNS_MINFO_DATAW),
        ("MX", DNS_MX_DATAW),
        ("Mx", DNS_MX_DATAW),
        ("AFSDB", DNS_MX_DATAW),
        ("Afsdb", DNS_MX_DATAW),
        ("RT", DNS_MX_DATAW),
        ("Rt", DNS_MX_DATAW),
        ("HINFO", DNS_TXT_DATAW),
        ("Hinfo", DNS_TXT_DATAW),
        ("ISDN", DNS_TXT_DATAW),
        ("Isdn", DNS_TXT_DATAW),
        ("TXT", DNS_TXT_DATAW),
        ("Txt", DNS_TXT_DATAW),
        ("X25", DNS_TXT_DATAW),
        ("Null", DNS_NULL_DATA),
        ("WKS", DNS_WKS_DATA),
        ("Wks", DNS_WKS_DATA),
        ("AAAA", DNS_AAAA_DATA),
        ("KEY", DNS_KEY_DATA),
        ("Key", DNS_KEY_DATA),
        ("SIG", DNS_SIG_DATAW),
        ("Sig", DNS_SIG_DATAW),
        ("ATMA", DNS_ATMA_DATA),
        ("Atma", DNS_ATMA_DATA),
        ("NXT", DNS_NXT_DATAW),
        ("Nxt", DNS_NXT_DATAW),
        ("SRV", DNS_SRV_DATAW),
        ("Srv", DNS_SRV_DATAW),
        ("NAPTR", DNS_NAPTR_DATAW),
        ("Naptr", DNS_NAPTR_DATAW),
        ("OPT", DNS_OPT_DATA),
        ("Opt", DNS_OPT_DATA),
        ("DS", DNS_DS_DATA),
        ("Ds", DNS_DS_DATA),
        ("RRSIG", DNS_RRSIG_DATAW),
        ("Rrsig", DNS_RRSIG_DATAW),
        ("NSEC", DNS_NSEC_DATAW),
        ("Nsec", DNS_NSEC_DATAW),
        ("DNSKEY", DNS_DNSKEY_DATA),
        ("Dnskey", DNS_DNSKEY_DATA),
        ("TKEY", DNS_TKEY_DATAW),
        ("Tkey", DNS_TKEY_DATAW),
        ("TSIG", DNS_TSIG_DATAW),
        ("Tsig", DNS_TSIG_DATAW),
        ("WINS", DNS_WINS_DATA),
        ("Wins", DNS_WINS_DATA),
        ("WINSR", DNS_WINSR_DATAW),
        ("WinsR", DNS_WINSR_DATAW),
        ("NBSTAT", DNS_WINSR_DATAW),
        ("Nbstat", DNS_WINSR_DATAW),
        ("DHCID", DNS_DHCID_DATA),
        ("NSEC3", DNS_NSEC3_DATA),
        ("Nsec3", DNS_NSEC3_DATA),
        ("NSEC3PARAM", DNS_NSEC3PARAM_DATA),
        ("Nsec3Param", DNS_NSEC3PARAM_DATA),
        ("TLSA", DNS_TLSA_DATA),
        ("Tlsa", DNS_TLSA_DATA),
        ("UNKNOWN", DNS_UNKNOWN_DATA),
        ("Unknown", DNS_UNKNOWN_DATA),
        ("pDataPtr", PBYTE),
    ]

# Self referencing struct tricks
class _DnsRecordW(Structure): pass
DNS_RECORDW = _DnsRecordW
PDNS_RECORDW = POINTER(_DnsRecordW)
_DnsRecordW._fields_ = [
    ("pNext", POINTER(_DnsRecordW)),
    ("pName", PWSTR),
    ("wType", WORD),
    ("wDataLength", WORD),
    ("Flags", _ANON__DNSRECORDW_SUB_UNION_1),
    ("dwTtl", DWORD),
    ("dwReserved", DWORD),
    ("Data", _ANON__DNSRECORDW_SUB_UNION_2),
]

class _DnsAddr(Structure):
    _fields_ = [
        ("MaxSa", CHAR * (DNS_ADDR_MAX_SOCKADDR_LENGTH)),
        ("DnsAddrUserDword", DWORD * (8)),
    ]
PDNS_ADDR = POINTER(_DnsAddr)
DNS_ADDR = _DnsAddr

class _DnsAddrArray(Structure):
    _fields_ = [
        ("MaxCount", DWORD),
        ("AddrCount", DWORD),
        ("Tag", DWORD),
        ("Family", WORD),
        ("WordReserved", WORD),
        ("Flags", DWORD),
        ("MatchFlag", DWORD),
        ("Reserved1", DWORD),
        ("Reserved2", DWORD),
        ("AddrArray", DNS_ADDR * (ANY_SIZE)),
    ]
PDNS_ADDR_ARRAY = POINTER(_DnsAddrArray)
DNS_ADDR_ARRAY = _DnsAddrArray

class _DNS_QUERY_REQUEST(Structure):
    _fields_ = [
        ("Version", ULONG),
        ("QueryName", PCWSTR),
        ("QueryType", WORD),
        ("QueryOptions", ULONG64),
        ("pDnsServerList", PDNS_ADDR_ARRAY),
        ("InterfaceIndex", ULONG),
        ("pQueryCompletionCallback", PDNS_QUERY_COMPLETION_ROUTINE),
        ("pQueryContext", PVOID),
    ]
PDNS_QUERY_REQUEST = POINTER(_DNS_QUERY_REQUEST)
DNS_QUERY_REQUEST = _DNS_QUERY_REQUEST

class _DNS_QUERY_CANCEL(Structure):
    _fields_ = [
        ("Reserved", CHAR * (32)),
    ]
PDNS_QUERY_CANCEL = POINTER(_DNS_QUERY_CANCEL)
DNS_QUERY_CANCEL = _DNS_QUERY_CANCEL

class _DNS_QUERY_RESULT(Structure):
    _fields_ = [
        ("Version", ULONG),
        ("QueryStatus", DNS_STATUS),
        ("QueryOptions", ULONG64),
        ("pQueryRecords", PVOID),
        ("Reserved", PVOID),
    ]
DNS_QUERY_RESULT = _DNS_QUERY_RESULT
PDNS_QUERY_RESULT = POINTER(_DNS_QUERY_RESULT)

class IP_ADDRESS_STRING(Structure):
    _fields_ = [
        ("String", CHAR * (4 * 4)),
    ]
IP_MASK_STRING = IP_ADDRESS_STRING
PIP_MASK_STRING = POINTER(IP_ADDRESS_STRING)
PIP_ADDRESS_STRING = POINTER(IP_ADDRESS_STRING)

# Self referencing struct tricks
class _IP_ADDR_STRING(Structure): pass
PIP_ADDR_STRING = POINTER(_IP_ADDR_STRING)
IP_ADDR_STRING = _IP_ADDR_STRING
_IP_ADDR_STRING._fields_ = [
    ("Next", POINTER(_IP_ADDR_STRING)),
    ("IpAddress", IP_ADDRESS_STRING),
    ("IpMask", IP_MASK_STRING),
    ("Context", DWORD),
]

# Self referencing struct tricks
class _IP_ADAPTER_INFO(Structure): pass
IP_ADAPTER_INFO = _IP_ADAPTER_INFO
PIP_ADAPTER_INFO = POINTER(_IP_ADAPTER_INFO)
_IP_ADAPTER_INFO._fields_ = [
    ("Next", POINTER(_IP_ADAPTER_INFO)),
    ("ComboIndex", DWORD),
    ("AdapterName", CHAR * (MAX_ADAPTER_NAME_LENGTH + 4)),
    ("Description", CHAR * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
    ("AddressLength", UINT),
    ("Address", BYTE * (MAX_ADAPTER_ADDRESS_LENGTH)),
    ("Index", DWORD),
    ("Type", UINT),
    ("DhcpEnabled", UINT),
    ("CurrentIpAddress", PIP_ADDR_STRING),
    ("IpAddressList", IP_ADDR_STRING),
    ("GatewayList", IP_ADDR_STRING),
    ("DhcpServer", IP_ADDR_STRING),
    ("HaveWins", BOOL),
    ("PrimaryWinsServer", IP_ADDR_STRING),
    ("SecondaryWinsServer", IP_ADDR_STRING),
    ("LeaseObtained", ULONGLONG),
    ("LeaseExpires", ULONGLONG),
]

class _IP_PER_ADAPTER_INFO_W2KSP1(Structure):
    _fields_ = [
        ("AutoconfigEnabled", UINT),
        ("AutoconfigActive", UINT),
        ("CurrentDnsServer", PIP_ADDR_STRING),
        ("DnsServerList", IP_ADDR_STRING),
    ]
PIP_PER_ADAPTER_INFO = POINTER(_IP_PER_ADAPTER_INFO_W2KSP1)
IP_PER_ADAPTER_INFO = _IP_PER_ADAPTER_INFO_W2KSP1
PIP_PER_ADAPTER_INFO_W2KSP1 = POINTER(_IP_PER_ADAPTER_INFO_W2KSP1)
IP_PER_ADAPTER_INFO_W2KSP1 = _IP_PER_ADAPTER_INFO_W2KSP1

KeyValueBasicInformation = EnumValue("_KEY_VALUE_INFORMATION_CLASS", "KeyValueBasicInformation", 0x0)
KeyValueFullInformation = EnumValue("_KEY_VALUE_INFORMATION_CLASS", "KeyValueFullInformation", 0x1)
KeyValuePartialInformation = EnumValue("_KEY_VALUE_INFORMATION_CLASS", "KeyValuePartialInformation", 0x2)
KeyValueFullInformationAlign64 = EnumValue("_KEY_VALUE_INFORMATION_CLASS", "KeyValueFullInformationAlign64", 0x3)
KeyValuePartialInformationAlign64 = EnumValue("_KEY_VALUE_INFORMATION_CLASS", "KeyValuePartialInformationAlign64", 0x4)
KeyValueLayerInformation = EnumValue("_KEY_VALUE_INFORMATION_CLASS", "KeyValueLayerInformation", 0x5)
MaxKeyValueInfoClass = EnumValue("_KEY_VALUE_INFORMATION_CLASS", "MaxKeyValueInfoClass", 0x6)
class _KEY_VALUE_INFORMATION_CLASS(EnumType):
    values = [KeyValueBasicInformation, KeyValueFullInformation, KeyValuePartialInformation, KeyValueFullInformationAlign64, KeyValuePartialInformationAlign64, KeyValueLayerInformation, MaxKeyValueInfoClass]
    mapper = FlagMapper(*values)
KEY_VALUE_INFORMATION_CLASS = _KEY_VALUE_INFORMATION_CLASS


KeyBasicInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyBasicInformation", 0x0)
KeyNodeInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyNodeInformation", 0x1)
KeyFullInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyFullInformation", 0x2)
KeyNameInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyNameInformation", 0x3)
KeyCachedInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyCachedInformation", 0x4)
KeyFlagsInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyFlagsInformation", 0x5)
KeyVirtualizationInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyVirtualizationInformation", 0x6)
KeyHandleTagsInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyHandleTagsInformation", 0x7)
KeyTrustInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyTrustInformation", 0x8)
KeyLayerInformation = EnumValue("_KEY_INFORMATION_CLASS", "KeyLayerInformation", 0x9)
MaxKeyInfoClass = EnumValue("_KEY_INFORMATION_CLASS", "MaxKeyInfoClass", 0xa)
class _KEY_INFORMATION_CLASS(EnumType):
    values = [KeyBasicInformation, KeyNodeInformation, KeyFullInformation, KeyNameInformation, KeyCachedInformation, KeyFlagsInformation, KeyVirtualizationInformation, KeyHandleTagsInformation, KeyTrustInformation, KeyLayerInformation, MaxKeyInfoClass]
    mapper = FlagMapper(*values)
KEY_INFORMATION_CLASS = _KEY_INFORMATION_CLASS


class _KEY_VALUE_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("TitleIndex", ULONG),
        ("Type", ULONG),
        ("NameLength", ULONG),
        ("Name", WCHAR * (1)),
    ]
PKEY_VALUE_BASIC_INFORMATION = POINTER(_KEY_VALUE_BASIC_INFORMATION)
KEY_VALUE_BASIC_INFORMATION = _KEY_VALUE_BASIC_INFORMATION

class _KEY_VALUE_FULL_INFORMATION(Structure):
    _fields_ = [
        ("TitleIndex", ULONG),
        ("Type", ULONG),
        ("DataOffset", ULONG),
        ("DataLength", ULONG),
        ("NameLength", ULONG),
        ("Name", WCHAR * (1)),
    ]
KEY_VALUE_FULL_INFORMATION = _KEY_VALUE_FULL_INFORMATION
PKEY_VALUE_FULL_INFORMATION = POINTER(_KEY_VALUE_FULL_INFORMATION)

class _KEY_VALUE_PARTIAL_INFORMATION(Structure):
    _fields_ = [
        ("TitleIndex", ULONG),
        ("Type", ULONG),
        ("DataLength", ULONG),
        ("Data", UCHAR * (1)),
    ]
PKEY_VALUE_PARTIAL_INFORMATION = POINTER(_KEY_VALUE_PARTIAL_INFORMATION)
KEY_VALUE_PARTIAL_INFORMATION = _KEY_VALUE_PARTIAL_INFORMATION

SC_STATUS_PROCESS_INFO = EnumValue("_SC_STATUS_TYPE", "SC_STATUS_PROCESS_INFO", 0x0)
class _SC_STATUS_TYPE(EnumType):
    values = [SC_STATUS_PROCESS_INFO]
    mapper = FlagMapper(*values)
SC_STATUS_TYPE = _SC_STATUS_TYPE


SC_ENUM_PROCESS_INFO = EnumValue("_SC_ENUM_TYPE", "SC_ENUM_PROCESS_INFO", 0x0)
class _SC_ENUM_TYPE(EnumType):
    values = [SC_ENUM_PROCESS_INFO]
    mapper = FlagMapper(*values)
SC_ENUM_TYPE = _SC_ENUM_TYPE


class _SERVICE_STATUS(Structure):
    _fields_ = [
        ("dwServiceType", DWORD),
        ("dwCurrentState", DWORD),
        ("dwControlsAccepted", DWORD),
        ("dwWin32ExitCode", DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint", DWORD),
        ("dwWaitHint", DWORD),
    ]
SERVICE_STATUS = _SERVICE_STATUS
LPSERVICE_STATUS = POINTER(_SERVICE_STATUS)

class _SERVICE_STATUS_PROCESS(Structure):
    _fields_ = [
        ("dwServiceType", DWORD),
        ("dwCurrentState", DWORD),
        ("dwControlsAccepted", DWORD),
        ("dwWin32ExitCode", DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint", DWORD),
        ("dwWaitHint", DWORD),
        ("dwProcessId", DWORD),
        ("dwServiceFlags", DWORD),
    ]
LPSERVICE_STATUS_PROCESS = POINTER(_SERVICE_STATUS_PROCESS)
SERVICE_STATUS_PROCESS = _SERVICE_STATUS_PROCESS

class _SERVICE_STATUS_PROCESS(_SERVICE_STATUS_PROCESS):

    SERVICE_STATE = FlagMapper(SERVICE_STOPPED,
        SERVICE_START_PENDING,
        SERVICE_STOP_PENDING,
        SERVICE_RUNNING,
        SERVICE_CONTINUE_PENDING,
        SERVICE_PAUSE_PENDING,
        SERVICE_PAUSED)

    SERVICE_TYPE = FlagMapper(SERVICE_KERNEL_DRIVER,
        SERVICE_FILE_SYSTEM_DRIVER,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_WIN32_SHARE_PROCESS,
        SERVICE_INTERACTIVE_PROCESS)

    SERVICE_CONTROLE_ACCEPTED = FlagMapper()

    SERVICE_FLAGS = FlagMapper(SERVICE_RUNS_IN_SYSTEM_PROCESS)


    @property
    def dwCurrentState(self):
        return self.SERVICE_STATE[super(_SERVICE_STATUS_PROCESS, self).dwCurrentState]

    @property
    def dwServiceType(self):
        return self.SERVICE_TYPE[super(_SERVICE_STATUS_PROCESS, self).dwServiceType]

    @property
    def dwControlsAccepted(self):
        return self.SERVICE_CONTROLE_ACCEPTED[super(_SERVICE_STATUS_PROCESS, self).dwControlsAccepted]

    @property
    def dwServiceFlags(self):
        return self.SERVICE_FLAGS[super(_SERVICE_STATUS_PROCESS, self).dwServiceFlags]

    # Python friendly names
    state = dwCurrentState
    type = dwServiceType
    control_accepted = dwControlsAccepted
    flags = dwServiceFlags


    def __repr__(self):
        return """<{0} type={1!r} state={2!r}>""".format(type(self).__name__,
            self.type,
            self.state)
LPSERVICE_STATUS_PROCESS = POINTER(_SERVICE_STATUS_PROCESS)
SERVICE_STATUS_PROCESS = _SERVICE_STATUS_PROCESS
class _ENUM_SERVICE_STATUS_PROCESSA(Structure):
    _fields_ = [
        ("lpServiceName", LPSTR),
        ("lpDisplayName", LPSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]
LPENUM_SERVICE_STATUS_PROCESSA = POINTER(_ENUM_SERVICE_STATUS_PROCESSA)
ENUM_SERVICE_STATUS_PROCESSA = _ENUM_SERVICE_STATUS_PROCESSA

class _ENUM_SERVICE_STATUS_PROCESSW(Structure):
    _fields_ = [
        ("lpServiceName", LPWSTR),
        ("lpDisplayName", LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]
ENUM_SERVICE_STATUS_PROCESSW = _ENUM_SERVICE_STATUS_PROCESSW
LPENUM_SERVICE_STATUS_PROCESSW = POINTER(_ENUM_SERVICE_STATUS_PROCESSW)

class _ENUM_SERVICE_STATUSA(Structure):
    _fields_ = [
        ("lpServiceName", LPSTR),
        ("lpDisplayName", LPSTR),
        ("ServiceStatus", SERVICE_STATUS),
    ]
LPENUM_SERVICE_STATUSA = POINTER(_ENUM_SERVICE_STATUSA)
ENUM_SERVICE_STATUSA = _ENUM_SERVICE_STATUSA

class _ENUM_SERVICE_STATUSW(Structure):
    _fields_ = [
        ("lpServiceName", LPWSTR),
        ("lpDisplayName", LPWSTR),
        ("ServiceStatus", SERVICE_STATUS),
    ]
ENUM_SERVICE_STATUSW = _ENUM_SERVICE_STATUSW
LPENUM_SERVICE_STATUSW = POINTER(_ENUM_SERVICE_STATUSW)

class _QUERY_SERVICE_CONFIGA(Structure):
    _fields_ = [
        ("dwServiceType", DWORD),
        ("dwStartType", DWORD),
        ("dwErrorControl", DWORD),
        ("lpBinaryPathName", LPSTR),
        ("lpLoadOrderGroup", LPSTR),
        ("dwTagId", DWORD),
        ("lpDependencies", LPSTR),
        ("lpServiceStartName", LPSTR),
        ("lpDisplayName", LPSTR),
    ]
QUERY_SERVICE_CONFIGA = _QUERY_SERVICE_CONFIGA
LPQUERY_SERVICE_CONFIGA = POINTER(_QUERY_SERVICE_CONFIGA)

class _QUERY_SERVICE_CONFIGW(Structure):
    _fields_ = [
        ("dwServiceType", DWORD),
        ("dwStartType", DWORD),
        ("dwErrorControl", DWORD),
        ("lpBinaryPathName", LPWSTR),
        ("lpLoadOrderGroup", LPWSTR),
        ("dwTagId", DWORD),
        ("lpDependencies", LPWSTR),
        ("lpServiceStartName", LPWSTR),
        ("lpDisplayName", LPWSTR),
    ]
LPQUERY_SERVICE_CONFIGW = POINTER(_QUERY_SERVICE_CONFIGW)
QUERY_SERVICE_CONFIGW = _QUERY_SERVICE_CONFIGW

class _SERVICE_TABLE_ENTRYA(Structure):
    _fields_ = [
        ("lpServiceName", LPSTR),
        ("lpServiceProc", LPSERVICE_MAIN_FUNCTIONA),
    ]
LPSERVICE_TABLE_ENTRYA = POINTER(_SERVICE_TABLE_ENTRYA)
SERVICE_TABLE_ENTRYA = _SERVICE_TABLE_ENTRYA

class _SERVICE_TABLE_ENTRYW(Structure):
    _fields_ = [
        ("lpServiceName", LPWSTR),
        ("lpServiceProc", LPSERVICE_MAIN_FUNCTIONW),
    ]
SERVICE_TABLE_ENTRYW = _SERVICE_TABLE_ENTRYW
LPSERVICE_TABLE_ENTRYW = POINTER(_SERVICE_TABLE_ENTRYW)

class _SP_DEVICE_INTERFACE_DATA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", DWORD),
        ("Reserved", ULONG_PTR),
    ]
PSP_DEVICE_INTERFACE_DATA = POINTER(_SP_DEVICE_INTERFACE_DATA)
SP_DEVICE_INTERFACE_DATA = _SP_DEVICE_INTERFACE_DATA

class _SP_DEVINFO_DATA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("ClassGuid", GUID),
        ("DevInst", DWORD),
        ("Reserved", ULONG_PTR),
    ]
PSP_DEVINFO_DATA = POINTER(_SP_DEVINFO_DATA)
SP_DEVINFO_DATA = _SP_DEVINFO_DATA

AO_NONE = EnumValue("ACTIVATEOPTIONS", "AO_NONE", 0x0)
AO_DESIGNMODE = EnumValue("ACTIVATEOPTIONS", "AO_DESIGNMODE", 0x1)
AO_NOERRORUI = EnumValue("ACTIVATEOPTIONS", "AO_NOERRORUI", 0x2)
AO_NOSPLASHSCREEN = EnumValue("ACTIVATEOPTIONS", "AO_NOSPLASHSCREEN", 0x4)
AO_PRELAUNCH = EnumValue("ACTIVATEOPTIONS", "AO_PRELAUNCH", 0x2000000)
class ACTIVATEOPTIONS(EnumType):
    values = [AO_NONE, AO_DESIGNMODE, AO_NOERRORUI, AO_NOSPLASHSCREEN, AO_PRELAUNCH]
    mapper = FlagMapper(*values)


PES_UNKNOWN = EnumValue("PACKAGE_EXECUTION_STATE", "PES_UNKNOWN", 0x0)
PES_RUNNING = EnumValue("PACKAGE_EXECUTION_STATE", "PES_RUNNING", 0x1)
PES_SUSPENDING = EnumValue("PACKAGE_EXECUTION_STATE", "PES_SUSPENDING", 0x2)
PES_SUSPENDED = EnumValue("PACKAGE_EXECUTION_STATE", "PES_SUSPENDED", 0x3)
PES_TERMINATED = EnumValue("PACKAGE_EXECUTION_STATE", "PES_TERMINATED", 0x4)
class PACKAGE_EXECUTION_STATE(EnumType):
    values = [PES_UNKNOWN, PES_RUNNING, PES_SUSPENDING, PES_SUSPENDED, PES_TERMINATED]
    mapper = FlagMapper(*values)


class _SHITEMID(Structure):
    _fields_ = [
        ("cb", USHORT),
        ("abID", BYTE * (1)),
    ]
SHITEMID = _SHITEMID

class _ITEMIDLIST(Structure):
    _fields_ = [
        ("mkid", SHITEMID),
    ]
ITEMIDLIST = _ITEMIDLIST
PCIDLIST_ABSOLUTE = POINTER(_ITEMIDLIST)
PIDLIST_ABSOLUTE = POINTER(_ITEMIDLIST)

class _SHFILEOPSTRUCTA(Structure):
    _fields_ = [
        ("hwnd", HWND),
        ("wFunc", UINT),
        ("pFrom", PCSTR),
        ("pTo", PCSTR),
        ("fFlags", FILEOP_FLAGS),
        ("fAnyOperationsAborted", BOOL),
        ("hNameMappings", LPVOID),
        ("lpszProgressTitle", PCSTR),
    ]
SHFILEOPSTRUCTA = _SHFILEOPSTRUCTA
LPSHFILEOPSTRUCTA = POINTER(_SHFILEOPSTRUCTA)

SymNone = EnumValue("SYM_TYPE", "SymNone", 0x0)
SymCoff = EnumValue("SYM_TYPE", "SymCoff", 0x1)
SymCv = EnumValue("SYM_TYPE", "SymCv", 0x2)
SymPdb = EnumValue("SYM_TYPE", "SymPdb", 0x3)
SymExport = EnumValue("SYM_TYPE", "SymExport", 0x4)
SymDeferred = EnumValue("SYM_TYPE", "SymDeferred", 0x5)
SymSym = EnumValue("SYM_TYPE", "SymSym", 0x6)
SymDia = EnumValue("SYM_TYPE", "SymDia", 0x7)
SymVirtual = EnumValue("SYM_TYPE", "SymVirtual", 0x8)
NumSymTypes = EnumValue("SYM_TYPE", "NumSymTypes", 0x9)
class SYM_TYPE(EnumType):
    values = [SymNone, SymCoff, SymCv, SymPdb, SymExport, SymDeferred, SymSym, SymDia, SymVirtual, NumSymTypes]
    mapper = FlagMapper(*values)


btNoType = EnumValue("BasicType", "btNoType", 0x0)
btVoid = EnumValue("BasicType", "btVoid", 0x1)
btChar = EnumValue("BasicType", "btChar", 0x2)
btWChar = EnumValue("BasicType", "btWChar", 0x3)
btInt = EnumValue("BasicType", "btInt", 0x6)
btUInt = EnumValue("BasicType", "btUInt", 0x7)
btFloat = EnumValue("BasicType", "btFloat", 0x8)
btBCD = EnumValue("BasicType", "btBCD", 0x9)
btBool = EnumValue("BasicType", "btBool", 0xa)
btLong = EnumValue("BasicType", "btLong", 0xd)
btULong = EnumValue("BasicType", "btULong", 0xe)
btCurrency = EnumValue("BasicType", "btCurrency", 0x19)
btDate = EnumValue("BasicType", "btDate", 0x1a)
btVariant = EnumValue("BasicType", "btVariant", 0x1b)
btComplex = EnumValue("BasicType", "btComplex", 0x1c)
btBit = EnumValue("BasicType", "btBit", 0x1d)
btBSTR = EnumValue("BasicType", "btBSTR", 0x1e)
btHresult = EnumValue("BasicType", "btHresult", 0x1f)
class BasicType(EnumType):
    values = [btNoType, btVoid, btChar, btWChar, btInt, btUInt, btFloat, btBCD, btBool, btLong, btULong, btCurrency, btDate, btVariant, btComplex, btBit, btBSTR, btHresult]
    mapper = FlagMapper(*values)


DataIsUnknown = EnumValue("DataKind", "DataIsUnknown", 0x0)
DataIsLocal = EnumValue("DataKind", "DataIsLocal", 0x1)
DataIsStaticLocal = EnumValue("DataKind", "DataIsStaticLocal", 0x2)
DataIsParam = EnumValue("DataKind", "DataIsParam", 0x3)
DataIsObjectPtr = EnumValue("DataKind", "DataIsObjectPtr", 0x4)
DataIsFileStatic = EnumValue("DataKind", "DataIsFileStatic", 0x5)
DataIsGlobal = EnumValue("DataKind", "DataIsGlobal", 0x6)
DataIsMember = EnumValue("DataKind", "DataIsMember", 0x7)
DataIsStaticMember = EnumValue("DataKind", "DataIsStaticMember", 0x8)
DataIsConstant = EnumValue("DataKind", "DataIsConstant", 0x9)
class DataKind(EnumType):
    values = [DataIsUnknown, DataIsLocal, DataIsStaticLocal, DataIsParam, DataIsObjectPtr, DataIsFileStatic, DataIsGlobal, DataIsMember, DataIsStaticMember, DataIsConstant]
    mapper = FlagMapper(*values)


UdtStruct = EnumValue("UdtKind", "UdtStruct", 0x0)
UdtClass = EnumValue("UdtKind", "UdtClass", 0x1)
UdtUnion = EnumValue("UdtKind", "UdtUnion", 0x2)
class UdtKind(EnumType):
    values = [UdtStruct, UdtClass, UdtUnion]
    mapper = FlagMapper(*values)


SymTagNull = EnumValue("_SymTagEnum", "SymTagNull", 0x0)
SymTagExe = EnumValue("_SymTagEnum", "SymTagExe", 0x1)
SymTagCompiland = EnumValue("_SymTagEnum", "SymTagCompiland", 0x2)
SymTagCompilandDetails = EnumValue("_SymTagEnum", "SymTagCompilandDetails", 0x3)
SymTagCompilandEnv = EnumValue("_SymTagEnum", "SymTagCompilandEnv", 0x4)
SymTagFunction = EnumValue("_SymTagEnum", "SymTagFunction", 0x5)
SymTagBlock = EnumValue("_SymTagEnum", "SymTagBlock", 0x6)
SymTagData = EnumValue("_SymTagEnum", "SymTagData", 0x7)
SymTagAnnotation = EnumValue("_SymTagEnum", "SymTagAnnotation", 0x8)
SymTagLabel = EnumValue("_SymTagEnum", "SymTagLabel", 0x9)
SymTagPublicSymbol = EnumValue("_SymTagEnum", "SymTagPublicSymbol", 0xa)
SymTagUDT = EnumValue("_SymTagEnum", "SymTagUDT", 0xb)
SymTagEnum = EnumValue("_SymTagEnum", "SymTagEnum", 0xc)
SymTagFunctionType = EnumValue("_SymTagEnum", "SymTagFunctionType", 0xd)
SymTagPointerType = EnumValue("_SymTagEnum", "SymTagPointerType", 0xe)
SymTagArrayType = EnumValue("_SymTagEnum", "SymTagArrayType", 0xf)
SymTagBaseType = EnumValue("_SymTagEnum", "SymTagBaseType", 0x10)
SymTagTypedef = EnumValue("_SymTagEnum", "SymTagTypedef", 0x11)
SymTagBaseClass = EnumValue("_SymTagEnum", "SymTagBaseClass", 0x12)
SymTagFriend = EnumValue("_SymTagEnum", "SymTagFriend", 0x13)
SymTagFunctionArgType = EnumValue("_SymTagEnum", "SymTagFunctionArgType", 0x14)
SymTagFuncDebugStart = EnumValue("_SymTagEnum", "SymTagFuncDebugStart", 0x15)
SymTagFuncDebugEnd = EnumValue("_SymTagEnum", "SymTagFuncDebugEnd", 0x16)
SymTagUsingNamespace = EnumValue("_SymTagEnum", "SymTagUsingNamespace", 0x17)
SymTagVTableShape = EnumValue("_SymTagEnum", "SymTagVTableShape", 0x18)
SymTagVTable = EnumValue("_SymTagEnum", "SymTagVTable", 0x19)
SymTagCustom = EnumValue("_SymTagEnum", "SymTagCustom", 0x1a)
SymTagThunk = EnumValue("_SymTagEnum", "SymTagThunk", 0x1b)
SymTagCustomType = EnumValue("_SymTagEnum", "SymTagCustomType", 0x1c)
SymTagManagedType = EnumValue("_SymTagEnum", "SymTagManagedType", 0x1d)
SymTagDimension = EnumValue("_SymTagEnum", "SymTagDimension", 0x1e)
class _SymTagEnum(EnumType):
    values = [SymTagNull, SymTagExe, SymTagCompiland, SymTagCompilandDetails, SymTagCompilandEnv, SymTagFunction, SymTagBlock, SymTagData, SymTagAnnotation, SymTagLabel, SymTagPublicSymbol, SymTagUDT, SymTagEnum, SymTagFunctionType, SymTagPointerType, SymTagArrayType, SymTagBaseType, SymTagTypedef, SymTagBaseClass, SymTagFriend, SymTagFunctionArgType, SymTagFuncDebugStart, SymTagFuncDebugEnd, SymTagUsingNamespace, SymTagVTableShape, SymTagVTable, SymTagCustom, SymTagThunk, SymTagCustomType, SymTagManagedType, SymTagDimension]
    mapper = FlagMapper(*values)
SymTagEnum = _SymTagEnum


SYMOPT_EX_DISABLEACCESSTIMEUPDATE = EnumValue("_IMAGEHLP_EXTENDED_OPTIONS", "SYMOPT_EX_DISABLEACCESSTIMEUPDATE", 0x0)
SYMOPT_EX_MAX = EnumValue("_IMAGEHLP_EXTENDED_OPTIONS", "SYMOPT_EX_MAX", 0x1)
SYMOPT_EX_LASTVALIDDEBUGDIRECTORY = EnumValue("_IMAGEHLP_EXTENDED_OPTIONS", "SYMOPT_EX_LASTVALIDDEBUGDIRECTORY", 0x2)
class _IMAGEHLP_EXTENDED_OPTIONS(EnumType):
    values = [SYMOPT_EX_DISABLEACCESSTIMEUPDATE, SYMOPT_EX_MAX, SYMOPT_EX_LASTVALIDDEBUGDIRECTORY]
    mapper = FlagMapper(*values)
IMAGEHLP_EXTENDED_OPTIONS = _IMAGEHLP_EXTENDED_OPTIONS


TI_GET_SYMTAG = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_SYMTAG", 0x0)
TI_GET_SYMNAME = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_SYMNAME", 0x1)
TI_GET_LENGTH = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_LENGTH", 0x2)
TI_GET_TYPE = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_TYPE", 0x3)
TI_GET_TYPEID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_TYPEID", 0x4)
TI_GET_BASETYPE = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_BASETYPE", 0x5)
TI_GET_ARRAYINDEXTYPEID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_ARRAYINDEXTYPEID", 0x6)
TI_FINDCHILDREN = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_FINDCHILDREN", 0x7)
TI_GET_DATAKIND = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_DATAKIND", 0x8)
TI_GET_ADDRESSOFFSET = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_ADDRESSOFFSET", 0x9)
TI_GET_OFFSET = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_OFFSET", 0xa)
TI_GET_VALUE = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VALUE", 0xb)
TI_GET_COUNT = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_COUNT", 0xc)
TI_GET_CHILDRENCOUNT = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_CHILDRENCOUNT", 0xd)
TI_GET_BITPOSITION = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_BITPOSITION", 0xe)
TI_GET_VIRTUALBASECLASS = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALBASECLASS", 0xf)
TI_GET_VIRTUALTABLESHAPEID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALTABLESHAPEID", 0x10)
TI_GET_VIRTUALBASEPOINTEROFFSET = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALBASEPOINTEROFFSET", 0x11)
TI_GET_CLASSPARENTID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_CLASSPARENTID", 0x12)
TI_GET_NESTED = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_NESTED", 0x13)
TI_GET_SYMINDEX = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_SYMINDEX", 0x14)
TI_GET_LEXICALPARENT = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_LEXICALPARENT", 0x15)
TI_GET_ADDRESS = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_ADDRESS", 0x16)
TI_GET_THISADJUST = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_THISADJUST", 0x17)
TI_GET_UDTKIND = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_UDTKIND", 0x18)
TI_IS_EQUIV_TO = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_IS_EQUIV_TO", 0x19)
TI_GET_CALLING_CONVENTION = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_CALLING_CONVENTION", 0x1a)
TI_IS_CLOSE_EQUIV_TO = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_IS_CLOSE_EQUIV_TO", 0x1b)
TI_GTIEX_REQS_VALID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GTIEX_REQS_VALID", 0x1c)
TI_GET_VIRTUALBASEOFFSET = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALBASEOFFSET", 0x1d)
TI_GET_VIRTUALBASEDISPINDEX = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALBASEDISPINDEX", 0x1e)
TI_GET_IS_REFERENCE = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_IS_REFERENCE", 0x1f)
TI_GET_INDIRECTVIRTUALBASECLASS = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_INDIRECTVIRTUALBASECLASS", 0x20)
IMAGEHLP_SYMBOL_TYPE_INFO_MAX = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "IMAGEHLP_SYMBOL_TYPE_INFO_MAX", 0x21)
class _IMAGEHLP_SYMBOL_TYPE_INFO(EnumType):
    values = [TI_GET_SYMTAG, TI_GET_SYMNAME, TI_GET_LENGTH, TI_GET_TYPE, TI_GET_TYPEID, TI_GET_BASETYPE, TI_GET_ARRAYINDEXTYPEID, TI_FINDCHILDREN, TI_GET_DATAKIND, TI_GET_ADDRESSOFFSET, TI_GET_OFFSET, TI_GET_VALUE, TI_GET_COUNT, TI_GET_CHILDRENCOUNT, TI_GET_BITPOSITION, TI_GET_VIRTUALBASECLASS, TI_GET_VIRTUALTABLESHAPEID, TI_GET_VIRTUALBASEPOINTEROFFSET, TI_GET_CLASSPARENTID, TI_GET_NESTED, TI_GET_SYMINDEX, TI_GET_LEXICALPARENT, TI_GET_ADDRESS, TI_GET_THISADJUST, TI_GET_UDTKIND, TI_IS_EQUIV_TO, TI_GET_CALLING_CONVENTION, TI_IS_CLOSE_EQUIV_TO, TI_GTIEX_REQS_VALID, TI_GET_VIRTUALBASEOFFSET, TI_GET_VIRTUALBASEDISPINDEX, TI_GET_IS_REFERENCE, TI_GET_INDIRECTVIRTUALBASECLASS, IMAGEHLP_SYMBOL_TYPE_INFO_MAX]
    mapper = FlagMapper(*values)
IMAGEHLP_SYMBOL_TYPE_INFO = _IMAGEHLP_SYMBOL_TYPE_INFO


sevInfo = EnumValue("_CBA_EVENT_SEVERITY", "sevInfo", 0x0)
sevProblem = EnumValue("_CBA_EVENT_SEVERITY", "sevProblem", 0x1)
sevAttn = EnumValue("_CBA_EVENT_SEVERITY", "sevAttn", 0x2)
sevFatal = EnumValue("_CBA_EVENT_SEVERITY", "sevFatal", 0x3)
sevMax = EnumValue("_CBA_EVENT_SEVERITY", "sevMax", 0x4)
class _CBA_EVENT_SEVERITY(EnumType):
    values = [sevInfo, sevProblem, sevAttn, sevFatal, sevMax]
    mapper = FlagMapper(*values)
CBA_EVENT_SEVERITY = _CBA_EVENT_SEVERITY


AddrMode1616 = EnumValue("ADDRESS_MODE", "AddrMode1616", 0x0)
AddrMode1632 = EnumValue("ADDRESS_MODE", "AddrMode1632", 0x1)
AddrModeReal = EnumValue("ADDRESS_MODE", "AddrModeReal", 0x2)
AddrModeFlat = EnumValue("ADDRESS_MODE", "AddrModeFlat", 0x3)
class ADDRESS_MODE(EnumType):
    values = [AddrMode1616, AddrMode1632, AddrModeReal, AddrModeFlat]
    mapper = FlagMapper(*values)


class _IMAGEHLP_MODULE64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("BaseOfImage", DWORD64),
        ("ImageSize", DWORD),
        ("TimeDateStamp", DWORD),
        ("CheckSum", DWORD),
        ("NumSyms", DWORD),
        ("SymType", SYM_TYPE),
        ("ModuleName", CHAR * (32)),
        ("ImageName", CHAR * (256)),
        ("LoadedImageName", CHAR * (256)),
        ("LoadedPdbName", CHAR * (256)),
        ("CVSig", DWORD),
        ("CVData", CHAR * (MAX_PATH * 3)),
        ("PdbSig", DWORD),
        ("PdbSig70", GUID),
        ("PdbAge", DWORD),
        ("PdbUnmatched", BOOL),
        ("DbgUnmatched", BOOL),
        ("LineNumbers", BOOL),
        ("GlobalSymbols", BOOL),
        ("TypeInfo", BOOL),
        ("SourceIndexed", BOOL),
        ("Publics", BOOL),
    ]
PIMAGEHLP_MODULE64 = POINTER(_IMAGEHLP_MODULE64)
IMAGEHLP_MODULE64 = _IMAGEHLP_MODULE64

class _IMAGEHLP_MODULEW64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("BaseOfImage", DWORD64),
        ("ImageSize", DWORD),
        ("TimeDateStamp", DWORD),
        ("CheckSum", DWORD),
        ("NumSyms", DWORD),
        ("SymType", SYM_TYPE),
        ("ModuleName", WCHAR * (32)),
        ("ImageName", WCHAR * (256)),
        ("LoadedImageName", WCHAR * (256)),
        ("LoadedPdbName", WCHAR * (256)),
        ("CVSig", DWORD),
        ("CVData", POINTER(WCHAR) * (MAX_PATH * 3)),
        ("PdbSig", DWORD),
        ("PdbSig70", GUID),
        ("PdbAge", DWORD),
        ("PdbUnmatched", BOOL),
        ("DbgUnmatched", BOOL),
        ("LineNumbers", BOOL),
        ("GlobalSymbols", BOOL),
        ("TypeInfo", BOOL),
        ("SourceIndexed", BOOL),
        ("Publics", BOOL),
        ("MachineType", DWORD),
        ("Reserved", DWORD),
    ]
PIMAGEHLP_MODULEW64 = POINTER(_IMAGEHLP_MODULEW64)
IMAGEHLP_MODULEW64 = _IMAGEHLP_MODULEW64

class _SYMBOL_INFO(Structure):
    _fields_ = [
        ("SizeOfStruct", ULONG),
        ("TypeIndex", ULONG),
        ("Reserved", ULONG64 * (2)),
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
        ("Name", CHAR * (1)),
    ]
SYMBOL_INFO = _SYMBOL_INFO
PSYMBOL_INFO = POINTER(_SYMBOL_INFO)

class _SYMBOL_INFOW(Structure):
    _fields_ = [
        ("SizeOfStruct", ULONG),
        ("TypeIndex", ULONG),
        ("Reserved", ULONG64 * (2)),
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
        ("Name", WCHAR * (1)),
    ]
SYMBOL_INFOW = _SYMBOL_INFOW
PSYMBOL_INFOW = POINTER(_SYMBOL_INFOW)

class SYMSRV_INDEX_INFOW(Structure):
    _fields_ = [
        ("sizeofstruct", DWORD),
        ("file", WCHAR * (MAX_PATH + 1)),
        ("stripped", BOOL),
        ("timestamp", DWORD),
        ("size", DWORD),
        ("dbgfile", WCHAR * (MAX_PATH + 1)),
        ("pdbfile", WCHAR * (MAX_PATH + 1)),
        ("guid", GUID),
        ("sig", DWORD),
        ("age", DWORD),
    ]
PSYMSRV_INDEX_INFOW = POINTER(SYMSRV_INDEX_INFOW)

class SYMSRV_INDEX_INFO(Structure):
    _fields_ = [
        ("sizeofstruct", DWORD),
        ("file", CHAR * (MAX_PATH + 1)),
        ("stripped", BOOL),
        ("timestamp", DWORD),
        ("size", DWORD),
        ("dbgfile", CHAR * (MAX_PATH + 1)),
        ("pdbfile", CHAR * (MAX_PATH + 1)),
        ("guid", GUID),
        ("sig", DWORD),
        ("age", DWORD),
    ]
PSYMSRV_INDEX_INFO = POINTER(SYMSRV_INDEX_INFO)

class _IMAGEHLP_SYMBOL(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("Address", DWORD),
        ("Size", DWORD),
        ("Flags", DWORD),
        ("MaxNameLength", DWORD),
        ("Name", CHAR * (1)),
    ]
PIMAGEHLP_SYMBOL = POINTER(_IMAGEHLP_SYMBOL)
IMAGEHLP_SYMBOL = _IMAGEHLP_SYMBOL

class _IMAGEHLP_SYMBOL64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("Address", DWORD64),
        ("Size", DWORD),
        ("Flags", DWORD),
        ("MaxNameLength", DWORD),
        ("Name", CHAR * (1)),
    ]
PIMAGEHLP_SYMBOL64 = POINTER(_IMAGEHLP_SYMBOL64)
IMAGEHLP_SYMBOL64 = _IMAGEHLP_SYMBOL64

class _IMAGEHLP_SYMBOLW64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("Address", DWORD64),
        ("Size", DWORD),
        ("Flags", DWORD),
        ("MaxNameLength", DWORD),
        ("Name", WCHAR * (1)),
    ]
PIMAGEHLP_SYMBOLW64 = POINTER(_IMAGEHLP_SYMBOLW64)
IMAGEHLP_SYMBOLW64 = _IMAGEHLP_SYMBOLW64

class _IMAGEHLP_STACK_FRAME(Structure):
    _fields_ = [
        ("InstructionOffset", ULONG64),
        ("ReturnOffset", ULONG64),
        ("FrameOffset", ULONG64),
        ("StackOffset", ULONG64),
        ("BackingStoreOffset", ULONG64),
        ("FuncTableEntry", ULONG64),
        ("Params", ULONG64 * (4)),
        ("Reserved", ULONG64 * (5)),
        ("Virtual", BOOL),
        ("Reserved2", ULONG),
    ]
IMAGEHLP_STACK_FRAME = _IMAGEHLP_STACK_FRAME
PIMAGEHLP_STACK_FRAME = POINTER(_IMAGEHLP_STACK_FRAME)

class _IMAGEHLP_CBA_EVENT(Structure):
    _fields_ = [
        ("severity", CBA_EVENT_SEVERITY),
        ("code", DWORD),
        ("desc", PCHAR),
        ("object", PVOID),
    ]
PIMAGEHLP_CBA_EVENT = POINTER(_IMAGEHLP_CBA_EVENT)
IMAGEHLP_CBA_EVENT = _IMAGEHLP_CBA_EVENT

class _IMAGEHLP_CBA_EVENTW(Structure):
    _fields_ = [
        ("severity", CBA_EVENT_SEVERITY),
        ("code", DWORD),
        ("desc", PCWSTR),
        ("object", PVOID),
    ]
PIMAGEHLP_CBA_EVENTW = POINTER(_IMAGEHLP_CBA_EVENTW)
IMAGEHLP_CBA_EVENTW = _IMAGEHLP_CBA_EVENTW

class _IMAGEHLP_CBA_READ_MEMORY(Structure):
    _fields_ = [
        ("addr", DWORD64),
        ("buf", PVOID),
        ("bytes", DWORD),
        ("bytesread", POINTER(DWORD)),
    ]
PIMAGEHLP_CBA_READ_MEMORY = POINTER(_IMAGEHLP_CBA_READ_MEMORY)
IMAGEHLP_CBA_READ_MEMORY = _IMAGEHLP_CBA_READ_MEMORY

class _IMAGEHLP_DEFERRED_SYMBOL_LOAD(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("BaseOfImage", DWORD),
        ("CheckSum", DWORD),
        ("TimeDateStamp", DWORD),
        ("FileName", CHAR * (MAX_PATH)),
        ("Reparse", BOOLEAN),
        ("hFile", HANDLE),
    ]
PIMAGEHLP_DEFERRED_SYMBOL_LOAD = POINTER(_IMAGEHLP_DEFERRED_SYMBOL_LOAD)
IMAGEHLP_DEFERRED_SYMBOL_LOAD = _IMAGEHLP_DEFERRED_SYMBOL_LOAD

class _IMAGEHLP_DEFERRED_SYMBOL_LOAD64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("BaseOfImage", DWORD64),
        ("CheckSum", DWORD),
        ("TimeDateStamp", DWORD),
        ("FileName", CHAR * (MAX_PATH)),
        ("Reparse", BOOLEAN),
        ("hFile", HANDLE),
        ("Flags", DWORD),
    ]
IMAGEHLP_DEFERRED_SYMBOL_LOAD64 = _IMAGEHLP_DEFERRED_SYMBOL_LOAD64
PIMAGEHLP_DEFERRED_SYMBOL_LOAD64 = POINTER(_IMAGEHLP_DEFERRED_SYMBOL_LOAD64)

class _IMAGEHLP_DEFERRED_SYMBOL_LOADW64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("BaseOfImage", DWORD64),
        ("CheckSum", DWORD),
        ("TimeDateStamp", DWORD),
        ("FileName", WCHAR * (MAX_PATH + 1)),
        ("Reparse", BOOLEAN),
        ("hFile", HANDLE),
        ("Flags", DWORD),
    ]
IMAGEHLP_DEFERRED_SYMBOL_LOADW64 = _IMAGEHLP_DEFERRED_SYMBOL_LOADW64
PIMAGEHLP_DEFERRED_SYMBOL_LOADW64 = POINTER(_IMAGEHLP_DEFERRED_SYMBOL_LOADW64)

class _IMAGEHLP_DUPLICATE_SYMBOL64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("NumberOfDups", DWORD),
        ("Symbol", PIMAGEHLP_SYMBOL64),
        ("SelectedSymbol", DWORD),
    ]
PIMAGEHLP_DUPLICATE_SYMBOL64 = POINTER(_IMAGEHLP_DUPLICATE_SYMBOL64)
IMAGEHLP_DUPLICATE_SYMBOL64 = _IMAGEHLP_DUPLICATE_SYMBOL64

class _IMAGEHLP_DUPLICATE_SYMBOL(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("NumberOfDups", DWORD),
        ("Symbol", PIMAGEHLP_SYMBOL),
        ("SelectedSymbol", DWORD),
    ]
PIMAGEHLP_DUPLICATE_SYMBOL = POINTER(_IMAGEHLP_DUPLICATE_SYMBOL)
IMAGEHLP_DUPLICATE_SYMBOL = _IMAGEHLP_DUPLICATE_SYMBOL

class _tagADDRESS(Structure):
    _fields_ = [
        ("Offset", DWORD),
        ("Segment", WORD),
        ("Mode", ADDRESS_MODE),
    ]
LPADDRESS = POINTER(_tagADDRESS)
ADDRESS = _tagADDRESS

class _tagADDRESS64(Structure):
    _fields_ = [
        ("Offset", DWORD64),
        ("Segment", WORD),
        ("Mode", ADDRESS_MODE),
    ]
LPADDRESS64 = POINTER(_tagADDRESS64)
ADDRESS64 = _tagADDRESS64

class _tagADDRESS64(_tagADDRESS64):
    def __repr__(self):
        if not self.Segment:
            return "<{0} {offset:#x}>".format(type(self).__name__, offset=self.Offset)
        return "<{0} {seg:#x}:{offset:#x}>".format(type(self).__name__, seg=self.Segment, offset=self.Offset)
LPADDRESS64 = POINTER(_tagADDRESS64)
ADDRESS64 = _tagADDRESS64
class _KDHELP(Structure):
    _fields_ = [
        ("Thread", DWORD),
        ("ThCallbackStack", DWORD),
        ("NextCallback", DWORD),
        ("FramePointer", DWORD),
        ("KiCallUserMode", DWORD),
        ("KeUserCallbackDispatcher", DWORD),
        ("SystemRangeStart", DWORD),
        ("ThCallbackBStore", DWORD),
        ("KiUserExceptionDispatcher", DWORD),
        ("StackBase", DWORD),
        ("StackLimit", DWORD),
        ("Reserved", DWORD * (5)),
    ]
KDHELP = _KDHELP
PKDHELP = POINTER(_KDHELP)

class _KDHELP64(Structure):
    _fields_ = [
        ("Thread", DWORD64),
        ("ThCallbackStack", DWORD),
        ("ThCallbackBStore", DWORD),
        ("NextCallback", DWORD),
        ("FramePointer", DWORD),
        ("KiCallUserMode", DWORD64),
        ("KeUserCallbackDispatcher", DWORD64),
        ("SystemRangeStart", DWORD64),
        ("KiUserExceptionDispatcher", DWORD64),
        ("StackBase", DWORD64),
        ("StackLimit", DWORD64),
        ("BuildVersion", DWORD),
        ("RetpolineStubFunctionTableSize", DWORD),
        ("RetpolineStubFunctionTable", DWORD64),
        ("RetpolineStubOffset", DWORD),
        ("RetpolineStubSize", DWORD),
        ("Reserved0", DWORD64 * (2)),
    ]
KDHELP64 = _KDHELP64
PKDHELP64 = POINTER(_KDHELP64)

class _tagSTACKFRAME(Structure):
    _fields_ = [
        ("AddrPC", ADDRESS),
        ("AddrReturn", ADDRESS),
        ("AddrFrame", ADDRESS),
        ("AddrStack", ADDRESS),
        ("FuncTableEntry", PVOID),
        ("Params", DWORD * (4)),
        ("Far", BOOL),
        ("Virtual", BOOL),
        ("Reserved", DWORD * (3)),
        ("KdHelp", KDHELP),
        ("AddrBStore", ADDRESS),
    ]
STACKFRAME = _tagSTACKFRAME
LPSTACKFRAME = POINTER(_tagSTACKFRAME)

class _tagSTACKFRAME64(Structure):
    _fields_ = [
        ("AddrPC", ADDRESS64),
        ("AddrReturn", ADDRESS64),
        ("AddrFrame", ADDRESS64),
        ("AddrStack", ADDRESS64),
        ("AddrBStore", ADDRESS64),
        ("FuncTableEntry", PVOID),
        ("Params", DWORD64 * (4)),
        ("Far", BOOL),
        ("Virtual", BOOL),
        ("Reserved", DWORD64 * (3)),
        ("KdHelp", KDHELP64),
    ]
STACKFRAME64 = _tagSTACKFRAME64
LPSTACKFRAME64 = POINTER(_tagSTACKFRAME64)

class _tagSTACKFRAME_EX(Structure):
    _fields_ = [
        ("AddrPC", ADDRESS64),
        ("AddrReturn", ADDRESS64),
        ("AddrFrame", ADDRESS64),
        ("AddrStack", ADDRESS64),
        ("AddrBStore", ADDRESS64),
        ("FuncTableEntry", PVOID),
        ("Params", DWORD64 * (4)),
        ("Far", BOOL),
        ("Virtual", BOOL),
        ("Reserved", DWORD64 * (3)),
        ("KdHelp", KDHELP64),
        ("StackFrameSize", DWORD),
        ("InlineFrameContext", DWORD),
    ]
LPSTACKFRAME_EX = POINTER(_tagSTACKFRAME_EX)
STACKFRAME_EX = _tagSTACKFRAME_EX

TASK_ACTION_EXEC = EnumValue("_TASK_ACTION_TYPE", "TASK_ACTION_EXEC", 0x0)
TASK_ACTION_COM_HANDLER = EnumValue("_TASK_ACTION_TYPE", "TASK_ACTION_COM_HANDLER", 0x5)
TASK_ACTION_SEND_EMAIL = EnumValue("_TASK_ACTION_TYPE", "TASK_ACTION_SEND_EMAIL", 0x6)
TASK_ACTION_SHOW_MESSAGE = EnumValue("_TASK_ACTION_TYPE", "TASK_ACTION_SHOW_MESSAGE", 0x7)
class _TASK_ACTION_TYPE(EnumType):
    values = [TASK_ACTION_EXEC, TASK_ACTION_COM_HANDLER, TASK_ACTION_SEND_EMAIL, TASK_ACTION_SHOW_MESSAGE]
    mapper = FlagMapper(*values)
TASK_ACTION_TYPE = _TASK_ACTION_TYPE


TASK_RUNLEVEL_LUA = EnumValue("_TASK_RUNLEVEL_TYPE", "TASK_RUNLEVEL_LUA", 0x0)
TASK_RUNLEVEL_HIGHEST = EnumValue("_TASK_RUNLEVEL_TYPE", "TASK_RUNLEVEL_HIGHEST", 0x1)
class _TASK_RUNLEVEL_TYPE(EnumType):
    values = [TASK_RUNLEVEL_LUA, TASK_RUNLEVEL_HIGHEST]
    mapper = FlagMapper(*values)
TASK_RUNLEVEL_TYPE = _TASK_RUNLEVEL_TYPE


TASK_LOGON_NONE = EnumValue("_TASK_LOGON_TYPE", "TASK_LOGON_NONE", 0x0)
TASK_LOGON_PASSWORD = EnumValue("_TASK_LOGON_TYPE", "TASK_LOGON_PASSWORD", 0x1)
TASK_LOGON_S4U = EnumValue("_TASK_LOGON_TYPE", "TASK_LOGON_S4U", 0x2)
TASK_LOGON_INTERACTIVE_TOKEN = EnumValue("_TASK_LOGON_TYPE", "TASK_LOGON_INTERACTIVE_TOKEN", 0x3)
TASK_LOGON_GROUP = EnumValue("_TASK_LOGON_TYPE", "TASK_LOGON_GROUP", 0x4)
TASK_LOGON_SERVICE_ACCOUNT = EnumValue("_TASK_LOGON_TYPE", "TASK_LOGON_SERVICE_ACCOUNT", 0x5)
TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD = EnumValue("_TASK_LOGON_TYPE", "TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD", 0x6)
class _TASK_LOGON_TYPE(EnumType):
    values = [TASK_LOGON_NONE, TASK_LOGON_PASSWORD, TASK_LOGON_S4U, TASK_LOGON_INTERACTIVE_TOKEN, TASK_LOGON_GROUP, TASK_LOGON_SERVICE_ACCOUNT, TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD]
    mapper = FlagMapper(*values)
TASK_LOGON_TYPE = _TASK_LOGON_TYPE


TASK_STATE_UNKNOWN = EnumValue("_TASK_STATE", "TASK_STATE_UNKNOWN", 0x0)
TASK_STATE_DISABLED = EnumValue("_TASK_STATE", "TASK_STATE_DISABLED", 0x1)
TASK_STATE_QUEUED = EnumValue("_TASK_STATE", "TASK_STATE_QUEUED", 0x2)
TASK_STATE_READY = EnumValue("_TASK_STATE", "TASK_STATE_READY", 0x3)
TASK_STATE_RUNNING = EnumValue("_TASK_STATE", "TASK_STATE_RUNNING", 0x4)
class _TASK_STATE(EnumType):
    values = [TASK_STATE_UNKNOWN, TASK_STATE_DISABLED, TASK_STATE_QUEUED, TASK_STATE_READY, TASK_STATE_RUNNING]
    mapper = FlagMapper(*values)
TASK_STATE = _TASK_STATE


TASK_INSTANCES_PARALLEL = EnumValue("_TASK_INSTANCES_POLICY", "TASK_INSTANCES_PARALLEL", 0x0)
TASK_INSTANCES_QUEUE = EnumValue("_TASK_INSTANCES_POLICY", "TASK_INSTANCES_QUEUE", 0x1)
TASK_INSTANCES_IGNORE_NEW = EnumValue("_TASK_INSTANCES_POLICY", "TASK_INSTANCES_IGNORE_NEW", 0x2)
TASK_INSTANCES_STOP_EXISTING = EnumValue("_TASK_INSTANCES_POLICY", "TASK_INSTANCES_STOP_EXISTING", 0x3)
class _TASK_INSTANCES_POLICY(EnumType):
    values = [TASK_INSTANCES_PARALLEL, TASK_INSTANCES_QUEUE, TASK_INSTANCES_IGNORE_NEW, TASK_INSTANCES_STOP_EXISTING]
    mapper = FlagMapper(*values)
TASK_INSTANCES_POLICY = _TASK_INSTANCES_POLICY


TASK_COMPATIBILITY_AT = EnumValue("_TASK_COMPATIBILITY", "TASK_COMPATIBILITY_AT", 0x0)
TASK_COMPATIBILITY_V1 = EnumValue("_TASK_COMPATIBILITY", "TASK_COMPATIBILITY_V1", 0x1)
TASK_COMPATIBILITY_V2 = EnumValue("_TASK_COMPATIBILITY", "TASK_COMPATIBILITY_V2", 0x2)
class _TASK_COMPATIBILITY(EnumType):
    values = [TASK_COMPATIBILITY_AT, TASK_COMPATIBILITY_V1, TASK_COMPATIBILITY_V2]
    mapper = FlagMapper(*values)
TASK_COMPATIBILITY = _TASK_COMPATIBILITY


TASK_TRIGGER_EVENT = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_EVENT", 0x0)
TASK_TRIGGER_TIME = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_TIME", 0x1)
TASK_TRIGGER_DAILY = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_DAILY", 0x2)
TASK_TRIGGER_WEEKLY = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_WEEKLY", 0x3)
TASK_TRIGGER_MONTHLY = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_MONTHLY", 0x4)
TASK_TRIGGER_MONTHLYDOW = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_MONTHLYDOW", 0x5)
TASK_TRIGGER_IDLE = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_IDLE", 0x6)
TASK_TRIGGER_REGISTRATION = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_REGISTRATION", 0x7)
TASK_TRIGGER_BOOT = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_BOOT", 0x8)
TASK_TRIGGER_LOGON = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_LOGON", 0x9)
TASK_TRIGGER_SESSION_STATE_CHANGE = EnumValue("_TASK_TRIGGER_TYPE2", "TASK_TRIGGER_SESSION_STATE_CHANGE", 0xb)
class _TASK_TRIGGER_TYPE2(EnumType):
    values = [TASK_TRIGGER_EVENT, TASK_TRIGGER_TIME, TASK_TRIGGER_DAILY, TASK_TRIGGER_WEEKLY, TASK_TRIGGER_MONTHLY, TASK_TRIGGER_MONTHLYDOW, TASK_TRIGGER_IDLE, TASK_TRIGGER_REGISTRATION, TASK_TRIGGER_BOOT, TASK_TRIGGER_LOGON, TASK_TRIGGER_SESSION_STATE_CHANGE]
    mapper = FlagMapper(*values)
TASK_TRIGGER_TYPE2 = _TASK_TRIGGER_TYPE2


TASK_ENUM_HIDDEN = EnumValue("_TASK_ENUM_FLAGS", "TASK_ENUM_HIDDEN", 0x1)
class _TASK_ENUM_FLAGS(EnumType):
    values = [TASK_ENUM_HIDDEN]
    mapper = FlagMapper(*values)
TASK_ENUM_FLAGS = _TASK_ENUM_FLAGS


TASK_VALIDATE_ONLY = EnumValue("_TASK_CREATION", "TASK_VALIDATE_ONLY", 0x1)
TASK_CREATE = EnumValue("_TASK_CREATION", "TASK_CREATE", 0x2)
TASK_UPDATE = EnumValue("_TASK_CREATION", "TASK_UPDATE", 0x4)
TASK_CREATE_OR_UPDATE = EnumValue("_TASK_CREATION", "TASK_CREATE_OR_UPDATE", 0x6)
TASK_DISABLE = EnumValue("_TASK_CREATION", "TASK_DISABLE", 0x8)
TASK_DONT_ADD_PRINCIPAL_ACE = EnumValue("_TASK_CREATION", "TASK_DONT_ADD_PRINCIPAL_ACE", 0x10)
TASK_IGNORE_REGISTRATION_TRIGGERS = EnumValue("_TASK_CREATION", "TASK_IGNORE_REGISTRATION_TRIGGERS", 0x20)
class _TASK_CREATION(EnumType):
    values = [TASK_VALIDATE_ONLY, TASK_CREATE, TASK_UPDATE, TASK_CREATE_OR_UPDATE, TASK_DISABLE, TASK_DONT_ADD_PRINCIPAL_ACE, TASK_IGNORE_REGISTRATION_TRIGGERS]
    mapper = FlagMapper(*values)
TASK_CREATION = _TASK_CREATION


TASK_RUN_NO_FLAGS = EnumValue("TASK_RUN_FLAGS", "TASK_RUN_NO_FLAGS", 0x0)
TASK_RUN_AS_SELF = EnumValue("TASK_RUN_FLAGS", "TASK_RUN_AS_SELF", 0x1)
TASK_RUN_IGNORE_CONSTRAINTS = EnumValue("TASK_RUN_FLAGS", "TASK_RUN_IGNORE_CONSTRAINTS", 0x2)
TASK_RUN_USE_SESSION_ID = EnumValue("TASK_RUN_FLAGS", "TASK_RUN_USE_SESSION_ID", 0x4)
TASK_RUN_USER_SID = EnumValue("TASK_RUN_FLAGS", "TASK_RUN_USER_SID", 0x8)
class TASK_RUN_FLAGS(EnumType):
    values = [TASK_RUN_NO_FLAGS, TASK_RUN_AS_SELF, TASK_RUN_IGNORE_CONSTRAINTS, TASK_RUN_USE_SESSION_ID, TASK_RUN_USER_SID]
    mapper = FlagMapper(*values)


class _TRACE_PROVIDER_INFO(Structure):
    _fields_ = [
        ("ProviderGuid", GUID),
        ("SchemaSource", ULONG),
        ("ProviderNameOffset", ULONG),
    ]
TRACE_PROVIDER_INFO = _TRACE_PROVIDER_INFO

class _PROVIDER_ENUMERATION_INFO(Structure):
    _fields_ = [
        ("NumberOfProviders", ULONG),
        ("Reserved", ULONG),
        ("TraceProviderInfoArray", TRACE_PROVIDER_INFO * (ANYSIZE_ARRAY)),
    ]
PPROVIDER_ENUMERATION_INFO = POINTER(_PROVIDER_ENUMERATION_INFO)
PROVIDER_ENUMERATION_INFO = _PROVIDER_ENUMERATION_INFO

class tagRGBTRIPLE(Structure):
    _fields_ = [
        ("rgbtBlue", BYTE),
        ("rgbtGreen", BYTE),
        ("rgbtRed", BYTE),
    ]
NPRGBTRIPLE = POINTER(tagRGBTRIPLE)
LPRGBTRIPLE = POINTER(tagRGBTRIPLE)
RGBTRIPLE = tagRGBTRIPLE
PRGBTRIPLE = POINTER(tagRGBTRIPLE)

class tagBITMAPFILEHEADER(Structure):
    _pack_ = 2
    _fields_ = [
        ("bfType", WORD),
        ("bfSize", DWORD),
        ("bfReserved1", WORD),
        ("bfReserved2", WORD),
        ("bfOffBits", DWORD),
    ]
BITMAPFILEHEADER = tagBITMAPFILEHEADER
PBITMAPFILEHEADER = POINTER(tagBITMAPFILEHEADER)
LPBITMAPFILEHEADER = POINTER(tagBITMAPFILEHEADER)

class tagBITMAPCOREHEADER(Structure):
    _fields_ = [
        ("bcSize", DWORD),
        ("bcWidth", WORD),
        ("bcHeight", WORD),
        ("bcPlanes", WORD),
        ("bcBitCount", WORD),
    ]
LPBITMAPCOREHEADER = POINTER(tagBITMAPCOREHEADER)
PBITMAPCOREHEADER = POINTER(tagBITMAPCOREHEADER)
BITMAPCOREHEADER = tagBITMAPCOREHEADER

class tagBITMAP(Structure):
    _fields_ = [
        ("bmType", LONG),
        ("bmWidth", LONG),
        ("bmHeight", LONG),
        ("bmWidthBytes", LONG),
        ("bmPlanes", WORD),
        ("bmBitsPixel", WORD),
        ("bmBits", LPVOID),
    ]
NPBITMAP = POINTER(tagBITMAP)
LPBITMAP = POINTER(tagBITMAP)
PBITMAP = POINTER(tagBITMAP)
BITMAP = tagBITMAP

class tagBITMAPINFOHEADER(Structure):
    _fields_ = [
        ("biSize", DWORD),
        ("biWidth", LONG),
        ("biHeight", LONG),
        ("biPlanes", WORD),
        ("biBitCount", WORD),
        ("biCompression", DWORD),
        ("biSizeImage", DWORD),
        ("biXPelsPerMeter", LONG),
        ("biYPelsPerMeter", LONG),
        ("biClrUsed", DWORD),
        ("biClrImportant", DWORD),
    ]
BITMAPINFOHEADER = tagBITMAPINFOHEADER
PBITMAPINFOHEADER = POINTER(tagBITMAPINFOHEADER)
LPBITMAPINFOHEADER = POINTER(tagBITMAPINFOHEADER)

class tagRGBQUAD(Structure):
    _fields_ = [
        ("rgbBlue", BYTE),
        ("rgbGreen", BYTE),
        ("rgbRed", BYTE),
        ("rgbReserved", BYTE),
    ]
RGBQUAD = tagRGBQUAD

class tagBITMAPINFO(Structure):
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", RGBQUAD * (1)),
    ]
LPBITMAPINFO = POINTER(tagBITMAPINFO)
PBITMAPINFO = POINTER(tagBITMAPINFO)
BITMAPINFO = tagBITMAPINFO

class tagBITMAPCOREINFO(Structure):
    _fields_ = [
        ("bmciHeader", BITMAPCOREHEADER),
        ("bmciColors", RGBTRIPLE * (1)),
    ]
LPBITMAPCOREINFO = POINTER(tagBITMAPCOREINFO)
BITMAPCOREINFO = tagBITMAPCOREINFO
PBITMAPCOREINFO = POINTER(tagBITMAPCOREINFO)

class tagWNDCLASSEXA(Structure):
    _fields_ = [
        ("cbSize", UINT),
        ("style", UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", INT),
        ("cbWndExtra", INT),
        ("hInstance", HINSTANCE),
        ("hIcon", HICON),
        ("hCursor", HCURSOR),
        ("hbrBackground", HBRUSH),
        ("lpszMenuName", LPCSTR),
        ("lpszClassName", LPCSTR),
        ("hIconSm", HICON),
    ]
PWNDCLASSEXA = POINTER(tagWNDCLASSEXA)
LPWNDCLASSEXA = POINTER(tagWNDCLASSEXA)
WNDCLASSEXA = tagWNDCLASSEXA

class tagWNDCLASSEXW(Structure):
    _fields_ = [
        ("cbSize", UINT),
        ("style", UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", INT),
        ("cbWndExtra", INT),
        ("hInstance", HINSTANCE),
        ("hIcon", HICON),
        ("hCursor", HCURSOR),
        ("hbrBackground", HBRUSH),
        ("lpszMenuName", LPWSTR),
        ("lpszClassName", LPWSTR),
        ("hIconSm", HICON),
    ]
WNDCLASSEXW = tagWNDCLASSEXW
LPWNDCLASSEXW = POINTER(tagWNDCLASSEXW)
PWNDCLASSEXW = POINTER(tagWNDCLASSEXW)

SystemBasicInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBasicInformation", 0x0)
SystemProcessorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorInformation", 0x1)
SystemPerformanceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPerformanceInformation", 0x2)
SystemTimeOfDayInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemTimeOfDayInformation", 0x3)
SystemPathInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPathInformation", 0x4)
SystemProcessInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessInformation", 0x5)
SystemCallCountInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCallCountInformation", 0x6)
SystemDeviceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDeviceInformation", 0x7)
SystemProcessorPerformanceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorPerformanceInformation", 0x8)
SystemFlagsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFlagsInformation", 0x9)
SystemCallTimeInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCallTimeInformation", 0xa)
SystemModuleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemModuleInformation", 0xb)
SystemLocksInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLocksInformation", 0xc)
SystemStackTraceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemStackTraceInformation", 0xd)
SystemPagedPoolInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPagedPoolInformation", 0xe)
SystemNonPagedPoolInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemNonPagedPoolInformation", 0xf)
SystemHandleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemHandleInformation", 0x10)
SystemObjectInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemObjectInformation", 0x11)
SystemPageFileInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPageFileInformation", 0x12)
SystemVdmInstemulInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVdmInstemulInformation", 0x13)
SystemVdmBopInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVdmBopInformation", 0x14)
SystemFileCacheInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFileCacheInformation", 0x15)
SystemPoolTagInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPoolTagInformation", 0x16)
SystemInterruptInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemInterruptInformation", 0x17)
SystemDpcBehaviorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDpcBehaviorInformation", 0x18)
SystemFullMemoryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFullMemoryInformation", 0x19)
SystemLoadGdiDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLoadGdiDriverInformation", 0x1a)
SystemUnloadGdiDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemUnloadGdiDriverInformation", 0x1b)
SystemTimeAdjustmentInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemTimeAdjustmentInformation", 0x1c)
SystemSummaryMemoryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSummaryMemoryInformation", 0x1d)
SystemMirrorMemoryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemMirrorMemoryInformation", 0x1e)
SystemPerformanceTraceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPerformanceTraceInformation", 0x1f)
SystemObsolete0 = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemObsolete0", 0x20)
SystemExceptionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemExceptionInformation", 0x21)
SystemCrashDumpStateInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCrashDumpStateInformation", 0x22)
SystemKernelDebuggerInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemKernelDebuggerInformation", 0x23)
SystemContextSwitchInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemContextSwitchInformation", 0x24)
SystemRegistryQuotaInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRegistryQuotaInformation", 0x25)
SystemExtendServiceTableInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemExtendServiceTableInformation", 0x26)
SystemPrioritySeperation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPrioritySeperation", 0x27)
SystemVerifierAddDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierAddDriverInformation", 0x28)
SystemVerifierRemoveDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierRemoveDriverInformation", 0x29)
SystemProcessorIdleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorIdleInformation", 0x2a)
SystemLegacyDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLegacyDriverInformation", 0x2b)
SystemCurrentTimeZoneInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCurrentTimeZoneInformation", 0x2c)
SystemLookasideInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLookasideInformation", 0x2d)
SystemTimeSlipNotification = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemTimeSlipNotification", 0x2e)
SystemSessionCreate = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionCreate", 0x2f)
SystemSessionDetach = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionDetach", 0x30)
SystemSessionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionInformation", 0x31)
SystemRangeStartInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRangeStartInformation", 0x32)
SystemVerifierInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierInformation", 0x33)
SystemVerifierThunkExtend = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierThunkExtend", 0x34)
SystemSessionProcessInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionProcessInformation", 0x35)
SystemLoadGdiDriverInSystemSpace = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLoadGdiDriverInSystemSpace", 0x36)
SystemNumaProcessorMap = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemNumaProcessorMap", 0x37)
SystemPrefetcherInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPrefetcherInformation", 0x38)
SystemExtendedProcessInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemExtendedProcessInformation", 0x39)
SystemRecommendedSharedDataAlignment = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRecommendedSharedDataAlignment", 0x3a)
SystemComPlusPackage = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemComPlusPackage", 0x3b)
SystemNumaAvailableMemory = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemNumaAvailableMemory", 0x3c)
SystemProcessorPowerInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorPowerInformation", 0x3d)
SystemEmulationBasicInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemEmulationBasicInformation", 0x3e)
SystemEmulationProcessorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemEmulationProcessorInformation", 0x3f)
SystemExtendedHandleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemExtendedHandleInformation", 0x40)
SystemLostDelayedWriteInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLostDelayedWriteInformation", 0x41)
SystemBigPoolInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBigPoolInformation", 0x42)
SystemSessionPoolTagInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionPoolTagInformation", 0x43)
SystemSessionMappedViewInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionMappedViewInformation", 0x44)
SystemHotpatchInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemHotpatchInformation", 0x45)
SystemObjectSecurityMode = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemObjectSecurityMode", 0x46)
SystemWatchdogTimerHandler = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWatchdogTimerHandler", 0x47)
SystemWatchdogTimerInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWatchdogTimerInformation", 0x48)
SystemLogicalProcessorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLogicalProcessorInformation", 0x49)
SystemWow64SharedInformationObsolete = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWow64SharedInformationObsolete", 0x4a)
SystemRegisterFirmwareTableInformationHandler = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRegisterFirmwareTableInformationHandler", 0x4b)
SystemFirmwareTableInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFirmwareTableInformation", 0x4c)
SystemModuleInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemModuleInformationEx", 0x4d)
SystemVerifierTriageInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierTriageInformation", 0x4e)
SystemSuperfetchInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSuperfetchInformation", 0x4f)
SystemMemoryListInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemMemoryListInformation", 0x50)
SystemFileCacheInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFileCacheInformationEx", 0x51)
SystemThreadPriorityClientIdInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemThreadPriorityClientIdInformation", 0x52)
SystemProcessorIdleCycleTimeInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorIdleCycleTimeInformation", 0x53)
SystemVerifierCancellationInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierCancellationInformation", 0x54)
SystemProcessorPowerInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorPowerInformationEx", 0x55)
SystemRefTraceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRefTraceInformation", 0x56)
SystemSpecialPoolInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSpecialPoolInformation", 0x57)
SystemProcessIdInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessIdInformation", 0x58)
SystemErrorPortInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemErrorPortInformation", 0x59)
SystemBootEnvironmentInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBootEnvironmentInformation", 0x5a)
SystemHypervisorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemHypervisorInformation", 0x5b)
SystemVerifierInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierInformationEx", 0x5c)
SystemTimeZoneInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemTimeZoneInformation", 0x5d)
SystemImageFileExecutionOptionsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemImageFileExecutionOptionsInformation", 0x5e)
SystemCoverageInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCoverageInformation", 0x5f)
SystemPrefetchPatchInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPrefetchPatchInformation", 0x60)
SystemVerifierFaultsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierFaultsInformation", 0x61)
SystemSystemPartitionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSystemPartitionInformation", 0x62)
SystemSystemDiskInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSystemDiskInformation", 0x63)
SystemProcessorPerformanceDistribution = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorPerformanceDistribution", 0x64)
SystemNumaProximityNodeInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemNumaProximityNodeInformation", 0x65)
SystemDynamicTimeZoneInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDynamicTimeZoneInformation", 0x66)
SystemCodeIntegrityInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityInformation", 0x67)
SystemProcessorMicrocodeUpdateInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorMicrocodeUpdateInformation", 0x68)
SystemProcessorBrandString = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorBrandString", 0x69)
SystemVirtualAddressInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVirtualAddressInformation", 0x6a)
SystemLogicalProcessorAndGroupInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLogicalProcessorAndGroupInformation", 0x6b)
SystemProcessorCycleTimeInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorCycleTimeInformation", 0x6c)
SystemStoreInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemStoreInformation", 0x6d)
SystemRegistryAppendString = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRegistryAppendString", 0x6e)
SystemAitSamplingValue = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemAitSamplingValue", 0x6f)
SystemVhdBootInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVhdBootInformation", 0x70)
SystemCpuQuotaInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCpuQuotaInformation", 0x71)
SystemNativeBasicInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemNativeBasicInformation", 0x72)
SystemErrorPortTimeouts = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemErrorPortTimeouts", 0x73)
SystemLowPriorityIoInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLowPriorityIoInformation", 0x74)
SystemBootEntropyInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBootEntropyInformation", 0x75)
SystemVerifierCountersInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierCountersInformation", 0x76)
SystemPagedPoolInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPagedPoolInformationEx", 0x77)
SystemSystemPtesInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSystemPtesInformationEx", 0x78)
SystemNodeDistanceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemNodeDistanceInformation", 0x79)
SystemAcpiAuditInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemAcpiAuditInformation", 0x7a)
SystemBasicPerformanceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBasicPerformanceInformation", 0x7b)
SystemQueryPerformanceCounterInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemQueryPerformanceCounterInformation", 0x7c)
SystemSessionBigPoolInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionBigPoolInformation", 0x7d)
SystemBootGraphicsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBootGraphicsInformation", 0x7e)
SystemScrubPhysicalMemoryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemScrubPhysicalMemoryInformation", 0x7f)
SystemBadPageInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBadPageInformation", 0x80)
SystemProcessorProfileControlArea = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorProfileControlArea", 0x81)
SystemCombinePhysicalMemoryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCombinePhysicalMemoryInformation", 0x82)
SystemEntropyInterruptTimingInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemEntropyInterruptTimingInformation", 0x83)
SystemConsoleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemConsoleInformation", 0x84)
SystemPlatformBinaryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPlatformBinaryInformation", 0x85)
SystemPolicyInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPolicyInformation", 0x86)
SystemHypervisorProcessorCountInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemHypervisorProcessorCountInformation", 0x87)
SystemDeviceDataInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDeviceDataInformation", 0x88)
SystemDeviceDataEnumerationInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDeviceDataEnumerationInformation", 0x89)
SystemMemoryTopologyInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemMemoryTopologyInformation", 0x8a)
SystemMemoryChannelInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemMemoryChannelInformation", 0x8b)
SystemBootLogoInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBootLogoInformation", 0x8c)
SystemProcessorPerformanceInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorPerformanceInformationEx", 0x8d)
SystemCriticalProcessErrorLogInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCriticalProcessErrorLogInformation", 0x8e)
SystemSecureBootPolicyInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSecureBootPolicyInformation", 0x8f)
SystemPageFileInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPageFileInformationEx", 0x90)
SystemSecureBootInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSecureBootInformation", 0x91)
SystemEntropyInterruptTimingRawInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemEntropyInterruptTimingRawInformation", 0x92)
SystemPortableWorkspaceEfiLauncherInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPortableWorkspaceEfiLauncherInformation", 0x93)
SystemFullProcessInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFullProcessInformation", 0x94)
SystemKernelDebuggerInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemKernelDebuggerInformationEx", 0x95)
SystemBootMetadataInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBootMetadataInformation", 0x96)
SystemSoftRebootInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSoftRebootInformation", 0x97)
SystemElamCertificateInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemElamCertificateInformation", 0x98)
SystemOfflineDumpConfigInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemOfflineDumpConfigInformation", 0x99)
SystemProcessorFeaturesInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorFeaturesInformation", 0x9a)
SystemRegistryReconciliationInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRegistryReconciliationInformation", 0x9b)
SystemEdidInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemEdidInformation", 0x9c)
SystemManufacturingInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemManufacturingInformation", 0x9d)
SystemEnergyEstimationConfigInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemEnergyEstimationConfigInformation", 0x9e)
SystemHypervisorDetailInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemHypervisorDetailInformation", 0x9f)
SystemProcessorCycleStatsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorCycleStatsInformation", 0xa0)
SystemVmGenerationCountInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVmGenerationCountInformation", 0xa1)
SystemTrustedPlatformModuleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemTrustedPlatformModuleInformation", 0xa2)
SystemKernelDebuggerFlags = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemKernelDebuggerFlags", 0xa3)
SystemCodeIntegrityPolicyInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityPolicyInformation", 0xa4)
SystemIsolatedUserModeInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemIsolatedUserModeInformation", 0xa5)
SystemHardwareSecurityTestInterfaceResultsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemHardwareSecurityTestInterfaceResultsInformation", 0xa6)
SystemSingleModuleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSingleModuleInformation", 0xa7)
SystemAllowedCpuSetsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemAllowedCpuSetsInformation", 0xa8)
SystemVsmProtectionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVsmProtectionInformation", 0xa9)
SystemInterruptCpuSetsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemInterruptCpuSetsInformation", 0xaa)
SystemSecureBootPolicyFullInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSecureBootPolicyFullInformation", 0xab)
SystemCodeIntegrityPolicyFullInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityPolicyFullInformation", 0xac)
SystemAffinitizedInterruptProcessorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemAffinitizedInterruptProcessorInformation", 0xad)
SystemRootSiloInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRootSiloInformation", 0xae)
SystemCpuSetInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCpuSetInformation", 0xaf)
SystemCpuSetTagInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCpuSetTagInformation", 0xb0)
SystemWin32WerStartCallout = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWin32WerStartCallout", 0xb1)
SystemSecureKernelProfileInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSecureKernelProfileInformation", 0xb2)
SystemCodeIntegrityPlatformManifestInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityPlatformManifestInformation", 0xb3)
SystemInterruptSteeringInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemInterruptSteeringInformation", 0xb4)
SystemSupportedProcessorArchitectures = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSupportedProcessorArchitectures", 0xb5)
SystemMemoryUsageInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemMemoryUsageInformation", 0xb6)
SystemCodeIntegrityCertificateInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityCertificateInformation", 0xb7)
SystemPhysicalMemoryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPhysicalMemoryInformation", 0xb8)
SystemControlFlowTransition = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemControlFlowTransition", 0xb9)
SystemKernelDebuggingAllowed = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemKernelDebuggingAllowed", 0xba)
SystemActivityModerationExeState = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemActivityModerationExeState", 0xbb)
SystemActivityModerationUserSettings = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemActivityModerationUserSettings", 0xbc)
SystemCodeIntegrityPoliciesFullInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityPoliciesFullInformation", 0xbd)
SystemCodeIntegrityUnlockInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityUnlockInformation", 0xbe)
SystemIntegrityQuotaInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemIntegrityQuotaInformation", 0xbf)
SystemFlushInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFlushInformation", 0xc0)
SystemProcessorIdleMaskInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorIdleMaskInformation", 0xc1)
SystemSecureDumpEncryptionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSecureDumpEncryptionInformation", 0xc2)
SystemWriteConstraintInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWriteConstraintInformation", 0xc3)
SystemKernelVaShadowInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemKernelVaShadowInformation", 0xc4)
SystemHypervisorSharedPageInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemHypervisorSharedPageInformation", 0xc5)
SystemFirmwareBootPerformanceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFirmwareBootPerformanceInformation", 0xc6)
SystemCodeIntegrityVerificationInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityVerificationInformation", 0xc7)
SystemFirmwarePartitionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFirmwarePartitionInformation", 0xc8)
SystemSpeculationControlInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSpeculationControlInformation", 0xc9)
SystemDmaGuardPolicyInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDmaGuardPolicyInformation", 0xca)
SystemEnclaveLaunchControlInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemEnclaveLaunchControlInformation", 0xcb)
SystemWorkloadAllowedCpuSetsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWorkloadAllowedCpuSetsInformation", 0xcc)
SystemCodeIntegrityUnlockModeInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityUnlockModeInformation", 0xcd)
SystemLeapSecondInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLeapSecondInformation", 0xce)
SystemFlags2Information = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFlags2Information", 0xcf)
SystemSecurityModelInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSecurityModelInformation", 0xd0)
SystemCodeIntegritySyntheticCacheInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegritySyntheticCacheInformation", 0xd1)
SystemFeatureConfigurationInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFeatureConfigurationInformation", 0xd2)
SystemFeatureConfigurationSectionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFeatureConfigurationSectionInformation", 0xd3)
SystemFeatureUsageSubscriptionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFeatureUsageSubscriptionInformation", 0xd4)
SystemSecureSpeculationControlInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSecureSpeculationControlInformation", 0xd5)
SystemSpacesBootInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSpacesBootInformation", 0xd6)
SystemFwRamdiskInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFwRamdiskInformation", 0xd7)
SystemWheaIpmiHardwareInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWheaIpmiHardwareInformation", 0xd8)
SystemDifSetRuleClassInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDifSetRuleClassInformation", 0xd9)
SystemDifClearRuleClassInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDifClearRuleClassInformation", 0xda)
SystemDifApplyPluginVerificationOnDriver = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDifApplyPluginVerificationOnDriver", 0xdb)
SystemDifRemovePluginVerificationOnDriver = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDifRemovePluginVerificationOnDriver", 0xdc)
SystemShadowStackInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemShadowStackInformation", 0xdd)
SystemBuildVersionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBuildVersionInformation", 0xde)
SystemPoolLimitInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPoolLimitInformation", 0xdf)
SystemCodeIntegrityAddDynamicStore = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityAddDynamicStore", 0xe0)
SystemCodeIntegrityClearDynamicStores = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCodeIntegrityClearDynamicStores", 0xe1)
SystemPoolZeroingInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPoolZeroingInformation", 0xe3)
MaxSystemInfoClass = EnumValue("_SYSTEM_INFORMATION_CLASS", "MaxSystemInfoClass", 0xe4)
class _SYSTEM_INFORMATION_CLASS(EnumType):
    values = [SystemBasicInformation, SystemProcessorInformation, SystemPerformanceInformation, SystemTimeOfDayInformation, SystemPathInformation, SystemProcessInformation, SystemCallCountInformation, SystemDeviceInformation, SystemProcessorPerformanceInformation, SystemFlagsInformation, SystemCallTimeInformation, SystemModuleInformation, SystemLocksInformation, SystemStackTraceInformation, SystemPagedPoolInformation, SystemNonPagedPoolInformation, SystemHandleInformation, SystemObjectInformation, SystemPageFileInformation, SystemVdmInstemulInformation, SystemVdmBopInformation, SystemFileCacheInformation, SystemPoolTagInformation, SystemInterruptInformation, SystemDpcBehaviorInformation, SystemFullMemoryInformation, SystemLoadGdiDriverInformation, SystemUnloadGdiDriverInformation, SystemTimeAdjustmentInformation, SystemSummaryMemoryInformation, SystemMirrorMemoryInformation, SystemPerformanceTraceInformation, SystemObsolete0, SystemExceptionInformation, SystemCrashDumpStateInformation, SystemKernelDebuggerInformation, SystemContextSwitchInformation, SystemRegistryQuotaInformation, SystemExtendServiceTableInformation, SystemPrioritySeperation, SystemVerifierAddDriverInformation, SystemVerifierRemoveDriverInformation, SystemProcessorIdleInformation, SystemLegacyDriverInformation, SystemCurrentTimeZoneInformation, SystemLookasideInformation, SystemTimeSlipNotification, SystemSessionCreate, SystemSessionDetach, SystemSessionInformation, SystemRangeStartInformation, SystemVerifierInformation, SystemVerifierThunkExtend, SystemSessionProcessInformation, SystemLoadGdiDriverInSystemSpace, SystemNumaProcessorMap, SystemPrefetcherInformation, SystemExtendedProcessInformation, SystemRecommendedSharedDataAlignment, SystemComPlusPackage, SystemNumaAvailableMemory, SystemProcessorPowerInformation, SystemEmulationBasicInformation, SystemEmulationProcessorInformation, SystemExtendedHandleInformation, SystemLostDelayedWriteInformation, SystemBigPoolInformation, SystemSessionPoolTagInformation, SystemSessionMappedViewInformation, SystemHotpatchInformation, SystemObjectSecurityMode, SystemWatchdogTimerHandler, SystemWatchdogTimerInformation, SystemLogicalProcessorInformation, SystemWow64SharedInformationObsolete, SystemRegisterFirmwareTableInformationHandler, SystemFirmwareTableInformation, SystemModuleInformationEx, SystemVerifierTriageInformation, SystemSuperfetchInformation, SystemMemoryListInformation, SystemFileCacheInformationEx, SystemThreadPriorityClientIdInformation, SystemProcessorIdleCycleTimeInformation, SystemVerifierCancellationInformation, SystemProcessorPowerInformationEx, SystemRefTraceInformation, SystemSpecialPoolInformation, SystemProcessIdInformation, SystemErrorPortInformation, SystemBootEnvironmentInformation, SystemHypervisorInformation, SystemVerifierInformationEx, SystemTimeZoneInformation, SystemImageFileExecutionOptionsInformation, SystemCoverageInformation, SystemPrefetchPatchInformation, SystemVerifierFaultsInformation, SystemSystemPartitionInformation, SystemSystemDiskInformation, SystemProcessorPerformanceDistribution, SystemNumaProximityNodeInformation, SystemDynamicTimeZoneInformation, SystemCodeIntegrityInformation, SystemProcessorMicrocodeUpdateInformation, SystemProcessorBrandString, SystemVirtualAddressInformation, SystemLogicalProcessorAndGroupInformation, SystemProcessorCycleTimeInformation, SystemStoreInformation, SystemRegistryAppendString, SystemAitSamplingValue, SystemVhdBootInformation, SystemCpuQuotaInformation, SystemNativeBasicInformation, SystemErrorPortTimeouts, SystemLowPriorityIoInformation, SystemBootEntropyInformation, SystemVerifierCountersInformation, SystemPagedPoolInformationEx, SystemSystemPtesInformationEx, SystemNodeDistanceInformation, SystemAcpiAuditInformation, SystemBasicPerformanceInformation, SystemQueryPerformanceCounterInformation, SystemSessionBigPoolInformation, SystemBootGraphicsInformation, SystemScrubPhysicalMemoryInformation, SystemBadPageInformation, SystemProcessorProfileControlArea, SystemCombinePhysicalMemoryInformation, SystemEntropyInterruptTimingInformation, SystemConsoleInformation, SystemPlatformBinaryInformation, SystemPolicyInformation, SystemHypervisorProcessorCountInformation, SystemDeviceDataInformation, SystemDeviceDataEnumerationInformation, SystemMemoryTopologyInformation, SystemMemoryChannelInformation, SystemBootLogoInformation, SystemProcessorPerformanceInformationEx, SystemCriticalProcessErrorLogInformation, SystemSecureBootPolicyInformation, SystemPageFileInformationEx, SystemSecureBootInformation, SystemEntropyInterruptTimingRawInformation, SystemPortableWorkspaceEfiLauncherInformation, SystemFullProcessInformation, SystemKernelDebuggerInformationEx, SystemBootMetadataInformation, SystemSoftRebootInformation, SystemElamCertificateInformation, SystemOfflineDumpConfigInformation, SystemProcessorFeaturesInformation, SystemRegistryReconciliationInformation, SystemEdidInformation, SystemManufacturingInformation, SystemEnergyEstimationConfigInformation, SystemHypervisorDetailInformation, SystemProcessorCycleStatsInformation, SystemVmGenerationCountInformation, SystemTrustedPlatformModuleInformation, SystemKernelDebuggerFlags, SystemCodeIntegrityPolicyInformation, SystemIsolatedUserModeInformation, SystemHardwareSecurityTestInterfaceResultsInformation, SystemSingleModuleInformation, SystemAllowedCpuSetsInformation, SystemVsmProtectionInformation, SystemInterruptCpuSetsInformation, SystemSecureBootPolicyFullInformation, SystemCodeIntegrityPolicyFullInformation, SystemAffinitizedInterruptProcessorInformation, SystemRootSiloInformation, SystemCpuSetInformation, SystemCpuSetTagInformation, SystemWin32WerStartCallout, SystemSecureKernelProfileInformation, SystemCodeIntegrityPlatformManifestInformation, SystemInterruptSteeringInformation, SystemSupportedProcessorArchitectures, SystemMemoryUsageInformation, SystemCodeIntegrityCertificateInformation, SystemPhysicalMemoryInformation, SystemControlFlowTransition, SystemKernelDebuggingAllowed, SystemActivityModerationExeState, SystemActivityModerationUserSettings, SystemCodeIntegrityPoliciesFullInformation, SystemCodeIntegrityUnlockInformation, SystemIntegrityQuotaInformation, SystemFlushInformation, SystemProcessorIdleMaskInformation, SystemSecureDumpEncryptionInformation, SystemWriteConstraintInformation, SystemKernelVaShadowInformation, SystemHypervisorSharedPageInformation, SystemFirmwareBootPerformanceInformation, SystemCodeIntegrityVerificationInformation, SystemFirmwarePartitionInformation, SystemSpeculationControlInformation, SystemDmaGuardPolicyInformation, SystemEnclaveLaunchControlInformation, SystemWorkloadAllowedCpuSetsInformation, SystemCodeIntegrityUnlockModeInformation, SystemLeapSecondInformation, SystemFlags2Information, SystemSecurityModelInformation, SystemCodeIntegritySyntheticCacheInformation, SystemFeatureConfigurationInformation, SystemFeatureConfigurationSectionInformation, SystemFeatureUsageSubscriptionInformation, SystemSecureSpeculationControlInformation, SystemSpacesBootInformation, SystemFwRamdiskInformation, SystemWheaIpmiHardwareInformation, SystemDifSetRuleClassInformation, SystemDifClearRuleClassInformation, SystemDifApplyPluginVerificationOnDriver, SystemDifRemovePluginVerificationOnDriver, SystemShadowStackInformation, SystemBuildVersionInformation, SystemPoolLimitInformation, SystemCodeIntegrityAddDynamicStore, SystemCodeIntegrityClearDynamicStores, SystemPoolZeroingInformation, MaxSystemInfoClass]
    mapper = FlagMapper(*values)
SYSTEM_INFORMATION_CLASS = _SYSTEM_INFORMATION_CLASS


WinNullSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNullSid", 0x0)
WinWorldSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinWorldSid", 0x1)
WinLocalSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLocalSid", 0x2)
WinCreatorOwnerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorOwnerSid", 0x3)
WinCreatorGroupSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorGroupSid", 0x4)
WinCreatorOwnerServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorOwnerServerSid", 0x5)
WinCreatorGroupServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorGroupServerSid", 0x6)
WinNtAuthoritySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNtAuthoritySid", 0x7)
WinDialupSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinDialupSid", 0x8)
WinNetworkSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNetworkSid", 0x9)
WinBatchSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBatchSid", 0xa)
WinInteractiveSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinInteractiveSid", 0xb)
WinServiceSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinServiceSid", 0xc)
WinAnonymousSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAnonymousSid", 0xd)
WinProxySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinProxySid", 0xe)
WinEnterpriseControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinEnterpriseControllersSid", 0xf)
WinSelfSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinSelfSid", 0x10)
WinAuthenticatedUserSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAuthenticatedUserSid", 0x11)
WinRestrictedCodeSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinRestrictedCodeSid", 0x12)
WinTerminalServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinTerminalServerSid", 0x13)
WinRemoteLogonIdSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinRemoteLogonIdSid", 0x14)
WinLogonIdsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLogonIdsSid", 0x15)
WinLocalSystemSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLocalSystemSid", 0x16)
WinLocalServiceSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLocalServiceSid", 0x17)
WinNetworkServiceSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNetworkServiceSid", 0x18)
WinBuiltinDomainSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinDomainSid", 0x19)
WinBuiltinAdministratorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinAdministratorsSid", 0x1a)
WinBuiltinUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinUsersSid", 0x1b)
WinBuiltinGuestsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinGuestsSid", 0x1c)
WinBuiltinPowerUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPowerUsersSid", 0x1d)
WinBuiltinAccountOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinAccountOperatorsSid", 0x1e)
WinBuiltinSystemOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinSystemOperatorsSid", 0x1f)
WinBuiltinPrintOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPrintOperatorsSid", 0x20)
WinBuiltinBackupOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinBackupOperatorsSid", 0x21)
WinBuiltinReplicatorSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinReplicatorSid", 0x22)
WinBuiltinPreWindows2000CompatibleAccessSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPreWindows2000CompatibleAccessSid", 0x23)
WinBuiltinRemoteDesktopUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinRemoteDesktopUsersSid", 0x24)
WinBuiltinNetworkConfigurationOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinNetworkConfigurationOperatorsSid", 0x25)
WinAccountAdministratorSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountAdministratorSid", 0x26)
WinAccountGuestSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountGuestSid", 0x27)
WinAccountKrbtgtSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountKrbtgtSid", 0x28)
WinAccountDomainAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountDomainAdminsSid", 0x29)
WinAccountDomainUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountDomainUsersSid", 0x2a)
WinAccountDomainGuestsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountDomainGuestsSid", 0x2b)
WinAccountComputersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountComputersSid", 0x2c)
WinAccountControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountControllersSid", 0x2d)
WinAccountCertAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountCertAdminsSid", 0x2e)
WinAccountSchemaAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountSchemaAdminsSid", 0x2f)
WinAccountEnterpriseAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountEnterpriseAdminsSid", 0x30)
WinAccountPolicyAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountPolicyAdminsSid", 0x31)
WinAccountRasAndIasServersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountRasAndIasServersSid", 0x32)
WinNTLMAuthenticationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNTLMAuthenticationSid", 0x33)
WinDigestAuthenticationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinDigestAuthenticationSid", 0x34)
WinSChannelAuthenticationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinSChannelAuthenticationSid", 0x35)
WinThisOrganizationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinThisOrganizationSid", 0x36)
WinOtherOrganizationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinOtherOrganizationSid", 0x37)
WinBuiltinIncomingForestTrustBuildersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinIncomingForestTrustBuildersSid", 0x38)
WinBuiltinPerfMonitoringUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPerfMonitoringUsersSid", 0x39)
WinBuiltinPerfLoggingUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPerfLoggingUsersSid", 0x3a)
WinBuiltinAuthorizationAccessSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinAuthorizationAccessSid", 0x3b)
WinBuiltinTerminalServerLicenseServersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinTerminalServerLicenseServersSid", 0x3c)
WinBuiltinDCOMUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinDCOMUsersSid", 0x3d)
WinBuiltinIUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinIUsersSid", 0x3e)
WinIUserSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinIUserSid", 0x3f)
WinBuiltinCryptoOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinCryptoOperatorsSid", 0x40)
WinUntrustedLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinUntrustedLabelSid", 0x41)
WinLowLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLowLabelSid", 0x42)
WinMediumLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinMediumLabelSid", 0x43)
WinHighLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinHighLabelSid", 0x44)
WinSystemLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinSystemLabelSid", 0x45)
WinWriteRestrictedCodeSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinWriteRestrictedCodeSid", 0x46)
WinCreatorOwnerRightsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorOwnerRightsSid", 0x47)
WinCacheablePrincipalsGroupSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCacheablePrincipalsGroupSid", 0x48)
WinNonCacheablePrincipalsGroupSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNonCacheablePrincipalsGroupSid", 0x49)
WinEnterpriseReadonlyControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinEnterpriseReadonlyControllersSid", 0x4a)
WinAccountReadonlyControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountReadonlyControllersSid", 0x4b)
WinBuiltinEventLogReadersGroup = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinEventLogReadersGroup", 0x4c)
WinNewEnterpriseReadonlyControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNewEnterpriseReadonlyControllersSid", 0x4d)
WinBuiltinCertSvcDComAccessGroup = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinCertSvcDComAccessGroup", 0x4e)
WinMediumPlusLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinMediumPlusLabelSid", 0x4f)
WinLocalLogonSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLocalLogonSid", 0x50)
WinConsoleLogonSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinConsoleLogonSid", 0x51)
WinThisOrganizationCertificateSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinThisOrganizationCertificateSid", 0x52)
WinApplicationPackageAuthoritySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinApplicationPackageAuthoritySid", 0x53)
WinBuiltinAnyPackageSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinAnyPackageSid", 0x54)
WinCapabilityInternetClientSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityInternetClientSid", 0x55)
WinCapabilityInternetClientServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityInternetClientServerSid", 0x56)
WinCapabilityPrivateNetworkClientServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityPrivateNetworkClientServerSid", 0x57)
WinCapabilityPicturesLibrarySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityPicturesLibrarySid", 0x58)
WinCapabilityVideosLibrarySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityVideosLibrarySid", 0x59)
WinCapabilityMusicLibrarySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityMusicLibrarySid", 0x5a)
WinCapabilityDocumentsLibrarySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityDocumentsLibrarySid", 0x5b)
WinCapabilitySharedUserCertificatesSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilitySharedUserCertificatesSid", 0x5c)
WinCapabilityEnterpriseAuthenticationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityEnterpriseAuthenticationSid", 0x5d)
WinCapabilityRemovableStorageSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityRemovableStorageSid", 0x5e)
class _WELL_KNOWN_SID_TYPE(EnumType):
    values = [WinNullSid, WinWorldSid, WinLocalSid, WinCreatorOwnerSid, WinCreatorGroupSid, WinCreatorOwnerServerSid, WinCreatorGroupServerSid, WinNtAuthoritySid, WinDialupSid, WinNetworkSid, WinBatchSid, WinInteractiveSid, WinServiceSid, WinAnonymousSid, WinProxySid, WinEnterpriseControllersSid, WinSelfSid, WinAuthenticatedUserSid, WinRestrictedCodeSid, WinTerminalServerSid, WinRemoteLogonIdSid, WinLogonIdsSid, WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid, WinBuiltinDomainSid, WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinBuiltinGuestsSid, WinBuiltinPowerUsersSid, WinBuiltinAccountOperatorsSid, WinBuiltinSystemOperatorsSid, WinBuiltinPrintOperatorsSid, WinBuiltinBackupOperatorsSid, WinBuiltinReplicatorSid, WinBuiltinPreWindows2000CompatibleAccessSid, WinBuiltinRemoteDesktopUsersSid, WinBuiltinNetworkConfigurationOperatorsSid, WinAccountAdministratorSid, WinAccountGuestSid, WinAccountKrbtgtSid, WinAccountDomainAdminsSid, WinAccountDomainUsersSid, WinAccountDomainGuestsSid, WinAccountComputersSid, WinAccountControllersSid, WinAccountCertAdminsSid, WinAccountSchemaAdminsSid, WinAccountEnterpriseAdminsSid, WinAccountPolicyAdminsSid, WinAccountRasAndIasServersSid, WinNTLMAuthenticationSid, WinDigestAuthenticationSid, WinSChannelAuthenticationSid, WinThisOrganizationSid, WinOtherOrganizationSid, WinBuiltinIncomingForestTrustBuildersSid, WinBuiltinPerfMonitoringUsersSid, WinBuiltinPerfLoggingUsersSid, WinBuiltinAuthorizationAccessSid, WinBuiltinTerminalServerLicenseServersSid, WinBuiltinDCOMUsersSid, WinBuiltinIUsersSid, WinIUserSid, WinBuiltinCryptoOperatorsSid, WinUntrustedLabelSid, WinLowLabelSid, WinMediumLabelSid, WinHighLabelSid, WinSystemLabelSid, WinWriteRestrictedCodeSid, WinCreatorOwnerRightsSid, WinCacheablePrincipalsGroupSid, WinNonCacheablePrincipalsGroupSid, WinEnterpriseReadonlyControllersSid, WinAccountReadonlyControllersSid, WinBuiltinEventLogReadersGroup, WinNewEnterpriseReadonlyControllersSid, WinBuiltinCertSvcDComAccessGroup, WinMediumPlusLabelSid, WinLocalLogonSid, WinConsoleLogonSid, WinThisOrganizationCertificateSid, WinApplicationPackageAuthoritySid, WinBuiltinAnyPackageSid, WinCapabilityInternetClientSid, WinCapabilityInternetClientServerSid, WinCapabilityPrivateNetworkClientServerSid, WinCapabilityPicturesLibrarySid, WinCapabilityVideosLibrarySid, WinCapabilityMusicLibrarySid, WinCapabilityDocumentsLibrarySid, WinCapabilitySharedUserCertificatesSid, WinCapabilityEnterpriseAuthenticationSid, WinCapabilityRemovableStorageSid]
    mapper = FlagMapper(*values)
WELL_KNOWN_SID_TYPE = _WELL_KNOWN_SID_TYPE


ViewShare = EnumValue("_SECTION_INHERIT", "ViewShare", 0x1)
ViewUnmap = EnumValue("_SECTION_INHERIT", "ViewUnmap", 0x2)
class _SECTION_INHERIT(EnumType):
    values = [ViewShare, ViewUnmap]
    mapper = FlagMapper(*values)
SECTION_INHERIT = _SECTION_INHERIT


ProcessBasicInformation = EnumValue("_PROCESSINFOCLASS", "ProcessBasicInformation", 0x0)
ProcessQuotaLimits = EnumValue("_PROCESSINFOCLASS", "ProcessQuotaLimits", 0x1)
ProcessIoCounters = EnumValue("_PROCESSINFOCLASS", "ProcessIoCounters", 0x2)
ProcessVmCounters = EnumValue("_PROCESSINFOCLASS", "ProcessVmCounters", 0x3)
ProcessTimes = EnumValue("_PROCESSINFOCLASS", "ProcessTimes", 0x4)
ProcessBasePriority = EnumValue("_PROCESSINFOCLASS", "ProcessBasePriority", 0x5)
ProcessRaisePriority = EnumValue("_PROCESSINFOCLASS", "ProcessRaisePriority", 0x6)
ProcessDebugPort = EnumValue("_PROCESSINFOCLASS", "ProcessDebugPort", 0x7)
ProcessExceptionPort = EnumValue("_PROCESSINFOCLASS", "ProcessExceptionPort", 0x8)
ProcessAccessToken = EnumValue("_PROCESSINFOCLASS", "ProcessAccessToken", 0x9)
ProcessLdtInformation = EnumValue("_PROCESSINFOCLASS", "ProcessLdtInformation", 0xa)
ProcessLdtSize = EnumValue("_PROCESSINFOCLASS", "ProcessLdtSize", 0xb)
ProcessDefaultHardErrorMode = EnumValue("_PROCESSINFOCLASS", "ProcessDefaultHardErrorMode", 0xc)
ProcessIoPortHandlers = EnumValue("_PROCESSINFOCLASS", "ProcessIoPortHandlers", 0xd)
ProcessPooledUsageAndLimits = EnumValue("_PROCESSINFOCLASS", "ProcessPooledUsageAndLimits", 0xe)
ProcessWorkingSetWatch = EnumValue("_PROCESSINFOCLASS", "ProcessWorkingSetWatch", 0xf)
ProcessUserModeIOPL = EnumValue("_PROCESSINFOCLASS", "ProcessUserModeIOPL", 0x10)
ProcessEnableAlignmentFaultFixup = EnumValue("_PROCESSINFOCLASS", "ProcessEnableAlignmentFaultFixup", 0x11)
ProcessPriorityClass = EnumValue("_PROCESSINFOCLASS", "ProcessPriorityClass", 0x12)
ProcessWx86Information = EnumValue("_PROCESSINFOCLASS", "ProcessWx86Information", 0x13)
ProcessHandleCount = EnumValue("_PROCESSINFOCLASS", "ProcessHandleCount", 0x14)
ProcessAffinityMask = EnumValue("_PROCESSINFOCLASS", "ProcessAffinityMask", 0x15)
ProcessPriorityBoost = EnumValue("_PROCESSINFOCLASS", "ProcessPriorityBoost", 0x16)
ProcessDeviceMap = EnumValue("_PROCESSINFOCLASS", "ProcessDeviceMap", 0x17)
ProcessSessionInformation = EnumValue("_PROCESSINFOCLASS", "ProcessSessionInformation", 0x18)
ProcessForegroundInformation = EnumValue("_PROCESSINFOCLASS", "ProcessForegroundInformation", 0x19)
ProcessWow64Information = EnumValue("_PROCESSINFOCLASS", "ProcessWow64Information", 0x1a)
ProcessImageFileName = EnumValue("_PROCESSINFOCLASS", "ProcessImageFileName", 0x1b)
ProcessLUIDDeviceMapsEnabled = EnumValue("_PROCESSINFOCLASS", "ProcessLUIDDeviceMapsEnabled", 0x1c)
ProcessBreakOnTermination = EnumValue("_PROCESSINFOCLASS", "ProcessBreakOnTermination", 0x1d)
ProcessDebugObjectHandle = EnumValue("_PROCESSINFOCLASS", "ProcessDebugObjectHandle", 0x1e)
ProcessDebugFlags = EnumValue("_PROCESSINFOCLASS", "ProcessDebugFlags", 0x1f)
ProcessHandleTracing = EnumValue("_PROCESSINFOCLASS", "ProcessHandleTracing", 0x20)
ProcessIoPriority = EnumValue("_PROCESSINFOCLASS", "ProcessIoPriority", 0x21)
ProcessExecuteFlags = EnumValue("_PROCESSINFOCLASS", "ProcessExecuteFlags", 0x22)
ProcessTlsInformation = EnumValue("_PROCESSINFOCLASS", "ProcessTlsInformation", 0x23)
ProcessCookie = EnumValue("_PROCESSINFOCLASS", "ProcessCookie", 0x24)
ProcessImageInformation = EnumValue("_PROCESSINFOCLASS", "ProcessImageInformation", 0x25)
ProcessCycleTime = EnumValue("_PROCESSINFOCLASS", "ProcessCycleTime", 0x26)
ProcessPagePriority = EnumValue("_PROCESSINFOCLASS", "ProcessPagePriority", 0x27)
ProcessInstrumentationCallback = EnumValue("_PROCESSINFOCLASS", "ProcessInstrumentationCallback", 0x28)
ProcessThreadStackAllocation = EnumValue("_PROCESSINFOCLASS", "ProcessThreadStackAllocation", 0x29)
ProcessWorkingSetWatchEx = EnumValue("_PROCESSINFOCLASS", "ProcessWorkingSetWatchEx", 0x2a)
ProcessImageFileNameWin32 = EnumValue("_PROCESSINFOCLASS", "ProcessImageFileNameWin32", 0x2b)
ProcessImageFileMapping = EnumValue("_PROCESSINFOCLASS", "ProcessImageFileMapping", 0x2c)
ProcessAffinityUpdateMode = EnumValue("_PROCESSINFOCLASS", "ProcessAffinityUpdateMode", 0x2d)
ProcessMemoryAllocationMode = EnumValue("_PROCESSINFOCLASS", "ProcessMemoryAllocationMode", 0x2e)
ProcessGroupInformation = EnumValue("_PROCESSINFOCLASS", "ProcessGroupInformation", 0x2f)
ProcessTokenVirtualizationEnabled = EnumValue("_PROCESSINFOCLASS", "ProcessTokenVirtualizationEnabled", 0x30)
ProcessOwnerInformation = EnumValue("_PROCESSINFOCLASS", "ProcessOwnerInformation", 0x31)
ProcessWindowInformation = EnumValue("_PROCESSINFOCLASS", "ProcessWindowInformation", 0x32)
ProcessHandleInformation = EnumValue("_PROCESSINFOCLASS", "ProcessHandleInformation", 0x33)
ProcessMitigationPolicy = EnumValue("_PROCESSINFOCLASS", "ProcessMitigationPolicy", 0x34)
ProcessDynamicFunctionTableInformation = EnumValue("_PROCESSINFOCLASS", "ProcessDynamicFunctionTableInformation", 0x35)
ProcessHandleCheckingMode = EnumValue("_PROCESSINFOCLASS", "ProcessHandleCheckingMode", 0x36)
ProcessKeepAliveCount = EnumValue("_PROCESSINFOCLASS", "ProcessKeepAliveCount", 0x37)
ProcessRevokeFileHandles = EnumValue("_PROCESSINFOCLASS", "ProcessRevokeFileHandles", 0x38)
ProcessWorkingSetControl = EnumValue("_PROCESSINFOCLASS", "ProcessWorkingSetControl", 0x39)
ProcessHandleTable = EnumValue("_PROCESSINFOCLASS", "ProcessHandleTable", 0x3a)
ProcessCheckStackExtentsMode = EnumValue("_PROCESSINFOCLASS", "ProcessCheckStackExtentsMode", 0x3b)
ProcessCommandLineInformation = EnumValue("_PROCESSINFOCLASS", "ProcessCommandLineInformation", 0x3c)
ProcessProtectionInformation = EnumValue("_PROCESSINFOCLASS", "ProcessProtectionInformation", 0x3d)
ProcessMemoryExhaustion = EnumValue("_PROCESSINFOCLASS", "ProcessMemoryExhaustion", 0x3e)
ProcessFaultInformation = EnumValue("_PROCESSINFOCLASS", "ProcessFaultInformation", 0x3f)
ProcessTelemetryIdInformation = EnumValue("_PROCESSINFOCLASS", "ProcessTelemetryIdInformation", 0x40)
ProcessCommitReleaseInformation = EnumValue("_PROCESSINFOCLASS", "ProcessCommitReleaseInformation", 0x41)
ProcessReserved1Information = EnumValue("_PROCESSINFOCLASS", "ProcessReserved1Information", 0x42)
ProcessReserved2Information = EnumValue("_PROCESSINFOCLASS", "ProcessReserved2Information", 0x43)
ProcessSubsystemProcess = EnumValue("_PROCESSINFOCLASS", "ProcessSubsystemProcess", 0x44)
ProcessInPrivate = EnumValue("_PROCESSINFOCLASS", "ProcessInPrivate", 0x46)
ProcessRaiseUMExceptionOnInvalidHandleClose = EnumValue("_PROCESSINFOCLASS", "ProcessRaiseUMExceptionOnInvalidHandleClose", 0x47)
ProcessSubsystemInformation = EnumValue("_PROCESSINFOCLASS", "ProcessSubsystemInformation", 0x4b)
ProcessWin32kSyscallFilterInformation = EnumValue("_PROCESSINFOCLASS", "ProcessWin32kSyscallFilterInformation", 0x4f)
ProcessEnergyTrackingState = EnumValue("_PROCESSINFOCLASS", "ProcessEnergyTrackingState", 0x52)
MaxProcessInfoClass = EnumValue("_PROCESSINFOCLASS", "MaxProcessInfoClass", 0x53)
class _PROCESSINFOCLASS(EnumType):
    values = [ProcessBasicInformation, ProcessQuotaLimits, ProcessIoCounters, ProcessVmCounters, ProcessTimes, ProcessBasePriority, ProcessRaisePriority, ProcessDebugPort, ProcessExceptionPort, ProcessAccessToken, ProcessLdtInformation, ProcessLdtSize, ProcessDefaultHardErrorMode, ProcessIoPortHandlers, ProcessPooledUsageAndLimits, ProcessWorkingSetWatch, ProcessUserModeIOPL, ProcessEnableAlignmentFaultFixup, ProcessPriorityClass, ProcessWx86Information, ProcessHandleCount, ProcessAffinityMask, ProcessPriorityBoost, ProcessDeviceMap, ProcessSessionInformation, ProcessForegroundInformation, ProcessWow64Information, ProcessImageFileName, ProcessLUIDDeviceMapsEnabled, ProcessBreakOnTermination, ProcessDebugObjectHandle, ProcessDebugFlags, ProcessHandleTracing, ProcessIoPriority, ProcessExecuteFlags, ProcessTlsInformation, ProcessCookie, ProcessImageInformation, ProcessCycleTime, ProcessPagePriority, ProcessInstrumentationCallback, ProcessThreadStackAllocation, ProcessWorkingSetWatchEx, ProcessImageFileNameWin32, ProcessImageFileMapping, ProcessAffinityUpdateMode, ProcessMemoryAllocationMode, ProcessGroupInformation, ProcessTokenVirtualizationEnabled, ProcessOwnerInformation, ProcessWindowInformation, ProcessHandleInformation, ProcessMitigationPolicy, ProcessDynamicFunctionTableInformation, ProcessHandleCheckingMode, ProcessKeepAliveCount, ProcessRevokeFileHandles, ProcessWorkingSetControl, ProcessHandleTable, ProcessCheckStackExtentsMode, ProcessCommandLineInformation, ProcessProtectionInformation, ProcessMemoryExhaustion, ProcessFaultInformation, ProcessTelemetryIdInformation, ProcessCommitReleaseInformation, ProcessReserved1Information, ProcessReserved2Information, ProcessSubsystemProcess, ProcessInPrivate, ProcessRaiseUMExceptionOnInvalidHandleClose, ProcessSubsystemInformation, ProcessWin32kSyscallFilterInformation, ProcessEnergyTrackingState, MaxProcessInfoClass]
    mapper = FlagMapper(*values)
PROCESSINFOCLASS = _PROCESSINFOCLASS


MemoryBasicInformation = EnumValue("_MEMORY_INFORMATION_CLASS", "MemoryBasicInformation", 0x0)
MemoryWorkingSetList = EnumValue("_MEMORY_INFORMATION_CLASS", "MemoryWorkingSetList", 0x1)
MemorySectionName = EnumValue("_MEMORY_INFORMATION_CLASS", "MemorySectionName", 0x2)
MemoryBasicVlmInformation = EnumValue("_MEMORY_INFORMATION_CLASS", "MemoryBasicVlmInformation", 0x3)
MemoryWorkingSetListEx = EnumValue("_MEMORY_INFORMATION_CLASS", "MemoryWorkingSetListEx", 0x4)
class _MEMORY_INFORMATION_CLASS(EnumType):
    values = [MemoryBasicInformation, MemoryWorkingSetList, MemorySectionName, MemoryBasicVlmInformation, MemoryWorkingSetListEx]
    mapper = FlagMapper(*values)
MEMORY_INFORMATION_CLASS = _MEMORY_INFORMATION_CLASS


ThreadBasicInformation = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadBasicInformation", 0x0)
ThreadTimes = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadTimes", 0x1)
ThreadPriority = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadPriority", 0x2)
ThreadBasePriority = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadBasePriority", 0x3)
ThreadAffinityMask = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadAffinityMask", 0x4)
ThreadImpersonationToken = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadImpersonationToken", 0x5)
ThreadDescriptorTableEntry = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadDescriptorTableEntry", 0x6)
ThreadEnableAlignmentFaultFixup = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadEnableAlignmentFaultFixup", 0x7)
ThreadEventPair = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadEventPair", 0x8)
ThreadQuerySetWin32StartAddress = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadQuerySetWin32StartAddress", 0x9)
ThreadZeroTlsCell = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadZeroTlsCell", 0xa)
ThreadPerformanceCount = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadPerformanceCount", 0xb)
ThreadAmILastThread = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadAmILastThread", 0xc)
ThreadIdealProcessor = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadIdealProcessor", 0xd)
ThreadPriorityBoost = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadPriorityBoost", 0xe)
ThreadSetTlsArrayAddress = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadSetTlsArrayAddress", 0xf)
ThreadIsIoPending = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadIsIoPending", 0x10)
ThreadHideFromDebugger = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadHideFromDebugger", 0x11)
class _THREAD_INFORMATION_CLASS(EnumType):
    values = [ThreadBasicInformation, ThreadTimes, ThreadPriority, ThreadBasePriority, ThreadAffinityMask, ThreadImpersonationToken, ThreadDescriptorTableEntry, ThreadEnableAlignmentFaultFixup, ThreadEventPair, ThreadQuerySetWin32StartAddress, ThreadZeroTlsCell, ThreadPerformanceCount, ThreadAmILastThread, ThreadIdealProcessor, ThreadPriorityBoost, ThreadSetTlsArrayAddress, ThreadIsIoPending, ThreadHideFromDebugger]
    mapper = FlagMapper(*values)
THREAD_INFORMATION_CLASS = _THREAD_INFORMATION_CLASS
PTHREAD_INFORMATION_CLASS = POINTER(_THREAD_INFORMATION_CLASS)


VT_EMPTY = EnumValue("_VARENUM", "VT_EMPTY", 0x0)
VT_NULL = EnumValue("_VARENUM", "VT_NULL", 0x1)
VT_I2 = EnumValue("_VARENUM", "VT_I2", 0x2)
VT_I4 = EnumValue("_VARENUM", "VT_I4", 0x3)
VT_R4 = EnumValue("_VARENUM", "VT_R4", 0x4)
VT_R8 = EnumValue("_VARENUM", "VT_R8", 0x5)
VT_CY = EnumValue("_VARENUM", "VT_CY", 0x6)
VT_DATE = EnumValue("_VARENUM", "VT_DATE", 0x7)
VT_BSTR = EnumValue("_VARENUM", "VT_BSTR", 0x8)
VT_DISPATCH = EnumValue("_VARENUM", "VT_DISPATCH", 0x9)
VT_ERROR = EnumValue("_VARENUM", "VT_ERROR", 0xa)
VT_BOOL = EnumValue("_VARENUM", "VT_BOOL", 0xb)
VT_VARIANT = EnumValue("_VARENUM", "VT_VARIANT", 0xc)
VT_UNKNOWN = EnumValue("_VARENUM", "VT_UNKNOWN", 0xd)
VT_DECIMAL = EnumValue("_VARENUM", "VT_DECIMAL", 0xe)
VT_I1 = EnumValue("_VARENUM", "VT_I1", 0x10)
VT_UI1 = EnumValue("_VARENUM", "VT_UI1", 0x11)
VT_UI2 = EnumValue("_VARENUM", "VT_UI2", 0x12)
VT_UI4 = EnumValue("_VARENUM", "VT_UI4", 0x13)
VT_I8 = EnumValue("_VARENUM", "VT_I8", 0x14)
VT_UI8 = EnumValue("_VARENUM", "VT_UI8", 0x15)
VT_INT = EnumValue("_VARENUM", "VT_INT", 0x16)
VT_UINT = EnumValue("_VARENUM", "VT_UINT", 0x17)
VT_VOID = EnumValue("_VARENUM", "VT_VOID", 0x18)
VT_HRESULT = EnumValue("_VARENUM", "VT_HRESULT", 0x19)
VT_PTR = EnumValue("_VARENUM", "VT_PTR", 0x1a)
VT_SAFEARRAY = EnumValue("_VARENUM", "VT_SAFEARRAY", 0x1b)
VT_CARRAY = EnumValue("_VARENUM", "VT_CARRAY", 0x1c)
VT_USERDEFINED = EnumValue("_VARENUM", "VT_USERDEFINED", 0x1d)
VT_LPSTR = EnumValue("_VARENUM", "VT_LPSTR", 0x1e)
VT_LPWSTR = EnumValue("_VARENUM", "VT_LPWSTR", 0x1f)
VT_RECORD = EnumValue("_VARENUM", "VT_RECORD", 0x24)
VT_INT_PTR = EnumValue("_VARENUM", "VT_INT_PTR", 0x25)
VT_UINT_PTR = EnumValue("_VARENUM", "VT_UINT_PTR", 0x26)
VT_FILETIME = EnumValue("_VARENUM", "VT_FILETIME", 0x40)
VT_BLOB = EnumValue("_VARENUM", "VT_BLOB", 0x41)
VT_STREAM = EnumValue("_VARENUM", "VT_STREAM", 0x42)
VT_STORAGE = EnumValue("_VARENUM", "VT_STORAGE", 0x43)
VT_STREAMED_OBJECT = EnumValue("_VARENUM", "VT_STREAMED_OBJECT", 0x44)
VT_STORED_OBJECT = EnumValue("_VARENUM", "VT_STORED_OBJECT", 0x45)
VT_BLOB_OBJECT = EnumValue("_VARENUM", "VT_BLOB_OBJECT", 0x46)
VT_CF = EnumValue("_VARENUM", "VT_CF", 0x47)
VT_CLSID = EnumValue("_VARENUM", "VT_CLSID", 0x48)
VT_VERSIONED_STREAM = EnumValue("_VARENUM", "VT_VERSIONED_STREAM", 0x49)
VT_BSTR_BLOB = EnumValue("_VARENUM", "VT_BSTR_BLOB", 0xfff)
VT_VECTOR = EnumValue("_VARENUM", "VT_VECTOR", 0x1000)
VT_ARRAY = EnumValue("_VARENUM", "VT_ARRAY", 0x2000)
VT_BYREF = EnumValue("_VARENUM", "VT_BYREF", 0x4000)
VT_RESERVED = EnumValue("_VARENUM", "VT_RESERVED", 0x8000)
VT_ILLEGAL = EnumValue("_VARENUM", "VT_ILLEGAL", 0xffff)
VT_ILLEGALMASKED = EnumValue("_VARENUM", "VT_ILLEGALMASKED", 0xfff)
VT_TYPEMASK = EnumValue("_VARENUM", "VT_TYPEMASK", 0xfff)
class _VARENUM(EnumType):
    values = [VT_EMPTY, VT_NULL, VT_I2, VT_I4, VT_R4, VT_R8, VT_CY, VT_DATE, VT_BSTR, VT_DISPATCH, VT_ERROR, VT_BOOL, VT_VARIANT, VT_UNKNOWN, VT_DECIMAL, VT_I1, VT_UI1, VT_UI2, VT_UI4, VT_I8, VT_UI8, VT_INT, VT_UINT, VT_VOID, VT_HRESULT, VT_PTR, VT_SAFEARRAY, VT_CARRAY, VT_USERDEFINED, VT_LPSTR, VT_LPWSTR, VT_RECORD, VT_INT_PTR, VT_UINT_PTR, VT_FILETIME, VT_BLOB, VT_STREAM, VT_STORAGE, VT_STREAMED_OBJECT, VT_STORED_OBJECT, VT_BLOB_OBJECT, VT_CF, VT_CLSID, VT_VERSIONED_STREAM, VT_BSTR_BLOB, VT_VECTOR, VT_ARRAY, VT_BYREF, VT_RESERVED, VT_ILLEGAL, VT_ILLEGALMASKED, VT_TYPEMASK]
    mapper = FlagMapper(*values)
VARENUM = _VARENUM


UDP_TABLE_BASIC = EnumValue("_UDP_TABLE_CLASS", "UDP_TABLE_BASIC", 0x0)
UDP_TABLE_OWNER_PID = EnumValue("_UDP_TABLE_CLASS", "UDP_TABLE_OWNER_PID", 0x1)
UDP_TABLE_OWNER_MODULE = EnumValue("_UDP_TABLE_CLASS", "UDP_TABLE_OWNER_MODULE", 0x2)
class _UDP_TABLE_CLASS(EnumType):
    values = [UDP_TABLE_BASIC, UDP_TABLE_OWNER_PID, UDP_TABLE_OWNER_MODULE]
    mapper = FlagMapper(*values)
UDP_TABLE_CLASS = _UDP_TABLE_CLASS


NET_FW_RULE_DIR_IN = EnumValue("NET_FW_RULE_DIRECTION_", "NET_FW_RULE_DIR_IN", 0x1)
NET_FW_RULE_DIR_OUT = EnumValue("NET_FW_RULE_DIRECTION_", "NET_FW_RULE_DIR_OUT", 0x2)
NET_FW_RULE_DIR_MAX = EnumValue("NET_FW_RULE_DIRECTION_", "NET_FW_RULE_DIR_MAX", 0x3)
class NET_FW_RULE_DIRECTION_(EnumType):
    values = [NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIR_MAX]
    mapper = FlagMapper(*values)
NET_FW_RULE_DIRECTION = NET_FW_RULE_DIRECTION_


NET_FW_PROFILE2_DOMAIN = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_DOMAIN", 0x1)
NET_FW_PROFILE2_PRIVATE = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_PRIVATE", 0x2)
NET_FW_PROFILE2_PUBLIC = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_PUBLIC", 0x4)
NET_FW_PROFILE2_ALL = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_ALL", 0x7fffffff)
class NET_FW_PROFILE_TYPE2_(EnumType):
    values = [NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE2_ALL]
    mapper = FlagMapper(*values)
NET_FW_PROFILE_TYPE2 = NET_FW_PROFILE_TYPE2_


TokenPrimary = EnumValue("tagTOKEN_TYPE", "TokenPrimary", 0x1)
TokenImpersonation = EnumValue("tagTOKEN_TYPE", "TokenImpersonation", 0x2)
class tagTOKEN_TYPE(EnumType):
    values = [TokenPrimary, TokenImpersonation]
    mapper = FlagMapper(*values)
TOKEN_TYPE = tagTOKEN_TYPE
PTOKEN_TYPE = POINTER(tagTOKEN_TYPE)


FileFsVolumeInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsVolumeInformation", 0x1)
FileFsLabelInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsLabelInformation", 0x2)
FileFsSizeInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsSizeInformation", 0x3)
FileFsDeviceInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsDeviceInformation", 0x4)
FileFsAttributeInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsAttributeInformation", 0x5)
FileFsControlInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsControlInformation", 0x6)
FileFsFullSizeInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsFullSizeInformation", 0x7)
FileFsObjectIdInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsObjectIdInformation", 0x8)
FileFsDriverPathInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsDriverPathInformation", 0x9)
FileFsVolumeFlagsInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsVolumeFlagsInformation", 0xa)
FileFsSectorSizeInformation = EnumValue("_FS_INFORMATION_CLASS", "FileFsSectorSizeInformation", 0xb)
class _FS_INFORMATION_CLASS(EnumType):
    values = [FileFsVolumeInformation, FileFsLabelInformation, FileFsSizeInformation, FileFsDeviceInformation, FileFsAttributeInformation, FileFsControlInformation, FileFsFullSizeInformation, FileFsObjectIdInformation, FileFsDriverPathInformation, FileFsVolumeFlagsInformation, FileFsSectorSizeInformation]
    mapper = FlagMapper(*values)
FS_INFORMATION_CLASS = _FS_INFORMATION_CLASS


SecurityAnonymous = EnumValue("_SECURITY_IMPERSONATION_LEVEL", "SecurityAnonymous", 0x0)
SecurityIdentification = EnumValue("_SECURITY_IMPERSONATION_LEVEL", "SecurityIdentification", 0x1)
SecurityImpersonation = EnumValue("_SECURITY_IMPERSONATION_LEVEL", "SecurityImpersonation", 0x2)
SecurityDelegation = EnumValue("_SECURITY_IMPERSONATION_LEVEL", "SecurityDelegation", 0x3)
class _SECURITY_IMPERSONATION_LEVEL(EnumType):
    values = [SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation]
    mapper = FlagMapper(*values)
SECURITY_IMPERSONATION_LEVEL = _SECURITY_IMPERSONATION_LEVEL
PSECURITY_IMPERSONATION_LEVEL = POINTER(_SECURITY_IMPERSONATION_LEVEL)


ObjectBasicInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectBasicInformation", 0x0)
ObjectNameInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectNameInformation", 0x1)
ObjectTypeInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectTypeInformation", 0x2)
ObjectTypesInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectTypesInformation", 0x3)
ObjectHandleFlagInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectHandleFlagInformation", 0x4)
ObjectSessionInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectSessionInformation", 0x5)
ObjectSessionObjectInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectSessionObjectInformation", 0x6)
MaxObjectInfoClass = EnumValue("_OBJECT_INFORMATION_CLASS", "MaxObjectInfoClass", 0x7)
class _OBJECT_INFORMATION_CLASS(EnumType):
    values = [ObjectBasicInformation, ObjectNameInformation, ObjectTypeInformation, ObjectTypesInformation, ObjectHandleFlagInformation, ObjectSessionInformation, ObjectSessionObjectInformation, MaxObjectInfoClass]
    mapper = FlagMapper(*values)
OBJECT_INFORMATION_CLASS = _OBJECT_INFORMATION_CLASS


SidTypeUser = EnumValue("_SID_NAME_USE", "SidTypeUser", 0x1)
SidTypeGroup = EnumValue("_SID_NAME_USE", "SidTypeGroup", 0x2)
SidTypeDomain = EnumValue("_SID_NAME_USE", "SidTypeDomain", 0x3)
SidTypeAlias = EnumValue("_SID_NAME_USE", "SidTypeAlias", 0x4)
SidTypeWellKnownGroup = EnumValue("_SID_NAME_USE", "SidTypeWellKnownGroup", 0x5)
SidTypeDeletedAccount = EnumValue("_SID_NAME_USE", "SidTypeDeletedAccount", 0x6)
SidTypeInvalid = EnumValue("_SID_NAME_USE", "SidTypeInvalid", 0x7)
SidTypeUnknown = EnumValue("_SID_NAME_USE", "SidTypeUnknown", 0x8)
SidTypeComputer = EnumValue("_SID_NAME_USE", "SidTypeComputer", 0x9)
SidTypeLabel = EnumValue("_SID_NAME_USE", "SidTypeLabel", 0xa)
class _SID_NAME_USE(EnumType):
    values = [SidTypeUser, SidTypeGroup, SidTypeDomain, SidTypeAlias, SidTypeWellKnownGroup, SidTypeDeletedAccount, SidTypeInvalid, SidTypeUnknown, SidTypeComputer, SidTypeLabel]
    mapper = FlagMapper(*values)
SID_NAME_USE = _SID_NAME_USE
PSID_NAME_USE = POINTER(_SID_NAME_USE)


NET_FW_ACTION_BLOCK = EnumValue("NET_FW_ACTION_", "NET_FW_ACTION_BLOCK", 0x0)
NET_FW_ACTION_ALLOW = EnumValue("NET_FW_ACTION_", "NET_FW_ACTION_ALLOW", 0x1)
NET_FW_ACTION_MAX = EnumValue("NET_FW_ACTION_", "NET_FW_ACTION_MAX", 0x2)
class NET_FW_ACTION_(EnumType):
    values = [NET_FW_ACTION_BLOCK, NET_FW_ACTION_ALLOW, NET_FW_ACTION_MAX]
    mapper = FlagMapper(*values)
NET_FW_ACTION = NET_FW_ACTION_


NET_FW_MODIFY_STATE_OK = EnumValue("NET_FW_MODIFY_STATE_", "NET_FW_MODIFY_STATE_OK", 0x0)
NET_FW_MODIFY_STATE_GP_OVERRIDE = EnumValue("NET_FW_MODIFY_STATE_", "NET_FW_MODIFY_STATE_GP_OVERRIDE", 0x1)
NET_FW_MODIFY_STATE_INBOUND_BLOCKED = EnumValue("NET_FW_MODIFY_STATE_", "NET_FW_MODIFY_STATE_INBOUND_BLOCKED", 0x2)
class NET_FW_MODIFY_STATE_(EnumType):
    values = [NET_FW_MODIFY_STATE_OK, NET_FW_MODIFY_STATE_GP_OVERRIDE, NET_FW_MODIFY_STATE_INBOUND_BLOCKED]
    mapper = FlagMapper(*values)
NET_FW_MODIFY_STATE = NET_FW_MODIFY_STATE_


CLSCTX_INPROC_SERVER = EnumValue("tagCLSCTX", "CLSCTX_INPROC_SERVER", 0x1)
CLSCTX_INPROC_HANDLER = EnumValue("tagCLSCTX", "CLSCTX_INPROC_HANDLER", 0x2)
CLSCTX_LOCAL_SERVER = EnumValue("tagCLSCTX", "CLSCTX_LOCAL_SERVER", 0x4)
CLSCTX_INPROC_SERVER16 = EnumValue("tagCLSCTX", "CLSCTX_INPROC_SERVER16", 0x8)
CLSCTX_REMOTE_SERVER = EnumValue("tagCLSCTX", "CLSCTX_REMOTE_SERVER", 0x10)
CLSCTX_INPROC_HANDLER16 = EnumValue("tagCLSCTX", "CLSCTX_INPROC_HANDLER16", 0x20)
CLSCTX_RESERVED1 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED1", 0x40)
CLSCTX_RESERVED2 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED2", 0x80)
CLSCTX_RESERVED3 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED3", 0x100)
CLSCTX_RESERVED4 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED4", 0x200)
CLSCTX_NO_CODE_DOWNLOAD = EnumValue("tagCLSCTX", "CLSCTX_NO_CODE_DOWNLOAD", 0x400)
CLSCTX_RESERVED5 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED5", 0x800)
CLSCTX_NO_CUSTOM_MARSHAL = EnumValue("tagCLSCTX", "CLSCTX_NO_CUSTOM_MARSHAL", 0x1000)
CLSCTX_ENABLE_CODE_DOWNLOAD = EnumValue("tagCLSCTX", "CLSCTX_ENABLE_CODE_DOWNLOAD", 0x2000)
CLSCTX_NO_FAILURE_LOG = EnumValue("tagCLSCTX", "CLSCTX_NO_FAILURE_LOG", 0x4000)
CLSCTX_DISABLE_AAA = EnumValue("tagCLSCTX", "CLSCTX_DISABLE_AAA", 0x8000)
CLSCTX_ENABLE_AAA = EnumValue("tagCLSCTX", "CLSCTX_ENABLE_AAA", 0x10000)
CLSCTX_FROM_DEFAULT_CONTEXT = EnumValue("tagCLSCTX", "CLSCTX_FROM_DEFAULT_CONTEXT", 0x20000)
CLSCTX_ACTIVATE_32_BIT_SERVER = EnumValue("tagCLSCTX", "CLSCTX_ACTIVATE_32_BIT_SERVER", 0x40000)
CLSCTX_ACTIVATE_64_BIT_SERVER = EnumValue("tagCLSCTX", "CLSCTX_ACTIVATE_64_BIT_SERVER", 0x80000)
CLSCTX_ENABLE_CLOAKING = EnumValue("tagCLSCTX", "CLSCTX_ENABLE_CLOAKING", 0x100000)
CLSCTX_APPCONTAINER = EnumValue("tagCLSCTX", "CLSCTX_APPCONTAINER", 0x400000)
CLSCTX_ACTIVATE_AAA_AS_IU = EnumValue("tagCLSCTX", "CLSCTX_ACTIVATE_AAA_AS_IU", 0x800000)
CLSCTX_PS_DLL = EnumValue("tagCLSCTX", "CLSCTX_PS_DLL", 0x80000000)
class tagCLSCTX(EnumType):
    values = [CLSCTX_INPROC_SERVER, CLSCTX_INPROC_HANDLER, CLSCTX_LOCAL_SERVER, CLSCTX_INPROC_SERVER16, CLSCTX_REMOTE_SERVER, CLSCTX_INPROC_HANDLER16, CLSCTX_RESERVED1, CLSCTX_RESERVED2, CLSCTX_RESERVED3, CLSCTX_RESERVED4, CLSCTX_NO_CODE_DOWNLOAD, CLSCTX_RESERVED5, CLSCTX_NO_CUSTOM_MARSHAL, CLSCTX_ENABLE_CODE_DOWNLOAD, CLSCTX_NO_FAILURE_LOG, CLSCTX_DISABLE_AAA, CLSCTX_ENABLE_AAA, CLSCTX_FROM_DEFAULT_CONTEXT, CLSCTX_ACTIVATE_32_BIT_SERVER, CLSCTX_ACTIVATE_64_BIT_SERVER, CLSCTX_ENABLE_CLOAKING, CLSCTX_APPCONTAINER, CLSCTX_ACTIVATE_AAA_AS_IU, CLSCTX_PS_DLL]
    mapper = FlagMapper(*values)
CLSCTX = tagCLSCTX


SE_UNKNOWN_OBJECT_TYPE = EnumValue("_SE_OBJECT_TYPE", "SE_UNKNOWN_OBJECT_TYPE", 0x0)
SE_FILE_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_FILE_OBJECT", 0x1)
SE_SERVICE = EnumValue("_SE_OBJECT_TYPE", "SE_SERVICE", 0x2)
SE_PRINTER = EnumValue("_SE_OBJECT_TYPE", "SE_PRINTER", 0x3)
SE_REGISTRY_KEY = EnumValue("_SE_OBJECT_TYPE", "SE_REGISTRY_KEY", 0x4)
SE_LMSHARE = EnumValue("_SE_OBJECT_TYPE", "SE_LMSHARE", 0x5)
SE_KERNEL_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_KERNEL_OBJECT", 0x6)
SE_WINDOW_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_WINDOW_OBJECT", 0x7)
SE_DS_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_DS_OBJECT", 0x8)
SE_DS_OBJECT_ALL = EnumValue("_SE_OBJECT_TYPE", "SE_DS_OBJECT_ALL", 0x9)
SE_PROVIDER_DEFINED_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_PROVIDER_DEFINED_OBJECT", 0xa)
SE_WMIGUID_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_WMIGUID_OBJECT", 0xb)
SE_REGISTRY_WOW64_32KEY = EnumValue("_SE_OBJECT_TYPE", "SE_REGISTRY_WOW64_32KEY", 0xc)
class _SE_OBJECT_TYPE(EnumType):
    values = [SE_UNKNOWN_OBJECT_TYPE, SE_FILE_OBJECT, SE_SERVICE, SE_PRINTER, SE_REGISTRY_KEY, SE_LMSHARE, SE_KERNEL_OBJECT, SE_WINDOW_OBJECT, SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_PROVIDER_DEFINED_OBJECT, SE_WMIGUID_OBJECT, SE_REGISTRY_WOW64_32KEY]
    mapper = FlagMapper(*values)
SE_OBJECT_TYPE = _SE_OBJECT_TYPE


ViewShare = EnumValue("_SECTION_INHERIT", "ViewShare", 0x1)
ViewUnmap = EnumValue("_SECTION_INHERIT", "ViewUnmap", 0x2)
class _SECTION_INHERIT(EnumType):
    values = [ViewShare, ViewUnmap]
    mapper = FlagMapper(*values)
SECTION_INHERIT = _SECTION_INHERIT


COINIT_APARTMENTTHREADED = EnumValue("tagCOINIT", "COINIT_APARTMENTTHREADED", 0x2)
COINIT_MULTITHREADED = EnumValue("tagCOINIT", "COINIT_MULTITHREADED", 0x0)
COINIT_DISABLE_OLE1DDE = EnumValue("tagCOINIT", "COINIT_DISABLE_OLE1DDE", 0x4)
COINIT_SPEED_OVER_MEMORY = EnumValue("tagCOINIT", "COINIT_SPEED_OVER_MEMORY", 0x8)
class tagCOINIT(EnumType):
    values = [COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED, COINIT_DISABLE_OLE1DDE, COINIT_SPEED_OVER_MEMORY]
    mapper = FlagMapper(*values)
COINIT = tagCOINIT


TKIND_ENUM = EnumValue("tagTYPEKIND", "TKIND_ENUM", 0x0)
TKIND_RECORD = EnumValue("tagTYPEKIND", "TKIND_RECORD", 0x1)
TKIND_MODULE = EnumValue("tagTYPEKIND", "TKIND_MODULE", 0x2)
TKIND_INTERFACE = EnumValue("tagTYPEKIND", "TKIND_INTERFACE", 0x3)
TKIND_DISPATCH = EnumValue("tagTYPEKIND", "TKIND_DISPATCH", 0x4)
TKIND_COCLASS = EnumValue("tagTYPEKIND", "TKIND_COCLASS", 0x5)
TKIND_ALIAS = EnumValue("tagTYPEKIND", "TKIND_ALIAS", 0x6)
TKIND_UNION = EnumValue("tagTYPEKIND", "TKIND_UNION", 0x7)
TKIND_MAX = EnumValue("tagTYPEKIND", "TKIND_MAX", 0x8)
class tagTYPEKIND(EnumType):
    values = [TKIND_ENUM, TKIND_RECORD, TKIND_MODULE, TKIND_INTERFACE, TKIND_DISPATCH, TKIND_COCLASS, TKIND_ALIAS, TKIND_UNION, TKIND_MAX]
    mapper = FlagMapper(*values)
TYPEKIND = tagTYPEKIND


RtlPathTypeUnknown = EnumValue("_RTL_PATH_TYPE", "RtlPathTypeUnknown", 0x0)
RtlPathTypeUncAbsolute = EnumValue("_RTL_PATH_TYPE", "RtlPathTypeUncAbsolute", 0x1)
RtlPathTypeDriveAbsolute = EnumValue("_RTL_PATH_TYPE", "RtlPathTypeDriveAbsolute", 0x2)
RtlPathTypeDriveRelative = EnumValue("_RTL_PATH_TYPE", "RtlPathTypeDriveRelative", 0x3)
RtlPathTypeRooted = EnumValue("_RTL_PATH_TYPE", "RtlPathTypeRooted", 0x4)
RtlPathTypeRelative = EnumValue("_RTL_PATH_TYPE", "RtlPathTypeRelative", 0x5)
RtlPathTypeLocalDevice = EnumValue("_RTL_PATH_TYPE", "RtlPathTypeLocalDevice", 0x6)
RtlPathTypeRootLocalDevice = EnumValue("_RTL_PATH_TYPE", "RtlPathTypeRootLocalDevice", 0x7)
class _RTL_PATH_TYPE(EnumType):
    values = [RtlPathTypeUnknown, RtlPathTypeUncAbsolute, RtlPathTypeDriveAbsolute, RtlPathTypeDriveRelative, RtlPathTypeRooted, RtlPathTypeRelative, RtlPathTypeLocalDevice, RtlPathTypeRootLocalDevice]
    mapper = FlagMapper(*values)
RTL_PATH_TYPE = _RTL_PATH_TYPE


# Self referencing struct tricks
class _LIST_ENTRY(Structure): pass
PLIST_ENTRY = POINTER(_LIST_ENTRY)
LIST_ENTRY = _LIST_ENTRY
PRLIST_ENTRY = POINTER(_LIST_ENTRY)
_LIST_ENTRY._fields_ = [
    ("Flink", POINTER(_LIST_ENTRY)),
    ("Blink", POINTER(_LIST_ENTRY)),
]

class _PEB_LDR_DATA(Structure):
    _fields_ = [
        ("Reserved1", BYTE * (8)),
        ("Reserved2", PVOID * (3)),
        ("InMemoryOrderModuleList", LIST_ENTRY),
    ]
PPEB_LDR_DATA = POINTER(_PEB_LDR_DATA)
PEB_LDR_DATA = _PEB_LDR_DATA

class _LSA_UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", PVOID),
    ]
PUNICODE_STRING = POINTER(_LSA_UNICODE_STRING)
UNICODE_STRING = _LSA_UNICODE_STRING
LSA_UNICODE_STRING = _LSA_UNICODE_STRING
PLSA_UNICODE_STRING = POINTER(_LSA_UNICODE_STRING)

INITIAL_LSA_UNICODE_STRING = _LSA_UNICODE_STRING

class _LSA_UNICODE_STRING(INITIAL_LSA_UNICODE_STRING):
    @property
    def str(self):
        """The python string of the LSA_UNICODE_STRING object

        :type: :class:`unicode`
        """
        if not self.Length:
            return ""
        if getattr(self, "_target", None) is not None: #remote ctypes :D -> TRICKS OF THE YEAR
            raw_data = self._target.read_memory(self.Buffer, self.Length)
            return raw_data.decode("utf16")
        size = int(self.Length / 2)
        return (ctypes.c_wchar * size).from_address(self.Buffer)[:]

    @classmethod
    def from_string(cls, s):
        utf16_len = len(s) * 2
        return cls(utf16_len, utf16_len, ctypes.cast(PWSTR(s), PVOID))

    @classmethod
    def from_size(cls, size):
        buffer = ctypes.create_string_buffer(size)
        return cls(size, size, ctypes.cast(buffer, PVOID))

    def __repr__(self):
        return """<{0} "{1}" at {2}>""".format(type(self).__name__, self.str, hex(id(self)))

    def __sprint__(self):
        try:
            return self.__repr__()
        except TypeError as e:
            # Bad buffer: print raw infos
            return """<{0} len={1} maxlen={2} buffer={3}>""".format(type(self).__name__, self.Length, self.MaximumLength, self.Buffer)

PUNICODE_STRING = POINTER(_LSA_UNICODE_STRING)
UNICODE_STRING = _LSA_UNICODE_STRING
LSA_UNICODE_STRING = _LSA_UNICODE_STRING
PLSA_UNICODE_STRING = POINTER(_LSA_UNICODE_STRING)
class _CURDIR(Structure):
    _fields_ = [
        ("DosPath", UNICODE_STRING),
        ("Handle", PVOID),
    ]
PCURDIR = POINTER(_CURDIR)
CURDIR = _CURDIR

class _RTL_DRIVE_LETTER_CURDIR(Structure):
    _fields_ = [
        ("Flags", WORD),
        ("Length", WORD),
        ("TimeStamp", ULONG),
        ("DosPath", UNICODE_STRING),
    ]
PRTL_DRIVE_LETTER_CURDIR = POINTER(_RTL_DRIVE_LETTER_CURDIR)
RTL_DRIVE_LETTER_CURDIR = _RTL_DRIVE_LETTER_CURDIR

class _RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [
        ("MaximumLength", ULONG),
        ("Length", ULONG),
        ("Flags", ULONG),
        ("DebugFlags", ULONG),
        ("ConsoleHandle", PVOID),
        ("ConsoleFlags", ULONG),
        ("StandardInput", PVOID),
        ("StandardOutput", PVOID),
        ("StandardError", PVOID),
        ("CurrentDirectory", CURDIR),
        ("DllPath", UNICODE_STRING),
        ("ImagePathName", UNICODE_STRING),
        ("CommandLine", UNICODE_STRING),
        ("Environment", PVOID),
        ("StartingX", ULONG),
        ("StartingY", ULONG),
        ("CountX", ULONG),
        ("CountY", ULONG),
        ("CountCharsX", ULONG),
        ("CountCharsY", ULONG),
        ("FillAttribute", ULONG),
        ("WindowFlags", ULONG),
        ("ShowWindowFlags", ULONG),
        ("WindowTitle", UNICODE_STRING),
        ("DesktopInfo", UNICODE_STRING),
        ("ShellInfo", UNICODE_STRING),
        ("RuntimeData", UNICODE_STRING),
        ("CurrentDirectores", RTL_DRIVE_LETTER_CURDIR * (32)),
    ]
PRTL_USER_PROCESS_PARAMETERS = POINTER(_RTL_USER_PROCESS_PARAMETERS)
RTL_USER_PROCESS_PARAMETERS = _RTL_USER_PROCESS_PARAMETERS

class _ANON_PEB_SYSTEM_DEPENDENT_02(Union):
    _fields_ = [
        ("FastPebLockRoutine", PVOID),
        ("SparePtr1", PVOID),
        ("AtlThunkSListPtr", PVOID),
    ]


class _ANON_PEB_SYSTEM_DEPENDENT_03(Union):
    _fields_ = [
        ("FastPebUnlockRoutine", PVOID),
        ("SparePtr2", PVOID),
        ("IFEOKey", PVOID),
    ]


class _ANON_PEB_SYSTEM_DEPENDENT_06(Union):
    _fields_ = [
        ("FreeList", PVOID),
        ("SparePebPtr0", PVOID),
        ("ApiSetMap", PVOID),
    ]


class _ANON_PEB_SYSTEM_DEPENDENT_07(Union):
    _fields_ = [
        ("ReadOnlySharedMemoryHeap", PVOID),
        ("HotpatchInformation", PVOID),
        ("SparePvoid0", PVOID),
    ]


class _ANON_PEB_UNION_1(Union):
    _fields_ = [
        ("KernelCallbackTable", PVOID),
        ("UserSharedInfoPtr", PVOID),
    ]


class _ANON_PEB_UNION_2(Union):
    _fields_ = [
        ("ImageProcessAffinityMask", PVOID),
        ("ActiveProcessAffinityMask", PVOID),
    ]


class _ANON__PEB_SUB_UNION_1(Union):
    _fields_ = [
        ("KernelCallbackTable", PVOID),
        ("UserSharedInfoPtr", PVOID),
    ]


class _ANON__PEB_SUB_UNION_2(Union):
    _fields_ = [
        ("ImageProcessAffinityMask", PVOID),
        ("ActiveProcessAffinityMask", PVOID),
    ]

class _PEB(Structure):
    _anonymous_ = ("_SYSTEM_DEPENDENT_02","_SYSTEM_DEPENDENT_03","anon_01","_SYSTEM_DEPENDENT_06","_SYSTEM_DEPENDENT_07","anon_02")
    _fields_ = [
        ("Reserved1", BYTE * (2)),
        ("BeingDebugged", BYTE),
        ("Reserved2", BYTE * (1)),
        ("Mutant", PVOID),
        ("ImageBaseAddress", PVOID),
        ("Ldr", PPEB_LDR_DATA),
        ("ProcessParameters", PRTL_USER_PROCESS_PARAMETERS),
        ("SubSystemData", PVOID),
        ("ProcessHeap", PVOID),
        ("FastPebLock", PVOID),
        ("_SYSTEM_DEPENDENT_02", _ANON_PEB_SYSTEM_DEPENDENT_02),
        ("_SYSTEM_DEPENDENT_03", _ANON_PEB_SYSTEM_DEPENDENT_03),
        ("_SYSTEM_DEPENDENT_04", PVOID),
        ("anon_01", _ANON__PEB_SUB_UNION_1),
        ("SystemReserved", DWORD),
        ("_SYSTEM_DEPENDENT_05", DWORD),
        ("_SYSTEM_DEPENDENT_06", _ANON_PEB_SYSTEM_DEPENDENT_06),
        ("TlsExpansionCounter", PVOID),
        ("TlsBitmap", PVOID),
        ("TlsBitmapBits", DWORD * (2)),
        ("ReadOnlySharedMemoryBase", PVOID),
        ("_SYSTEM_DEPENDENT_07", _ANON_PEB_SYSTEM_DEPENDENT_07),
        ("ReadOnlyStaticServerData", PVOID),
        ("AnsiCodePageData", PVOID),
        ("OemCodePageData", PVOID),
        ("UnicodeCaseTableData", PVOID),
        ("NumberOfProcessors", DWORD),
        ("NtGlobalFlag", DWORD),
        ("CriticalSectionTimeout", LARGE_INTEGER),
        ("HeapSegmentReserve", PVOID),
        ("HeapSegmentCommit", PVOID),
        ("HeapDeCommitTotalFreeThreshold", PVOID),
        ("HeapDeCommitFreeBlockThreshold", PVOID),
        ("NumberOfHeaps", DWORD),
        ("MaximumNumberOfHeaps", DWORD),
        ("ProcessHeaps", PVOID),
        ("GdiSharedHandleTable", PVOID),
        ("ProcessStarterHelper", PVOID),
        ("GdiDCAttributeList", PVOID),
        ("LoaderLock", PVOID),
        ("OSMajorVersion", DWORD),
        ("OSMinorVersion", DWORD),
        ("OSBuildNumber", WORD),
        ("OSCSDVersion", WORD),
        ("OSPlatformId", DWORD),
        ("ImageSubsystem", DWORD),
        ("ImageSubsystemMajorVersion", DWORD),
        ("ImageSubsystemMinorVersion", PVOID),
        ("anon_02", _ANON__PEB_SUB_UNION_2),
        ("GdiHandleBuffer", PVOID * (26)),
        ("GdiHandleBuffer2", BYTE * (32)),
        ("PostProcessInitRoutine", PVOID),
        ("TlsExpansionBitmap", PVOID),
        ("TlsExpansionBitmapBits", DWORD * (32)),
        ("SessionId", PVOID),
        ("AppCompatFlags", ULARGE_INTEGER),
        ("AppCompatFlagsUser", ULARGE_INTEGER),
        ("pShimData", PVOID),
        ("AppCompatInfo", PVOID),
        ("CSDVersion", UNICODE_STRING),
        ("ActivationContextData", PVOID),
        ("ProcessAssemblyStorageMap", PVOID),
        ("SystemDefaultActivationContextData", PVOID),
        ("SystemAssemblyStorageMap", PVOID),
        ("MinimumStackCommit", PVOID),
    ]
PPEB = POINTER(_PEB)
PEB = _PEB

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL),
    ]
SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
PSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)

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

class _SYSTEM_PROCESS_ID_INFORMATION(Structure):
    _fields_ = [
        ("ProcessId", HANDLE),
        ("ImageName", UNICODE_STRING),
    ]
SYSTEM_PROCESS_ID_INFORMATION = _SYSTEM_PROCESS_ID_INFORMATION
PSYSTEM_PROCESS_ID_INFORMATION = POINTER(_SYSTEM_PROCESS_ID_INFORMATION)

class _CLIENT_ID(Structure):
    _fields_ = [
        ("UniqueProcess", HANDLE),
        ("UniqueThread", HANDLE),
    ]
PCLIENT_ID = POINTER(_CLIENT_ID)
CLIENT_ID = _CLIENT_ID

class _CLIENT_ID64(Structure):
    _fields_ = [
        ("UniqueProcess", ULONG64),
        ("UniqueThread", ULONG64),
    ]
PCLIENT_ID64 = POINTER(_CLIENT_ID64)
CLIENT_ID64 = _CLIENT_ID64

class _CLIENT_ID32(Structure):
    _fields_ = [
        ("UniqueProcess", ULONG),
        ("UniqueThread", ULONG),
    ]
CLIENT_ID32 = _CLIENT_ID32
PCLIENT_ID32 = POINTER(_CLIENT_ID32)

class _LDR_DATA_TABLE_ENTRY(Structure):
    _fields_ = [
        ("Reserved1", PVOID * (2)),
        ("InMemoryOrderLinks", LIST_ENTRY),
        ("Reserved2", PVOID * (2)),
        ("DllBase", PVOID),
        ("EntryPoint", PVOID),
        ("SizeOfImage", PVOID),
        ("FullDllName", UNICODE_STRING),
        ("BaseDllName", UNICODE_STRING),
        ("Reserved5", PVOID * (3)),
        ("CheckSum", ULONG),
        ("TimeDateStamp", ULONG),
    ]
PLDR_DATA_TABLE_ENTRY = POINTER(_LDR_DATA_TABLE_ENTRY)
LDR_DATA_TABLE_ENTRY = _LDR_DATA_TABLE_ENTRY

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

class _IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ("VirtualAddress", DWORD),
        ("Size", DWORD),
    ]
IMAGE_DATA_DIRECTORY = _IMAGE_DATA_DIRECTORY
PIMAGE_DATA_DIRECTORY = POINTER(_IMAGE_DATA_DIRECTORY)

class _IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ("Name", BYTE * (IMAGE_SIZEOF_SHORT_NAME)),
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
        ("DataDirectory", IMAGE_DATA_DIRECTORY * (IMAGE_NUMBEROF_DIRECTORY_ENTRIES)),
    ]
PIMAGE_OPTIONAL_HEADER64 = POINTER(_IMAGE_OPTIONAL_HEADER64)
IMAGE_OPTIONAL_HEADER64 = _IMAGE_OPTIONAL_HEADER64

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
        ("DataDirectory", IMAGE_DATA_DIRECTORY * (IMAGE_NUMBEROF_DIRECTORY_ENTRIES)),
    ]
PIMAGE_OPTIONAL_HEADER32 = POINTER(_IMAGE_OPTIONAL_HEADER)
IMAGE_OPTIONAL_HEADER32 = _IMAGE_OPTIONAL_HEADER

class _IMAGE_NT_HEADERS64(Structure):
    _fields_ = [
        ("Signature", DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER64),
    ]
PIMAGE_NT_HEADERS64 = POINTER(_IMAGE_NT_HEADERS64)
IMAGE_NT_HEADERS64 = _IMAGE_NT_HEADERS64

class _IMAGE_NT_HEADERS(Structure):
    _fields_ = [
        ("Signature", DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER32),
    ]
IMAGE_NT_HEADERS32 = _IMAGE_NT_HEADERS
PIMAGE_NT_HEADERS32 = POINTER(_IMAGE_NT_HEADERS)

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

class _IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [
        ("Hint", WORD),
        ("Name", BYTE * (1)),
    ]
PIMAGE_IMPORT_BY_NAME = POINTER(_IMAGE_IMPORT_BY_NAME)
IMAGE_IMPORT_BY_NAME = _IMAGE_IMPORT_BY_NAME

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

class _IMAGE_DEBUG_DIRECTORY(Structure):
    _fields_ = [
        ("Characteristics", DWORD),
        ("TimeDateStamp", DWORD),
        ("MajorVersion", WORD),
        ("MinorVersion", WORD),
        ("Type", DWORD),
        ("SizeOfData", DWORD),
        ("AddressOfRawData", DWORD),
        ("PointerToRawData", DWORD),
    ]
PIMAGE_DEBUG_DIRECTORY = POINTER(_IMAGE_DEBUG_DIRECTORY)
IMAGE_DEBUG_DIRECTORY = _IMAGE_DEBUG_DIRECTORY

class _IMAGE_BASE_RELOCATION(Structure):
    _fields_ = [
        ("VirtualAddress", DWORD),
        ("SizeOfBlock", DWORD),
    ]
PIMAGE_BASE_RELOCATION = POINTER(_IMAGE_BASE_RELOCATION)
IMAGE_BASE_RELOCATION = _IMAGE_BASE_RELOCATION

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

class _THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus", NTSTATUS),
        ("TebBaseAddress", PVOID),
        ("ClientId", CLIENT_ID),
        ("AffinityMask", KAFFINITY),
        ("Priority", KPRIORITY),
        ("BasePriority", KPRIORITY),
    ]
THREAD_BASIC_INFORMATION = _THREAD_BASIC_INFORMATION
PTHREAD_BASIC_INFORMATION = POINTER(_THREAD_BASIC_INFORMATION)

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

INITIAL_MEMORY_BASIC_INFORMATION32 = _MEMORY_BASIC_INFORMATION32

class _MEMORY_BASIC_INFORMATION32(INITIAL_MEMORY_BASIC_INFORMATION32):
    STATE_MAPPER = FlagMapper(MEM_COMMIT, MEM_FREE, MEM_RESERVE)
    TYPE_MAPPER = FlagMapper(MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE)
    PROTECT_MAPPER = FlagMapper(PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
                                    PAGE_WRITECOPY, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                                    PAGE_EXECUTE_WRITECOPY)


    @property
    def State(self):
        raw_state = super(_MEMORY_BASIC_INFORMATION32, self).State
        # Finally make a chooser somewhere ?
        return self.STATE_MAPPER[raw_state]

    @property
    def Type(self):
        raw_type = super(_MEMORY_BASIC_INFORMATION32, self).Type
        # Finally make a chooser somewhere ?
        return self.TYPE_MAPPER[raw_type]

    @property
    def Protect(self):
        raw_protect = super(_MEMORY_BASIC_INFORMATION32, self).Protect
        # Finally make a chooser somewhere ?
        return self.PROTECT_MAPPER[raw_protect]

    @property
    def AllocationProtect(self):
        raw_protect = super(_MEMORY_BASIC_INFORMATION32, self).AllocationProtect
        # Finally make a chooser somewhere ?
        return self.PROTECT_MAPPER[raw_protect]

    def __repr__(self):
        return "<MEMORY_BASIC_INFORMATION32 BaseAddress={0:#08x} RegionSize={1:#08x} State={2} Type={3} Protect={4}>".format(
            self.BaseAddress, self.RegionSize, self.State, self.Type, self.Protect)
MEMORY_BASIC_INFORMATION32 = _MEMORY_BASIC_INFORMATION32
PMEMORY_BASIC_INFORMATION32 = POINTER(_MEMORY_BASIC_INFORMATION32)
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

INITIAL_MEMORY_BASIC_INFORMATION64 = _MEMORY_BASIC_INFORMATION64

class _MEMORY_BASIC_INFORMATION64(INITIAL_MEMORY_BASIC_INFORMATION64):
    STATE_MAPPER = FlagMapper(MEM_COMMIT, MEM_FREE, MEM_RESERVE)
    TYPE_MAPPER = FlagMapper(MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE)
    PROTECT_MAPPER = FlagMapper(PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
                                    PAGE_WRITECOPY, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                                    PAGE_EXECUTE_WRITECOPY)


    @property
    def State(self):
        raw_state = super(_MEMORY_BASIC_INFORMATION64, self).State
        # Finally make a chooser somewhere ?
        return self.STATE_MAPPER[raw_state]

    @property
    def Type(self):
        raw_type = super(_MEMORY_BASIC_INFORMATION64, self).Type
        # Finally make a chooser somewhere ?
        return self.TYPE_MAPPER[raw_type]

    @property
    def Protect(self):
        raw_protect = super(_MEMORY_BASIC_INFORMATION64, self).Protect
        # Finally make a chooser somewhere ?
        return self.PROTECT_MAPPER[raw_protect]

    @property
    def AllocationProtect(self):
        raw_protect = super(_MEMORY_BASIC_INFORMATION64, self).AllocationProtect
        # Finally make a chooser somewhere ?
        return self.PROTECT_MAPPER[raw_protect]

    def __repr__(self):
        return "<MEMORY_BASIC_INFORMATION64 BaseAddress={0:#08x} RegionSize={1:#08x} State={2} Type={3} Protect={4}>".format(
            self.BaseAddress, self.RegionSize, self.State, self.Type, self.Protect)
PMEMORY_BASIC_INFORMATION64 = POINTER(_MEMORY_BASIC_INFORMATION64)
MEMORY_BASIC_INFORMATION64 = _MEMORY_BASIC_INFORMATION64
class _PSAPI_WORKING_SET_BLOCK(Union):
    _fields_ = [
        ("Flags", PVOID),
    ]
PSAPI_WORKING_SET_BLOCK = _PSAPI_WORKING_SET_BLOCK
PPSAPI_WORKING_SET_BLOCK = POINTER(_PSAPI_WORKING_SET_BLOCK)

class _PSAPI_WORKING_SET_BLOCK32(Union):
    _fields_ = [
        ("Flags", DWORD),
    ]
PSAPI_WORKING_SET_BLOCK32 = _PSAPI_WORKING_SET_BLOCK32
PPSAPI_WORKING_SET_BLOCK32 = POINTER(_PSAPI_WORKING_SET_BLOCK32)

class _PSAPI_WORKING_SET_BLOCK64(Union):
    _fields_ = [
        ("Flags", ULONG64),
    ]
PSAPI_WORKING_SET_BLOCK64 = _PSAPI_WORKING_SET_BLOCK64
PPSAPI_WORKING_SET_BLOCK64 = POINTER(_PSAPI_WORKING_SET_BLOCK64)

class _PSAPI_WORKING_SET_INFORMATION(Structure):
    _fields_ = [
        ("NumberOfEntries", PVOID),
        ("WorkingSetInfo", PSAPI_WORKING_SET_BLOCK * (1)),
    ]
PPSAPI_WORKING_SET_INFORMATION = POINTER(_PSAPI_WORKING_SET_INFORMATION)
PSAPI_WORKING_SET_INFORMATION = _PSAPI_WORKING_SET_INFORMATION

class _PSAPI_WORKING_SET_INFORMATION32(Structure):
    _fields_ = [
        ("NumberOfEntries", DWORD),
        ("WorkingSetInfo", PSAPI_WORKING_SET_BLOCK32 * (1)),
    ]
PPSAPI_WORKING_SET_INFORMATION32 = POINTER(_PSAPI_WORKING_SET_INFORMATION32)
PSAPI_WORKING_SET_INFORMATION32 = _PSAPI_WORKING_SET_INFORMATION32

class _PSAPI_WORKING_SET_INFORMATION64(Structure):
    _fields_ = [
        ("NumberOfEntries", ULONG64),
        ("WorkingSetInfo", PSAPI_WORKING_SET_BLOCK64 * (1)),
    ]
PSAPI_WORKING_SET_INFORMATION64 = _PSAPI_WORKING_SET_INFORMATION64
PPSAPI_WORKING_SET_INFORMATION64 = POINTER(_PSAPI_WORKING_SET_INFORMATION64)

class _PSAPI_WORKING_SET_EX_BLOCK(Union):
    _fields_ = [
        ("Flags", PVOID),
    ]
PSAPI_WORKING_SET_EX_BLOCK = _PSAPI_WORKING_SET_EX_BLOCK
PPSAPI_WORKING_SET_EX_BLOCK = POINTER(_PSAPI_WORKING_SET_EX_BLOCK)

class _PSAPI_WORKING_SET_EX_BLOCK32(Union):
    _fields_ = [
        ("Flags", DWORD),
    ]
PPSAPI_WORKING_SET_EX_BLOCK32 = POINTER(_PSAPI_WORKING_SET_EX_BLOCK32)
PSAPI_WORKING_SET_EX_BLOCK32 = _PSAPI_WORKING_SET_EX_BLOCK32

class _PSAPI_WORKING_SET_EX_BLOCK64(Union):
    _fields_ = [
        ("Flags", ULONG64),
    ]
PSAPI_WORKING_SET_EX_BLOCK64 = _PSAPI_WORKING_SET_EX_BLOCK64
PPSAPI_WORKING_SET_EX_BLOCK64 = POINTER(_PSAPI_WORKING_SET_EX_BLOCK64)

class _PSAPI_WORKING_SET_EX_INFORMATION(Structure):
    _fields_ = [
        ("VirtualAddress", PVOID),
        ("VirtualAttributes", PSAPI_WORKING_SET_EX_BLOCK),
    ]
PPSAPI_WORKING_SET_EX_INFORMATION = POINTER(_PSAPI_WORKING_SET_EX_INFORMATION)
PSAPI_WORKING_SET_EX_INFORMATION = _PSAPI_WORKING_SET_EX_INFORMATION

class _PSAPI_WORKING_SET_EX_INFORMATION32(Structure):
    _fields_ = [
        ("VirtualAddress", DWORD),
        ("VirtualAttributes", PSAPI_WORKING_SET_EX_BLOCK32),
    ]
PSAPI_WORKING_SET_EX_INFORMATION32 = _PSAPI_WORKING_SET_EX_INFORMATION32
PPSAPI_WORKING_SET_EX_INFORMATION32 = POINTER(_PSAPI_WORKING_SET_EX_INFORMATION32)

class _PSAPI_WORKING_SET_EX_INFORMATION64(Structure):
    _fields_ = [
        ("VirtualAddress", ULONG64),
        ("VirtualAttributes", PSAPI_WORKING_SET_EX_BLOCK64),
    ]
PPSAPI_WORKING_SET_EX_INFORMATION64 = POINTER(_PSAPI_WORKING_SET_EX_INFORMATION64)
PSAPI_WORKING_SET_EX_INFORMATION64 = _PSAPI_WORKING_SET_EX_INFORMATION64

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

class _STARTUPINFOEXA(Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOA),
        ("lpAttributeList", LPPROC_THREAD_ATTRIBUTE_LIST),
    ]
LPSTARTUPINFOEXA = POINTER(_STARTUPINFOEXA)
STARTUPINFOEXA = _STARTUPINFOEXA

class _STARTUPINFOEXW(Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", LPPROC_THREAD_ATTRIBUTE_LIST),
    ]
STARTUPINFOEXW = _STARTUPINFOEXW
LPSTARTUPINFOEXW = POINTER(_STARTUPINFOEXW)

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

class _FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * (80)),
        ("Cr0NpxState", DWORD),
    ]
FLOATING_SAVE_AREA = _FLOATING_SAVE_AREA

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
        ("ExtendedRegisters", BYTE * (512)),
    ]
PCONTEXT32 = POINTER(_CONTEXT32)
CONTEXT32 = _CONTEXT32
LPCONTEXT32 = POINTER(_CONTEXT32)

class _WOW64_FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * (WOW64_SIZE_OF_80387_REGISTERS)),
        ("Cr0NpxState", DWORD),
    ]
WOW64_FLOATING_SAVE_AREA = _WOW64_FLOATING_SAVE_AREA

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
        ("ExtendedRegisters", BYTE * (WOW64_MAXIMUM_SUPPORTED_EXTENSION)),
    ]
PWOW64_CONTEXT = POINTER(_WOW64_CONTEXT)
WOW64_CONTEXT = _WOW64_CONTEXT

class _M128A(Structure):
    _fields_ = [
        ("Low", ULONGLONG),
        ("High", LONGLONG),
    ]
M128A = _M128A
PM128A = POINTER(_M128A)

class _XSAVE_FORMAT_64(Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * (8)),
        ("XmmRegisters", M128A * (16)),
        ("Reserved4", BYTE * (96)),
    ]
XSAVE_FORMAT_64 = _XSAVE_FORMAT_64
PXSAVE_FORMAT_64 = POINTER(_XSAVE_FORMAT_64)

class _XSAVE_FORMAT_32(Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * (8)),
        ("XmmRegisters", M128A * (8)),
        ("Reserved4", BYTE * (192)),
        ("StackControl", DWORD * (7)),
        ("Cr0NpxState", DWORD),
    ]
XSAVE_FORMAT_32 = _XSAVE_FORMAT_32
PXSAVE_FORMAT_32 = POINTER(_XSAVE_FORMAT_32)

class _TMP_DUMMYSTRUCTNAME(Structure):
    _fields_ = [
        ("Header", M128A * (2)),
        ("Legacy", M128A * (8)),
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
    ]
TMP_DUMMYSTRUCTNAME = _TMP_DUMMYSTRUCTNAME

class _TMP_CONTEXT64_SUBUNION(Union):
    _fields_ = [
        ("FltSave", XSAVE_FORMAT_64),
        ("DUMMYSTRUCTNAME", TMP_DUMMYSTRUCTNAME),
    ]
TMP_CONTEXT64_SUBUNION = _TMP_CONTEXT64_SUBUNION

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
        ("DUMMYUNIONNAME", TMP_CONTEXT64_SUBUNION),
        ("VectorRegister", M128A * (26)),
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
        ("szExeFile", WCHAR * (MAX_PATH)),
    ]
PPROCESSENTRY32W = POINTER(tagPROCESSENTRY32W)
LPPROCESSENTRY32W = POINTER(tagPROCESSENTRY32W)
PROCESSENTRY32W = tagPROCESSENTRY32W

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
        ("szExeFile", CHAR * (MAX_PATH)),
    ]
PROCESSENTRY32 = tagPROCESSENTRY32
PPROCESSENTRY32 = POINTER(tagPROCESSENTRY32)
LPPROCESSENTRY32 = POINTER(tagPROCESSENTRY32)

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

class _LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]
LUID = _LUID
PLUID = POINTER(_LUID)

_INITIAL_LUID = _LUID
class _LUID(_INITIAL_LUID):
    def __int__(self):
        return (self.HighPart << 32) | self.LowPart

    def __eq__(self, other):
        return (self.HighPart, self.LowPart) == (other.HighPart, other.LowPart)

    def __repr__(self):
        return "<{0} HighPart={1} LowPart={2}>".format(type(self).__name__, self.HighPart, self.LowPart)
LUID = _LUID
PLUID = POINTER(_LUID)
class _LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]
LUID_AND_ATTRIBUTES = _LUID_AND_ATTRIBUTES
PLUID_AND_ATTRIBUTES = POINTER(_LUID_AND_ATTRIBUTES)

class _OSVERSIONINFOA(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", CHAR * (128)),
    ]
POSVERSIONINFOA = POINTER(_OSVERSIONINFOA)
OSVERSIONINFOA = _OSVERSIONINFOA
LPOSVERSIONINFOA = POINTER(_OSVERSIONINFOA)

class _OSVERSIONINFOW(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", WCHAR * (128)),
    ]
RTL_OSVERSIONINFOW = _OSVERSIONINFOW
PRTL_OSVERSIONINFOW = POINTER(_OSVERSIONINFOW)
LPOSVERSIONINFOW = POINTER(_OSVERSIONINFOW)
POSVERSIONINFOW = POINTER(_OSVERSIONINFOW)
OSVERSIONINFOW = _OSVERSIONINFOW

class _OSVERSIONINFOEXA(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", CHAR * (128)),
        ("wServicePackMajor", WORD),
        ("wServicePackMinor", WORD),
        ("wSuiteMask", WORD),
        ("wProductType", BYTE),
        ("wReserved", BYTE),
    ]
OSVERSIONINFOEXA = _OSVERSIONINFOEXA
POSVERSIONINFOEXA = POINTER(_OSVERSIONINFOEXA)
LPOSVERSIONINFOEXA = POINTER(_OSVERSIONINFOEXA)

class _OSVERSIONINFOEXW(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", WCHAR * (128)),
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

class _OVERLAPPED(Structure):
    _fields_ = [
        ("Internal", ULONG_PTR),
        ("InternalHigh", ULONG_PTR),
        ("Pointer", PVOID),
        ("hEvent", HANDLE),
    ]
LPOVERLAPPED = POINTER(_OVERLAPPED)
OVERLAPPED = _OVERLAPPED

# Self referencing struct tricks
class _EXCEPTION_RECORD(Structure): pass
PEXCEPTION_RECORD = POINTER(_EXCEPTION_RECORD)
EXCEPTION_RECORD = _EXCEPTION_RECORD
_EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", POINTER(_EXCEPTION_RECORD)),
    ("ExceptionAddress", PVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", ULONG_PTR * (EXCEPTION_MAXIMUM_PARAMETERS)),
]

class _EXCEPTION_RECORD32(Structure):
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", DWORD),
        ("ExceptionAddress", DWORD),
        ("NumberParameters", DWORD),
        ("ExceptionInformation", DWORD * (EXCEPTION_MAXIMUM_PARAMETERS)),
    ]
EXCEPTION_RECORD32 = _EXCEPTION_RECORD32
PEXCEPTION_RECORD32 = POINTER(_EXCEPTION_RECORD32)

class _EXCEPTION_RECORD64(Structure):
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", DWORD64),
        ("ExceptionAddress", DWORD64),
        ("NumberParameters", DWORD),
        ("__unusedAlignment", DWORD),
        ("ExceptionInformation", DWORD64 * (EXCEPTION_MAXIMUM_PARAMETERS)),
    ]
PEXCEPTION_RECORD64 = POINTER(_EXCEPTION_RECORD64)
EXCEPTION_RECORD64 = _EXCEPTION_RECORD64

class _EXCEPTION_POINTERS64(Structure):
    _fields_ = [
        ("ExceptionRecord", PEXCEPTION_RECORD),
        ("ContextRecord", PCONTEXT64),
    ]
EXCEPTION_POINTERS64 = _EXCEPTION_POINTERS64
PEXCEPTION_POINTERS64 = POINTER(_EXCEPTION_POINTERS64)

class _EXCEPTION_POINTERS32(Structure):
    _fields_ = [
        ("ExceptionRecord", PEXCEPTION_RECORD),
        ("ContextRecord", PCONTEXT32),
    ]
PEXCEPTION_POINTERS32 = POINTER(_EXCEPTION_POINTERS32)
EXCEPTION_POINTERS32 = _EXCEPTION_POINTERS32

class _DEBUG_PROCESSOR_IDENTIFICATION_ALPHA(Structure):
    _fields_ = [
        ("Type", ULONG),
        ("Revision", ULONG),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_ALPHA = _DEBUG_PROCESSOR_IDENTIFICATION_ALPHA
PDEBUG_PROCESSOR_IDENTIFICATION_ALPHA = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_ALPHA)

class _DEBUG_PROCESSOR_IDENTIFICATION_AMD64(Structure):
    _fields_ = [
        ("Family", ULONG),
        ("Model", ULONG),
        ("Stepping", ULONG),
        ("VendorString", CHAR * (16)),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_AMD64 = _DEBUG_PROCESSOR_IDENTIFICATION_AMD64
PDEBUG_PROCESSOR_IDENTIFICATION_AMD64 = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_AMD64)

class _DEBUG_PROCESSOR_IDENTIFICATION_IA64(Structure):
    _fields_ = [
        ("Model", ULONG),
        ("Revision", ULONG),
        ("Family", ULONG),
        ("ArchRev", ULONG),
        ("VendorString", CHAR * (16)),
    ]
PDEBUG_PROCESSOR_IDENTIFICATION_IA64 = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_IA64)
DEBUG_PROCESSOR_IDENTIFICATION_IA64 = _DEBUG_PROCESSOR_IDENTIFICATION_IA64

class _DEBUG_PROCESSOR_IDENTIFICATION_X86(Structure):
    _fields_ = [
        ("Family", ULONG),
        ("Model", ULONG),
        ("Stepping", ULONG),
        ("VendorString", CHAR * (16)),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_X86 = _DEBUG_PROCESSOR_IDENTIFICATION_X86
PDEBUG_PROCESSOR_IDENTIFICATION_X86 = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_X86)

class _DEBUG_PROCESSOR_IDENTIFICATION_ARM(Structure):
    _fields_ = [
        ("Type", ULONG),
        ("Revision", ULONG),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_ARM = _DEBUG_PROCESSOR_IDENTIFICATION_ARM
PDEBUG_PROCESSOR_IDENTIFICATION_ARM = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_ARM)

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

class _SYSTEM_MODULE32(Structure):
    _fields_ = [
        ("Reserved", ULONG * (2)),
        ("Base", ULONG),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Index", USHORT),
        ("Unknown", USHORT),
        ("LoadCount", USHORT),
        ("ModuleNameOffset", USHORT),
        ("ImageName", CHAR * (256)),
    ]
SYSTEM_MODULE32 = _SYSTEM_MODULE32
PSYSTEM_MODULE32 = POINTER(_SYSTEM_MODULE32)

class _SYSTEM_MODULE64(Structure):
    _fields_ = [
        ("Reserved", ULONG * (4)),
        ("Base", ULONG64),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Index", USHORT),
        ("Unknown", USHORT),
        ("LoadCount", USHORT),
        ("ModuleNameOffset", USHORT),
        ("ImageName", CHAR * (256)),
    ]
SYSTEM_MODULE64 = _SYSTEM_MODULE64
PSYSTEM_MODULE64 = POINTER(_SYSTEM_MODULE64)

class _SYSTEM_MODULE_INFORMATION32(Structure):
    _fields_ = [
        ("ModulesCount", ULONG),
        ("Modules", SYSTEM_MODULE32 * (0)),
    ]
PSYSTEM_MODULE_INFORMATION32 = POINTER(_SYSTEM_MODULE_INFORMATION32)
SYSTEM_MODULE_INFORMATION32 = _SYSTEM_MODULE_INFORMATION32

class _SYSTEM_MODULE_INFORMATION64(Structure):
    _fields_ = [
        ("ModulesCount", ULONG),
        ("Modules", SYSTEM_MODULE64 * (0)),
    ]
PSYSTEM_MODULE_INFORMATION64 = POINTER(_SYSTEM_MODULE_INFORMATION64)
SYSTEM_MODULE_INFORMATION64 = _SYSTEM_MODULE_INFORMATION64

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

class _DEBUG_STACK_FRAME(Structure):
    _fields_ = [
        ("InstructionOffset", ULONG64),
        ("ReturnOffset", ULONG64),
        ("FrameOffset", ULONG64),
        ("StackOffset", ULONG64),
        ("FuncTableEntry", ULONG64),
        ("Params", ULONG64 * (4)),
        ("Reserved", ULONG64 * (6)),
        ("Virtual", BOOL),
        ("FrameNumber", ULONG),
    ]
PDEBUG_STACK_FRAME = POINTER(_DEBUG_STACK_FRAME)
DEBUG_STACK_FRAME = _DEBUG_STACK_FRAME

class _DEBUG_LAST_EVENT_INFO_BREAKPOINT(Structure):
    _fields_ = [
        ("Id", ULONG),
    ]
DEBUG_LAST_EVENT_INFO_BREAKPOINT = _DEBUG_LAST_EVENT_INFO_BREAKPOINT
PDEBUG_LAST_EVENT_INFO_BREAKPOINT = POINTER(_DEBUG_LAST_EVENT_INFO_BREAKPOINT)

class _DEBUG_LAST_EVENT_INFO_EXCEPTION(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD64),
        ("FirstChance", ULONG),
    ]
DEBUG_LAST_EVENT_INFO_EXCEPTION = _DEBUG_LAST_EVENT_INFO_EXCEPTION
PDEBUG_LAST_EVENT_INFO_EXCEPTION = POINTER(_DEBUG_LAST_EVENT_INFO_EXCEPTION)

class _DEBUG_LAST_EVENT_INFO_EXIT_THREAD(Structure):
    _fields_ = [
        ("ExitCode", ULONG),
    ]
PDEBUG_LAST_EVENT_INFO_EXIT_THREAD = POINTER(_DEBUG_LAST_EVENT_INFO_EXIT_THREAD)
DEBUG_LAST_EVENT_INFO_EXIT_THREAD = _DEBUG_LAST_EVENT_INFO_EXIT_THREAD

class _DEBUG_LAST_EVENT_INFO_EXIT_PROCESS(Structure):
    _fields_ = [
        ("ExitCode", ULONG),
    ]
PDEBUG_LAST_EVENT_INFO_EXIT_PROCESS = POINTER(_DEBUG_LAST_EVENT_INFO_EXIT_PROCESS)
DEBUG_LAST_EVENT_INFO_EXIT_PROCESS = _DEBUG_LAST_EVENT_INFO_EXIT_PROCESS

class _DEBUG_LAST_EVENT_INFO_LOAD_MODULE(Structure):
    _fields_ = [
        ("Base", ULONG64),
    ]
PDEBUG_LAST_EVENT_INFO_LOAD_MODULE = POINTER(_DEBUG_LAST_EVENT_INFO_LOAD_MODULE)
DEBUG_LAST_EVENT_INFO_LOAD_MODULE = _DEBUG_LAST_EVENT_INFO_LOAD_MODULE

class _DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE(Structure):
    _fields_ = [
        ("Base", ULONG64),
    ]
PDEBUG_LAST_EVENT_INFO_UNLOAD_MODULE = POINTER(_DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE)
DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE = _DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE

class _DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR(Structure):
    _fields_ = [
        ("Error", ULONG),
        ("Level", ULONG),
    ]
PDEBUG_LAST_EVENT_INFO_SYSTEM_ERROR = POINTER(_DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR)
DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR = _DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR

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

class _TMP_signscale(Structure):
    _fields_ = [
        ("scale", BYTE),
        ("sign", BYTE),
    ]


class _TMP_lowmid(Structure):
    _fields_ = [
        ("Lo32", ULONG),
        ("Mid32", ULONG),
    ]


class TMP_signscale_union(Union):
    _fields_ = [
        ("s", _TMP_signscale),
        ("signscale", USHORT),
    ]


class TMP_lowmid_union(Union):
    _fields_ = [
        ("s", _TMP_lowmid),
        ("Lo64", ULONGLONG),
    ]


class tagDEC(Structure):
    _fields_ = [
        ("wReserved", USHORT),
        ("u1", TMP_signscale_union),
        ("Hi32", ULONG),
        ("u2", TMP_signscale_union),
    ]
DECIMAL = tagDEC

class tagDISPPARAMS(Structure):
    _fields_ = [
        ("rgvarg", POINTER(VARIANTARG)),
        ("rgdispidNamedArgs", POINTER(DISPID)),
        ("cArgs", UINT),
        ("cNamedArgs", UINT),
    ]
DISPPARAMS = tagDISPPARAMS

class tagEXCEPINFO(Structure):
    _fields_ = [
        ("wCode", WORD),
        ("wReserved", WORD),
        ("bstrSource", BSTR),
        ("bstrDescription", BSTR),
        ("bstrHelpFile", BSTR),
        ("dwHelpContext", DWORD),
        ("pvReserved", ULONG_PTR),
        ("pfnDeferredFillIn", ULONG_PTR),
        ("scode", SCODE),
    ]
EXCEPINFO = tagEXCEPINFO

class _PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus", NTSTATUS),
        ("PebBaseAddress", PPEB),
        ("AffinityMask", ULONG_PTR),
        ("BasePriority", KPRIORITY),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", HANDLE),
    ]
PPROCESS_BASIC_INFORMATION = POINTER(_PROCESS_BASIC_INFORMATION)
PROCESS_BASIC_INFORMATION = _PROCESS_BASIC_INFORMATION

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

class _SID_IDENTIFIER_AUTHORITY(Structure):
    _fields_ = [
        ("Value", BYTE * (6)),
    ]
SID_IDENTIFIER_AUTHORITY = _SID_IDENTIFIER_AUTHORITY
PSID_IDENTIFIER_AUTHORITY = POINTER(_SID_IDENTIFIER_AUTHORITY)

class _STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPCSTR),
    ]
PCANSI_STRING = POINTER(_STRING)
PSTRING = POINTER(_STRING)
STRING = _STRING
PANSI_STRING = POINTER(_STRING)

class _OBJECT_ATTRIBUTES(Structure):
    _fields_ = [
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", PUNICODE_STRING),
        ("Attributes", ULONG),
        ("SecurityDescriptor", PVOID),
        ("SecurityQualityOfService", PVOID),
    ]
POBJECT_ATTRIBUTES = POINTER(_OBJECT_ATTRIBUTES)
OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES

class _OBJECT_ATTRIBUTES(_OBJECT_ATTRIBUTES):
    @classmethod
    def from_string(cls, path, attributes=OBJ_CASE_INSENSITIVE): # Directly on constructor ?
        self = cls()
        self.Length = ctypes.sizeof(self)
        self.RootDirectory = 0
        self.ObjectName = ctypes.pointer(LSA_UNICODE_STRING.from_string(path))
        self.Attributes = attributes
        self.SecurityDescriptor = 0
        self.SecurityQualityOfService = 0
        return self

    def __repr__(self):
        if not self.ObjectName:
            return super(_OBJECT_ATTRIBUTES, self).__repr__()
        return """<{0} ObjectName="{1}">""".format(type(self).__name__, self.ObjectName[0].str)
POBJECT_ATTRIBUTES = POINTER(_OBJECT_ATTRIBUTES)
OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES
class _TMP_UNION_IO_STATUS_BLOCK(Union):
    _fields_ = [
        ("Status", NTSTATUS),
        ("Pointer", PVOID),
    ]
TMP_UNION_IO_STATUS_BLOCK = _TMP_UNION_IO_STATUS_BLOCK

class _IO_STATUS_BLOCK(Structure):
    _fields_ = [
        ("DUMMYUNIONNAME", TMP_UNION_IO_STATUS_BLOCK),
        ("Information", ULONG_PTR),
    ]
IO_STATUS_BLOCK = _IO_STATUS_BLOCK
PIO_STATUS_BLOCK = POINTER(_IO_STATUS_BLOCK)

class _SECURITY_QUALITY_OF_SERVICE(Structure):
    _fields_ = [
        ("Length", DWORD),
        ("ImpersonationLevel", SECURITY_IMPERSONATION_LEVEL),
        ("ContextTrackingMode", SECURITY_CONTEXT_TRACKING_MODE),
        ("EffectiveOnly", BOOLEAN),
    ]
PSECURITY_QUALITY_OF_SERVICE = POINTER(_SECURITY_QUALITY_OF_SERVICE)
SECURITY_QUALITY_OF_SERVICE = _SECURITY_QUALITY_OF_SERVICE

class CATALOG_INFO_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("wszCatalogFile", WCHAR * (MAX_PATH)),
    ]
CATALOG_INFO = CATALOG_INFO_

class _SYSTEM_HANDLE(Structure):
    _fields_ = [
        ("dwProcessId", DWORD),
        ("bObjectType", BYTE),
        ("bFlags", BYTE),
        ("wValue", WORD),
        ("pAddress", PVOID),
        ("GrantedAccess", DWORD),
    ]
SYSTEM_HANDLE = _SYSTEM_HANDLE

class _SYSTEM_HANDLE64(Structure):
    _fields_ = [
        ("dwProcessId", DWORD),
        ("bObjectType", BYTE),
        ("bFlags", BYTE),
        ("wValue", WORD),
        ("pAddress", ULONG64),
        ("GrantedAccess", DWORD),
    ]
SYSTEM_HANDLE64 = _SYSTEM_HANDLE64

class _SYSTEM_HANDLE_INFORMATION(Structure):
    _fields_ = [
        ("HandleCount", ULONG),
        ("Handles", SYSTEM_HANDLE * (1)),
    ]
PSYSTEM_HANDLE_INFORMATION = POINTER(_SYSTEM_HANDLE_INFORMATION)
SYSTEM_HANDLE_INFORMATION = _SYSTEM_HANDLE_INFORMATION

class _SYSTEM_HANDLE_INFORMATION64(Structure):
    _fields_ = [
        ("HandleCount", ULONG),
        ("Handles", SYSTEM_HANDLE64 * (1)),
    ]
SYSTEM_HANDLE_INFORMATION64 = _SYSTEM_HANDLE_INFORMATION64
PSYSTEM_HANDLE_INFORMATION64 = POINTER(_SYSTEM_HANDLE_INFORMATION64)

class __PUBLIC_OBJECT_TYPE_INFORMATION(Structure):
    _fields_ = [
        ("TypeName", UNICODE_STRING),
        ("Reserved", ULONG * (22)),
    ]
PPUBLIC_OBJECT_TYPE_INFORMATION = POINTER(__PUBLIC_OBJECT_TYPE_INFORMATION)
PUBLIC_OBJECT_TYPE_INFORMATION = __PUBLIC_OBJECT_TYPE_INFORMATION

class _PUBLIC_OBJECT_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("Attributes", ULONG),
        ("GrantedAccess", ACCESS_MASK),
        ("HandleCount", ULONG),
        ("PointerCount", ULONG),
        ("Reserved", ULONG * (10)),
    ]
PUBLIC_OBJECT_BASIC_INFORMATION = _PUBLIC_OBJECT_BASIC_INFORMATION
PPUBLIC_OBJECT_BASIC_INFORMATION = POINTER(_PUBLIC_OBJECT_BASIC_INFORMATION)

class _OBJECT_TYPES_INFORMATION(Structure):
    _fields_ = [
        ("NumberOfTypes", ULONG),
    ]
OBJECT_TYPES_INFORMATION = _OBJECT_TYPES_INFORMATION
POBJECT_TYPES_INFORMATION = POINTER(_OBJECT_TYPES_INFORMATION)

class tagSOLE_AUTHENTICATION_SERVICE(Structure):
    _fields_ = [
        ("dwAuthnSvc", DWORD),
        ("dwAuthzSvc", DWORD),
        ("pPrincipalName", POINTER(OLECHAR)),
        ("hr", HRESULT),
    ]
PSOLE_AUTHENTICATION_SERVICE = POINTER(tagSOLE_AUTHENTICATION_SERVICE)
SOLE_AUTHENTICATION_SERVICE = tagSOLE_AUTHENTICATION_SERVICE

class _OBJECT_DIRECTORY_INFORMATION(Structure):
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("TypeName", UNICODE_STRING),
    ]
OBJECT_DIRECTORY_INFORMATION = _OBJECT_DIRECTORY_INFORMATION
POBJECT_DIRECTORY_INFORMATION = POINTER(_OBJECT_DIRECTORY_INFORMATION)

class _DEBUG_VALUE_TMP_SUBSTRUCT1(Structure):
    _fields_ = [
        ("I64", ULONG64),
        ("Nat", BOOL),
    ]
DEBUG_VALUE_TMP_SUBSTRUCT1 = _DEBUG_VALUE_TMP_SUBSTRUCT1

class _DEBUG_VALUE_TMP_SUBSTRUCT2(Structure):
    _fields_ = [
        ("LowPart", ULONG),
        ("HighPart", ULONG),
    ]
DEBUG_VALUE_TMP_SUBSTRUCT2 = _DEBUG_VALUE_TMP_SUBSTRUCT2

class _DEBUG_VALUE_TMP_SUBSTRUCT3(Structure):
    _fields_ = [
        ("LowPart", ULONG64),
        ("HighPart", LONG64),
    ]
DEBUG_VALUE_TMP_SUBSTRUCT3 = _DEBUG_VALUE_TMP_SUBSTRUCT3

class _DEBUG_VALUE_TMP_UNION(Union):
    _fields_ = [
        ("I8", UCHAR),
        ("I16", USHORT),
        ("I32", ULONG),
        ("tmp_sub_struct_1", _DEBUG_VALUE_TMP_SUBSTRUCT1),
        ("F32", FLOAT),
        ("F64", DOUBLE),
        ("F80Bytes", UCHAR * (10)),
        ("F82Bytes", UCHAR * (11)),
        ("F128Bytes", UCHAR * (16)),
        ("VI8", UCHAR * (16)),
        ("VI16", USHORT * (8)),
        ("VI32", ULONG * (4)),
        ("VI64", ULONG64 * (2)),
        ("VF32", FLOAT * (4)),
        ("VF64", DOUBLE * (2)),
        ("I64Parts32", DEBUG_VALUE_TMP_SUBSTRUCT2),
        ("F128Parts64", DEBUG_VALUE_TMP_SUBSTRUCT3),
        ("RawBytes", UCHAR * (24)),
    ]
DEBUG_VALUE_TMP_UNION = _DEBUG_VALUE_TMP_UNION

class _DEBUG_VALUE(Structure):
    _fields_ = [
        ("u", _DEBUG_VALUE_TMP_UNION),
        ("TailOfRawBytes", ULONG),
        ("Type", ULONG),
    ]
DEBUG_VALUE = _DEBUG_VALUE
PDEBUG_VALUE = POINTER(_DEBUG_VALUE)

class _DEBUG_SYMBOL_PARAMETERS(Structure):
    _fields_ = [
        ("Module", ULONG64),
        ("TypeId", ULONG),
        ("ParentSymbol", ULONG),
        ("SubElements", ULONG),
        ("Flags", ULONG),
        ("Reserved", ULONG64),
    ]
DEBUG_SYMBOL_PARAMETERS = _DEBUG_SYMBOL_PARAMETERS
PDEBUG_SYMBOL_PARAMETERS = POINTER(_DEBUG_SYMBOL_PARAMETERS)

class _DEBUG_SYMBOL_ENTRY(Structure):
    _fields_ = [
        ("ModuleBase", ULONG64),
        ("Offset", ULONG64),
        ("Id", ULONG64),
        ("Arg64", ULONG64),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("TypeId", ULONG),
        ("NameSize", ULONG),
        ("Token", ULONG),
        ("Tag", ULONG),
        ("Arg32", ULONG),
        ("Reserved", ULONG),
    ]
PDEBUG_SYMBOL_ENTRY = POINTER(_DEBUG_SYMBOL_ENTRY)
DEBUG_SYMBOL_ENTRY = _DEBUG_SYMBOL_ENTRY

class _DEBUG_MODULE_PARAMETERS(Structure):
    _fields_ = [
        ("Base", ULONG64),
        ("Size", ULONG),
        ("TimeDateStamp", ULONG),
        ("Checksum", ULONG),
        ("Flags", ULONG),
        ("SymbolType", ULONG),
        ("ImageNameSize", ULONG),
        ("ModuleNameSize", ULONG),
        ("LoadedImageNameSize", ULONG),
        ("SymbolFileNameSize", ULONG),
        ("MappedImageNameSize", ULONG),
        ("Reserved", ULONG64 * (2)),
    ]
PDEBUG_MODULE_PARAMETERS = POINTER(_DEBUG_MODULE_PARAMETERS)
DEBUG_MODULE_PARAMETERS = _DEBUG_MODULE_PARAMETERS

class _DEBUG_MODULE_AND_ID(Structure):
    _fields_ = [
        ("ModuleBase", ULONG64),
        ("Id", ULONG64),
    ]
DEBUG_MODULE_AND_ID = _DEBUG_MODULE_AND_ID
PDEBUG_MODULE_AND_ID = POINTER(_DEBUG_MODULE_AND_ID)

class _DEBUG_OFFSET_REGION(Structure):
    _fields_ = [
        ("Base", ULONG64),
        ("Size", ULONG64),
    ]
DEBUG_OFFSET_REGION = _DEBUG_OFFSET_REGION
PDEBUG_OFFSET_REGION = POINTER(_DEBUG_OFFSET_REGION)

class _DEBUG_SYMBOL_SOURCE_ENTRY(Structure):
    _fields_ = [
        ("ModuleBase", ULONG64),
        ("Offset", ULONG64),
        ("FileNameId", ULONG64),
        ("EngineInternal", ULONG64),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("FileNameSize", ULONG),
        ("StartLine", ULONG),
        ("EndLine", ULONG),
        ("StartColumn", ULONG),
        ("EndColumn", ULONG),
        ("Reserved", ULONG),
    ]
DEBUG_SYMBOL_SOURCE_ENTRY = _DEBUG_SYMBOL_SOURCE_ENTRY
PDEBUG_SYMBOL_SOURCE_ENTRY = POINTER(_DEBUG_SYMBOL_SOURCE_ENTRY)

class _RTL_UNLOAD_EVENT_TRACE(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("SizeOfImage", SIZE_T),
        ("Sequence", ULONG),
        ("TimeDateStamp", ULONG),
        ("CheckSum", ULONG),
        ("ImageName", WCHAR * (32)),
        ("Version", ULONG * (2)),
    ]
PRTL_UNLOAD_EVENT_TRACE = POINTER(_RTL_UNLOAD_EVENT_TRACE)
RTL_UNLOAD_EVENT_TRACE = _RTL_UNLOAD_EVENT_TRACE

class _RTL_UNLOAD_EVENT_TRACE32(Structure):
    _fields_ = [
        ("BaseAddress", DWORD),
        ("SizeOfImage", DWORD),
        ("Sequence", ULONG),
        ("TimeDateStamp", ULONG),
        ("CheckSum", ULONG),
        ("ImageName", WCHAR * (32)),
        ("Version", ULONG * (2)),
    ]
RTL_UNLOAD_EVENT_TRACE32 = _RTL_UNLOAD_EVENT_TRACE32
PRTL_UNLOAD_EVENT_TRACE32 = POINTER(_RTL_UNLOAD_EVENT_TRACE32)

class _RTL_UNLOAD_EVENT_TRACE64(Structure):
    _fields_ = [
        ("BaseAddress", ULONGLONG),
        ("SizeOfImage", ULONGLONG),
        ("Sequence", ULONG),
        ("TimeDateStamp", ULONG),
        ("CheckSum", ULONG),
        ("ImageName", WCHAR * (32)),
        ("Version", ULONG * (2)),
    ]
PRTL_UNLOAD_EVENT_TRACE64 = POINTER(_RTL_UNLOAD_EVENT_TRACE64)
RTL_UNLOAD_EVENT_TRACE64 = _RTL_UNLOAD_EVENT_TRACE64

class _FILE_FS_ATTRIBUTE_INFORMATION(Structure):
    _fields_ = [
        ("FileSystemAttributes", ULONG),
        ("MaximumComponentNameLength", LONG),
        ("FileSystemNameLength", ULONG),
        ("FileSystemName", WCHAR * (1)),
    ]
PFILE_FS_ATTRIBUTE_INFORMATION = POINTER(_FILE_FS_ATTRIBUTE_INFORMATION)
FILE_FS_ATTRIBUTE_INFORMATION = _FILE_FS_ATTRIBUTE_INFORMATION

class _FILE_FS_LABEL_INFORMATION(Structure):
    _fields_ = [
        ("VolumeLabelLength", ULONG),
        ("VolumeLabel", WCHAR * (1)),
    ]
FILE_FS_LABEL_INFORMATION = _FILE_FS_LABEL_INFORMATION
PFILE_FS_LABEL_INFORMATION = POINTER(_FILE_FS_LABEL_INFORMATION)

class _FILE_FS_SIZE_INFORMATION(Structure):
    _fields_ = [
        ("TotalAllocationUnits", LARGE_INTEGER),
        ("AvailableAllocationUnits", LARGE_INTEGER),
        ("SectorsPerAllocationUnit", ULONG),
        ("BytesPerSector", ULONG),
    ]
PFILE_FS_SIZE_INFORMATION = POINTER(_FILE_FS_SIZE_INFORMATION)
FILE_FS_SIZE_INFORMATION = _FILE_FS_SIZE_INFORMATION

class _FILE_FS_DEVICE_INFORMATION(Structure):
    _fields_ = [
        ("DeviceType", DEVICE_TYPE),
        ("Characteristics", ULONG),
    ]
FILE_FS_DEVICE_INFORMATION = _FILE_FS_DEVICE_INFORMATION
PFILE_FS_DEVICE_INFORMATION = POINTER(_FILE_FS_DEVICE_INFORMATION)

class _FILE_FS_CONTROL_INFORMATION(Structure):
    _fields_ = [
        ("FreeSpaceStartFiltering", LARGE_INTEGER),
        ("FreeSpaceThreshold", LARGE_INTEGER),
        ("FreeSpaceStopFiltering", LARGE_INTEGER),
        ("DefaultQuotaThreshold", LARGE_INTEGER),
        ("DefaultQuotaLimit", LARGE_INTEGER),
        ("FileSystemControlFlags", ULONG),
    ]
FILE_FS_CONTROL_INFORMATION = _FILE_FS_CONTROL_INFORMATION
PFILE_FS_CONTROL_INFORMATION = POINTER(_FILE_FS_CONTROL_INFORMATION)

class _FILE_FS_FULL_SIZE_INFORMATION(Structure):
    _fields_ = [
        ("TotalAllocationUnits", LARGE_INTEGER),
        ("CallerAvailableAllocationUnits", LARGE_INTEGER),
        ("ActualAvailableAllocationUnits", LARGE_INTEGER),
        ("SectorsPerAllocationUnit", ULONG),
        ("BytesPerSector", ULONG),
    ]
PFILE_FS_FULL_SIZE_INFORMATION = POINTER(_FILE_FS_FULL_SIZE_INFORMATION)
FILE_FS_FULL_SIZE_INFORMATION = _FILE_FS_FULL_SIZE_INFORMATION

class _FILE_FS_OBJECTID_INFORMATION(Structure):
    _fields_ = [
        ("ObjectId", UCHAR * (16)),
        ("ExtendedInfo", UCHAR * (48)),
    ]
FILE_FS_OBJECTID_INFORMATION = _FILE_FS_OBJECTID_INFORMATION
PFILE_FS_OBJECTID_INFORMATION = POINTER(_FILE_FS_OBJECTID_INFORMATION)

class _FILE_FS_DRIVER_PATH_INFORMATION(Structure):
    _fields_ = [
        ("DriverInPath", BOOLEAN),
        ("DriverNameLength", ULONG),
        ("DriverName", WCHAR * (1)),
    ]
FILE_FS_DRIVER_PATH_INFORMATION = _FILE_FS_DRIVER_PATH_INFORMATION
PFILE_FS_DRIVER_PATH_INFORMATION = POINTER(_FILE_FS_DRIVER_PATH_INFORMATION)

class _FILE_FS_DRIVER_PATH_INFORMATION(Structure):
    _fields_ = [
        ("DriverInPath", BOOLEAN),
        ("DriverNameLength", ULONG),
        ("DriverName", WCHAR * (1)),
    ]
FILE_FS_DRIVER_PATH_INFORMATION = _FILE_FS_DRIVER_PATH_INFORMATION
PFILE_FS_DRIVER_PATH_INFORMATION = POINTER(_FILE_FS_DRIVER_PATH_INFORMATION)

class _FILE_FS_VOLUME_INFORMATION(Structure):
    _fields_ = [
        ("VolumeCreationTime", LARGE_INTEGER),
        ("VolumeSerialNumber", ULONG),
        ("VolumeLabelLength", ULONG),
        ("SupportsObjects", BOOLEAN),
        ("VolumeLabel", WCHAR * (1)),
    ]
FILE_FS_VOLUME_INFORMATION = _FILE_FS_VOLUME_INFORMATION
PFILE_FS_VOLUME_INFORMATION = POINTER(_FILE_FS_VOLUME_INFORMATION)

class _FILE_FS_SECTOR_SIZE_INFORMATION(Structure):
    _fields_ = [
        ("LogicalBytesPerSector", ULONG),
        ("PhysicalBytesPerSectorForAtomicity", ULONG),
        ("PhysicalBytesPerSectorForPerformance", ULONG),
        ("FileSystemEffectivePhysicalBytesPerSectorForAtomicity", ULONG),
        ("Flags", ULONG),
        ("ByteOffsetForSectorAlignment", ULONG),
        ("ByteOffsetForPartitionAlignment", ULONG),
    ]
PFILE_FS_SECTOR_SIZE_INFORMATION = POINTER(_FILE_FS_SECTOR_SIZE_INFORMATION)
FILE_FS_SECTOR_SIZE_INFORMATION = _FILE_FS_SECTOR_SIZE_INFORMATION

class _RTLP_CURDIR_REF(Structure):
    _fields_ = [
        ("RefCount", LONG),
        ("Handle", HANDLE),
    ]
PRTLP_CURDIR_REF = POINTER(_RTLP_CURDIR_REF)
RTLP_CURDIR_REF = _RTLP_CURDIR_REF

class _RTL_RELATIVE_NAME_U(Structure):
    _fields_ = [
        ("RelativeName", UNICODE_STRING),
        ("ContainingDirectory", HANDLE),
        ("CurDirRef", PRTLP_CURDIR_REF),
    ]
PRTL_RELATIVE_NAME_U = POINTER(_RTL_RELATIVE_NAME_U)
RTL_RELATIVE_NAME_U = _RTL_RELATIVE_NAME_U

class _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION(Structure):
    _fields_ = [
        ("Version", ULONG),
        ("Reserved", ULONG),
        ("Callback", PVOID),
    ]
PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION = POINTER(_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION)
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION = _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION

class _PROCESS_MEMORY_COUNTERS(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("PageFaultCount", DWORD),
        ("PeakWorkingSetSize", SIZE_T),
        ("WorkingSetSize", SIZE_T),
        ("QuotaPeakPagedPoolUsage", SIZE_T),
        ("QuotaPagedPoolUsage", SIZE_T),
        ("QuotaPeakNonPagedPoolUsage", SIZE_T),
        ("QuotaNonPagedPoolUsage", SIZE_T),
        ("PagefileUsage", SIZE_T),
        ("PeakPagefileUsage", SIZE_T),
    ]
PPROCESS_MEMORY_COUNTERS = POINTER(_PROCESS_MEMORY_COUNTERS)
PROCESS_MEMORY_COUNTERS = _PROCESS_MEMORY_COUNTERS

class _PROCESS_MEMORY_COUNTERS_EX(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("PageFaultCount", DWORD),
        ("PeakWorkingSetSize", SIZE_T),
        ("WorkingSetSize", SIZE_T),
        ("QuotaPeakPagedPoolUsage", SIZE_T),
        ("QuotaPagedPoolUsage", SIZE_T),
        ("QuotaPeakNonPagedPoolUsage", SIZE_T),
        ("QuotaNonPagedPoolUsage", SIZE_T),
        ("PagefileUsage", SIZE_T),
        ("PeakPagefileUsage", SIZE_T),
        ("PrivateUsage", SIZE_T),
    ]
PROCESS_MEMORY_COUNTERS_EX = _PROCESS_MEMORY_COUNTERS_EX

class _FILETIME(Structure):
    _fields_ = [
        ("dwLowDateTime", DWORD),
        ("dwHighDateTime", DWORD),
    ]
LPFILETIME = POINTER(_FILETIME)
PFILETIME = POINTER(_FILETIME)
FILETIME = _FILETIME

INITIAL_FILETIME = FILETIME

class _FILETIME(INITIAL_FILETIME):
    def __int__(self):
        return (self.dwHighDateTime << 32) + self.dwLowDateTime
LPFILETIME = POINTER(_FILETIME)
PFILETIME = POINTER(_FILETIME)
FILETIME = _FILETIME
AlpcBasicInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcBasicInformation", 0x0)
AlpcPortInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcPortInformation", 0x1)
AlpcAssociateCompletionPortInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcAssociateCompletionPortInformation", 0x2)
AlpcConnectedSIDInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcConnectedSIDInformation", 0x3)
AlpcServerInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcServerInformation", 0x4)
AlpcMessageZoneInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcMessageZoneInformation", 0x5)
AlpcRegisterCompletionListInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcRegisterCompletionListInformation", 0x6)
AlpcUnregisterCompletionListInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcUnregisterCompletionListInformation", 0x7)
AlpcAdjustCompletionListConcurrencyCountInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcAdjustCompletionListConcurrencyCountInformation", 0x8)
AlpcRegisterCallbackInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcRegisterCallbackInformation", 0x9)
AlpcCompletionListRundownInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcCompletionListRundownInformation", 0xa)
AlpcWaitForPortReferences = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcWaitForPortReferences", 0xb)
MaxAlpcPortInfoClass = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "MaxAlpcPortInfoClass", 0xc)
class _ALPC_PORT_INFORMATION_CLASS(EnumType):
    values = [AlpcBasicInformation, AlpcPortInformation, AlpcAssociateCompletionPortInformation, AlpcConnectedSIDInformation, AlpcServerInformation, AlpcMessageZoneInformation, AlpcRegisterCompletionListInformation, AlpcUnregisterCompletionListInformation, AlpcAdjustCompletionListConcurrencyCountInformation, AlpcRegisterCallbackInformation, AlpcCompletionListRundownInformation, AlpcWaitForPortReferences, MaxAlpcPortInfoClass]
    mapper = FlagMapper(*values)
ALPC_PORT_INFORMATION_CLASS = _ALPC_PORT_INFORMATION_CLASS


AlpcMessageSidInformation = EnumValue("_ALPC_MESSAGE_INFORMATION_CLASS", "AlpcMessageSidInformation", 0x0)
AlpcMessageTokenModifiedIdInformation = EnumValue("_ALPC_MESSAGE_INFORMATION_CLASS", "AlpcMessageTokenModifiedIdInformation", 0x1)
MaxAlpcMessageInfoClass = EnumValue("_ALPC_MESSAGE_INFORMATION_CLASS", "MaxAlpcMessageInfoClass", 0x2)
AlpcMessageHandleInformation = EnumValue("_ALPC_MESSAGE_INFORMATION_CLASS", "AlpcMessageHandleInformation", 0x3)
class _ALPC_MESSAGE_INFORMATION_CLASS(EnumType):
    values = [AlpcMessageSidInformation, AlpcMessageTokenModifiedIdInformation, MaxAlpcMessageInfoClass, AlpcMessageHandleInformation]
    mapper = FlagMapper(*values)
ALPC_MESSAGE_INFORMATION_CLASS = _ALPC_MESSAGE_INFORMATION_CLASS
PALPC_MESSAGE_INFORMATION_CLASS = POINTER(_ALPC_MESSAGE_INFORMATION_CLASS)


class _ALPC_PORT_ATTRIBUTES32(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SecurityQos", SECURITY_QUALITY_OF_SERVICE),
        ("MaxMessageLength", SIZE_T),
        ("MemoryBandwidth", SIZE_T),
        ("MaxPoolUsage", SIZE_T),
        ("MaxSectionSize", SIZE_T),
        ("MaxViewSize", SIZE_T),
        ("MaxTotalSectionSize", SIZE_T),
        ("DupObjectTypes", ULONG),
    ]
PALPC_PORT_ATTRIBUTES32 = POINTER(_ALPC_PORT_ATTRIBUTES32)
ALPC_PORT_ATTRIBUTES32 = _ALPC_PORT_ATTRIBUTES32

class _ALPC_PORT_ATTRIBUTES64(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SecurityQos", SECURITY_QUALITY_OF_SERVICE),
        ("MaxMessageLength", SIZE_T),
        ("MemoryBandwidth", SIZE_T),
        ("MaxPoolUsage", SIZE_T),
        ("MaxSectionSize", SIZE_T),
        ("MaxViewSize", SIZE_T),
        ("MaxTotalSectionSize", SIZE_T),
        ("DupObjectTypes", ULONG),
        ("Reserved", ULONG),
    ]
ALPC_PORT_ATTRIBUTES64 = _ALPC_PORT_ATTRIBUTES64
PALPC_PORT_ATTRIBUTES64 = POINTER(_ALPC_PORT_ATTRIBUTES64)

class _ALPC_MESSAGE_ATTRIBUTES(Structure):
    _fields_ = [
        ("AllocatedAttributes", ULONG),
        ("ValidAttributes", ULONG),
    ]
ALPC_MESSAGE_ATTRIBUTES = _ALPC_MESSAGE_ATTRIBUTES
PALPC_MESSAGE_ATTRIBUTES = POINTER(_ALPC_MESSAGE_ATTRIBUTES)

class _PORT_MESSAGE32_TMP_UNION(Union):
    _fields_ = [
        ("ClientViewSize", ULONG),
        ("CallbackId", ULONG),
    ]
PORT_MESSAGE_TMP_UNION = _PORT_MESSAGE32_TMP_UNION

class _PORT_MESSAGE64_TMP_UNION(Union):
    _fields_ = [
        ("ClientViewSize", ULONGLONG),
        ("CallbackId", ULONG),
    ]
PORT_MESSAGE_TMP_UNION = _PORT_MESSAGE64_TMP_UNION

class _PORT_MESSAGE_TMP_SUBSTRUCT_S1(Structure):
    _fields_ = [
        ("DataLength", CSHORT),
        ("TotalLength", CSHORT),
    ]


class _PORT_MESSAGE_TMP_UNION_U1(Union):
    _fields_ = [
        ("Length", ULONG),
        ("s1", _PORT_MESSAGE_TMP_SUBSTRUCT_S1),
    ]


class _PORT_MESSAGE_TMP_SUBSTRUCT_S2(Structure):
    _fields_ = [
        ("Type", CSHORT),
        ("DataInfoOffset", CSHORT),
    ]


class _PORT_MESSAGE_TMP_UNION_U2(Union):
    _fields_ = [
        ("ZeroInit", ULONG),
        ("s2", _PORT_MESSAGE_TMP_SUBSTRUCT_S2),
    ]


class _PORT_MESSAGE32(Structure):
    _fields_ = [
        ("u1", _PORT_MESSAGE_TMP_UNION_U1),
        ("u2", _PORT_MESSAGE_TMP_UNION_U2),
        ("ClientId", CLIENT_ID32),
        ("MessageId", ULONG),
        ("tmp_union", _PORT_MESSAGE32_TMP_UNION),
    ]
PORT_MESSAGE32 = _PORT_MESSAGE32
PPORT_MESSAGE32 = POINTER(_PORT_MESSAGE32)

class _PORT_MESSAGE64(Structure):
    _fields_ = [
        ("u1", _PORT_MESSAGE_TMP_UNION_U1),
        ("u2", _PORT_MESSAGE_TMP_UNION_U2),
        ("ClientId", CLIENT_ID64),
        ("MessageId", ULONG),
        ("tmp_union", _PORT_MESSAGE64_TMP_UNION),
    ]
PPORT_MESSAGE64 = POINTER(_PORT_MESSAGE64)
PORT_MESSAGE64 = _PORT_MESSAGE64

class _ALPC_SERVER_INFORMATION_TMP_IN(Structure):
    _fields_ = [
        ("ThreadHandle", HANDLE),
    ]
ALPC_SERVER_INFORMATION_TMP_IN = _ALPC_SERVER_INFORMATION_TMP_IN

class _ALPC_SERVER_INFORMATION_TMP_OUT(Structure):
    _fields_ = [
        ("ThreadBlocked", BOOLEAN),
        ("ConnectedProcessId", HANDLE),
        ("ConnectionPortName", UNICODE_STRING),
    ]
ALPC_SERVER_INFORMATION_TMP_OUT = _ALPC_SERVER_INFORMATION_TMP_OUT

class ALPC_SERVER_INFORMATION(Union):
    _fields_ = [
        ("In", ALPC_SERVER_INFORMATION_TMP_IN),
        ("Out", ALPC_SERVER_INFORMATION_TMP_OUT),
    ]


class _ALPC_CONTEXT_ATTR(Structure):
    _fields_ = [
        ("PortContext", PVOID),
        ("MessageContext", PVOID),
        ("Sequence", ULONG),
        ("MessageId", ULONG),
        ("CallbackId", ULONG),
    ]
PALPC_CONTEXT_ATTR = POINTER(_ALPC_CONTEXT_ATTR)
ALPC_CONTEXT_ATTR = _ALPC_CONTEXT_ATTR

class _ALPC_CONTEXT_ATTR32(Structure):
    _fields_ = [
        ("PortContext", ULONG),
        ("MessageContext", ULONG),
        ("Sequence", ULONG),
        ("MessageId", ULONG),
        ("CallbackId", ULONG),
    ]
ALPC_CONTEXT_ATTR32 = _ALPC_CONTEXT_ATTR32
PALPC_CONTEXT_ATTR32 = POINTER(_ALPC_CONTEXT_ATTR32)

class _ALPC_CONTEXT_ATTR64(Structure):
    _fields_ = [
        ("PortContext", ULONGLONG),
        ("MessageContext", ULONGLONG),
        ("Sequence", ULONG),
        ("MessageId", ULONG),
        ("CallbackId", ULONG),
    ]
ALPC_CONTEXT_ATTR64 = _ALPC_CONTEXT_ATTR64
PALPC_CONTEXT_ATTR64 = POINTER(_ALPC_CONTEXT_ATTR64)

class _ALPC_HANDLE_ATTR(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("Handle", HANDLE),
        ("ObjectType", ULONG),
        ("DesiredAccess", ACCESS_MASK),
    ]
PALPC_HANDLE_ATTR = POINTER(_ALPC_HANDLE_ATTR)
ALPC_HANDLE_ATTR = _ALPC_HANDLE_ATTR

class _ALPC_HANDLE_ATTR32(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("Handle", ULONG),
        ("ObjectType", ULONG),
        ("DesiredAccess", ACCESS_MASK),
    ]
ALPC_HANDLE_ATTR32 = _ALPC_HANDLE_ATTR32
PALPC_HANDLE_ATTR32 = POINTER(_ALPC_HANDLE_ATTR32)

class _ALPC_HANDLE_ATTR64(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("Handle", ULONGLONG),
        ("ObjectType", ULONG),
        ("DesiredAccess", ACCESS_MASK),
    ]
PALPC_HANDLE_ATTR64 = POINTER(_ALPC_HANDLE_ATTR64)
ALPC_HANDLE_ATTR64 = _ALPC_HANDLE_ATTR64

class _ALPC_SECURITY_ATTR(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("QoS", PSECURITY_QUALITY_OF_SERVICE),
        ("ContextHandle", ALPC_HANDLE),
    ]
PALPC_SECURITY_ATTR = POINTER(_ALPC_SECURITY_ATTR)
ALPC_SECURITY_ATTR = _ALPC_SECURITY_ATTR

class _ALPC_SECURITY_ATTR32(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("QoS", ULONG),
        ("ContextHandle", ULONG),
    ]
ALPC_SECURITY_ATTR32 = _ALPC_SECURITY_ATTR32
PALPC_SECURITY_ATTR32 = POINTER(_ALPC_SECURITY_ATTR32)

class _ALPC_SECURITY_ATTR64(Structure):
    _fields_ = [
        ("Flags", ULONGLONG),
        ("QoS", ULONGLONG),
        ("ContextHandle", ULONGLONG),
    ]
PALPC_SECURITY_ATTR64 = POINTER(_ALPC_SECURITY_ATTR64)
ALPC_SECURITY_ATTR64 = _ALPC_SECURITY_ATTR64

class _ALPC_DATA_VIEW_ATTR(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SectionHandle", ALPC_HANDLE),
        ("ViewBase", PVOID),
        ("ViewSize", PVOID),
    ]
PALPC_DATA_VIEW_ATTR = POINTER(_ALPC_DATA_VIEW_ATTR)
ALPC_DATA_VIEW_ATTR = _ALPC_DATA_VIEW_ATTR

class _ALPC_DATA_VIEW_ATTR32(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SectionHandle", ULONG),
        ("ViewBase", ULONG),
        ("ViewSize", ULONG),
    ]
PALPC_DATA_VIEW_ATTR32 = POINTER(_ALPC_DATA_VIEW_ATTR32)
ALPC_DATA_VIEW_ATTR32 = _ALPC_DATA_VIEW_ATTR32

class _ALPC_DATA_VIEW_ATTR64(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SectionHandle", ULONGLONG),
        ("ViewBase", ULONGLONG),
        ("ViewSize", ULONGLONG),
    ]
PALPC_DATA_VIEW_ATTR64 = POINTER(_ALPC_DATA_VIEW_ATTR64)
ALPC_DATA_VIEW_ATTR64 = _ALPC_DATA_VIEW_ATTR64

class _ALPC_TOKEN_ATTR(Structure):
    _fields_ = [
        ("TokenId", ULONGLONG),
        ("AuthenticationId", ULONGLONG),
        ("ModifiedId", ULONGLONG),
    ]
ALPC_TOKEN_ATTR = _ALPC_TOKEN_ATTR
PALPC_TOKEN_ATTR = POINTER(_ALPC_TOKEN_ATTR)

class _ALPC_DIRECT_ATTR(Structure):
    _fields_ = [
        ("Event", HANDLE),
    ]
ALPC_DIRECT_ATTR = _ALPC_DIRECT_ATTR
PALPC_DIRECT_ATTR = POINTER(_ALPC_DIRECT_ATTR)

class _ALPC_DIRECT_ATTR32(Structure):
    _fields_ = [
        ("Event", ULONG),
    ]
PALPC_DIRECT_ATTR32 = POINTER(_ALPC_DIRECT_ATTR32)
ALPC_DIRECT_ATTR32 = _ALPC_DIRECT_ATTR32

class _ALPC_DIRECT_ATTR64(Structure):
    _fields_ = [
        ("Event", ULONGLONG),
    ]
ALPC_DIRECT_ATTR64 = _ALPC_DIRECT_ATTR64
PALPC_DIRECT_ATTR64 = POINTER(_ALPC_DIRECT_ATTR64)

class _ALPC_WORK_ON_BEHALF_ATTR(Structure):
    _fields_ = [
        ("Ticket", ULONGLONG),
    ]
PALPC_WORK_ON_BEHALF_ATTR = POINTER(_ALPC_WORK_ON_BEHALF_ATTR)
ALPC_WORK_ON_BEHALF_ATTR = _ALPC_WORK_ON_BEHALF_ATTR

class _RPC_IF_ID(Structure):
    _fields_ = [
        ("Uuid", IID),
        ("VersMajor", USHORT),
        ("VersMinor", USHORT),
    ]
RPC_IF_ID = _RPC_IF_ID

INITIAL_RPC_IF_ID = RPC_IF_ID

class _RPC_IF_ID(INITIAL_RPC_IF_ID):
    def __repr__(self):
        return '<RPC_IF_ID "{0}" ({1}, {2})>'.format(self.Uuid.to_string(), self.VersMajor, self.VersMinor)
RPC_IF_ID = _RPC_IF_ID
class _PORT_VIEW(Structure):
    _fields_ = [
        ("Length", ULONG),
        ("SectionHandle", HANDLE),
        ("SectionOffset", ULONG),
        ("ViewSize", ULONG),
        ("ViewBase", PVOID),
        ("TargetViewBase", PVOID),
    ]
PPORT_VIEW = POINTER(_PORT_VIEW)
PORT_VIEW = _PORT_VIEW

class _REMOTE_PORT_VIEW(Structure):
    _fields_ = [
        ("Length", ULONG),
        ("ViewSize", ULONG),
        ("ViewBase", PVOID),
    ]
REMOTE_PORT_VIEW = _REMOTE_PORT_VIEW
PREMOTE_PORT_VIEW = POINTER(_REMOTE_PORT_VIEW)

class tagCOMVERSION(Structure):
    _fields_ = [
        ("MajorVersion", USHORT),
        ("MinorVersion", USHORT),
    ]
COMVERSION = tagCOMVERSION

class tagORPCTHIS(Structure):
    _fields_ = [
        ("version", COMVERSION),
        ("flags", ULONG),
        ("reserved1", ULONG),
        ("cid", GUID),
        ("extensions", PVOID),
    ]
ORPCTHIS = tagORPCTHIS

class __MIDL_XmitDefs_0001(Structure):
    _fields_ = [
        ("asyncOperationId", GUID),
        ("oxidClientProcessNA", ULONG64),
        ("originalClientLogicalThreadId", GUID),
        ("uClientCausalityTraceId", ULONG64),
    ]
MIDL_XmitDefs_0001 = __MIDL_XmitDefs_0001

class _LOCALTHIS(Structure):
    _fields_ = [
        ("dwFlags", DWORD),
        ("dwClientThread", DWORD),
        ("passthroughTraceActivity", GUID),
        ("callTraceActivity", GUID),
        ("asyncRequestBlock", MIDL_XmitDefs_0001),
        ("reserved", DWORD),
        ("pTouchedAstaArray", PVOID),
    ]
LOCALTHIS = _LOCALTHIS

ECS_ENABLED = EnumValue("_EXPCMDSTATE", "ECS_ENABLED", 0x0)
ECS_DISABLED = EnumValue("_EXPCMDSTATE", "ECS_DISABLED", 0x1)
ECS_HIDDEN = EnumValue("_EXPCMDSTATE", "ECS_HIDDEN", 0x2)
ECS_CHECKBOX = EnumValue("_EXPCMDSTATE", "ECS_CHECKBOX", 0x3)
ECS_CHECKED = EnumValue("_EXPCMDSTATE", "ECS_CHECKED", 0x4)
ECS_RADIOCHECK = EnumValue("_EXPCMDSTATE", "ECS_RADIOCHECK", 0x5)
class _EXPCMDSTATE(EnumType):
    values = [ECS_ENABLED, ECS_DISABLED, ECS_HIDDEN, ECS_CHECKBOX, ECS_CHECKED, ECS_RADIOCHECK]
    mapper = FlagMapper(*values)
EXPCMDSTATE = _EXPCMDSTATE


ECF_DEFAULT = EnumValue("_EXPCMDFLAGS", "ECF_DEFAULT", 0x0)
ECF_HASSUBCOMMANDS = EnumValue("_EXPCMDFLAGS", "ECF_HASSUBCOMMANDS", 0x1)
ECF_HASSPLITBUTTON = EnumValue("_EXPCMDFLAGS", "ECF_HASSPLITBUTTON", 0x2)
ECF_HIDELABEL = EnumValue("_EXPCMDFLAGS", "ECF_HIDELABEL", 0x4)
ECF_ISSEPARATOR = EnumValue("_EXPCMDFLAGS", "ECF_ISSEPARATOR", 0x8)
ECF_HASLUASHIELD = EnumValue("_EXPCMDFLAGS", "ECF_HASLUASHIELD", 0x10)
ECF_SEPARATORBEFORE = EnumValue("_EXPCMDFLAGS", "ECF_SEPARATORBEFORE", 0x20)
ECF_SEPARATORAFTER = EnumValue("_EXPCMDFLAGS", "ECF_SEPARATORAFTER", 0x40)
ECF_ISDROPDOWN = EnumValue("_EXPCMDFLAGS", "ECF_ISDROPDOWN", 0x80)
ECF_TOGGLEABLE = EnumValue("_EXPCMDFLAGS", "ECF_TOGGLEABLE", 0x100)
ECF_AUTOMENUICONS = EnumValue("_EXPCMDFLAGS", "ECF_AUTOMENUICONS", 0x200)
class _EXPCMDFLAGS(EnumType):
    values = [ECF_DEFAULT, ECF_HASSUBCOMMANDS, ECF_HASSPLITBUTTON, ECF_HIDELABEL, ECF_ISSEPARATOR, ECF_HASLUASHIELD, ECF_SEPARATORBEFORE, ECF_SEPARATORAFTER, ECF_ISDROPDOWN, ECF_TOGGLEABLE, ECF_AUTOMENUICONS]
    mapper = FlagMapper(*values)
EXPCMDFLAGS = _EXPCMDFLAGS


SIGDN_NORMALDISPLAY = EnumValue("_SIGDN", "SIGDN_NORMALDISPLAY", 0x0)
SIGDN_PARENTRELATIVEPARSING = EnumValue("_SIGDN", "SIGDN_PARENTRELATIVEPARSING", 0x80018001)
SIGDN_DESKTOPABSOLUTEPARSING = EnumValue("_SIGDN", "SIGDN_DESKTOPABSOLUTEPARSING", 0x80028000)
SIGDN_PARENTRELATIVEEDITING = EnumValue("_SIGDN", "SIGDN_PARENTRELATIVEEDITING", 0x80031001)
SIGDN_DESKTOPABSOLUTEEDITING = EnumValue("_SIGDN", "SIGDN_DESKTOPABSOLUTEEDITING", 0x8004c000)
SIGDN_FILESYSPATH = EnumValue("_SIGDN", "SIGDN_FILESYSPATH", 0x80058000)
SIGDN_URL = EnumValue("_SIGDN", "SIGDN_URL", 0x80068000)
SIGDN_PARENTRELATIVEFORADDRESSBAR = EnumValue("_SIGDN", "SIGDN_PARENTRELATIVEFORADDRESSBAR", 0x8007c001)
SIGDN_PARENTRELATIVE = EnumValue("_SIGDN", "SIGDN_PARENTRELATIVE", 0x80080001)
SIGDN_PARENTRELATIVEFORUI = EnumValue("_SIGDN", "SIGDN_PARENTRELATIVEFORUI", 0x80094001)
class _SIGDN(EnumType):
    values = [SIGDN_NORMALDISPLAY, SIGDN_PARENTRELATIVEPARSING, SIGDN_DESKTOPABSOLUTEPARSING, SIGDN_PARENTRELATIVEEDITING, SIGDN_DESKTOPABSOLUTEEDITING, SIGDN_FILESYSPATH, SIGDN_URL, SIGDN_PARENTRELATIVEFORADDRESSBAR, SIGDN_PARENTRELATIVE, SIGDN_PARENTRELATIVEFORUI]
    mapper = FlagMapper(*values)
SIGDN = _SIGDN


SICHINT_DISPLAY = EnumValue("SICHINTF", "SICHINT_DISPLAY", 0x0)
SICHINT_ALLFIELDS = EnumValue("SICHINTF", "SICHINT_ALLFIELDS", 0x80000000)
SICHINT_CANONICAL = EnumValue("SICHINTF", "SICHINT_CANONICAL", 0x10000000)
SICHINT_TEST_FILESYSPATH_IF_NOT_EQUAL = EnumValue("SICHINTF", "SICHINT_TEST_FILESYSPATH_IF_NOT_EQUAL", 0x20000000)
class SICHINTF(EnumType):
    values = [SICHINT_DISPLAY, SICHINT_ALLFIELDS, SICHINT_CANONICAL, SICHINT_TEST_FILESYSPATH_IF_NOT_EQUAL]
    mapper = FlagMapper(*values)


GPS_DEFAULT = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_DEFAULT", 0x0)
GPS_HANDLERPROPERTIESONLY = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_HANDLERPROPERTIESONLY", 0x1)
GPS_READWRITE = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_READWRITE", 0x2)
GPS_TEMPORARY = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_TEMPORARY", 0x4)
GPS_FASTPROPERTIESONLY = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_FASTPROPERTIESONLY", 0x8)
GPS_OPENSLOWITEM = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_OPENSLOWITEM", 0x10)
GPS_DELAYCREATION = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_DELAYCREATION", 0x20)
GPS_BESTEFFORT = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_BESTEFFORT", 0x40)
GPS_NO_OPLOCK = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_NO_OPLOCK", 0x80)
GPS_PREFERQUERYPROPERTIES = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_PREFERQUERYPROPERTIES", 0x100)
GPS_EXTRINSICPROPERTIES = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_EXTRINSICPROPERTIES", 0x200)
GPS_EXTRINSICPROPERTIESONLY = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_EXTRINSICPROPERTIESONLY", 0x400)
GPS_MASK_VALID = EnumValue("GETPROPERTYSTOREFLAGS", "GPS_MASK_VALID", 0x7ff)
class GETPROPERTYSTOREFLAGS(EnumType):
    values = [GPS_DEFAULT, GPS_HANDLERPROPERTIESONLY, GPS_READWRITE, GPS_TEMPORARY, GPS_FASTPROPERTIESONLY, GPS_OPENSLOWITEM, GPS_DELAYCREATION, GPS_BESTEFFORT, GPS_NO_OPLOCK, GPS_PREFERQUERYPROPERTIES, GPS_EXTRINSICPROPERTIES, GPS_EXTRINSICPROPERTIESONLY, GPS_MASK_VALID]
    mapper = FlagMapper(*values)


SIATTRIBFLAGS_AND = EnumValue("SIATTRIBFLAGS", "SIATTRIBFLAGS_AND", 0x1)
SIATTRIBFLAGS_OR = EnumValue("SIATTRIBFLAGS", "SIATTRIBFLAGS_OR", 0x2)
SIATTRIBFLAGS_APPCOMPAT = EnumValue("SIATTRIBFLAGS", "SIATTRIBFLAGS_APPCOMPAT", 0x3)
SIATTRIBFLAGS_MASK = EnumValue("SIATTRIBFLAGS", "SIATTRIBFLAGS_MASK", 0x3)
SIATTRIBFLAGS_ALLITEMS = EnumValue("SIATTRIBFLAGS", "SIATTRIBFLAGS_ALLITEMS", 0x4000)
class SIATTRIBFLAGS(EnumType):
    values = [SIATTRIBFLAGS_AND, SIATTRIBFLAGS_OR, SIATTRIBFLAGS_APPCOMPAT, SIATTRIBFLAGS_MASK, SIATTRIBFLAGS_ALLITEMS]
    mapper = FlagMapper(*values)


class tagBIND_OPTS(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("grfFlags", DWORD),
        ("grfMode", DWORD),
        ("dwTickCountDeadline", DWORD),
    ]
BIND_OPTS = tagBIND_OPTS
LPBIND_OPTS = POINTER(tagBIND_OPTS)

class _tagpropertykey(Structure):
    _fields_ = [
        ("fmtid", GUID),
        ("pid", DWORD),
    ]
PROPERTYKEY = _tagpropertykey
REFPROPERTYKEY = POINTER(_tagpropertykey)

class tagSTATSTG(Structure):
    _fields_ = [
        ("pwcsName", LPOLESTR),
        ("type", DWORD),
        ("cbSize", ULARGE_INTEGER),
        ("mtime", FILETIME),
        ("ctime", FILETIME),
        ("atime", FILETIME),
        ("grfMode", DWORD),
        ("grfLocksSupported", DWORD),
        ("clsid", CLSID),
        ("grfStateBits", DWORD),
        ("reserved", DWORD),
    ]
STATSTG = tagSTATSTG

VAR_PERINSTANCE = EnumValue("tagVARKIND", "VAR_PERINSTANCE", 0x0)
VAR_STATIC = EnumValue("tagVARKIND", "VAR_STATIC", 0x1)
VAR_CONST = EnumValue("tagVARKIND", "VAR_CONST", 0x2)
VAR_DISPATCH = EnumValue("tagVARKIND", "VAR_DISPATCH", 0x3)
class tagVARKIND(EnumType):
    values = [VAR_PERINSTANCE, VAR_STATIC, VAR_CONST, VAR_DISPATCH]
    mapper = FlagMapper(*values)
VARKIND = tagVARKIND


INVOKE_FUNC = EnumValue("tagINVOKEKIND", "INVOKE_FUNC", 0x0)
INVOKE_PROPERTYGET = EnumValue("tagINVOKEKIND", "INVOKE_PROPERTYGET", 0x1)
INVOKE_PROPERTYPUT = EnumValue("tagINVOKEKIND", "INVOKE_PROPERTYPUT", 0x2)
INVOKE_PROPERTYPUTREF = EnumValue("tagINVOKEKIND", "INVOKE_PROPERTYPUTREF", 0x3)
class tagINVOKEKIND(EnumType):
    values = [INVOKE_FUNC, INVOKE_PROPERTYGET, INVOKE_PROPERTYPUT, INVOKE_PROPERTYPUTREF]
    mapper = FlagMapper(*values)
INVOKEKIND = tagINVOKEKIND


FUNC_VIRTUAL = EnumValue("tagFUNCKIND", "FUNC_VIRTUAL", 0x0)
FUNC_PUREVIRTUAL = EnumValue("tagFUNCKIND", "FUNC_PUREVIRTUAL", 0x1)
FUNC_NONVIRTUAL = EnumValue("tagFUNCKIND", "FUNC_NONVIRTUAL", 0x2)
FUNC_STATIC = EnumValue("tagFUNCKIND", "FUNC_STATIC", 0x3)
FUNC_DISPATCH = EnumValue("tagFUNCKIND", "FUNC_DISPATCH", 0x4)
class tagFUNCKIND(EnumType):
    values = [FUNC_VIRTUAL, FUNC_PUREVIRTUAL, FUNC_NONVIRTUAL, FUNC_STATIC, FUNC_DISPATCH]
    mapper = FlagMapper(*values)
FUNCKIND = tagFUNCKIND


SYS_WIN16 = EnumValue("tagSYSKIND", "SYS_WIN16", 0x0)
SYS_WIN32 = EnumValue("tagSYSKIND", "SYS_WIN32", 0x1)
SYS_MAC = EnumValue("tagSYSKIND", "SYS_MAC", 0x2)
SYS_WIN64 = EnumValue("tagSYSKIND", "SYS_WIN64", 0x3)
class tagSYSKIND(EnumType):
    values = [SYS_WIN16, SYS_WIN32, SYS_MAC, SYS_WIN64]
    mapper = FlagMapper(*values)
SYSKIND = tagSYSKIND


CC_FASTCALL = EnumValue("tagCALLCONV", "CC_FASTCALL", 0x0)
CC_CDECL = EnumValue("tagCALLCONV", "CC_CDECL", 0x1)
CC_MSCPASCAL = EnumValue("tagCALLCONV", "CC_MSCPASCAL", 0x2)
CC_PASCAL = EnumValue("tagCALLCONV", "CC_PASCAL", 0x3)
CC_MACPASCAL = EnumValue("tagCALLCONV", "CC_MACPASCAL", 0x4)
CC_STDCALL = EnumValue("tagCALLCONV", "CC_STDCALL", 0x5)
CC_FPFASTCALL = EnumValue("tagCALLCONV", "CC_FPFASTCALL", 0x6)
CC_SYSCALL = EnumValue("tagCALLCONV", "CC_SYSCALL", 0x7)
CC_MPWCDECL = EnumValue("tagCALLCONV", "CC_MPWCDECL", 0x8)
CC_MPWPASCAL = EnumValue("tagCALLCONV", "CC_MPWPASCAL", 0x9)
CC_MAX = EnumValue("tagCALLCONV", "CC_MAX", 0xa)
class tagCALLCONV(EnumType):
    values = [CC_FASTCALL, CC_CDECL, CC_MSCPASCAL, CC_PASCAL, CC_MACPASCAL, CC_STDCALL, CC_FPFASTCALL, CC_SYSCALL, CC_MPWCDECL, CC_MPWPASCAL, CC_MAX]
    mapper = FlagMapper(*values)
CALLCONV = tagCALLCONV


DESCKIND_NONE = EnumValue("tagDESCKIND", "DESCKIND_NONE", 0x0)
DESCKIND_FUNCDESC = EnumValue("tagDESCKIND", "DESCKIND_FUNCDESC", 0x1)
DESCKIND_VARDESC = EnumValue("tagDESCKIND", "DESCKIND_VARDESC", 0x2)
DESCKIND_TYPECOMP = EnumValue("tagDESCKIND", "DESCKIND_TYPECOMP", 0x3)
DESCKIND_IMPLICITAPPOBJ = EnumValue("tagDESCKIND", "DESCKIND_IMPLICITAPPOBJ", 0x4)
DESCKIND_MAX = EnumValue("tagDESCKIND", "DESCKIND_MAX", 0x5)
class tagDESCKIND(EnumType):
    values = [DESCKIND_NONE, DESCKIND_FUNCDESC, DESCKIND_VARDESC, DESCKIND_TYPECOMP, DESCKIND_IMPLICITAPPOBJ, DESCKIND_MAX]
    mapper = FlagMapper(*values)
DESCKIND = tagDESCKIND


class tagPARAMDESCEX(Structure):
    _fields_ = [
        ("cBytes", ULONG),
        ("varDefaultValue", VARIANTARG),
    ]
PARAMDESCEX = tagPARAMDESCEX
LPPARAMDESCEX = POINTER(tagPARAMDESCEX)

class tagPARAMDESC(Structure):
    _fields_ = [
        ("pparamdescex", LPPARAMDESCEX),
        ("wParamFlags", USHORT),
    ]
LPPARAMDESC = POINTER(tagPARAMDESC)
PARAMDESC = tagPARAMDESC

class _TMP_TYPEDESC_UNION(Union):
    _fields_ = [
        ("lptdesc", PVOID),
        ("lpadesc", PVOID),
        ("hreftype", HREFTYPE),
    ]
TMP_TYPEDESC_UNION = _TMP_TYPEDESC_UNION

class tagTYPEDESC(Structure):
    _fields_ = [
        ("DUMMYUNIONNAME", TMP_TYPEDESC_UNION),
        ("vt", VARTYPE),
    ]
TYPEDESC = tagTYPEDESC

class tagARRAYDESC(Structure):
    _fields_ = [
        ("tdescElem", TYPEDESC),
        ("cDims", USHORT),
        ("rgbounds", SAFEARRAYBOUND * (1)),
    ]
ARRAYDESC = tagARRAYDESC

class tagELEMDESC(Structure):
    _fields_ = [
        ("tdesc", TYPEDESC),
        ("paramdesc", PARAMDESC),
    ]
ELEMDESC = tagELEMDESC
LPELEMDESC = POINTER(tagELEMDESC)

class tagFUNCDESC(Structure):
    _fields_ = [
        ("memid", MEMBERID),
        ("lprgscode", POINTER(SCODE)),
        ("lprgelemdescParam", POINTER(ELEMDESC)),
        ("funckind", FUNCKIND),
        ("invkind", INVOKEKIND),
        ("callconv", CALLCONV),
        ("cParams", SHORT),
        ("cParamsOpt", SHORT),
        ("oVft", SHORT),
        ("cScodes", SHORT),
        ("elemdescFunc", ELEMDESC),
        ("wFuncFlags", WORD),
    ]
LPFUNCDESC = POINTER(tagFUNCDESC)
FUNCDESC = tagFUNCDESC

class _TMP_VARDESC_UNION(Union):
    _fields_ = [
        ("oInst", ULONG),
        ("lpvarValue", POINTER(VARIANT)),
    ]
TMP_VARDESC_UNION = _TMP_VARDESC_UNION

class tagVARDESC(Structure):
    _fields_ = [
        ("memid", MEMBERID),
        ("lpstrSchema", LPOLESTR),
        ("DUMMYUNIONNAME", TMP_VARDESC_UNION),
        ("elemdescVar", ELEMDESC),
        ("wVarFlags", WORD),
        ("varkind", VARKIND),
    ]
LPVARDESC = POINTER(tagVARDESC)
VARDESC = tagVARDESC

class tagBINDPTR(Union):
    _fields_ = [
        ("lpfuncdesc", POINTER(FUNCDESC)),
        ("lpvardesc", POINTER(VARDESC)),
        ("lptcomp", PVOID),
    ]
LPBINDPTR = POINTER(tagBINDPTR)
BINDPTR = tagBINDPTR

class tagIDLDESC(Structure):
    _fields_ = [
        ("dwReserved", ULONG_PTR),
        ("wIDLFlags", USHORT),
    ]
IDLDESC = tagIDLDESC
LPIDLDESC = POINTER(tagIDLDESC)

class tagTLIBATTR(Structure):
    _fields_ = [
        ("guid", GUID),
        ("lcid", LCID),
        ("syskind", SYSKIND),
        ("wMajorVerNum", WORD),
        ("wMinorVerNum", WORD),
        ("wLibFlags", WORD),
    ]
LPTLIBATTR = POINTER(tagTLIBATTR)
TLIBATTR = tagTLIBATTR

class tagTYPEATTR(Structure):
    _fields_ = [
        ("guid", GUID),
        ("lcid", LCID),
        ("dwReserved", DWORD),
        ("memidConstructor", MEMBERID),
        ("memidDestructor", MEMBERID),
        ("lpstrSchema", LPOLESTR),
        ("cbSizeInstance", ULONG),
        ("typekind", TYPEKIND),
        ("cFuncs", WORD),
        ("cVars", WORD),
        ("cImplTypes", WORD),
        ("cbSizeVft", WORD),
        ("cbAlignment", WORD),
        ("wTypeFlags", WORD),
        ("wMajorVerNum", WORD),
        ("wMinorVerNum", WORD),
        ("tdescAlias", TYPEDESC),
        ("idldescType", IDLDESC),
    ]
TYPEATTR = tagTYPEATTR
LPTYPEATTR = POINTER(tagTYPEATTR)

class _CERT_STRONG_SIGN_SERIALIZED_INFO(Structure):
    _fields_ = [
        ("dwFlags", DWORD),
        ("pwszCNGSignHashAlgids", LPWSTR),
        ("pwszCNGPubKeyMinBitLengths", LPWSTR),
    ]
CERT_STRONG_SIGN_SERIALIZED_INFO = _CERT_STRONG_SIGN_SERIALIZED_INFO
PCERT_STRONG_SIGN_SERIALIZED_INFO = POINTER(_CERT_STRONG_SIGN_SERIALIZED_INFO)

class TMP_CERT_STRONG_SIGN_PARA_UNION_TYPE(Union):
    _fields_ = [
        ("pvInfo", PVOID),
        ("pSerializedInfo", PCERT_STRONG_SIGN_SERIALIZED_INFO),
        ("pszOID", LPSTR),
    ]


class _CERT_STRONG_SIGN_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwInfoChoice", DWORD),
        ("tmp_union", TMP_CERT_STRONG_SIGN_PARA_UNION_TYPE),
    ]
CERT_STRONG_SIGN_PARA = _CERT_STRONG_SIGN_PARA
PCCERT_STRONG_SIGN_PARA = POINTER(_CERT_STRONG_SIGN_PARA)
PCERT_STRONG_SIGN_PARA = POINTER(_CERT_STRONG_SIGN_PARA)

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

class _CRYPTOAPI_BLOB(_CRYPTOAPI_BLOB):
    @classmethod
    def from_string(cls, buf):
        self = cls()
        self.cbData = len(buf)
        self.pbData = (BYTE * self.cbData)(*bytearray(buf))
        return self

    @property
    def data(self):
        return bytearray(self.pbData[:self.cbData])
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
class CRYPTCATATTRIBUTE_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("pwszReferenceTag", LPWSTR),
        ("dwAttrTypeAndAction", DWORD),
        ("cbValue", DWORD),
        ("pbValue", POINTER(BYTE)),
        ("dwReserved", DWORD),
    ]
CRYPTCATATTRIBUTE = CRYPTCATATTRIBUTE_
PCRYPTCATATTRIBUTE = POINTER(CRYPTCATATTRIBUTE_)

class _CRYPT_ATTRIBUTE_TYPE_VALUE(Structure):
    _fields_ = [
        ("pszObjId", LPSTR),
        ("Value", CRYPT_OBJID_BLOB),
    ]
CRYPT_ATTRIBUTE_TYPE_VALUE = _CRYPT_ATTRIBUTE_TYPE_VALUE
PCRYPT_ATTRIBUTE_TYPE_VALUE = POINTER(_CRYPT_ATTRIBUTE_TYPE_VALUE)

class _CRYPT_ALGORITHM_IDENTIFIER(Structure):
    _fields_ = [
        ("pszObjId", LPSTR),
        ("Parameters", CRYPT_OBJID_BLOB),
    ]
CRYPT_ALGORITHM_IDENTIFIER = _CRYPT_ALGORITHM_IDENTIFIER
PCRYPT_ALGORITHM_IDENTIFIER = POINTER(_CRYPT_ALGORITHM_IDENTIFIER)

class SIP_INDIRECT_DATA_(Structure):
    _fields_ = [
        ("Data", CRYPT_ATTRIBUTE_TYPE_VALUE),
        ("DigestAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Digest", CRYPT_HASH_BLOB),
    ]
SIP_INDIRECT_DATA = SIP_INDIRECT_DATA_
PSIP_INDIRECT_DATA = POINTER(SIP_INDIRECT_DATA_)

class CRYPTCATMEMBER_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("pwszReferenceTag", LPWSTR),
        ("pwszFileName", LPWSTR),
        ("gSubjectType", GUID),
        ("fdwMemberFlags", DWORD),
        ("pIndirectData", POINTER(SIP_INDIRECT_DATA)),
        ("dwCertVersion", DWORD),
        ("dwReserved", DWORD),
        ("hReserved", HANDLE),
        ("sEncodedIndirectData", CRYPT_ATTR_BLOB),
        ("sEncodedMemberInfo", CRYPT_ATTR_BLOB),
    ]
CRYPTCATMEMBER = CRYPTCATMEMBER_
PCRYPTCATMEMBER = POINTER(CRYPTCATMEMBER_)

class WINTRUST_FILE_INFO_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("pcwszFilePath", LPCWSTR),
        ("hFile", HANDLE),
        ("pgKnownSubject", POINTER(GUID)),
    ]
WINTRUST_FILE_INFO = WINTRUST_FILE_INFO_
PWINTRUST_FILE_INFO = POINTER(WINTRUST_FILE_INFO_)

class _CRYPT_ATTRIBUTE(Structure):
    _fields_ = [
        ("pszObjId", LPSTR),
        ("cValue", DWORD),
        ("rgValue", PCRYPT_ATTR_BLOB),
    ]
PCRYPT_ATTRIBUTE = POINTER(_CRYPT_ATTRIBUTE)
CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE

OLD_CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE

class _CRYPT_ATTRIBUTE(_CRYPT_ATTRIBUTE):
    @property
    def count(self): # __len__ ?
        return self.cValue

    @property
    def values(self):
        return self.rgValue[:self.cValue]

    @property
    def objid(self):
        # SZOID_MAPPER defined in the generated structures template.py
        return SZOID_MAPPER[self.pszObjId]

    def __repr__(self):
        # return """<{0} pszObjId={1!r} Values={2}>""".format(type(self).__name__, self.objid, self.cValue)
        if not self.pszObjId in SZOID_MAPPER:
            return """<{0} pszObjId="{1}" Values={2}>""".format(type(self).__name__, self.pszObjId, self.cValue)
        flag = SZOID_MAPPER[self.pszObjId]
        return """<{0} pszObjId="{1}" ({2}) Values={3}>""".format(type(self).__name__, flag, flag.name, self.cValue)
PCRYPT_ATTRIBUTE = POINTER(_CRYPT_ATTRIBUTE)
CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE
class _CTL_ENTRY(Structure):
    _fields_ = [
        ("SubjectIdentifier", CRYPT_DATA_BLOB),
        ("cAttribute", DWORD),
        ("rgAttribute", PCRYPT_ATTRIBUTE),
    ]
PCTL_ENTRY = POINTER(_CTL_ENTRY)
CTL_ENTRY = _CTL_ENTRY

class _CRYPT_ATTRIBUTE(Structure):
    _fields_ = [
        ("pszObjId", LPSTR),
        ("cValue", DWORD),
        ("rgValue", PCRYPT_ATTR_BLOB),
    ]
PCRYPT_ATTRIBUTE = POINTER(_CRYPT_ATTRIBUTE)
CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE

OLD_CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE

class _CRYPT_ATTRIBUTE(_CRYPT_ATTRIBUTE):
    @property
    def count(self): # __len__ ?
        return self.cValue

    @property
    def values(self):
        return self.rgValue[:self.cValue]

    @property
    def objid(self):
        # SZOID_MAPPER defined in the generated structures template.py
        return SZOID_MAPPER[self.pszObjId]

    def __repr__(self):
        # return """<{0} pszObjId={1!r} Values={2}>""".format(type(self).__name__, self.objid, self.cValue)
        if not self.pszObjId in SZOID_MAPPER:
            return """<{0} pszObjId="{1}" Values={2}>""".format(type(self).__name__, self.pszObjId, self.cValue)
        flag = SZOID_MAPPER[self.pszObjId]
        return """<{0} pszObjId="{1}" ({2}) Values={3}>""".format(type(self).__name__, flag, flag.name, self.cValue)
PCRYPT_ATTRIBUTE = POINTER(_CRYPT_ATTRIBUTE)
CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE
class _CRYPT_ATTRIBUTES(Structure):
    _fields_ = [
        ("cAttr", DWORD),
        ("rgAttr", PCRYPT_ATTRIBUTE),
    ]
CRYPT_ATTRIBUTES = _CRYPT_ATTRIBUTES
PCRYPT_ATTRIBUTES = POINTER(_CRYPT_ATTRIBUTES)

OLD_CRYPT_ATTRIBUTES = _CRYPT_ATTRIBUTES
class _CRYPT_ATTRIBUTES(_CRYPT_ATTRIBUTES):
    @property
    def count(self): # __len__ ?
        return self.cAttr

    @property
    def attributes(self):
        return self.rgAttr[:self.cAttr]

    def __getitem__(self, oid):
        return [x for x in self.attributes if x.pszObjId == oid]

    def __repr__(self):
        return """<{0} Attributes={1}>""".format(type(self).__name__, self.cAttr)
CRYPT_ATTRIBUTES = _CRYPT_ATTRIBUTES
PCRYPT_ATTRIBUTES = POINTER(_CRYPT_ATTRIBUTES)
class _CERT_EXTENSION(Structure):
    _fields_ = [
        ("pszObjId", LPSTR),
        ("fCritical", BOOL),
        ("Value", CRYPT_OBJID_BLOB),
    ]
CERT_EXTENSION = _CERT_EXTENSION
PCERT_EXTENSION = POINTER(_CERT_EXTENSION)

class _CRL_ENTRY(Structure):
    _fields_ = [
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("RevocationDate", FILETIME),
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
CRL_ENTRY = _CRL_ENTRY
PCRL_ENTRY = POINTER(_CRL_ENTRY)

class _CRL_INFO(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Issuer", CERT_NAME_BLOB),
        ("ThisUpdate", FILETIME),
        ("NextUpdate", FILETIME),
        ("cCRLEntry", DWORD),
        ("rgCRLEntry", PCRL_ENTRY),
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
CRL_INFO = _CRL_INFO
PCRL_INFO = POINTER(_CRL_INFO)

class _CRL_CONTEXT(Structure):
    _fields_ = [
        ("dwCertEncodingType", DWORD),
        ("pbCrlEncoded", POINTER(BYTE)),
        ("cbCrlEncoded", DWORD),
        ("pCrlInfo", PCRL_INFO),
        ("hCertStore", HCERTSTORE),
    ]
PCCRL_CONTEXT = POINTER(_CRL_CONTEXT)
CRL_CONTEXT = _CRL_CONTEXT
PCRL_CONTEXT = POINTER(_CRL_CONTEXT)

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

class _CTL_USAGE(Structure):
    _fields_ = [
        ("cUsageIdentifier", DWORD),
        ("rgpszUsageIdentifier", POINTER(LPSTR)),
    ]
CERT_ENHKEY_USAGE = _CTL_USAGE
PCTL_USAGE = POINTER(_CTL_USAGE)
CTL_USAGE = _CTL_USAGE
PCERT_ENHKEY_USAGE = POINTER(_CTL_USAGE)

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

class _CRYPT_BIT_BLOB(Structure):
    _fields_ = [
        ("cbData", DWORD),
        ("pbData", POINTER(BYTE)),
        ("cUnusedBits", DWORD),
    ]
CRYPT_BIT_BLOB = _CRYPT_BIT_BLOB
PCRYPT_BIT_BLOB = POINTER(_CRYPT_BIT_BLOB)

class _CRYPT_BIT_BLOB(_CRYPT_BIT_BLOB):
    @property
    def data(self):
        return bytearray(self.pbData[:self.cbData])
CRYPT_BIT_BLOB = _CRYPT_BIT_BLOB
PCRYPT_BIT_BLOB = POINTER(_CRYPT_BIT_BLOB)
class _CERT_PUBLIC_KEY_INFO(Structure):
    _fields_ = [
        ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("PublicKey", CRYPT_BIT_BLOB),
    ]
PCERT_PUBLIC_KEY_INFO = POINTER(_CERT_PUBLIC_KEY_INFO)
CERT_PUBLIC_KEY_INFO = _CERT_PUBLIC_KEY_INFO

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

class _CERT_ISSUER_SERIAL_NUMBER(Structure):
    _fields_ = [
        ("Issuer", CERT_NAME_BLOB),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
    ]
CERT_ISSUER_SERIAL_NUMBER = _CERT_ISSUER_SERIAL_NUMBER
PCERT_ISSUER_SERIAL_NUMBER = POINTER(_CERT_ISSUER_SERIAL_NUMBER)

class _TMPUNION_CERT_ID(Union):
    _fields_ = [
        ("IssuerSerialNumber", CERT_ISSUER_SERIAL_NUMBER),
        ("KeyId", CRYPT_HASH_BLOB),
        ("HashId", CRYPT_HASH_BLOB),
    ]
TMPUNION_CERT_ID = _TMPUNION_CERT_ID

class _CERT_ID(Structure):
    _fields_ = [
        ("dwIdChoice", DWORD),
        ("DUMMYUNIONNAME", TMPUNION_CERT_ID),
    ]
CERT_ID = _CERT_ID
PCERT_ID = POINTER(_CERT_ID)

class _CERT_CONTEXT(Structure):
    _fields_ = [
        ("dwCertEncodingType", DWORD),
        ("pbCertEncoded", POINTER(BYTE)),
        ("cbCertEncoded", DWORD),
        ("pCertInfo", PCERT_INFO),
        ("hCertStore", HCERTSTORE),
    ]
PCCERT_CONTEXT = POINTER(_CERT_CONTEXT)
CERT_CONTEXT = _CERT_CONTEXT
PCERT_CONTEXT = POINTER(_CERT_CONTEXT)

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

class _TMP_WINTRUST_UNION_TYPE(Union):
    _fields_ = [
        ("pFile", POINTER(WINTRUST_FILE_INFO)),
        ("pCatalog", POINTER(WINTRUST_CATALOG_INFO)),
        ("pBlob", POINTER(WINTRUST_BLOB_INFO)),
        ("pSgnr", POINTER(WINTRUST_SGNR_INFO)),
        ("pCert", POINTER(WINTRUST_CERT_INFO)),
    ]
TMP_WINTRUST_UNION_TYPE = _TMP_WINTRUST_UNION_TYPE

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

class _CRYPT_SIGN_MESSAGE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwMsgEncodingType", DWORD),
        ("pSigningCert", PCCERT_CONTEXT),
        ("HashAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvHashAuxInfo", PVOID),
        ("cMsgCert", DWORD),
        ("rgpMsgCert", POINTER(PCCERT_CONTEXT)),
        ("cMsgCrl", DWORD),
        ("rgpMsgCrl", POINTER(PCCRL_CONTEXT)),
        ("cAuthAttr", DWORD),
        ("rgAuthAttr", PCRYPT_ATTRIBUTE),
        ("cUnauthAttr", DWORD),
        ("rgUnauthAttr", PCRYPT_ATTRIBUTE),
        ("dwFlags", DWORD),
        ("dwInnerContentType", DWORD),
        ("HashEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvHashEncryptionAuxInfo", PVOID),
    ]
CRYPT_SIGN_MESSAGE_PARA = _CRYPT_SIGN_MESSAGE_PARA
PCRYPT_SIGN_MESSAGE_PARA = POINTER(_CRYPT_SIGN_MESSAGE_PARA)

class _CRYPT_HASH_MESSAGE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwMsgEncodingType", DWORD),
        ("hCryptProv", HCRYPTPROV_LEGACY),
        ("HashAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvHashAuxInfo", PVOID),
    ]
PCRYPT_HASH_MESSAGE_PARA = POINTER(_CRYPT_HASH_MESSAGE_PARA)
CRYPT_HASH_MESSAGE_PARA = _CRYPT_HASH_MESSAGE_PARA

class _CRYPT_KEY_VERIFY_MESSAGE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwMsgEncodingType", DWORD),
        ("hCryptProv", HCRYPTPROV_LEGACY),
    ]
CRYPT_KEY_VERIFY_MESSAGE_PARA = _CRYPT_KEY_VERIFY_MESSAGE_PARA
PCRYPT_KEY_VERIFY_MESSAGE_PARA = POINTER(_CRYPT_KEY_VERIFY_MESSAGE_PARA)

class _CRYPT_VERIFY_MESSAGE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwMsgAndCertEncodingType", DWORD),
        ("hCryptProv", HCRYPTPROV_LEGACY),
        ("pfnGetSignerCertificate", PFN_CRYPT_GET_SIGNER_CERTIFICATE),
        ("pvGetArg", PVOID),
        ("pStrongSignPara", PCCERT_STRONG_SIGN_PARA),
    ]
CRYPT_VERIFY_MESSAGE_PARA = _CRYPT_VERIFY_MESSAGE_PARA
PCRYPT_VERIFY_MESSAGE_PARA = POINTER(_CRYPT_VERIFY_MESSAGE_PARA)

class _SPC_SERIALIZED_OBJECT(Structure):
    _fields_ = [
        ("ClassId", SPC_UUID),
        ("SerializedData", CRYPT_DATA_BLOB),
    ]
SPC_SERIALIZED_OBJECT = _SPC_SERIALIZED_OBJECT
PSPC_SERIALIZED_OBJECT = POINTER(_SPC_SERIALIZED_OBJECT)

class _TMP_SPC_LINK_UNION(Union):
    _fields_ = [
        ("pwszUrl", LPWSTR),
        ("Moniker", SPC_SERIALIZED_OBJECT),
        ("pwszFile", LPWSTR),
    ]
TMP_SPC_LINK_UNION = _TMP_SPC_LINK_UNION

class SPC_LINK_(Structure):
    _fields_ = [
        ("dwLinkChoice", DWORD),
        ("u", TMP_SPC_LINK_UNION),
    ]
PSPC_LINK = POINTER(SPC_LINK_)
SPC_LINK = SPC_LINK_

class _SPC_SP_OPUS_INFO(Structure):
    _fields_ = [
        ("pwszProgramName", LPCWSTR),
        ("pMoreInfo", POINTER(SPC_LINK)),
        ("pPublisherInfo", POINTER(SPC_LINK)),
    ]
PSPC_SP_OPUS_INFO = POINTER(_SPC_SP_OPUS_INFO)
SPC_SP_OPUS_INFO = _SPC_SP_OPUS_INFO

class _CERT_TRUST_STATUS(Structure):
    _fields_ = [
        ("dwErrorStatus", DWORD),
        ("dwInfoStatus", DWORD),
    ]
PCERT_TRUST_STATUS = POINTER(_CERT_TRUST_STATUS)
CERT_TRUST_STATUS = _CERT_TRUST_STATUS

class _CERT_TRUST_LIST_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("pCtlEntry", PCTL_ENTRY),
        ("pCtlContext", PCCTL_CONTEXT),
    ]
PCERT_TRUST_LIST_INFO = POINTER(_CERT_TRUST_LIST_INFO)
CERT_TRUST_LIST_INFO = _CERT_TRUST_LIST_INFO

class _CERT_REVOCATION_CRL_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("pBaseCrlContext", PCCRL_CONTEXT),
        ("pDeltaCrlContext", PCCRL_CONTEXT),
        ("pCrlEntry", PCRL_ENTRY),
        ("fDeltaCrlEntry", BOOL),
    ]
CERT_REVOCATION_CRL_INFO = _CERT_REVOCATION_CRL_INFO
PCERT_REVOCATION_CRL_INFO = POINTER(_CERT_REVOCATION_CRL_INFO)

class _CERT_REVOCATION_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwRevocationResult", DWORD),
        ("pszRevocationOid", LPCSTR),
        ("pvOidSpecificInfo", LPVOID),
        ("fHasFreshnessTime", BOOL),
        ("dwFreshnessTime", DWORD),
        ("pCrlInfo", PCERT_REVOCATION_CRL_INFO),
    ]
CERT_REVOCATION_INFO = _CERT_REVOCATION_INFO
PCERT_REVOCATION_INFO = POINTER(_CERT_REVOCATION_INFO)

class _CERT_CHAIN_ELEMENT(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("pCertContext", PCCERT_CONTEXT),
        ("TrustStatus", CERT_TRUST_STATUS),
        ("pRevocationInfo", PCERT_REVOCATION_INFO),
        ("pIssuanceUsage", PCERT_ENHKEY_USAGE),
        ("pApplicationUsage", PCERT_ENHKEY_USAGE),
        ("pwszExtendedErrorInfo", LPCWSTR),
    ]
PCERT_CHAIN_ELEMENT = POINTER(_CERT_CHAIN_ELEMENT)
CERT_CHAIN_ELEMENT = _CERT_CHAIN_ELEMENT
PCCERT_CHAIN_ELEMENT = POINTER(_CERT_CHAIN_ELEMENT)

class _CERT_SIMPLE_CHAIN(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("TrustStatus", CERT_TRUST_STATUS),
        ("cElement", DWORD),
        ("rgpElement", POINTER(PCERT_CHAIN_ELEMENT)),
        ("pTrustListInfo", PCERT_TRUST_LIST_INFO),
        ("fHasRevocationFreshnessTime", BOOL),
        ("dwRevocationFreshnessTime", DWORD),
    ]
CERT_SIMPLE_CHAIN = _CERT_SIMPLE_CHAIN
PCERT_SIMPLE_CHAIN = POINTER(_CERT_SIMPLE_CHAIN)
PCCERT_SIMPLE_CHAIN = POINTER(_CERT_SIMPLE_CHAIN)

# Self referencing struct tricks
class _CERT_CHAIN_CONTEXT(Structure): pass
CERT_CHAIN_CONTEXT = _CERT_CHAIN_CONTEXT
PCERT_CHAIN_CONTEXT = POINTER(_CERT_CHAIN_CONTEXT)
PCCERT_CHAIN_CONTEXT = POINTER(_CERT_CHAIN_CONTEXT)
_CERT_CHAIN_CONTEXT._fields_ = [
    ("cbSize", DWORD),
    ("TrustStatus", CERT_TRUST_STATUS),
    ("cChain", DWORD),
    ("rgpChain", POINTER(PCERT_SIMPLE_CHAIN)),
    ("cLowerQualityChainContext", DWORD),
    ("rgpLowerQualityChainContext", POINTER(PCCERT_CHAIN_CONTEXT)),
    ("fHasRevocationFreshnessTime", BOOL),
    ("dwRevocationFreshnessTime", DWORD),
    ("dwCreateFlags", DWORD),
    ("ChainId", GUID),
]

class _CERT_USAGE_MATCH(Structure):
    _fields_ = [
        ("dwType", DWORD),
        ("Usage", CERT_ENHKEY_USAGE),
    ]
CERT_USAGE_MATCH = _CERT_USAGE_MATCH
PCERT_USAGE_MATCH = POINTER(_CERT_USAGE_MATCH)

class _CERT_CHAIN_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("RequestedUsage", CERT_USAGE_MATCH),
        ("RequestedIssuancePolicy", CERT_USAGE_MATCH),
        ("dwUrlRetrievalTimeout", DWORD),
        ("fCheckRevocationFreshnessTime", BOOL),
        ("dwRevocationFreshnessTime", DWORD),
        ("pftCacheResync", LPFILETIME),
    ]
CERT_CHAIN_PARA = _CERT_CHAIN_PARA
PCERT_CHAIN_PARA = POINTER(_CERT_CHAIN_PARA)

class _CERT_CHAIN_ENGINE_CONFIG(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("hRestrictedRoot", HCERTSTORE),
        ("hRestrictedTrust", HCERTSTORE),
        ("hRestrictedOther", HCERTSTORE),
        ("cAdditionalStore", DWORD),
        ("rghAdditionalStore", POINTER(HCERTSTORE)),
        ("dwFlags", DWORD),
        ("dwUrlRetrievalTimeout", DWORD),
        ("MaximumCachedCertificates", DWORD),
        ("CycleDetectionModulus", DWORD),
    ]
CERT_CHAIN_ENGINE_CONFIG = _CERT_CHAIN_ENGINE_CONFIG
PCERT_CHAIN_ENGINE_CONFIG = POINTER(_CERT_CHAIN_ENGINE_CONFIG)

class _SYSTEMTIME(Structure):
    _fields_ = [
        ("wYear", WORD),
        ("wMonth", WORD),
        ("wDayOfWeek", WORD),
        ("wDay", WORD),
        ("wHour", WORD),
        ("wMinute", WORD),
        ("wSecond", WORD),
        ("wMilliseconds", WORD),
    ]
LPSYSTEMTIME = POINTER(_SYSTEMTIME)
SYSTEMTIME = _SYSTEMTIME
PSYSTEMTIME = POINTER(_SYSTEMTIME)

class _CERT_EXTENSIONS(Structure):
    _fields_ = [
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
PCERT_EXTENSIONS = POINTER(_CERT_EXTENSIONS)
CERT_EXTENSIONS = _CERT_EXTENSIONS

class _CRYPT_KEY_PROV_PARAM(Structure):
    _fields_ = [
        ("dwParam", DWORD),
        ("pbData", POINTER(BYTE)),
        ("cbData", DWORD),
        ("dwFlags", DWORD),
    ]
CRYPT_KEY_PROV_PARAM = _CRYPT_KEY_PROV_PARAM
PCRYPT_KEY_PROV_PARAM = POINTER(_CRYPT_KEY_PROV_PARAM)

class _CRYPT_KEY_PROV_INFO(Structure):
    _fields_ = [
        ("pwszContainerName", LPWSTR),
        ("pwszProvName", LPWSTR),
        ("dwProvType", DWORD),
        ("dwFlags", DWORD),
        ("cProvParam", DWORD),
        ("rgProvParam", PCRYPT_KEY_PROV_PARAM),
        ("dwKeySpec", DWORD),
    ]
CRYPT_KEY_PROV_INFO = _CRYPT_KEY_PROV_INFO
PCRYPT_KEY_PROV_INFO = POINTER(_CRYPT_KEY_PROV_INFO)

class _CRYPT_ENCRYPT_MESSAGE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwMsgEncodingType", DWORD),
        ("hCryptProv", HCRYPTPROV_LEGACY),
        ("ContentEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvEncryptionAuxInfo", POINTER(VOID)),
        ("dwFlags", DWORD),
        ("dwInnerContentType", DWORD),
    ]
PCRYPT_ENCRYPT_MESSAGE_PARA = POINTER(_CRYPT_ENCRYPT_MESSAGE_PARA)
CRYPT_ENCRYPT_MESSAGE_PARA = _CRYPT_ENCRYPT_MESSAGE_PARA

class _CRYPT_DECRYPT_MESSAGE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwMsgAndCertEncodingType", DWORD),
        ("cCertStore", DWORD),
        ("rghCertStore", POINTER(HCERTSTORE)),
        ("dwFlags", DWORD),
    ]
PCRYPT_DECRYPT_MESSAGE_PARA = POINTER(_CRYPT_DECRYPT_MESSAGE_PARA)
CRYPT_DECRYPT_MESSAGE_PARA = _CRYPT_DECRYPT_MESSAGE_PARA

class _CERT_KEY_CONTEXT(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("hCryptProv", HCRYPTPROV),
        ("dwKeySpec", DWORD),
    ]
CERT_KEY_CONTEXT = _CERT_KEY_CONTEXT
PCERT_KEY_CONTEXT = POINTER(_CERT_KEY_CONTEXT)

class _CRYPT_ENCODE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("pfnAlloc", PVOID),
        ("pfnFree", PVOID),
    ]
PCRYPT_ENCODE_PARA = POINTER(_CRYPT_ENCODE_PARA)
CRYPT_ENCODE_PARA = _CRYPT_ENCODE_PARA

class _TMPUNION_CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO(Union):
    _fields_ = [
        ("hKeyEncryptionKey", HCRYPTKEY),
        ("pvKeyEncryptionKey", PVOID),
    ]
TMPUNION_CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO = _TMPUNION_CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO

class _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("KeyEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvKeyEncryptionAuxInfo", PVOID),
        ("hCryptProv", HCRYPTPROV),
        ("dwKeyChoice", DWORD),
        ("DUMMYUNIONNAME", TMPUNION_CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO),
        ("KeyId", CRYPT_DATA_BLOB),
        ("Date", FILETIME),
        ("pOtherAttr", PCRYPT_ATTRIBUTE_TYPE_VALUE),
    ]
PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO = POINTER(_CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO)
CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO = _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO

class _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("KeyEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvKeyEncryptionAuxInfo", PVOID),
        ("hCryptProv", HCRYPTPROV_LEGACY),
        ("RecipientPublicKey", CRYPT_BIT_BLOB),
        ("RecipientId", CERT_ID),
    ]
PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO = POINTER(_CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO)
CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO = _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO

class _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("KeyEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvKeyEncryptionAuxInfo", PVOID),
        ("hCryptProv", HCRYPTPROV_LEGACY),
        ("RecipientPublicKey", CRYPT_BIT_BLOB),
        ("RecipientId", CERT_ID),
    ]
PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO = POINTER(_CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO)
CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO = _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO

class _TMPUNION_CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO(Union):
    _fields_ = [
        ("pEphemeralAlgorithm", PCRYPT_ALGORITHM_IDENTIFIER),
        ("pSenderId", PCERT_ID),
    ]
TMPUNION_CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO = _TMPUNION_CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO

class _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("RecipientPublicKey", CRYPT_BIT_BLOB),
        ("RecipientId", CERT_ID),
        ("Date", FILETIME),
        ("pOtherAttr", PCRYPT_ATTRIBUTE_TYPE_VALUE),
    ]
PCMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO = POINTER(_CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO)
CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO = _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO

class _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("KeyEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvKeyEncryptionAuxInfo", PVOID),
        ("KeyWrapAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvKeyWrapAuxInfo", PVOID),
        ("hCryptProv", HCRYPTPROV_LEGACY),
        ("dwKeySpec", DWORD),
        ("dwKeyChoice", DWORD),
        ("DUMMYUNIONNAME", TMPUNION_CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO),
        ("UserKeyingMaterial", CRYPT_DATA_BLOB),
        ("cRecipientEncryptedKeys", DWORD),
        ("rgpRecipientEncryptedKeys", POINTER(PCMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO)),
    ]
PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO = POINTER(_CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO)
CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO = _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO

class _TMP_CMSG_RECIPIENT_ENCODE_INFO_UNION(Union):
    _fields_ = [
        ("pKeyTrans", PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO),
        ("pKeyAgree", PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO),
        ("pMailList", PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO),
    ]
TMP_CMSG_RECIPIENT_ENCODE_INFO_UNION = _TMP_CMSG_RECIPIENT_ENCODE_INFO_UNION

class _CMSG_RECIPIENT_ENCODE_INFO(Structure):
    _fields_ = [
        ("dwRecipientChoice", DWORD),
        ("DUMMYUNIONNAME", TMP_CMSG_RECIPIENT_ENCODE_INFO_UNION),
    ]
CMSG_RECIPIENT_ENCODE_INFO = _CMSG_RECIPIENT_ENCODE_INFO
PCMSG_RECIPIENT_ENCODE_INFO = POINTER(_CMSG_RECIPIENT_ENCODE_INFO)

class _CMSG_ENVELOPED_ENCODE_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("hCryptProv", HCRYPTPROV_LEGACY),
        ("ContentEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvEncryptionAuxInfo", PVOID),
        ("cRecipients", DWORD),
        ("rgpRecipients", POINTER(PCERT_INFO)),
        ("rgCmsRecipients", PCMSG_RECIPIENT_ENCODE_INFO),
        ("cCertEncoded", DWORD),
        ("rgCertEncoded", PCERT_BLOB),
        ("cCrlEncoded", DWORD),
        ("rgCrlEncoded", PCRL_BLOB),
        ("cAttrCertEncoded", DWORD),
        ("rgAttrCertEncoded", PCERT_BLOB),
        ("cUnprotectedAttr", DWORD),
        ("rgUnprotectedAttr", PCRYPT_ATTRIBUTE),
    ]
PCMSG_ENVELOPED_ENCODE_INFO = POINTER(_CMSG_ENVELOPED_ENCODE_INFO)
CMSG_ENVELOPED_ENCODE_INFO = _CMSG_ENVELOPED_ENCODE_INFO

class _CMSG_STREAM_INFO(Structure):
    _fields_ = [
        ("cbContent", DWORD),
        ("pfnStreamOutput", PVOID),
        ("pvArg", PVOID),
    ]
CMSG_STREAM_INFO = _CMSG_STREAM_INFO
PCMSG_STREAM_INFO = POINTER(_CMSG_STREAM_INFO)

class _TMPUNION_CMSG_CTRL_DECRYPT_PARA(Union):
    _fields_ = [
        ("hCryptProv", HCRYPTPROV),
        ("hNCryptKey", NCRYPT_KEY_HANDLE),
    ]
TMPUNION_CMSG_CTRL_DECRYPT_PARA = _TMPUNION_CMSG_CTRL_DECRYPT_PARA

class _CMSG_CTRL_DECRYPT_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("DUMMYUNIONNAME", TMPUNION_CMSG_CTRL_DECRYPT_PARA),
        ("dwKeySpec", DWORD),
        ("dwRecipientIndex", DWORD),
    ]
PCMSG_CTRL_DECRYPT_PARA = POINTER(_CMSG_CTRL_DECRYPT_PARA)
CMSG_CTRL_DECRYPT_PARA = _CMSG_CTRL_DECRYPT_PARA

class _SPC_PE_IMAGE_DATA(Structure):
    _fields_ = [
        ("Flags", CRYPT_BIT_BLOB),
        ("pFile", PSPC_LINK),
    ]
PSPC_PE_IMAGE_DATA = POINTER(_SPC_PE_IMAGE_DATA)
SPC_PE_IMAGE_DATA = _SPC_PE_IMAGE_DATA

class _SPC_INDIRECT_DATA_CONTENT(Structure):
    _fields_ = [
        ("Data", CRYPT_ATTRIBUTE_TYPE_VALUE),
        ("DigestAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Digest", CRYPT_HASH_BLOB),
    ]
PSPC_INDIRECT_DATA_CONTENT = POINTER(_SPC_INDIRECT_DATA_CONTENT)
SPC_INDIRECT_DATA_CONTENT = _SPC_INDIRECT_DATA_CONTENT

class _PUBLICKEYSTRUC(Structure):
    _fields_ = [
        ("bType", BYTE),
        ("bVersion", BYTE),
        ("reserved", WORD),
        ("aiKeyAlg", ALG_ID),
    ]
PUBLICKEYSTRUC = _PUBLICKEYSTRUC
BLOBHEADER = _PUBLICKEYSTRUC

class _STRUCT_PLAINTEXTKEYBLOB(Structure):
    _fields_ = [
        ("hdr", BLOBHEADER),
        ("dwKeySize", DWORD),
        ("rgbKeyData", BYTE * (0)),
    ]
STRUCT_PLAINTEXTKEYBLOB = _STRUCT_PLAINTEXTKEYBLOB
PSTRUCT_PLAINTEXTKEYBLOB = POINTER(_STRUCT_PLAINTEXTKEYBLOB)

class _EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD),
    ]
LPEXCEPTION_DEBUG_INFO = POINTER(_EXCEPTION_DEBUG_INFO)
EXCEPTION_DEBUG_INFO = _EXCEPTION_DEBUG_INFO

class _CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPTHREAD_START_ROUTINE),
    ]
LPCREATE_THREAD_DEBUG_INFO = POINTER(_CREATE_THREAD_DEBUG_INFO)
CREATE_THREAD_DEBUG_INFO = _CREATE_THREAD_DEBUG_INFO

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

class _EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", DWORD),
    ]
EXIT_THREAD_DEBUG_INFO = _EXIT_THREAD_DEBUG_INFO
LPEXIT_THREAD_DEBUG_INFO = POINTER(_EXIT_THREAD_DEBUG_INFO)

class _EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", DWORD),
    ]
LPEXIT_PROCESS_DEBUG_INFO = POINTER(_EXIT_PROCESS_DEBUG_INFO)
EXIT_PROCESS_DEBUG_INFO = _EXIT_PROCESS_DEBUG_INFO

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

# typedef struct _LOAD_DLL_DEBUG_INFO {
#     HANDLE hFile;
#     LPVOID lpBaseOfDll;
#     DWORD dwDebugInfoFileOffset;
#     DWORD nDebugInfoSize;
#     LPVOID lpImageName;
#     WORD fUnicode;
# } LOAD_DLL_DEBUG_INFO, *LPLOAD_DLL_DEBUG_INFO;

class _LOAD_DLL_DEBUG_INFO(_LOAD_DLL_DEBUG_INFO):
    def hello(self):
        return "hello"
LPLOAD_DLL_DEBUG_INFO = POINTER(_LOAD_DLL_DEBUG_INFO)
LOAD_DLL_DEBUG_INFO = _LOAD_DLL_DEBUG_INFO
class _UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", LPVOID),
    ]
UNLOAD_DLL_DEBUG_INFO = _UNLOAD_DLL_DEBUG_INFO
LPUNLOAD_DLL_DEBUG_INFO = POINTER(_UNLOAD_DLL_DEBUG_INFO)

class _OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData", LPSTR),
        ("fUnicode", WORD),
        ("nDebugStringLength", WORD),
    ]
OUTPUT_DEBUG_STRING_INFO = _OUTPUT_DEBUG_STRING_INFO
LPOUTPUT_DEBUG_STRING_INFO = POINTER(_OUTPUT_DEBUG_STRING_INFO)

class _RIP_INFO(Structure):
    _fields_ = [
        ("dwError", DWORD),
        ("dwType", DWORD),
    ]
LPRIP_INFO = POINTER(_RIP_INFO)
RIP_INFO = _RIP_INFO

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

class _DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", _TMP_UNION_DEBUG_INFO),
    ]
LPDEBUG_EVENT = POINTER(_DEBUG_EVENT)
DEBUG_EVENT = _DEBUG_EVENT

EvtRpcLogin = EnumValue("_EVT_LOGIN_CLASS", "EvtRpcLogin", 0x1)
class _EVT_LOGIN_CLASS(EnumType):
    values = [EvtRpcLogin]
    mapper = FlagMapper(*values)
EVT_LOGIN_CLASS = _EVT_LOGIN_CLASS


EvtVarTypeNull = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeNull", 0x0)
EvtVarTypeString = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeString", 0x1)
EvtVarTypeAnsiString = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeAnsiString", 0x2)
EvtVarTypeSByte = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeSByte", 0x3)
EvtVarTypeByte = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeByte", 0x4)
EvtVarTypeInt16 = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeInt16", 0x5)
EvtVarTypeUInt16 = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeUInt16", 0x6)
EvtVarTypeInt32 = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeInt32", 0x7)
EvtVarTypeUInt32 = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeUInt32", 0x8)
EvtVarTypeInt64 = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeInt64", 0x9)
EvtVarTypeUInt64 = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeUInt64", 0xa)
EvtVarTypeSingle = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeSingle", 0xb)
EvtVarTypeDouble = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeDouble", 0xc)
EvtVarTypeBoolean = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeBoolean", 0xd)
EvtVarTypeBinary = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeBinary", 0xe)
EvtVarTypeGuid = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeGuid", 0xf)
EvtVarTypeSizeT = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeSizeT", 0x10)
EvtVarTypeFileTime = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeFileTime", 0x11)
EvtVarTypeSysTime = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeSysTime", 0x12)
EvtVarTypeSid = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeSid", 0x13)
EvtVarTypeHexInt32 = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeHexInt32", 0x14)
EvtVarTypeHexInt64 = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeHexInt64", 0x15)
EvtVarTypeEvtHandle = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeEvtHandle", 0x20)
EvtVarTypeEvtXml = EnumValue("_EVT_VARIANT_TYPE", "EvtVarTypeEvtXml", 0x23)
class _EVT_VARIANT_TYPE(EnumType):
    values = [EvtVarTypeNull, EvtVarTypeString, EvtVarTypeAnsiString, EvtVarTypeSByte, EvtVarTypeByte, EvtVarTypeInt16, EvtVarTypeUInt16, EvtVarTypeInt32, EvtVarTypeUInt32, EvtVarTypeInt64, EvtVarTypeUInt64, EvtVarTypeSingle, EvtVarTypeDouble, EvtVarTypeBoolean, EvtVarTypeBinary, EvtVarTypeGuid, EvtVarTypeSizeT, EvtVarTypeFileTime, EvtVarTypeSysTime, EvtVarTypeSid, EvtVarTypeHexInt32, EvtVarTypeHexInt64, EvtVarTypeEvtHandle, EvtVarTypeEvtXml]
    mapper = FlagMapper(*values)
EVT_VARIANT_TYPE = _EVT_VARIANT_TYPE


EvtSeekRelativeToFirst = EnumValue("_EVT_SEEK_FLAGS", "EvtSeekRelativeToFirst", 0x1)
EvtSeekRelativeToLast = EnumValue("_EVT_SEEK_FLAGS", "EvtSeekRelativeToLast", 0x2)
EvtSeekRelativeToCurrent = EnumValue("_EVT_SEEK_FLAGS", "EvtSeekRelativeToCurrent", 0x3)
EvtSeekRelativeToBookmark = EnumValue("_EVT_SEEK_FLAGS", "EvtSeekRelativeToBookmark", 0x4)
EvtSeekOriginMask = EnumValue("_EVT_SEEK_FLAGS", "EvtSeekOriginMask", 0x7)
EvtSeekStrict = EnumValue("_EVT_SEEK_FLAGS", "EvtSeekStrict", 0x10000)
class _EVT_SEEK_FLAGS(EnumType):
    values = [EvtSeekRelativeToFirst, EvtSeekRelativeToLast, EvtSeekRelativeToCurrent, EvtSeekRelativeToBookmark, EvtSeekOriginMask, EvtSeekStrict]
    mapper = FlagMapper(*values)
EVT_SEEK_FLAGS = _EVT_SEEK_FLAGS


EvtRenderContextValues = EnumValue("_EVT_RENDER_CONTEXT_FLAGS", "EvtRenderContextValues", 0x0)
EvtRenderContextSystem = EnumValue("_EVT_RENDER_CONTEXT_FLAGS", "EvtRenderContextSystem", 0x1)
EvtRenderContextUser = EnumValue("_EVT_RENDER_CONTEXT_FLAGS", "EvtRenderContextUser", 0x2)
class _EVT_RENDER_CONTEXT_FLAGS(EnumType):
    values = [EvtRenderContextValues, EvtRenderContextSystem, EvtRenderContextUser]
    mapper = FlagMapper(*values)
EVT_RENDER_CONTEXT_FLAGS = _EVT_RENDER_CONTEXT_FLAGS


EvtSystemProviderName = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemProviderName", 0x0)
EvtSystemProviderGuid = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemProviderGuid", 0x1)
EvtSystemEventID = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemEventID", 0x2)
EvtSystemQualifiers = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemQualifiers", 0x3)
EvtSystemLevel = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemLevel", 0x4)
EvtSystemTask = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemTask", 0x5)
EvtSystemOpcode = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemOpcode", 0x6)
EvtSystemKeywords = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemKeywords", 0x7)
EvtSystemTimeCreated = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemTimeCreated", 0x8)
EvtSystemEventRecordId = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemEventRecordId", 0x9)
EvtSystemActivityID = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemActivityID", 0xa)
EvtSystemRelatedActivityID = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemRelatedActivityID", 0xb)
EvtSystemProcessID = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemProcessID", 0xc)
EvtSystemThreadID = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemThreadID", 0xd)
EvtSystemChannel = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemChannel", 0xe)
EvtSystemComputer = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemComputer", 0xf)
EvtSystemUserID = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemUserID", 0x10)
EvtSystemVersion = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemVersion", 0x11)
EvtSystemPropertyIdEND = EnumValue("_EVT_SYSTEM_PROPERTY_ID", "EvtSystemPropertyIdEND", 0x12)
class _EVT_SYSTEM_PROPERTY_ID(EnumType):
    values = [EvtSystemProviderName, EvtSystemProviderGuid, EvtSystemEventID, EvtSystemQualifiers, EvtSystemLevel, EvtSystemTask, EvtSystemOpcode, EvtSystemKeywords, EvtSystemTimeCreated, EvtSystemEventRecordId, EvtSystemActivityID, EvtSystemRelatedActivityID, EvtSystemProcessID, EvtSystemThreadID, EvtSystemChannel, EvtSystemComputer, EvtSystemUserID, EvtSystemVersion, EvtSystemPropertyIdEND]
    mapper = FlagMapper(*values)
EVT_SYSTEM_PROPERTY_ID = _EVT_SYSTEM_PROPERTY_ID


EvtRenderEventValues = EnumValue("_EVT_RENDER_FLAGS", "EvtRenderEventValues", 0x0)
EvtRenderEventXml = EnumValue("_EVT_RENDER_FLAGS", "EvtRenderEventXml", 0x1)
EvtRenderBookmark = EnumValue("_EVT_RENDER_FLAGS", "EvtRenderBookmark", 0x2)
class _EVT_RENDER_FLAGS(EnumType):
    values = [EvtRenderEventValues, EvtRenderEventXml, EvtRenderBookmark]
    mapper = FlagMapper(*values)
EVT_RENDER_FLAGS = _EVT_RENDER_FLAGS


EvtQueryChannelPath = EnumValue("_EVT_QUERY_FLAGS", "EvtQueryChannelPath", 0x1)
EvtQueryFilePath = EnumValue("_EVT_QUERY_FLAGS", "EvtQueryFilePath", 0x2)
EvtQueryForwardDirection = EnumValue("_EVT_QUERY_FLAGS", "EvtQueryForwardDirection", 0x100)
EvtQueryReverseDirection = EnumValue("_EVT_QUERY_FLAGS", "EvtQueryReverseDirection", 0x200)
EvtQueryTolerateQueryErrors = EnumValue("_EVT_QUERY_FLAGS", "EvtQueryTolerateQueryErrors", 0x1000)
class _EVT_QUERY_FLAGS(EnumType):
    values = [EvtQueryChannelPath, EvtQueryFilePath, EvtQueryForwardDirection, EvtQueryReverseDirection, EvtQueryTolerateQueryErrors]
    mapper = FlagMapper(*values)
EVT_QUERY_FLAGS = _EVT_QUERY_FLAGS


EvtLogCreationTime = EnumValue("_EVT_LOG_PROPERTY_ID", "EvtLogCreationTime", 0x0)
EvtLogLastAccessTime = EnumValue("_EVT_LOG_PROPERTY_ID", "EvtLogLastAccessTime", 0x1)
EvtLogLastWriteTime = EnumValue("_EVT_LOG_PROPERTY_ID", "EvtLogLastWriteTime", 0x2)
EvtLogFileSize = EnumValue("_EVT_LOG_PROPERTY_ID", "EvtLogFileSize", 0x3)
EvtLogAttributes = EnumValue("_EVT_LOG_PROPERTY_ID", "EvtLogAttributes", 0x4)
EvtLogNumberOfLogRecords = EnumValue("_EVT_LOG_PROPERTY_ID", "EvtLogNumberOfLogRecords", 0x5)
EvtLogOldestRecordNumber = EnumValue("_EVT_LOG_PROPERTY_ID", "EvtLogOldestRecordNumber", 0x6)
EvtLogFull = EnumValue("_EVT_LOG_PROPERTY_ID", "EvtLogFull", 0x7)
class _EVT_LOG_PROPERTY_ID(EnumType):
    values = [EvtLogCreationTime, EvtLogLastAccessTime, EvtLogLastWriteTime, EvtLogFileSize, EvtLogAttributes, EvtLogNumberOfLogRecords, EvtLogOldestRecordNumber, EvtLogFull]
    mapper = FlagMapper(*values)
EVT_LOG_PROPERTY_ID = _EVT_LOG_PROPERTY_ID


EvtOpenChannelPath = EnumValue("_EVT_OPEN_LOG_FLAGS", "EvtOpenChannelPath", 0x1)
EvtOpenFilePath = EnumValue("_EVT_OPEN_LOG_FLAGS", "EvtOpenFilePath", 0x2)
class _EVT_OPEN_LOG_FLAGS(EnumType):
    values = [EvtOpenChannelPath, EvtOpenFilePath]
    mapper = FlagMapper(*values)
EVT_OPEN_LOG_FLAGS = _EVT_OPEN_LOG_FLAGS


EvtChannelConfigEnabled = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelConfigEnabled", 0x0)
EvtChannelConfigIsolation = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelConfigIsolation", 0x1)
EvtChannelConfigType = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelConfigType", 0x2)
EvtChannelConfigOwningPublisher = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelConfigOwningPublisher", 0x3)
EvtChannelConfigClassicEventlog = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelConfigClassicEventlog", 0x4)
EvtChannelConfigAccess = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelConfigAccess", 0x5)
EvtChannelLoggingConfigRetention = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelLoggingConfigRetention", 0x6)
EvtChannelLoggingConfigAutoBackup = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelLoggingConfigAutoBackup", 0x7)
EvtChannelLoggingConfigMaxSize = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelLoggingConfigMaxSize", 0x8)
EvtChannelLoggingConfigLogFilePath = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelLoggingConfigLogFilePath", 0x9)
EvtChannelPublishingConfigLevel = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigLevel", 0xa)
EvtChannelPublishingConfigKeywords = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigKeywords", 0xb)
EvtChannelPublishingConfigControlGuid = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigControlGuid", 0xc)
EvtChannelPublishingConfigBufferSize = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigBufferSize", 0xd)
EvtChannelPublishingConfigMinBuffers = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigMinBuffers", 0xe)
EvtChannelPublishingConfigMaxBuffers = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigMaxBuffers", 0xf)
EvtChannelPublishingConfigLatency = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigLatency", 0x10)
EvtChannelPublishingConfigClockType = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigClockType", 0x11)
EvtChannelPublishingConfigSidType = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigSidType", 0x12)
EvtChannelPublisherList = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublisherList", 0x13)
EvtChannelPublishingConfigFileMax = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelPublishingConfigFileMax", 0x14)
EvtChannelConfigPropertyIdEND = EnumValue("_EVT_CHANNEL_CONFIG_PROPERTY_ID", "EvtChannelConfigPropertyIdEND", 0x15)
class _EVT_CHANNEL_CONFIG_PROPERTY_ID(EnumType):
    values = [EvtChannelConfigEnabled, EvtChannelConfigIsolation, EvtChannelConfigType, EvtChannelConfigOwningPublisher, EvtChannelConfigClassicEventlog, EvtChannelConfigAccess, EvtChannelLoggingConfigRetention, EvtChannelLoggingConfigAutoBackup, EvtChannelLoggingConfigMaxSize, EvtChannelLoggingConfigLogFilePath, EvtChannelPublishingConfigLevel, EvtChannelPublishingConfigKeywords, EvtChannelPublishingConfigControlGuid, EvtChannelPublishingConfigBufferSize, EvtChannelPublishingConfigMinBuffers, EvtChannelPublishingConfigMaxBuffers, EvtChannelPublishingConfigLatency, EvtChannelPublishingConfigClockType, EvtChannelPublishingConfigSidType, EvtChannelPublisherList, EvtChannelPublishingConfigFileMax, EvtChannelConfigPropertyIdEND]
    mapper = FlagMapper(*values)
EVT_CHANNEL_CONFIG_PROPERTY_ID = _EVT_CHANNEL_CONFIG_PROPERTY_ID


EvtChannelTypeAdmin = EnumValue("_EVT_CHANNEL_TYPE", "EvtChannelTypeAdmin", 0x0)
EvtChannelTypeOperational = EnumValue("_EVT_CHANNEL_TYPE", "EvtChannelTypeOperational", 0x1)
EvtChannelTypeAnalytic = EnumValue("_EVT_CHANNEL_TYPE", "EvtChannelTypeAnalytic", 0x2)
EvtChannelTypeDebug = EnumValue("_EVT_CHANNEL_TYPE", "EvtChannelTypeDebug", 0x3)
class _EVT_CHANNEL_TYPE(EnumType):
    values = [EvtChannelTypeAdmin, EvtChannelTypeOperational, EvtChannelTypeAnalytic, EvtChannelTypeDebug]
    mapper = FlagMapper(*values)
EVT_CHANNEL_TYPE = _EVT_CHANNEL_TYPE


EvtChannelIsolationTypeApplication = EnumValue("_EVT_CHANNEL_ISOLATION_TYPE", "EvtChannelIsolationTypeApplication", 0x0)
EvtChannelIsolationTypeSystem = EnumValue("_EVT_CHANNEL_ISOLATION_TYPE", "EvtChannelIsolationTypeSystem", 0x1)
EvtChannelIsolationTypeCustom = EnumValue("_EVT_CHANNEL_ISOLATION_TYPE", "EvtChannelIsolationTypeCustom", 0x2)
class _EVT_CHANNEL_ISOLATION_TYPE(EnumType):
    values = [EvtChannelIsolationTypeApplication, EvtChannelIsolationTypeSystem, EvtChannelIsolationTypeCustom]
    mapper = FlagMapper(*values)
EVT_CHANNEL_ISOLATION_TYPE = _EVT_CHANNEL_ISOLATION_TYPE


EventMetadataEventID = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EventMetadataEventID", 0x0)
EventMetadataEventVersion = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EventMetadataEventVersion", 0x1)
EventMetadataEventChannel = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EventMetadataEventChannel", 0x2)
EventMetadataEventLevel = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EventMetadataEventLevel", 0x3)
EventMetadataEventOpcode = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EventMetadataEventOpcode", 0x4)
EventMetadataEventTask = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EventMetadataEventTask", 0x5)
EventMetadataEventKeyword = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EventMetadataEventKeyword", 0x6)
EventMetadataEventMessageID = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EventMetadataEventMessageID", 0x7)
EventMetadataEventTemplate = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EventMetadataEventTemplate", 0x8)
EvtEventMetadataPropertyIdEND = EnumValue("_EVT_EVENT_METADATA_PROPERTY_ID", "EvtEventMetadataPropertyIdEND", 0x9)
class _EVT_EVENT_METADATA_PROPERTY_ID(EnumType):
    values = [EventMetadataEventID, EventMetadataEventVersion, EventMetadataEventChannel, EventMetadataEventLevel, EventMetadataEventOpcode, EventMetadataEventTask, EventMetadataEventKeyword, EventMetadataEventMessageID, EventMetadataEventTemplate, EvtEventMetadataPropertyIdEND]
    mapper = FlagMapper(*values)
EVT_EVENT_METADATA_PROPERTY_ID = _EVT_EVENT_METADATA_PROPERTY_ID


EvtPublisherMetadataPublisherGuid = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataPublisherGuid", 0x0)
EvtPublisherMetadataResourceFilePath = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataResourceFilePath", 0x1)
EvtPublisherMetadataParameterFilePath = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataParameterFilePath", 0x2)
EvtPublisherMetadataMessageFilePath = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataMessageFilePath", 0x3)
EvtPublisherMetadataHelpLink = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataHelpLink", 0x4)
EvtPublisherMetadataPublisherMessageID = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataPublisherMessageID", 0x5)
EvtPublisherMetadataChannelReferences = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataChannelReferences", 0x6)
EvtPublisherMetadataChannelReferencePath = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataChannelReferencePath", 0x7)
EvtPublisherMetadataChannelReferenceIndex = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataChannelReferenceIndex", 0x8)
EvtPublisherMetadataChannelReferenceID = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataChannelReferenceID", 0x9)
EvtPublisherMetadataChannelReferenceFlags = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataChannelReferenceFlags", 0xa)
EvtPublisherMetadataChannelReferenceMessageID = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataChannelReferenceMessageID", 0xb)
EvtPublisherMetadataLevels = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataLevels", 0xc)
EvtPublisherMetadataLevelName = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataLevelName", 0xd)
EvtPublisherMetadataLevelValue = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataLevelValue", 0xe)
EvtPublisherMetadataLevelMessageID = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataLevelMessageID", 0xf)
EvtPublisherMetadataTasks = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataTasks", 0x10)
EvtPublisherMetadataTaskName = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataTaskName", 0x11)
EvtPublisherMetadataTaskEventGuid = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataTaskEventGuid", 0x12)
EvtPublisherMetadataTaskValue = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataTaskValue", 0x13)
EvtPublisherMetadataTaskMessageID = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataTaskMessageID", 0x14)
EvtPublisherMetadataOpcodes = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataOpcodes", 0x15)
EvtPublisherMetadataOpcodeName = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataOpcodeName", 0x16)
EvtPublisherMetadataOpcodeValue = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataOpcodeValue", 0x17)
EvtPublisherMetadataOpcodeMessageID = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataOpcodeMessageID", 0x18)
EvtPublisherMetadataKeywords = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataKeywords", 0x19)
EvtPublisherMetadataKeywordName = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataKeywordName", 0x1a)
EvtPublisherMetadataKeywordValue = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataKeywordValue", 0x1b)
EvtPublisherMetadataKeywordMessageID = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataKeywordMessageID", 0x1c)
EvtPublisherMetadataPropertyIdEND = EnumValue("_EVT_PUBLISHER_METADATA_PROPERTY_ID", "EvtPublisherMetadataPropertyIdEND", 0x1d)
class _EVT_PUBLISHER_METADATA_PROPERTY_ID(EnumType):
    values = [EvtPublisherMetadataPublisherGuid, EvtPublisherMetadataResourceFilePath, EvtPublisherMetadataParameterFilePath, EvtPublisherMetadataMessageFilePath, EvtPublisherMetadataHelpLink, EvtPublisherMetadataPublisherMessageID, EvtPublisherMetadataChannelReferences, EvtPublisherMetadataChannelReferencePath, EvtPublisherMetadataChannelReferenceIndex, EvtPublisherMetadataChannelReferenceID, EvtPublisherMetadataChannelReferenceFlags, EvtPublisherMetadataChannelReferenceMessageID, EvtPublisherMetadataLevels, EvtPublisherMetadataLevelName, EvtPublisherMetadataLevelValue, EvtPublisherMetadataLevelMessageID, EvtPublisherMetadataTasks, EvtPublisherMetadataTaskName, EvtPublisherMetadataTaskEventGuid, EvtPublisherMetadataTaskValue, EvtPublisherMetadataTaskMessageID, EvtPublisherMetadataOpcodes, EvtPublisherMetadataOpcodeName, EvtPublisherMetadataOpcodeValue, EvtPublisherMetadataOpcodeMessageID, EvtPublisherMetadataKeywords, EvtPublisherMetadataKeywordName, EvtPublisherMetadataKeywordValue, EvtPublisherMetadataKeywordMessageID, EvtPublisherMetadataPropertyIdEND]
    mapper = FlagMapper(*values)
EVT_PUBLISHER_METADATA_PROPERTY_ID = _EVT_PUBLISHER_METADATA_PROPERTY_ID


EvtFormatMessageEvent = EnumValue("_EVT_FORMAT_MESSAGE_FLAGS", "EvtFormatMessageEvent", 0x1)
EvtFormatMessageLevel = EnumValue("_EVT_FORMAT_MESSAGE_FLAGS", "EvtFormatMessageLevel", 0x2)
EvtFormatMessageTask = EnumValue("_EVT_FORMAT_MESSAGE_FLAGS", "EvtFormatMessageTask", 0x3)
EvtFormatMessageOpcode = EnumValue("_EVT_FORMAT_MESSAGE_FLAGS", "EvtFormatMessageOpcode", 0x4)
EvtFormatMessageKeyword = EnumValue("_EVT_FORMAT_MESSAGE_FLAGS", "EvtFormatMessageKeyword", 0x5)
EvtFormatMessageChannel = EnumValue("_EVT_FORMAT_MESSAGE_FLAGS", "EvtFormatMessageChannel", 0x6)
EvtFormatMessageProvider = EnumValue("_EVT_FORMAT_MESSAGE_FLAGS", "EvtFormatMessageProvider", 0x7)
EvtFormatMessageId = EnumValue("_EVT_FORMAT_MESSAGE_FLAGS", "EvtFormatMessageId", 0x8)
EvtFormatMessageXml = EnumValue("_EVT_FORMAT_MESSAGE_FLAGS", "EvtFormatMessageXml", 0x9)
class _EVT_FORMAT_MESSAGE_FLAGS(EnumType):
    values = [EvtFormatMessageEvent, EvtFormatMessageLevel, EvtFormatMessageTask, EvtFormatMessageOpcode, EvtFormatMessageKeyword, EvtFormatMessageChannel, EvtFormatMessageProvider, EvtFormatMessageId, EvtFormatMessageXml]
    mapper = FlagMapper(*values)
EVT_FORMAT_MESSAGE_FLAGS = _EVT_FORMAT_MESSAGE_FLAGS


class _EVENTLOGRECORD(Structure):
    _fields_ = [
        ("Length", DWORD),
        ("Reserved", DWORD),
        ("RecordNumber", DWORD),
        ("TimeGenerated", DWORD),
        ("TimeWritten", DWORD),
        ("EventID", DWORD),
        ("EventType", WORD),
        ("NumStrings", WORD),
        ("EventCategory", WORD),
        ("ReservedFlags", WORD),
        ("ClosingRecordNumber", DWORD),
        ("StringOffset", DWORD),
        ("UserSidLength", DWORD),
        ("UserSidOffset", DWORD),
        ("DataLength", DWORD),
        ("DataOffset", DWORD),
    ]
PEVENTLOGRECORD = POINTER(_EVENTLOGRECORD)
EVENTLOGRECORD = _EVENTLOGRECORD

class _EVENTLOG_FULL_INFORMATION(Structure):
    _fields_ = [
        ("dwFull", DWORD),
    ]
EVENTLOG_FULL_INFORMATION = _EVENTLOG_FULL_INFORMATION
LPEVENTLOG_FULL_INFORMATION = POINTER(_EVENTLOG_FULL_INFORMATION)

class _ANON__EVT_VARIANT_SUB_UNION_1(Union):
    _fields_ = [
        ("BooleanVal", BOOL),
        ("SByteVal", INT8),
        ("Int16Val", INT16),
        ("Int32Val", INT32),
        ("Int64Val", INT64),
        ("ByteVal", UINT8),
        ("UInt16Val", UINT16),
        ("UInt32Val", UINT32),
        ("UInt64Val", UINT64),
        ("SingleVal", FLOAT),
        ("DoubleVal", DOUBLE),
        ("FileTimeVal", ULONGLONG),
        ("SysTimeVal", POINTER(SYSTEMTIME)),
        ("GuidVal", POINTER(GUID)),
        ("StringVal", LPCWSTR),
        ("AnsiStringVal", LPCSTR),
        ("BinaryVal", PBYTE),
        ("SidVal", PSID),
        ("SizeTVal", SIZE_T),
        ("BooleanArr", POINTER(BOOL)),
        ("SByteArr", POINTER(INT8)),
        ("Int16Arr", POINTER(INT16)),
        ("Int32Arr", POINTER(INT32)),
        ("Int64Arr", POINTER(INT64)),
        ("ByteArr", POINTER(UINT8)),
        ("UInt16Arr", POINTER(UINT16)),
        ("UInt32Arr", POINTER(UINT32)),
        ("UInt64Arr", POINTER(UINT64)),
        ("SingleArr", POINTER(FLOAT)),
        ("DoubleArr", POINTER(DOUBLE)),
        ("FileTimeArr", POINTER(FILETIME)),
        ("SysTimeArr", POINTER(SYSTEMTIME)),
        ("GuidArr", POINTER(GUID)),
        ("StringArr", POINTER(LPWSTR)),
        ("AnsiStringArr", POINTER(LPSTR)),
        ("SidArr", POINTER(PSID)),
        ("SizeTArr", POINTER(SIZE_T)),
        ("EvtHandleVal", EVT_HANDLE),
        ("XmlVal", LPCWSTR),
        ("XmlValArr", POINTER(LPCWSTR)),
    ]

class _EVT_VARIANT(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__EVT_VARIANT_SUB_UNION_1),
        ("Count", DWORD),
        ("Type", DWORD),
    ]
PEVT_VARIANT = POINTER(_EVT_VARIANT)
EVT_VARIANT = _EVT_VARIANT

class _EVT_RPC_LOGIN(Structure):
    _fields_ = [
        ("Server", LPWSTR),
        ("User", LPWSTR),
        ("Domain", LPWSTR),
        ("Password", LPWSTR),
        ("Flags", DWORD),
    ]
EVT_RPC_LOGIN = _EVT_RPC_LOGIN

FakeFileInformationZero = EnumValue("_FILE_INFORMATION_CLASS", "FakeFileInformationZero", 0x0)
FileDirectoryInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileDirectoryInformation", 0x1)
FileFullDirectoryInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileFullDirectoryInformation", 0x2)
FileBothDirectoryInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileBothDirectoryInformation", 0x3)
FileBasicInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileBasicInformation", 0x4)
FileStandardInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileStandardInformation", 0x5)
FileInternalInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileInternalInformation", 0x6)
FileEaInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileEaInformation", 0x7)
FileAccessInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileAccessInformation", 0x8)
FileNameInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileNameInformation", 0x9)
FileRenameInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileRenameInformation", 0xa)
FileLinkInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileLinkInformation", 0xb)
FileNamesInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileNamesInformation", 0xc)
FileDispositionInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileDispositionInformation", 0xd)
FilePositionInformation = EnumValue("_FILE_INFORMATION_CLASS", "FilePositionInformation", 0xe)
FileFullEaInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileFullEaInformation", 0xf)
FileModeInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileModeInformation", 0x10)
FileAlignmentInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileAlignmentInformation", 0x11)
FileAllInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileAllInformation", 0x12)
FileAllocationInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileAllocationInformation", 0x13)
FileEndOfFileInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileEndOfFileInformation", 0x14)
FileAlternateNameInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileAlternateNameInformation", 0x15)
FileStreamInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileStreamInformation", 0x16)
FilePipeInformation = EnumValue("_FILE_INFORMATION_CLASS", "FilePipeInformation", 0x17)
FilePipeLocalInformation = EnumValue("_FILE_INFORMATION_CLASS", "FilePipeLocalInformation", 0x18)
FilePipeRemoteInformation = EnumValue("_FILE_INFORMATION_CLASS", "FilePipeRemoteInformation", 0x19)
FileMailslotQueryInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileMailslotQueryInformation", 0x1a)
FileMailslotSetInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileMailslotSetInformation", 0x1b)
FileCompressionInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileCompressionInformation", 0x1c)
FileObjectIdInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileObjectIdInformation", 0x1d)
FileCompletionInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileCompletionInformation", 0x1e)
FileMoveClusterInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileMoveClusterInformation", 0x1f)
FileQuotaInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileQuotaInformation", 0x20)
FileReparsePointInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileReparsePointInformation", 0x21)
FileNetworkOpenInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileNetworkOpenInformation", 0x22)
FileAttributeTagInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileAttributeTagInformation", 0x23)
FileTrackingInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileTrackingInformation", 0x24)
FileIdBothDirectoryInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIdBothDirectoryInformation", 0x25)
FileIdFullDirectoryInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIdFullDirectoryInformation", 0x26)
FileValidDataLengthInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileValidDataLengthInformation", 0x27)
FileShortNameInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileShortNameInformation", 0x28)
FileIoCompletionNotificationInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIoCompletionNotificationInformation", 0x29)
FileIoStatusBlockRangeInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIoStatusBlockRangeInformation", 0x2a)
FileIoPriorityHintInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIoPriorityHintInformation", 0x2b)
FileSfioReserveInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileSfioReserveInformation", 0x2c)
FileSfioVolumeInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileSfioVolumeInformation", 0x2d)
FileHardLinkInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileHardLinkInformation", 0x2e)
FileProcessIdsUsingFileInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileProcessIdsUsingFileInformation", 0x2f)
FileNormalizedNameInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileNormalizedNameInformation", 0x30)
FileNetworkPhysicalNameInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileNetworkPhysicalNameInformation", 0x31)
FileIdGlobalTxDirectoryInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIdGlobalTxDirectoryInformation", 0x32)
FileIsRemoteDeviceInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIsRemoteDeviceInformation", 0x33)
FileUnusedInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileUnusedInformation", 0x34)
FileNumaNodeInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileNumaNodeInformation", 0x35)
FileStandardLinkInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileStandardLinkInformation", 0x36)
FileRemoteProtocolInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileRemoteProtocolInformation", 0x37)
FileRenameInformationBypassAccessCheck = EnumValue("_FILE_INFORMATION_CLASS", "FileRenameInformationBypassAccessCheck", 0x38)
FileLinkInformationBypassAccessCheck = EnumValue("_FILE_INFORMATION_CLASS", "FileLinkInformationBypassAccessCheck", 0x39)
FileVolumeNameInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileVolumeNameInformation", 0x3a)
FileIdInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIdInformation", 0x3b)
FileIdExtdDirectoryInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIdExtdDirectoryInformation", 0x3c)
FileReplaceCompletionInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileReplaceCompletionInformation", 0x3d)
FileHardLinkFullIdInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileHardLinkFullIdInformation", 0x3e)
FileIdExtdBothDirectoryInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileIdExtdBothDirectoryInformation", 0x3f)
FileDispositionInformationEx = EnumValue("_FILE_INFORMATION_CLASS", "FileDispositionInformationEx", 0x40)
FileRenameInformationEx = EnumValue("_FILE_INFORMATION_CLASS", "FileRenameInformationEx", 0x41)
FileRenameInformationExBypassAccessCheck = EnumValue("_FILE_INFORMATION_CLASS", "FileRenameInformationExBypassAccessCheck", 0x42)
FileMaximumInformation = EnumValue("_FILE_INFORMATION_CLASS", "FileMaximumInformation", 0x43)
class _FILE_INFORMATION_CLASS(EnumType):
    values = [FakeFileInformationZero, FileDirectoryInformation, FileFullDirectoryInformation, FileBothDirectoryInformation, FileBasicInformation, FileStandardInformation, FileInternalInformation, FileEaInformation, FileAccessInformation, FileNameInformation, FileRenameInformation, FileLinkInformation, FileNamesInformation, FileDispositionInformation, FilePositionInformation, FileFullEaInformation, FileModeInformation, FileAlignmentInformation, FileAllInformation, FileAllocationInformation, FileEndOfFileInformation, FileAlternateNameInformation, FileStreamInformation, FilePipeInformation, FilePipeLocalInformation, FilePipeRemoteInformation, FileMailslotQueryInformation, FileMailslotSetInformation, FileCompressionInformation, FileObjectIdInformation, FileCompletionInformation, FileMoveClusterInformation, FileQuotaInformation, FileReparsePointInformation, FileNetworkOpenInformation, FileAttributeTagInformation, FileTrackingInformation, FileIdBothDirectoryInformation, FileIdFullDirectoryInformation, FileValidDataLengthInformation, FileShortNameInformation, FileIoCompletionNotificationInformation, FileIoStatusBlockRangeInformation, FileIoPriorityHintInformation, FileSfioReserveInformation, FileSfioVolumeInformation, FileHardLinkInformation, FileProcessIdsUsingFileInformation, FileNormalizedNameInformation, FileNetworkPhysicalNameInformation, FileIdGlobalTxDirectoryInformation, FileIsRemoteDeviceInformation, FileUnusedInformation, FileNumaNodeInformation, FileStandardLinkInformation, FileRemoteProtocolInformation, FileRenameInformationBypassAccessCheck, FileLinkInformationBypassAccessCheck, FileVolumeNameInformation, FileIdInformation, FileIdExtdDirectoryInformation, FileReplaceCompletionInformation, FileHardLinkFullIdInformation, FileIdExtdBothDirectoryInformation, FileDispositionInformationEx, FileRenameInformationEx, FileRenameInformationExBypassAccessCheck, FileMaximumInformation]
    mapper = FlagMapper(*values)
FILE_INFORMATION_CLASS = _FILE_INFORMATION_CLASS
PFILE_INFORMATION_CLASS = POINTER(_FILE_INFORMATION_CLASS)


IoPriorityVeryLow = EnumValue("_IO_PRIORITY_HINT", "IoPriorityVeryLow", 0x0)
IoPriorityLow = EnumValue("_IO_PRIORITY_HINT", "IoPriorityLow", 0x1)
IoPriorityNormal = EnumValue("_IO_PRIORITY_HINT", "IoPriorityNormal", 0x2)
IoPriorityHigh = EnumValue("_IO_PRIORITY_HINT", "IoPriorityHigh", 0x3)
IoPriorityCritical = EnumValue("_IO_PRIORITY_HINT", "IoPriorityCritical", 0x4)
MaxIoPriorityTypes = EnumValue("_IO_PRIORITY_HINT", "MaxIoPriorityTypes", 0x5)
class _IO_PRIORITY_HINT(EnumType):
    values = [IoPriorityVeryLow, IoPriorityLow, IoPriorityNormal, IoPriorityHigh, IoPriorityCritical, MaxIoPriorityTypes]
    mapper = FlagMapper(*values)
IO_PRIORITY_HINT = _IO_PRIORITY_HINT


ReadDirectoryNotifyInformation = EnumValue("_READ_DIRECTORY_NOTIFY_INFORMATION_CLASS", "ReadDirectoryNotifyInformation", 0x0)
ReadDirectoryNotifyExtendedInformation = EnumValue("_READ_DIRECTORY_NOTIFY_INFORMATION_CLASS", "ReadDirectoryNotifyExtendedInformation", 0x1)
class _READ_DIRECTORY_NOTIFY_INFORMATION_CLASS(EnumType):
    values = [ReadDirectoryNotifyInformation, ReadDirectoryNotifyExtendedInformation]
    mapper = FlagMapper(*values)
PREAD_DIRECTORY_NOTIFY_INFORMATION_CLASS = POINTER(_READ_DIRECTORY_NOTIFY_INFORMATION_CLASS)
READ_DIRECTORY_NOTIFY_INFORMATION_CLASS = _READ_DIRECTORY_NOTIFY_INFORMATION_CLASS


class _FILE_INTERNAL_INFORMATION(Structure):
    _fields_ = [
        ("IndexNumber", LARGE_INTEGER),
    ]
FILE_INTERNAL_INFORMATION = _FILE_INTERNAL_INFORMATION
PFILE_INTERNAL_INFORMATION = POINTER(_FILE_INTERNAL_INFORMATION)

class _FILE_ALIGNMENT_INFORMATION(Structure):
    _fields_ = [
        ("AlignmentRequirement", ULONG),
    ]
PFILE_ALIGNMENT_INFORMATION = POINTER(_FILE_ALIGNMENT_INFORMATION)
FILE_ALIGNMENT_INFORMATION = _FILE_ALIGNMENT_INFORMATION

class _FILE_ATTRIBUTE_TAG_INFORMATION(Structure):
    _fields_ = [
        ("FileAttributes", ULONG),
        ("ReparseTag", ULONG),
    ]
PFILE_ATTRIBUTE_TAG_INFORMATION = POINTER(_FILE_ATTRIBUTE_TAG_INFORMATION)
FILE_ATTRIBUTE_TAG_INFORMATION = _FILE_ATTRIBUTE_TAG_INFORMATION

class _FILE_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("CreationTime", LARGE_INTEGER),
        ("LastAccessTime", LARGE_INTEGER),
        ("LastWriteTime", LARGE_INTEGER),
        ("ChangeTime", LARGE_INTEGER),
        ("FileAttributes", ULONG),
    ]
FILE_BASIC_INFORMATION = _FILE_BASIC_INFORMATION
PFILE_BASIC_INFORMATION = POINTER(_FILE_BASIC_INFORMATION)

class _FILE_EA_INFORMATION(Structure):
    _fields_ = [
        ("EaSize", ULONG),
    ]
PFILE_EA_INFORMATION = POINTER(_FILE_EA_INFORMATION)
FILE_EA_INFORMATION = _FILE_EA_INFORMATION

class _FILE_IO_PRIORITY_HINT_INFORMATION(Structure):
    _fields_ = [
        ("PriorityHint", IO_PRIORITY_HINT),
    ]
PFILE_IO_PRIORITY_HINT_INFORMATION = POINTER(_FILE_IO_PRIORITY_HINT_INFORMATION)
FILE_IO_PRIORITY_HINT_INFORMATION = _FILE_IO_PRIORITY_HINT_INFORMATION

class _FILE_MODE_INFORMATION(Structure):
    _fields_ = [
        ("Mode", ULONG),
    ]
PFILE_MODE_INFORMATION = POINTER(_FILE_MODE_INFORMATION)
FILE_MODE_INFORMATION = _FILE_MODE_INFORMATION

class _FILE_NAME_INFORMATION(Structure):
    _fields_ = [
        ("FileNameLength", ULONG),
        ("FileName", WCHAR * (1)),
    ]
PFILE_NAME_INFORMATION = POINTER(_FILE_NAME_INFORMATION)
FILE_NAME_INFORMATION = _FILE_NAME_INFORMATION

class _FILE_NETWORK_OPEN_INFORMATION(Structure):
    _fields_ = [
        ("CreationTime", LARGE_INTEGER),
        ("LastAccessTime", LARGE_INTEGER),
        ("LastWriteTime", LARGE_INTEGER),
        ("ChangeTime", LARGE_INTEGER),
        ("AllocationSize", LARGE_INTEGER),
        ("EndOfFile", LARGE_INTEGER),
        ("FileAttributes", ULONG),
    ]
PFILE_NETWORK_OPEN_INFORMATION = POINTER(_FILE_NETWORK_OPEN_INFORMATION)
FILE_NETWORK_OPEN_INFORMATION = _FILE_NETWORK_OPEN_INFORMATION

class _FILE_STANDARD_INFORMATION(Structure):
    _fields_ = [
        ("AllocationSize", LARGE_INTEGER),
        ("EndOfFile", LARGE_INTEGER),
        ("NumberOfLinks", ULONG),
        ("DeletePending", BOOLEAN),
        ("Directory", BOOLEAN),
    ]
FILE_STANDARD_INFORMATION = _FILE_STANDARD_INFORMATION
PFILE_STANDARD_INFORMATION = POINTER(_FILE_STANDARD_INFORMATION)

class _FILE_ACCESS_INFORMATION(Structure):
    _fields_ = [
        ("AccessFlags", ACCESS_MASK),
    ]
FILE_ACCESS_INFORMATION = _FILE_ACCESS_INFORMATION
PFILE_ACCESS_INFORMATION = POINTER(_FILE_ACCESS_INFORMATION)

class _FILE_POSITION_INFORMATION(Structure):
    _fields_ = [
        ("CurrentByteOffset", LARGE_INTEGER),
    ]
PFILE_POSITION_INFORMATION = POINTER(_FILE_POSITION_INFORMATION)
FILE_POSITION_INFORMATION = _FILE_POSITION_INFORMATION

class _FILE_IS_REMOTE_DEVICE_INFORMATION(Structure):
    _fields_ = [
        ("IsRemote", BOOLEAN),
    ]
FILE_IS_REMOTE_DEVICE_INFORMATION = _FILE_IS_REMOTE_DEVICE_INFORMATION
PFILE_IS_REMOTE_DEVICE_INFORMATION = POINTER(_FILE_IS_REMOTE_DEVICE_INFORMATION)

class _FILE_ALL_INFORMATION(Structure):
    _fields_ = [
        ("BasicInformation", FILE_BASIC_INFORMATION),
        ("StandardInformation", FILE_STANDARD_INFORMATION),
        ("InternalInformation", FILE_INTERNAL_INFORMATION),
        ("EaInformation", FILE_EA_INFORMATION),
        ("AccessInformation", FILE_ACCESS_INFORMATION),
        ("PositionInformation", FILE_POSITION_INFORMATION),
        ("ModeInformation", FILE_MODE_INFORMATION),
        ("AlignmentInformation", FILE_ALIGNMENT_INFORMATION),
        ("NameInformation", FILE_NAME_INFORMATION),
    ]
PFILE_ALL_INFORMATION = POINTER(_FILE_ALL_INFORMATION)
FILE_ALL_INFORMATION = _FILE_ALL_INFORMATION

class _FILE_STREAM_INFORMATION(Structure):
    _fields_ = [
        ("NextEntryOffset", ULONG),
        ("StreamNameLength", ULONG),
        ("StreamSize", LARGE_INTEGER),
        ("StreamAllocationSize", LARGE_INTEGER),
        ("StreamName", WCHAR * (1)),
    ]
FILE_STREAM_INFORMATION = _FILE_STREAM_INFORMATION
PFILE_STREAM_INFORMATION = POINTER(_FILE_STREAM_INFORMATION)

class _FILE_DISPOSITION_INFORMATION(Structure):
    _fields_ = [
        ("DeleteFile", BOOLEAN),
    ]
PFILE_DISPOSITION_INFORMATION = POINTER(_FILE_DISPOSITION_INFORMATION)
FILE_DISPOSITION_INFORMATION = _FILE_DISPOSITION_INFORMATION

class _FILE_FULL_EA_INFORMATION(Structure):
    _fields_ = [
        ("NextEntryOffset", ULONG),
        ("Flags", BYTE),
        ("EaNameLength", BYTE),
        ("EaValueLength", USHORT),
        ("EaName", CHAR * (1)),
    ]
FILE_FULL_EA_INFORMATION = _FILE_FULL_EA_INFORMATION
PFILE_FULL_EA_INFORMATION = POINTER(_FILE_FULL_EA_INFORMATION)

class _FILE_GET_EA_INFORMATION(Structure):
    _fields_ = [
        ("NextEntryOffset", ULONG),
        ("EaNameLength", UCHAR),
        ("EaName", CHAR * (1)),
    ]
FILE_GET_EA_INFORMATION = _FILE_GET_EA_INFORMATION
PFILE_GET_EA_INFORMATION = POINTER(_FILE_GET_EA_INFORMATION)

class tagVS_FIXEDFILEINFO(Structure):
    _fields_ = [
        ("dwSignature", DWORD),
        ("dwStrucVersion", DWORD),
        ("dwFileVersionMS", DWORD),
        ("dwFileVersionLS", DWORD),
        ("dwProductVersionMS", DWORD),
        ("dwProductVersionLS", DWORD),
        ("dwFileFlagsMask", DWORD),
        ("dwFileFlags", DWORD),
        ("dwFileOS", DWORD),
        ("dwFileType", DWORD),
        ("dwFileSubtype", DWORD),
        ("dwFileDateMS", DWORD),
        ("dwFileDateLS", DWORD),
    ]
VS_FIXEDFILEINFO = tagVS_FIXEDFILEINFO

class _ANON__FILE_LINK_INFORMATION_SUB_UNION_1(Union):
    _fields_ = [
        ("ReplaceIfExists", BOOLEAN),
        ("Flags", ULONG),
    ]

class _FILE_LINK_INFORMATION(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__FILE_LINK_INFORMATION_SUB_UNION_1),
        ("RootDirectory", HANDLE),
        ("FileNameLength", ULONG),
        ("FileName", WCHAR * (1)),
    ]
PFILE_LINK_INFORMATION = POINTER(_FILE_LINK_INFORMATION)
FILE_LINK_INFORMATION = _FILE_LINK_INFORMATION

class _WIN32_FIND_DATAA(Structure):
    _fields_ = [
        ("dwFileAttributes", DWORD),
        ("ftCreationTime", FILETIME),
        ("ftLastAccessTime", FILETIME),
        ("ftLastWriteTime", FILETIME),
        ("nFileSizeHigh", DWORD),
        ("nFileSizeLow", DWORD),
        ("dwReserved0", DWORD),
        ("dwReserved1", DWORD),
        ("cFileName", CHAR * (MAX_PATH)),
        ("cAlternateFileName", CHAR * (14)),
        ("dwFileType", DWORD),
        ("dwCreatorType", DWORD),
        ("wFinderFlags", WORD),
    ]
LPWIN32_FIND_DATAA = POINTER(_WIN32_FIND_DATAA)
PWIN32_FIND_DATAA = POINTER(_WIN32_FIND_DATAA)
WIN32_FIND_DATAA = _WIN32_FIND_DATAA

class _WIN32_FIND_DATAW(Structure):
    _fields_ = [
        ("dwFileAttributes", DWORD),
        ("ftCreationTime", FILETIME),
        ("ftLastAccessTime", FILETIME),
        ("ftLastWriteTime", FILETIME),
        ("nFileSizeHigh", DWORD),
        ("nFileSizeLow", DWORD),
        ("dwReserved0", DWORD),
        ("dwReserved1", DWORD),
        ("cFileName", WCHAR * (MAX_PATH)),
        ("cAlternateFileName", WCHAR * (14)),
        ("dwFileType", DWORD),
        ("dwCreatorType", DWORD),
        ("wFinderFlags", WORD),
    ]
PWIN32_FIND_DATAW = POINTER(_WIN32_FIND_DATAW)
WIN32_FIND_DATAW = _WIN32_FIND_DATAW
LPWIN32_FIND_DATAW = POINTER(_WIN32_FIND_DATAW)

class _FILE_NOTIFY_INFORMATION(Structure):
    _fields_ = [
        ("NextEntryOffset", DWORD),
        ("Action", DWORD),
        ("FileNameLength", DWORD),
        ("FileName", WCHAR * (1)),
    ]
FILE_NOTIFY_INFORMATION = _FILE_NOTIFY_INFORMATION
PFILE_NOTIFY_INFORMATION = POINTER(_FILE_NOTIFY_INFORMATION)

class _FILE_NOTIFY_EXTENDED_INFORMATION(Structure):
    _fields_ = [
        ("NextEntryOffset", DWORD),
        ("Action", DWORD),
        ("CreationTime", LARGE_INTEGER),
        ("LastModificationTime", LARGE_INTEGER),
        ("LastChangeTime", LARGE_INTEGER),
        ("LastAccessTime", LARGE_INTEGER),
        ("AllocatedLength", LARGE_INTEGER),
        ("FileSize", LARGE_INTEGER),
        ("FileAttributes", DWORD),
        ("ReparsePointTag", DWORD),
        ("FileId", LARGE_INTEGER),
        ("ParentFileId", LARGE_INTEGER),
        ("FileNameLength", DWORD),
        ("FileName", WCHAR * (1)),
    ]
PFILE_NOTIFY_EXTENDED_INFORMATION = POINTER(_FILE_NOTIFY_EXTENDED_INFORMATION)
FILE_NOTIFY_EXTENDED_INFORMATION = _FILE_NOTIFY_EXTENDED_INFORMATION

class _ANON__FILE_RENAME_INFORMATION_SUB_UNION_1(Union):
    _fields_ = [
        ("ReplaceIfExists", BOOLEAN),
        ("Flags", ULONG),
    ]

class _FILE_RENAME_INFORMATION(Structure):
    _anonymous_ = ("__ANON_DUMMYUNIONNAME_FILE_RENAME_INFORMATION",)
    _fields_ = [
        ("__ANON_DUMMYUNIONNAME_FILE_RENAME_INFORMATION", _ANON__FILE_RENAME_INFORMATION_SUB_UNION_1),
        ("RootDirectory", HANDLE),
        ("FileNameLength", ULONG),
        ("FileName", WCHAR * (1)),
    ]
FILE_RENAME_INFORMATION = _FILE_RENAME_INFORMATION
PFILE_RENAME_INFORMATION = POINTER(_FILE_RENAME_INFORMATION)

INITIAL_FILE_RENAME_INFORMATION = _FILE_RENAME_INFORMATION

class _FILE_RENAME_INFORMATION(INITIAL_FILE_RENAME_INFORMATION):
    @property
    def filename(self):
        filename_addr = ctypes.addressof(self) + type(self).FileName.offset
        if getattr(self, "_target", None) is not None: #remote ctypes :D -> TRICKS OF THE YEAR
            raw_data = self._target.read_memory(filename_addr, self.FileNameLength)
            return raw_data.decode("utf16")
        size = int(self.FileNameLength / 2)
        return (ctypes.c_wchar * size).from_address(filename_addr)[:]

FILE_RENAME_INFORMATION = _FILE_RENAME_INFORMATION
PFILE_RENAME_INFORMATION = POINTER(_FILE_RENAME_INFORMATION)
PolicyAuditLogInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyAuditLogInformation", 0x1)
PolicyAuditEventsInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyAuditEventsInformation", 0x2)
PolicyPrimaryDomainInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyPrimaryDomainInformation", 0x3)
PolicyPdAccountInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyPdAccountInformation", 0x4)
PolicyAccountDomainInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyAccountDomainInformation", 0x5)
PolicyLsaServerRoleInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyLsaServerRoleInformation", 0x6)
PolicyReplicaSourceInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyReplicaSourceInformation", 0x7)
PolicyDefaultQuotaInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyDefaultQuotaInformation", 0x8)
PolicyModificationInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyModificationInformation", 0x9)
PolicyAuditFullSetInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyAuditFullSetInformation", 0xa)
PolicyAuditFullQueryInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyAuditFullQueryInformation", 0xb)
PolicyDnsDomainInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyDnsDomainInformation", 0xc)
PolicyDnsDomainInformationInt = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyDnsDomainInformationInt", 0xd)
PolicyLocalAccountDomainInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyLocalAccountDomainInformation", 0xe)
PolicyMachineAccountInformation = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyMachineAccountInformation", 0xf)
PolicyLastEntry = EnumValue("_POLICY_INFORMATION_CLASS", "PolicyLastEntry", 0x10)
class _POLICY_INFORMATION_CLASS(EnumType):
    values = [PolicyAuditLogInformation, PolicyAuditEventsInformation, PolicyPrimaryDomainInformation, PolicyPdAccountInformation, PolicyAccountDomainInformation, PolicyLsaServerRoleInformation, PolicyReplicaSourceInformation, PolicyDefaultQuotaInformation, PolicyModificationInformation, PolicyAuditFullSetInformation, PolicyAuditFullQueryInformation, PolicyDnsDomainInformation, PolicyDnsDomainInformationInt, PolicyLocalAccountDomainInformation, PolicyMachineAccountInformation, PolicyLastEntry]
    mapper = FlagMapper(*values)
POLICY_INFORMATION_CLASS = _POLICY_INFORMATION_CLASS
PPOLICY_INFORMATION_CLASS = POINTER(_POLICY_INFORMATION_CLASS)


PolicyServerRoleBackup = EnumValue("_POLICY_LSA_SERVER_ROLE", "PolicyServerRoleBackup", 0x0)
PolicyServerRolePrimary = EnumValue("_POLICY_LSA_SERVER_ROLE", "PolicyServerRolePrimary", 0x1)
class _POLICY_LSA_SERVER_ROLE(EnumType):
    values = [PolicyServerRoleBackup, PolicyServerRolePrimary]
    mapper = FlagMapper(*values)
POLICY_LSA_SERVER_ROLE = _POLICY_LSA_SERVER_ROLE
PPOLICY_LSA_SERVER_ROLE = POINTER(_POLICY_LSA_SERVER_ROLE)


class _LSA_OBJECT_ATTRIBUTES(Structure):
    _fields_ = [
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", PLSA_UNICODE_STRING),
        ("Attributes", ULONG),
        ("SecurityDescriptor", PVOID),
        ("SecurityQualityOfService", PVOID),
    ]
PLSA_OBJECT_ATTRIBUTES = POINTER(_LSA_OBJECT_ATTRIBUTES)
LSA_OBJECT_ATTRIBUTES = _LSA_OBJECT_ATTRIBUTES

class _POLICY_PRIMARY_DOMAIN_INFO(Structure):
    _fields_ = [
        ("Name", LSA_UNICODE_STRING),
        ("Sid", PSID),
    ]
PPOLICY_PRIMARY_DOMAIN_INFO = POINTER(_POLICY_PRIMARY_DOMAIN_INFO)
POLICY_PRIMARY_DOMAIN_INFO = _POLICY_PRIMARY_DOMAIN_INFO

class _POLICY_LSA_SERVER_ROLE_INFO(Structure):
    _fields_ = [
        ("LsaServerRole", POLICY_LSA_SERVER_ROLE),
    ]
POLICY_LSA_SERVER_ROLE_INFO = _POLICY_LSA_SERVER_ROLE_INFO
PPOLICY_LSA_SERVER_ROLE_INFO = POINTER(_POLICY_LSA_SERVER_ROLE_INFO)

class _POLICY_ACCOUNT_DOMAIN_INFO(Structure):
    _fields_ = [
        ("DomainName", LSA_UNICODE_STRING),
        ("DomainSid", PSID),
    ]
POLICY_ACCOUNT_DOMAIN_INFO = _POLICY_ACCOUNT_DOMAIN_INFO
PPOLICY_ACCOUNT_DOMAIN_INFO = POINTER(_POLICY_ACCOUNT_DOMAIN_INFO)

class _POLICY_PRIMARY_DOMAIN_INFO(Structure):
    _fields_ = [
        ("Name", LSA_UNICODE_STRING),
        ("Sid", PSID),
    ]
PPOLICY_PRIMARY_DOMAIN_INFO = POINTER(_POLICY_PRIMARY_DOMAIN_INFO)
POLICY_PRIMARY_DOMAIN_INFO = _POLICY_PRIMARY_DOMAIN_INFO

class _LSA_TRANSLATED_SID(Structure):
    _fields_ = [
        ("Use", SID_NAME_USE),
        ("RelativeId", ULONG),
        ("DomainIndex", LONG),
    ]
LSA_TRANSLATED_SID = _LSA_TRANSLATED_SID
PLSA_TRANSLATED_SID = POINTER(_LSA_TRANSLATED_SID)

class _LSA_TRANSLATED_SID2(Structure):
    _fields_ = [
        ("Use", SID_NAME_USE),
        ("Sid", PSID),
        ("DomainIndex", LONG),
        ("Flags", ULONG),
    ]
PLSA_TRANSLATED_SID2 = POINTER(_LSA_TRANSLATED_SID2)
LSA_TRANSLATED_SID2 = _LSA_TRANSLATED_SID2

class _LSA_TRANSLATED_NAME(Structure):
    _fields_ = [
        ("Use", SID_NAME_USE),
        ("Name", LSA_UNICODE_STRING),
        ("DomainIndex", LONG),
    ]
LSA_TRANSLATED_NAME = _LSA_TRANSLATED_NAME
PLSA_TRANSLATED_NAME = POINTER(_LSA_TRANSLATED_NAME)

class _LSA_TRUST_INFORMATION(Structure):
    _fields_ = [
        ("Name", LSA_UNICODE_STRING),
        ("Sid", PSID),
    ]
LSA_TRUST_INFORMATION = _LSA_TRUST_INFORMATION
PLSA_TRUST_INFORMATION = POINTER(_LSA_TRUST_INFORMATION)

class _LSA_REFERENCED_DOMAIN_LIST(Structure):
    _fields_ = [
        ("Entries", ULONG),
        ("Domains", PLSA_TRUST_INFORMATION),
    ]
LSA_REFERENCED_DOMAIN_LIST = _LSA_REFERENCED_DOMAIN_LIST
PLSA_REFERENCED_DOMAIN_LIST = POINTER(_LSA_REFERENCED_DOMAIN_LIST)

class _LOCALGROUP_INFO_0(Structure):
    _fields_ = [
        ("lgrpi0_name", LPWSTR),
    ]
LPLOCALGROUP_INFO_0 = POINTER(_LOCALGROUP_INFO_0)
LOCALGROUP_INFO_0 = _LOCALGROUP_INFO_0
PLOCALGROUP_INFO_0 = POINTER(_LOCALGROUP_INFO_0)

class _LOCALGROUP_INFO_1(Structure):
    _fields_ = [
        ("lgrpi1_name", LPWSTR),
        ("lgrpi1_comment", LPWSTR),
    ]
LPLOCALGROUP_INFO_1 = POINTER(_LOCALGROUP_INFO_1)
LOCALGROUP_INFO_1 = _LOCALGROUP_INFO_1
PLOCALGROUP_INFO_1 = POINTER(_LOCALGROUP_INFO_1)

class _LOCALGROUP_MEMBERS_INFO_0(Structure):
    _fields_ = [
        ("lgrmi0_sid", PSID),
    ]
LPLOCALGROUP_MEMBERS_INFO_0 = POINTER(_LOCALGROUP_MEMBERS_INFO_0)
LOCALGROUP_MEMBERS_INFO_0 = _LOCALGROUP_MEMBERS_INFO_0
PLOCALGROUP_MEMBERS_INFO_0 = POINTER(_LOCALGROUP_MEMBERS_INFO_0)

class _LOCALGROUP_MEMBERS_INFO_1(Structure):
    _fields_ = [
        ("lgrmi1_sid", PSID),
        ("lgrmi1_sidusage", SID_NAME_USE),
        ("lgrmi1_name", LPWSTR),
    ]
LPLOCALGROUP_MEMBERS_INFO_1 = POINTER(_LOCALGROUP_MEMBERS_INFO_1)
LOCALGROUP_MEMBERS_INFO_1 = _LOCALGROUP_MEMBERS_INFO_1
PLOCALGROUP_MEMBERS_INFO_1 = POINTER(_LOCALGROUP_MEMBERS_INFO_1)

class _LOCALGROUP_MEMBERS_INFO_2(Structure):
    _fields_ = [
        ("lgrmi2_sid", PSID),
        ("lgrmi2_sidusage", SID_NAME_USE),
        ("lgrmi2_domainandname", LPWSTR),
    ]
LPLOCALGROUP_MEMBERS_INFO_2 = POINTER(_LOCALGROUP_MEMBERS_INFO_2)
PLOCALGROUP_MEMBERS_INFO_2 = POINTER(_LOCALGROUP_MEMBERS_INFO_2)
LOCALGROUP_MEMBERS_INFO_2 = _LOCALGROUP_MEMBERS_INFO_2

class _LOCALGROUP_MEMBERS_INFO_3(Structure):
    _fields_ = [
        ("lgrmi3_domainandname", LPWSTR),
    ]
LPLOCALGROUP_MEMBERS_INFO_3 = POINTER(_LOCALGROUP_MEMBERS_INFO_3)
PLOCALGROUP_MEMBERS_INFO_3 = POINTER(_LOCALGROUP_MEMBERS_INFO_3)
LOCALGROUP_MEMBERS_INFO_3 = _LOCALGROUP_MEMBERS_INFO_3

class _NET_DISPLAY_USER(Structure):
    _fields_ = [
        ("usri1_name", LPWSTR),
        ("usri1_comment", LPWSTR),
        ("usri1_flags", DWORD),
        ("usri1_full_name", LPWSTR),
        ("usri1_user_id", DWORD),
        ("usri1_next_index", DWORD),
    ]
NET_DISPLAY_USER = _NET_DISPLAY_USER
PNET_DISPLAY_USER = POINTER(_NET_DISPLAY_USER)

class _NET_DISPLAY_MACHINE(Structure):
    _fields_ = [
        ("usri2_name", LPWSTR),
        ("usri2_comment", LPWSTR),
        ("usri2_flags", DWORD),
        ("usri2_user_id", DWORD),
        ("usri2_next_index", DWORD),
    ]
PNET_DISPLAY_MACHINE = POINTER(_NET_DISPLAY_MACHINE)
NET_DISPLAY_MACHINE = _NET_DISPLAY_MACHINE

class _NET_DISPLAY_GROUP(Structure):
    _fields_ = [
        ("grpi3_name", LPWSTR),
        ("grpi3_comment", LPWSTR),
        ("grpi3_group_id", DWORD),
        ("grpi3_attributes", DWORD),
        ("grpi3_next_index", DWORD),
    ]
PNET_DISPLAY_GROUP = POINTER(_NET_DISPLAY_GROUP)
NET_DISPLAY_GROUP = _NET_DISPLAY_GROUP

class _USER_INFO_0(Structure):
    _fields_ = [
        ("usri0_name", LPWSTR),
    ]
PUSER_INFO_0 = POINTER(_USER_INFO_0)
LPUSER_INFO_0 = POINTER(_USER_INFO_0)
USER_INFO_0 = _USER_INFO_0

class _USER_INFO_1(Structure):
    _fields_ = [
        ("usri1_name", LPWSTR),
        ("usri1_password", LPWSTR),
        ("usri1_password_age", DWORD),
        ("usri1_priv", DWORD),
        ("usri1_home_dir", LPWSTR),
        ("usri1_comment", LPWSTR),
        ("usri1_flags", DWORD),
        ("usri1_script_path", LPWSTR),
    ]
PUSER_INFO_1 = POINTER(_USER_INFO_1)
LPUSER_INFO_1 = POINTER(_USER_INFO_1)
USER_INFO_1 = _USER_INFO_1

class _USER_INFO_2(Structure):
    _fields_ = [
        ("usri2_name", LPWSTR),
        ("usri2_password", LPWSTR),
        ("usri2_password_age", DWORD),
        ("usri2_priv", DWORD),
        ("usri2_home_dir", LPWSTR),
        ("usri2_comment", LPWSTR),
        ("usri2_flags", DWORD),
        ("usri2_script_path", LPWSTR),
        ("usri2_auth_flags", DWORD),
        ("usri2_full_name", LPWSTR),
        ("usri2_usr_comment", LPWSTR),
        ("usri2_parms", LPWSTR),
        ("usri2_workstations", LPWSTR),
        ("usri2_last_logon", DWORD),
        ("usri2_last_logoff", DWORD),
        ("usri2_acct_expires", DWORD),
        ("usri2_max_storage", DWORD),
        ("usri2_units_per_week", DWORD),
        ("usri2_logon_hours", PBYTE),
        ("usri2_bad_pw_count", DWORD),
        ("usri2_num_logons", DWORD),
        ("usri2_logon_server", LPWSTR),
        ("usri2_country_code", DWORD),
        ("usri2_code_page", DWORD),
    ]
PUSER_INFO_2 = POINTER(_USER_INFO_2)
USER_INFO_2 = _USER_INFO_2
LPUSER_INFO_2 = POINTER(_USER_INFO_2)

class _USER_INFO_3(Structure):
    _fields_ = [
        ("usri3_name", LPWSTR),
        ("usri3_password", LPWSTR),
        ("usri3_password_age", DWORD),
        ("usri3_priv", DWORD),
        ("usri3_home_dir", LPWSTR),
        ("usri3_comment", LPWSTR),
        ("usri3_flags", DWORD),
        ("usri3_script_path", LPWSTR),
        ("usri3_auth_flags", DWORD),
        ("usri3_full_name", LPWSTR),
        ("usri3_usr_comment", LPWSTR),
        ("usri3_parms", LPWSTR),
        ("usri3_workstations", LPWSTR),
        ("usri3_last_logon", DWORD),
        ("usri3_last_logoff", DWORD),
        ("usri3_acct_expires", DWORD),
        ("usri3_max_storage", DWORD),
        ("usri3_units_per_week", DWORD),
        ("usri3_logon_hours", PBYTE),
        ("usri3_bad_pw_count", DWORD),
        ("usri3_num_logons", DWORD),
        ("usri3_logon_server", LPWSTR),
        ("usri3_country_code", DWORD),
        ("usri3_code_page", DWORD),
        ("usri3_user_id", DWORD),
        ("usri3_primary_group_id", DWORD),
        ("usri3_profile", LPWSTR),
        ("usri3_home_dir_drive", LPWSTR),
        ("usri3_password_expired", DWORD),
    ]
PUSER_INFO_3 = POINTER(_USER_INFO_3)
USER_INFO_3 = _USER_INFO_3
LPUSER_INFO_3 = POINTER(_USER_INFO_3)

class _USER_INFO_10(Structure):
    _fields_ = [
        ("usri10_name", LPWSTR),
        ("usri10_comment", LPWSTR),
        ("usri10_usr_comment", LPWSTR),
        ("usri10_full_name", LPWSTR),
    ]
USER_INFO_10 = _USER_INFO_10
PUSER_INFO_10 = POINTER(_USER_INFO_10)
LPUSER_INFO_10 = POINTER(_USER_INFO_10)

class _USER_INFO_11(Structure):
    _fields_ = [
        ("usri11_name", LPWSTR),
        ("usri11_comment", LPWSTR),
        ("usri11_usr_comment", LPWSTR),
        ("usri11_full_name", LPWSTR),
        ("usri11_priv", DWORD),
        ("usri11_auth_flags", DWORD),
        ("usri11_password_age", DWORD),
        ("usri11_home_dir", LPWSTR),
        ("usri11_parms", LPWSTR),
        ("usri11_last_logon", DWORD),
        ("usri11_last_logoff", DWORD),
        ("usri11_bad_pw_count", DWORD),
        ("usri11_num_logons", DWORD),
        ("usri11_logon_server", LPWSTR),
        ("usri11_country_code", DWORD),
        ("usri11_workstations", LPWSTR),
        ("usri11_max_storage", DWORD),
        ("usri11_units_per_week", DWORD),
        ("usri11_logon_hours", PBYTE),
        ("usri11_code_page", DWORD),
    ]
PUSER_INFO_11 = POINTER(_USER_INFO_11)
USER_INFO_11 = _USER_INFO_11
LPUSER_INFO_11 = POINTER(_USER_INFO_11)

class _USER_INFO_20(Structure):
    _fields_ = [
        ("usri20_name", LPWSTR),
        ("usri20_full_name", LPWSTR),
        ("usri20_comment", LPWSTR),
        ("usri20_flags", DWORD),
        ("usri20_user_id", DWORD),
    ]
PUSER_INFO_20 = POINTER(_USER_INFO_20)
USER_INFO_20 = _USER_INFO_20
LPUSER_INFO_20 = POINTER(_USER_INFO_20)

class _USER_INFO_23(Structure):
    _fields_ = [
        ("usri23_name", LPWSTR),
        ("usri23_full_name", LPWSTR),
        ("usri23_comment", LPWSTR),
        ("usri23_flags", DWORD),
        ("usri23_user_sid", PSID),
    ]
USER_INFO_23 = _USER_INFO_23
PUSER_INFO_23 = POINTER(_USER_INFO_23)
LPUSER_INFO_23 = POINTER(_USER_INFO_23)

class _GROUP_INFO_0(Structure):
    _fields_ = [
        ("grpi0_name", LPWSTR),
    ]
PGROUP_INFO_0 = POINTER(_GROUP_INFO_0)
GROUP_INFO_0 = _GROUP_INFO_0
LPGROUP_INFO_0 = POINTER(_GROUP_INFO_0)

class _GROUP_INFO_1(Structure):
    _fields_ = [
        ("grpi1_name", LPWSTR),
        ("grpi1_comment", LPWSTR),
    ]
GROUP_INFO_1 = _GROUP_INFO_1
PGROUP_INFO_1 = POINTER(_GROUP_INFO_1)
LPGROUP_INFO_1 = POINTER(_GROUP_INFO_1)

class _GROUP_INFO_2(Structure):
    _fields_ = [
        ("grpi2_name", LPWSTR),
        ("grpi2_comment", LPWSTR),
        ("grpi2_group_id", DWORD),
        ("grpi2_attributes", DWORD),
    ]
PGROUP_INFO_2 = POINTER(_GROUP_INFO_2)
GROUP_INFO_2 = _GROUP_INFO_2

class _GROUP_INFO_3(Structure):
    _fields_ = [
        ("grpi3_name", LPWSTR),
        ("grpi3_comment", LPWSTR),
        ("grpi3_group_sid", PSID),
        ("grpi3_attributes", DWORD),
    ]
GROUP_INFO_3 = _GROUP_INFO_3
PGROUP_INFO_3 = POINTER(_GROUP_INFO_3)

class _GROUP_USERS_INFO_0(Structure):
    _fields_ = [
        ("grui0_name", LPWSTR),
    ]
GROUP_USERS_INFO_0 = _GROUP_USERS_INFO_0
PGROUP_USERS_INFO_0 = POINTER(_GROUP_USERS_INFO_0)
LPGROUP_USERS_INFO_0 = POINTER(_GROUP_USERS_INFO_0)

class _GROUP_USERS_INFO_1(Structure):
    _fields_ = [
        ("grui1_name", LPWSTR),
        ("grui1_attributes", DWORD),
    ]
PGROUP_USERS_INFO_1 = POINTER(_GROUP_USERS_INFO_1)
GROUP_USERS_INFO_1 = _GROUP_USERS_INFO_1
LPGROUP_USERS_INFO_1 = POINTER(_GROUP_USERS_INFO_1)

AclRevisionInformation = EnumValue("_ACL_INFORMATION_CLASS", "AclRevisionInformation", 0x1)
AclSizeInformation = EnumValue("_ACL_INFORMATION_CLASS", "AclSizeInformation", 0x2)
class _ACL_INFORMATION_CLASS(EnumType):
    values = [AclRevisionInformation, AclSizeInformation]
    mapper = FlagMapper(*values)
ACL_INFORMATION_CLASS = _ACL_INFORMATION_CLASS


NO_MULTIPLE_TRUSTEE = EnumValue("_MULTIPLE_TRUSTEE_OPERATION", "NO_MULTIPLE_TRUSTEE", 0x0)
TRUSTEE_IS_IMPERSONATE = EnumValue("_MULTIPLE_TRUSTEE_OPERATION", "TRUSTEE_IS_IMPERSONATE", 0x1)
class _MULTIPLE_TRUSTEE_OPERATION(EnumType):
    values = [NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_IMPERSONATE]
    mapper = FlagMapper(*values)
MULTIPLE_TRUSTEE_OPERATION = _MULTIPLE_TRUSTEE_OPERATION


TRUSTEE_IS_SID = EnumValue("_TRUSTEE_FORM", "TRUSTEE_IS_SID", 0x0)
TRUSTEE_IS_NAME = EnumValue("_TRUSTEE_FORM", "TRUSTEE_IS_NAME", 0x1)
TRUSTEE_BAD_FORM = EnumValue("_TRUSTEE_FORM", "TRUSTEE_BAD_FORM", 0x2)
TRUSTEE_IS_OBJECTS_AND_SID = EnumValue("_TRUSTEE_FORM", "TRUSTEE_IS_OBJECTS_AND_SID", 0x3)
TRUSTEE_IS_OBJECTS_AND_NAME = EnumValue("_TRUSTEE_FORM", "TRUSTEE_IS_OBJECTS_AND_NAME", 0x4)
class _TRUSTEE_FORM(EnumType):
    values = [TRUSTEE_IS_SID, TRUSTEE_IS_NAME, TRUSTEE_BAD_FORM, TRUSTEE_IS_OBJECTS_AND_SID, TRUSTEE_IS_OBJECTS_AND_NAME]
    mapper = FlagMapper(*values)
TRUSTEE_FORM = _TRUSTEE_FORM


TRUSTEE_IS_UNKNOWN = EnumValue("_TRUSTEE_TYPE", "TRUSTEE_IS_UNKNOWN", 0x0)
TRUSTEE_IS_USER = EnumValue("_TRUSTEE_TYPE", "TRUSTEE_IS_USER", 0x1)
TRUSTEE_IS_GROUP = EnumValue("_TRUSTEE_TYPE", "TRUSTEE_IS_GROUP", 0x2)
TRUSTEE_IS_DOMAIN = EnumValue("_TRUSTEE_TYPE", "TRUSTEE_IS_DOMAIN", 0x3)
TRUSTEE_IS_ALIAS = EnumValue("_TRUSTEE_TYPE", "TRUSTEE_IS_ALIAS", 0x4)
TRUSTEE_IS_WELL_KNOWN_GROUP = EnumValue("_TRUSTEE_TYPE", "TRUSTEE_IS_WELL_KNOWN_GROUP", 0x5)
TRUSTEE_IS_DELETED = EnumValue("_TRUSTEE_TYPE", "TRUSTEE_IS_DELETED", 0x6)
TRUSTEE_IS_INVALID = EnumValue("_TRUSTEE_TYPE", "TRUSTEE_IS_INVALID", 0x7)
TRUSTEE_IS_COMPUTER = EnumValue("_TRUSTEE_TYPE", "TRUSTEE_IS_COMPUTER", 0x8)
class _TRUSTEE_TYPE(EnumType):
    values = [TRUSTEE_IS_UNKNOWN, TRUSTEE_IS_USER, TRUSTEE_IS_GROUP, TRUSTEE_IS_DOMAIN, TRUSTEE_IS_ALIAS, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_IS_DELETED, TRUSTEE_IS_INVALID, TRUSTEE_IS_COMPUTER]
    mapper = FlagMapper(*values)
TRUSTEE_TYPE = _TRUSTEE_TYPE


NOT_USED_ACCESS = EnumValue("_ACCESS_MODE", "NOT_USED_ACCESS", 0x0)
GRANT_ACCESS = EnumValue("_ACCESS_MODE", "GRANT_ACCESS", 0x1)
SET_ACCESS = EnumValue("_ACCESS_MODE", "SET_ACCESS", 0x2)
DENY_ACCESS = EnumValue("_ACCESS_MODE", "DENY_ACCESS", 0x3)
REVOKE_ACCESS = EnumValue("_ACCESS_MODE", "REVOKE_ACCESS", 0x4)
SET_AUDIT_SUCCESS = EnumValue("_ACCESS_MODE", "SET_AUDIT_SUCCESS", 0x5)
SET_AUDIT_FAILURE = EnumValue("_ACCESS_MODE", "SET_AUDIT_FAILURE", 0x6)
class _ACCESS_MODE(EnumType):
    values = [NOT_USED_ACCESS, GRANT_ACCESS, SET_ACCESS, DENY_ACCESS, REVOKE_ACCESS, SET_AUDIT_SUCCESS, SET_AUDIT_FAILURE]
    mapper = FlagMapper(*values)
ACCESS_MODE = _ACCESS_MODE


class _ACL(Structure):
    _fields_ = [
        ("AclRevision", BYTE),
        ("Sbz1", BYTE),
        ("AclSize", WORD),
        ("AceCount", WORD),
        ("Sbz2", WORD),
    ]
PACL = POINTER(_ACL)
ACL = _ACL

class _ACL_REVISION_INFORMATION(Structure):
    _fields_ = [
        ("AclRevision", DWORD),
    ]
PACL_REVISION_INFORMATION = POINTER(_ACL_REVISION_INFORMATION)
ACL_REVISION_INFORMATION = _ACL_REVISION_INFORMATION

class _ACL_SIZE_INFORMATION(Structure):
    _fields_ = [
        ("AceCount", DWORD),
        ("AclBytesInUse", DWORD),
        ("AclBytesFree", DWORD),
    ]
PACL_SIZE_INFORMATION = POINTER(_ACL_SIZE_INFORMATION)
ACL_SIZE_INFORMATION = _ACL_SIZE_INFORMATION

class _ACE_HEADER(Structure):
    _fields_ = [
        ("AceType", BYTE),
        ("AceFlags", BYTE),
        ("AceSize", WORD),
    ]
PACE_HEADER = POINTER(_ACE_HEADER)
ACE_HEADER = _ACE_HEADER

class _ACCESS_ALLOWED_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
PACCESS_ALLOWED_ACE = POINTER(_ACCESS_ALLOWED_ACE)
ACCESS_ALLOWED_ACE = _ACCESS_ALLOWED_ACE

class _ACCESS_ALLOWED_CALLBACK_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
PACCESS_ALLOWED_CALLBACK_ACE = POINTER(_ACCESS_ALLOWED_CALLBACK_ACE)
ACCESS_ALLOWED_CALLBACK_ACE = _ACCESS_ALLOWED_CALLBACK_ACE

class _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
PACCESS_ALLOWED_CALLBACK_OBJECT_ACE = POINTER(_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE)
ACCESS_ALLOWED_CALLBACK_OBJECT_ACE = _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE

class _ACCESS_DENIED_CALLBACK_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
ACCESS_DENIED_CALLBACK_OBJECT_ACE = _ACCESS_DENIED_CALLBACK_OBJECT_ACE
PACCESS_DENIED_CALLBACK_OBJECT_ACE = POINTER(_ACCESS_DENIED_CALLBACK_OBJECT_ACE)

class _ACCESS_ALLOWED_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
PACCESS_ALLOWED_OBJECT_ACE = POINTER(_ACCESS_ALLOWED_OBJECT_ACE)
ACCESS_ALLOWED_OBJECT_ACE = _ACCESS_ALLOWED_OBJECT_ACE

class _ACCESS_DENIED_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
ACCESS_DENIED_ACE = _ACCESS_DENIED_ACE
PACCESS_DENIED_ACE = POINTER(_ACCESS_DENIED_ACE)

class _ACCESS_DENIED_CALLBACK_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
ACCESS_DENIED_CALLBACK_ACE = _ACCESS_DENIED_CALLBACK_ACE
PACCESS_DENIED_CALLBACK_ACE = POINTER(_ACCESS_DENIED_CALLBACK_ACE)

class _ACCESS_DENIED_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
ACCESS_DENIED_OBJECT_ACE = _ACCESS_DENIED_OBJECT_ACE
PACCESS_DENIED_OBJECT_ACE = POINTER(_ACCESS_DENIED_OBJECT_ACE)

class _SYSTEM_MANDATORY_LABEL_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
SYSTEM_MANDATORY_LABEL_ACE = _SYSTEM_MANDATORY_LABEL_ACE
PSYSTEM_MANDATORY_LABEL_ACE = POINTER(_SYSTEM_MANDATORY_LABEL_ACE)

class _SYSTEM_AUDIT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
SYSTEM_AUDIT_ACE = _SYSTEM_AUDIT_ACE

class _SYSTEM_ALARM_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
SYSTEM_ALARM_ACE = _SYSTEM_ALARM_ACE

class _SYSTEM_RESOURCE_ATTRIBUTE_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
PSYSTEM_RESOURCE_ATTRIBUTE_ACE = POINTER(_SYSTEM_RESOURCE_ATTRIBUTE_ACE)
SYSTEM_RESOURCE_ATTRIBUTE_ACE = _SYSTEM_RESOURCE_ATTRIBUTE_ACE

class _SYSTEM_SCOPED_POLICY_ID_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
SYSTEM_SCOPED_POLICY_ID_ACE = _SYSTEM_SCOPED_POLICY_ID_ACE
PSYSTEM_SCOPED_POLICY_ID_ACE = POINTER(_SYSTEM_SCOPED_POLICY_ID_ACE)

class _SYSTEM_PROCESS_TRUST_LABEL_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
PSYSTEM_PROCESS_TRUST_LABEL_ACE = POINTER(_SYSTEM_PROCESS_TRUST_LABEL_ACE)
SYSTEM_PROCESS_TRUST_LABEL_ACE = _SYSTEM_PROCESS_TRUST_LABEL_ACE

class _SYSTEM_AUDIT_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
SYSTEM_AUDIT_OBJECT_ACE = _SYSTEM_AUDIT_OBJECT_ACE
PSYSTEM_AUDIT_OBJECT_ACE = POINTER(_SYSTEM_AUDIT_OBJECT_ACE)

class _SYSTEM_ALARM_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
SYSTEM_ALARM_OBJECT_ACE = _SYSTEM_ALARM_OBJECT_ACE
PSYSTEM_ALARM_OBJECT_ACE = POINTER(_SYSTEM_ALARM_OBJECT_ACE)

class _SYSTEM_AUDIT_CALLBACK_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
PSYSTEM_AUDIT_CALLBACK_ACE = POINTER(_SYSTEM_AUDIT_CALLBACK_ACE)
SYSTEM_AUDIT_CALLBACK_ACE = _SYSTEM_AUDIT_CALLBACK_ACE

class _SYSTEM_ALARM_CALLBACK_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
SYSTEM_ALARM_CALLBACK_ACE = _SYSTEM_ALARM_CALLBACK_ACE
PSYSTEM_ALARM_CALLBACK_ACE = POINTER(_SYSTEM_ALARM_CALLBACK_ACE)

class _SYSTEM_AUDIT_CALLBACK_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE = POINTER(_SYSTEM_AUDIT_CALLBACK_OBJECT_ACE)
SYSTEM_AUDIT_CALLBACK_OBJECT_ACE = _SYSTEM_AUDIT_CALLBACK_OBJECT_ACE

class _SYSTEM_ALARM_CALLBACK_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
PSYSTEM_ALARM_CALLBACK_OBJECT_ACE = POINTER(_SYSTEM_ALARM_CALLBACK_OBJECT_ACE)
SYSTEM_ALARM_CALLBACK_OBJECT_ACE = _SYSTEM_ALARM_CALLBACK_OBJECT_ACE

class _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1_UNION(Union):
    _fields_ = [
        ("pInt64", DWORD * (ANYSIZE_ARRAY)),
        ("pUint64", DWORD * (ANYSIZE_ARRAY)),
        ("ppString", DWORD * (ANYSIZE_ARRAY)),
        ("pFqbn", DWORD * (ANYSIZE_ARRAY)),
        ("pOctetString", DWORD * (ANYSIZE_ARRAY)),
    ]
CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1_UNION = _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1_UNION

class _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1(Structure):
    _fields_ = [
        ("Name", DWORD),
        ("ValueType", WORD),
        ("Reserved", WORD),
        ("Flags", DWORD),
        ("ValueCount", DWORD),
        ("Values", CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1_UNION),
    ]
PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 = POINTER(_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)
CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 = _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1

class _CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE(Structure):
    _fields_ = [
        ("Version", DWORD64),
        ("Name", PWSTR),
    ]
PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE = POINTER(_CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE)
CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE = _CLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE

class _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE(Structure):
    _fields_ = [
        ("pValue", PVOID),
        ("ValueLength", DWORD),
    ]
PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE = POINTER(_CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)
CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE = _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE

class _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE(Structure):
    _fields_ = [
        ("Length", DWORD),
        ("OctetString", BYTE * (ANYSIZE_ARRAY)),
    ]
PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE = POINTER(_CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE)
CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE = _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE

class _CLAIM_SECURITY_ATTRIBUTE_V1_UNION(Union):
    _fields_ = [
        ("pInt64", PLONG64),
        ("pUint64", PDWORD64),
        ("ppString", POINTER(PWSTR)),
        ("pFqbn", PCLAIM_SECURITY_ATTRIBUTE_FQBN_VALUE),
        ("pOctetString", PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE),
    ]
CLAIM_SECURITY_ATTRIBUTE_V1_UNION = _CLAIM_SECURITY_ATTRIBUTE_V1_UNION

class _CLAIM_SECURITY_ATTRIBUTE_V1(Structure):
    _fields_ = [
        ("Name", PWSTR),
        ("ValueType", WORD),
        ("Reserved", WORD),
        ("Flags", DWORD),
        ("ValueCount", DWORD),
        ("Values", CLAIM_SECURITY_ATTRIBUTE_V1_UNION),
    ]
CLAIM_SECURITY_ATTRIBUTE_V1 = _CLAIM_SECURITY_ATTRIBUTE_V1
PCLAIM_SECURITY_ATTRIBUTE_V1 = POINTER(_CLAIM_SECURITY_ATTRIBUTE_V1)

class _CLAIM_SECURITY_ATTRIBUTES_INFORMATION_UNION(Union):
    _fields_ = [
        ("pAttributeV1", PCLAIM_SECURITY_ATTRIBUTE_V1),
    ]
CLAIM_SECURITY_ATTRIBUTES_INFORMATION_UNION = _CLAIM_SECURITY_ATTRIBUTES_INFORMATION_UNION

class _CLAIM_SECURITY_ATTRIBUTES_INFORMATION(Structure):
    _fields_ = [
        ("Version", WORD),
        ("Reserved", WORD),
        ("AttributeCount", DWORD),
        ("Attribute", CLAIM_SECURITY_ATTRIBUTES_INFORMATION_UNION),
    ]
CLAIM_SECURITY_ATTRIBUTES_INFORMATION = _CLAIM_SECURITY_ATTRIBUTES_INFORMATION
PCLAIM_SECURITY_ATTRIBUTES_INFORMATION = POINTER(_CLAIM_SECURITY_ATTRIBUTES_INFORMATION)

class _SECURITY_DESCRIPTOR(Structure):
    _fields_ = [
        ("Revision", BYTE),
        ("Sbz1", BYTE),
        ("Control", SECURITY_DESCRIPTOR_CONTROL),
        ("Owner", PSID),
        ("Group", PSID),
        ("Sacl", PACL),
        ("Dacl", PACL),
    ]
PISECURITY_DESCRIPTOR = POINTER(_SECURITY_DESCRIPTOR)
SECURITY_DESCRIPTOR = _SECURITY_DESCRIPTOR

class _GENERIC_MAPPING(Structure):
    _fields_ = [
        ("GenericRead", ACCESS_MASK),
        ("GenericWrite", ACCESS_MASK),
        ("GenericExecute", ACCESS_MASK),
        ("GenericAll", ACCESS_MASK),
    ]
PGENERIC_MAPPING = POINTER(_GENERIC_MAPPING)
GENERIC_MAPPING = _GENERIC_MAPPING

class _PRIVILEGE_SET(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Control", DWORD),
        ("Privilege", LUID_AND_ATTRIBUTES * (ANYSIZE_ARRAY)),
    ]
PRIVILEGE_SET = _PRIVILEGE_SET
PPRIVILEGE_SET = POINTER(_PRIVILEGE_SET)

class _OBJECTS_AND_NAME_A(Structure):
    _fields_ = [
        ("ObjectsPresent", DWORD),
        ("ObjectType", SE_OBJECT_TYPE),
        ("ObjectTypeName", LPSTR),
        ("InheritedObjectTypeName", LPSTR),
        ("ptstrName", LPSTR),
    ]
OBJECTS_AND_NAME_A = _OBJECTS_AND_NAME_A
POBJECTS_AND_NAME_A = POINTER(_OBJECTS_AND_NAME_A)

class _OBJECTS_AND_SID(Structure):
    _fields_ = [
        ("ObjectsPresent", DWORD),
        ("ObjectTypeGuid", GUID),
        ("InheritedObjectTypeGuid", GUID),
        ("pSid", PSID),
    ]
POBJECTS_AND_SID = POINTER(_OBJECTS_AND_SID)
OBJECTS_AND_SID = _OBJECTS_AND_SID

class _ANON__TRUSTEE_A_SUB_UNION_1(Union):
    _fields_ = [
        ("ptstrName", LPSTR),
        ("pSid", PSID),
        ("pObjectsAndSid", POINTER(OBJECTS_AND_SID)),
        ("pObjectsAndName", POINTER(OBJECTS_AND_NAME_A)),
    ]

# Self referencing struct tricks
class _TRUSTEE_A(Structure): pass
PTRUSTEEA = POINTER(_TRUSTEE_A)
TRUSTEEA = _TRUSTEE_A
TRUSTEE_A = _TRUSTEE_A
PTRUSTEE_A = POINTER(_TRUSTEE_A)
_TRUSTEE_A._fields_ = [
    ("pMultipleTrustee", POINTER(_TRUSTEE_A)),
    ("MultipleTrusteeOperation", MULTIPLE_TRUSTEE_OPERATION),
    ("TrusteeForm", TRUSTEE_FORM),
    ("TrusteeType", TRUSTEE_TYPE),
    ("anon_01", _ANON__TRUSTEE_A_SUB_UNION_1),
    ("ptstrName", LPCH),
]

class _OBJECTS_AND_NAME_W(Structure):
    _fields_ = [
        ("ObjectsPresent", DWORD),
        ("ObjectType", SE_OBJECT_TYPE),
        ("ObjectTypeName", LPWSTR),
        ("InheritedObjectTypeName", LPWSTR),
        ("ptstrName", LPWSTR),
    ]
OBJECTS_AND_NAME_W = _OBJECTS_AND_NAME_W
POBJECTS_AND_NAME_W = POINTER(_OBJECTS_AND_NAME_W)

class _ANON__TRUSTEE_W_SUB_UNION_1(Union):
    _fields_ = [
        ("ptstrName", LPWSTR),
        ("pSid", PSID),
        ("pObjectsAndSid", POINTER(OBJECTS_AND_SID)),
        ("pObjectsAndName", POINTER(OBJECTS_AND_NAME_W)),
    ]

# Self referencing struct tricks
class _TRUSTEE_W(Structure): pass
PTRUSTEE_W = POINTER(_TRUSTEE_W)
TRUSTEE_W = _TRUSTEE_W
PTRUSTEEW = POINTER(_TRUSTEE_W)
TRUSTEEW = _TRUSTEE_W
_TRUSTEE_W._fields_ = [
    ("pMultipleTrustee", POINTER(_TRUSTEE_W)),
    ("MultipleTrusteeOperation", MULTIPLE_TRUSTEE_OPERATION),
    ("TrusteeForm", TRUSTEE_FORM),
    ("TrusteeType", TRUSTEE_TYPE),
    ("anon_01", _ANON__TRUSTEE_W_SUB_UNION_1),
    ("ptstrName", LPWCH),
]

class _EXPLICIT_ACCESS_W(Structure):
    _fields_ = [
        ("grfAccessPermissions", DWORD),
        ("grfAccessMode", ACCESS_MODE),
        ("grfInheritance", DWORD),
        ("Trustee", TRUSTEE_W),
    ]
EXPLICIT_ACCESSW = _EXPLICIT_ACCESS_W
PEXPLICIT_ACCESSW = POINTER(_EXPLICIT_ACCESS_W)
PEXPLICIT_ACCESS_W = POINTER(_EXPLICIT_ACCESS_W)
EXPLICIT_ACCESS_W = _EXPLICIT_ACCESS_W

ComputerNameNetBIOS = EnumValue("_COMPUTER_NAME_FORMAT", "ComputerNameNetBIOS", 0x0)
ComputerNameDnsHostname = EnumValue("_COMPUTER_NAME_FORMAT", "ComputerNameDnsHostname", 0x1)
ComputerNameDnsDomain = EnumValue("_COMPUTER_NAME_FORMAT", "ComputerNameDnsDomain", 0x2)
ComputerNameDnsFullyQualified = EnumValue("_COMPUTER_NAME_FORMAT", "ComputerNameDnsFullyQualified", 0x3)
ComputerNamePhysicalNetBIOS = EnumValue("_COMPUTER_NAME_FORMAT", "ComputerNamePhysicalNetBIOS", 0x4)
ComputerNamePhysicalDnsHostname = EnumValue("_COMPUTER_NAME_FORMAT", "ComputerNamePhysicalDnsHostname", 0x5)
ComputerNamePhysicalDnsDomain = EnumValue("_COMPUTER_NAME_FORMAT", "ComputerNamePhysicalDnsDomain", 0x6)
ComputerNamePhysicalDnsFullyQualified = EnumValue("_COMPUTER_NAME_FORMAT", "ComputerNamePhysicalDnsFullyQualified", 0x7)
ComputerNameMax = EnumValue("_COMPUTER_NAME_FORMAT", "ComputerNameMax", 0x8)
class _COMPUTER_NAME_FORMAT(EnumType):
    values = [ComputerNameNetBIOS, ComputerNameDnsHostname, ComputerNameDnsDomain, ComputerNameDnsFullyQualified, ComputerNamePhysicalNetBIOS, ComputerNamePhysicalDnsHostname, ComputerNamePhysicalDnsDomain, ComputerNamePhysicalDnsFullyQualified, ComputerNameMax]
    mapper = FlagMapper(*values)
COMPUTER_NAME_FORMAT = _COMPUTER_NAME_FORMAT


class _SYSTEM_PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("NextEntryOffset", ULONG),
        ("NumberOfThreads", ULONG),
        ("Reserved1", BYTE * (24)),
        ("CreateTime", LARGE_INTEGER),
        ("UserTime", LARGE_INTEGER),
        ("KernelTime", LARGE_INTEGER),
        ("ImageName", UNICODE_STRING),
        ("BasePriority", LONG),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", PVOID),
        ("HandleCount", ULONG),
        ("Reserved4", BYTE * (4)),
        ("Reserved5", PVOID * (1)),
        ("PeakVirtualSize", PVOID),
        ("VirtualSize", PVOID),
        ("PageFaultCount", PVOID),
        ("PeakWorkingSetSize", PVOID),
        ("WorkingSetSize", PVOID),
        ("QuotaPeakPagedPoolUsage", PVOID),
        ("QuotaPagedPoolUsage", PVOID),
        ("QuotaPeakNonPagedPoolUsage", PVOID),
        ("QuotaNonPagedPoolUsage", PVOID),
        ("PagefileUsage", PVOID),
        ("PeakPagefileUsage", SIZE_T),
        ("PrivatePageCount", SIZE_T),
        ("Reserved6", LARGE_INTEGER * (6)),
    ]
SYSTEM_PROCESS_INFORMATION = _SYSTEM_PROCESS_INFORMATION
PSYSTEM_PROCESS_INFORMATION = POINTER(_SYSTEM_PROCESS_INFORMATION)

class _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION(Structure):
    _fields_ = [
        ("IdleTime", LARGE_INTEGER),
        ("KernelTime", LARGE_INTEGER),
        ("UserTime", LARGE_INTEGER),
        ("Reserved1", LARGE_INTEGER * (2)),
        ("Reserved2", ULONG),
    ]
SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION = _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION = POINTER(_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)

class _SYSTEM_REGISTRY_QUOTA_INFORMATION(Structure):
    _fields_ = [
        ("RegistryQuotaAllowed", ULONG),
        ("RegistryQuotaUsed", ULONG),
        ("Reserved1", PVOID),
    ]
SYSTEM_REGISTRY_QUOTA_INFORMATION = _SYSTEM_REGISTRY_QUOTA_INFORMATION
PSYSTEM_REGISTRY_QUOTA_INFORMATION = POINTER(_SYSTEM_REGISTRY_QUOTA_INFORMATION)

class _SYSTEM_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("Reserved1", BYTE * (24)),
        ("Reserved2", PVOID * (4)),
        ("NumberOfProcessors", CHAR),
    ]
PSYSTEM_BASIC_INFORMATION = POINTER(_SYSTEM_BASIC_INFORMATION)
SYSTEM_BASIC_INFORMATION = _SYSTEM_BASIC_INFORMATION

class _TIME_ZONE_INFORMATION(Structure):
    _fields_ = [
        ("Bias", LONG),
        ("StandardName", WCHAR * (32)),
        ("StandardDate", SYSTEMTIME),
        ("StandardBias", LONG),
        ("DaylightName", WCHAR * (32)),
        ("DaylightDate", SYSTEMTIME),
        ("DaylightBias", LONG),
    ]
LPTIME_ZONE_INFORMATION = POINTER(_TIME_ZONE_INFORMATION)
PTIME_ZONE_INFORMATION = POINTER(_TIME_ZONE_INFORMATION)
TIME_ZONE_INFORMATION = _TIME_ZONE_INFORMATION

TraceGuidQueryList = EnumValue("TRACE_INFO_CLASS", "TraceGuidQueryList", 0x0)
TraceGuidQueryInfo = EnumValue("TRACE_INFO_CLASS", "TraceGuidQueryInfo", 0x1)
TraceGuidQueryProcess = EnumValue("TRACE_INFO_CLASS", "TraceGuidQueryProcess", 0x2)
TraceStackTracingInfo = EnumValue("TRACE_INFO_CLASS", "TraceStackTracingInfo", 0x3)
TraceSystemTraceEnableFlagsInfo = EnumValue("TRACE_INFO_CLASS", "TraceSystemTraceEnableFlagsInfo", 0x4)
TraceSampledProfileIntervalInfo = EnumValue("TRACE_INFO_CLASS", "TraceSampledProfileIntervalInfo", 0x5)
TraceProfileSourceConfigInfo = EnumValue("TRACE_INFO_CLASS", "TraceProfileSourceConfigInfo", 0x6)
TraceProfileSourceListInfo = EnumValue("TRACE_INFO_CLASS", "TraceProfileSourceListInfo", 0x7)
TracePmcEventListInfo = EnumValue("TRACE_INFO_CLASS", "TracePmcEventListInfo", 0x8)
TracePmcCounterListInfo = EnumValue("TRACE_INFO_CLASS", "TracePmcCounterListInfo", 0x9)
TraceSetDisallowList = EnumValue("TRACE_INFO_CLASS", "TraceSetDisallowList", 0xa)
TraceVersionInfo = EnumValue("TRACE_INFO_CLASS", "TraceVersionInfo", 0xb)
TraceGroupQueryList = EnumValue("TRACE_INFO_CLASS", "TraceGroupQueryList", 0xc)
TraceGroupQueryInfo = EnumValue("TRACE_INFO_CLASS", "TraceGroupQueryInfo", 0xd)
TraceDisallowListQuery = EnumValue("TRACE_INFO_CLASS", "TraceDisallowListQuery", 0xe)
TraceInfoReserved15 = EnumValue("TRACE_INFO_CLASS", "TraceInfoReserved15", 0xf)
TracePeriodicCaptureStateListInfo = EnumValue("TRACE_INFO_CLASS", "TracePeriodicCaptureStateListInfo", 0x10)
TracePeriodicCaptureStateInfo = EnumValue("TRACE_INFO_CLASS", "TracePeriodicCaptureStateInfo", 0x11)
TraceProviderBinaryTracking = EnumValue("TRACE_INFO_CLASS", "TraceProviderBinaryTracking", 0x12)
TraceMaxLoggersQuery = EnumValue("TRACE_INFO_CLASS", "TraceMaxLoggersQuery", 0x13)
MaxTraceSetInfoClass = EnumValue("TRACE_INFO_CLASS", "MaxTraceSetInfoClass", 0x14)
class TRACE_INFO_CLASS(EnumType):
    values = [TraceGuidQueryList, TraceGuidQueryInfo, TraceGuidQueryProcess, TraceStackTracingInfo, TraceSystemTraceEnableFlagsInfo, TraceSampledProfileIntervalInfo, TraceProfileSourceConfigInfo, TraceProfileSourceListInfo, TracePmcEventListInfo, TracePmcCounterListInfo, TraceSetDisallowList, TraceVersionInfo, TraceGroupQueryList, TraceGroupQueryInfo, TraceDisallowListQuery, TraceInfoReserved15, TracePeriodicCaptureStateListInfo, TracePeriodicCaptureStateInfo, TraceProviderBinaryTracking, TraceMaxLoggersQuery, MaxTraceSetInfoClass]
    mapper = FlagMapper(*values)
TRACE_QUERY_INFO_CLASS = TRACE_INFO_CLASS


class _TRACE_GUID_INFO(Structure):
    _fields_ = [
        ("InstanceCount", ULONG),
        ("Reserved", ULONG),
    ]
PTRACE_GUID_INFO = POINTER(_TRACE_GUID_INFO)
TRACE_GUID_INFO = _TRACE_GUID_INFO

class _TRACE_PROVIDER_INSTANCE_INFO(Structure):
    _fields_ = [
        ("NextOffset", ULONG),
        ("EnableCount", ULONG),
        ("Pid", ULONG),
        ("Flags", ULONG),
    ]
TRACE_PROVIDER_INSTANCE_INFO = _TRACE_PROVIDER_INSTANCE_INFO
PTRACE_PROVIDER_INSTANCE_INFO = POINTER(_TRACE_PROVIDER_INSTANCE_INFO)

class _TRACE_ENABLE_INFO(Structure):
    _fields_ = [
        ("IsEnabled", ULONG),
        ("Level", UCHAR),
        ("Reserved1", UCHAR),
        ("LoggerId", USHORT),
        ("EnableProperty", ULONG),
        ("Reserved2", ULONG),
        ("MatchAnyKeyword", ULONGLONG),
        ("MatchAllKeyword", ULONGLONG),
    ]
PTRACE_ENABLE_INFO = POINTER(_TRACE_ENABLE_INFO)
TRACE_ENABLE_INFO = _TRACE_ENABLE_INFO

class _ANON__ANON__WNODE_HEADER_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("Version", ULONG),
        ("Linkage", ULONG),
    ]

class _ANON__WNODE_HEADER_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("HistoricalContext", ULONG64),
        ("anon_01", _ANON__ANON__WNODE_HEADER_SUB_UNION_1_SUB_STRUCTURE_1),
    ]


class _ANON__WNODE_HEADER_SUB_UNION_2(Union):
    _fields_ = [
        ("KernelHandle", HANDLE),
        ("TimeStamp", LARGE_INTEGER),
    ]

class _WNODE_HEADER(Structure):
    _anonymous_ = ("anon_01","anon_02")
    _fields_ = [
        ("BufferSize", ULONG),
        ("ProviderId", ULONG),
        ("anon_01", _ANON__WNODE_HEADER_SUB_UNION_1),
        ("anon_02", _ANON__WNODE_HEADER_SUB_UNION_2),
        ("Guid", GUID),
        ("ClientContext", ULONG),
        ("Flags", ULONG),
    ]
PWNODE_HEADER = POINTER(_WNODE_HEADER)
WNODE_HEADER = _WNODE_HEADER

class _EVENT_TRACE_PROPERTIES(Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", ULONG),
        ("MinimumBuffers", ULONG),
        ("MaximumBuffers", ULONG),
        ("MaximumFileSize", ULONG),
        ("LogFileMode", ULONG),
        ("FlushTimer", ULONG),
        ("EnableFlags", ULONG),
        ("AgeLimit", LONG),
        ("NumberOfBuffers", ULONG),
        ("FreeBuffers", ULONG),
        ("EventsLost", ULONG),
        ("BuffersWritten", ULONG),
        ("LogBuffersLost", ULONG),
        ("RealTimeBuffersLost", ULONG),
        ("LoggerThreadId", HANDLE),
        ("LogFileNameOffset", ULONG),
        ("LoggerNameOffset", ULONG),
    ]
EVENT_TRACE_PROPERTIES = _EVENT_TRACE_PROPERTIES
PEVENT_TRACE_PROPERTIES = POINTER(_EVENT_TRACE_PROPERTIES)

class _ANON__ANON__EVENT_TRACE_HEADER_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("HeaderType", BYTE),
        ("MarkerFlags", BYTE),
    ]

class _ANON__EVENT_TRACE_HEADER_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("FieldTypeFlags", USHORT),
        ("anon_01", _ANON__ANON__EVENT_TRACE_HEADER_SUB_UNION_1_SUB_STRUCTURE_1),
    ]


class _ANON__ANON__EVENT_TRACE_HEADER_SUB_UNION_2_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("Type", BYTE),
        ("Level", BYTE),
        ("Version", USHORT),
    ]

class _ANON__EVENT_TRACE_HEADER_SUB_UNION_2(Union):
    _anonymous_ = ("Class",)
    _fields_ = [
        ("Version", ULONG),
        ("Class", _ANON__ANON__EVENT_TRACE_HEADER_SUB_UNION_2_SUB_STRUCTURE_1),
    ]


class _ANON__EVENT_TRACE_HEADER_SUB_UNION_3(Union):
    _fields_ = [
        ("Guid", GUID),
        ("GuidPtr", ULONGLONG),
    ]


class _ANON__ANON__EVENT_TRACE_HEADER_SUB_UNION_4_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("KernelTime", ULONG),
        ("UserTime", ULONG),
    ]


class _ANON__ANON__EVENT_TRACE_HEADER_SUB_UNION_4_SUB_STRUCTURE_2(Structure):
    _fields_ = [
        ("ClientContext", ULONG),
        ("Flags", ULONG),
    ]

class _ANON__EVENT_TRACE_HEADER_SUB_UNION_4(Union):
    _anonymous_ = ("anon_01","anon_02")
    _fields_ = [
        ("anon_01", _ANON__ANON__EVENT_TRACE_HEADER_SUB_UNION_4_SUB_STRUCTURE_1),
        ("ProcessorTime", ULONG64),
        ("anon_02", _ANON__ANON__EVENT_TRACE_HEADER_SUB_UNION_4_SUB_STRUCTURE_2),
    ]

class _EVENT_TRACE_HEADER(Structure):
    _anonymous_ = ("anon_01","anon_02","anon_03","anon_04")
    _fields_ = [
        ("Size", USHORT),
        ("anon_01", _ANON__EVENT_TRACE_HEADER_SUB_UNION_1),
        ("anon_02", _ANON__EVENT_TRACE_HEADER_SUB_UNION_2),
        ("ThreadId", ULONG),
        ("ProcessId", ULONG),
        ("TimeStamp", LARGE_INTEGER),
        ("anon_03", _ANON__EVENT_TRACE_HEADER_SUB_UNION_3),
        ("anon_04", _ANON__EVENT_TRACE_HEADER_SUB_UNION_4),
    ]
EVENT_TRACE_HEADER = _EVENT_TRACE_HEADER
PEVENT_TRACE_HEADER = POINTER(_EVENT_TRACE_HEADER)

class _ANON__ANON__ETW_BUFFER_CONTEXT_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("ProcessorNumber", BYTE),
        ("Alignment", BYTE),
    ]

class _ANON__ETW_BUFFER_CONTEXT_SUB_UNION_1(Union):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__ANON__ETW_BUFFER_CONTEXT_SUB_UNION_1_SUB_STRUCTURE_1),
        ("ProcessorIndex", USHORT),
    ]

class _ETW_BUFFER_CONTEXT(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("anon_01", _ANON__ETW_BUFFER_CONTEXT_SUB_UNION_1),
        ("LoggerId", USHORT),
    ]
PETW_BUFFER_CONTEXT = POINTER(_ETW_BUFFER_CONTEXT)
ETW_BUFFER_CONTEXT = _ETW_BUFFER_CONTEXT

class _ANON__EVENT_TRACE_SUB_UNION_1(Union):
    _fields_ = [
        ("ClientContext", ULONG),
        ("BufferContext", ETW_BUFFER_CONTEXT),
    ]

class _EVENT_TRACE(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Header", EVENT_TRACE_HEADER),
        ("InstanceId", ULONG),
        ("ParentInstanceId", ULONG),
        ("ParentGuid", GUID),
        ("MofData", PVOID),
        ("MofLength", ULONG),
        ("anon_01", _ANON__EVENT_TRACE_SUB_UNION_1),
    ]
EVENT_TRACE = _EVENT_TRACE
PEVENT_TRACE = POINTER(_EVENT_TRACE)

class _ANON__ANON__TRACE_LOGFILE_HEADER_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("MajorVersion", UCHAR),
        ("MinorVersion", UCHAR),
        ("SubVersion", UCHAR),
        ("SubMinorVersion", UCHAR),
    ]

class _ANON__TRACE_LOGFILE_HEADER_SUB_UNION_1(Union):
    _anonymous_ = ("VersionDetail",)
    _fields_ = [
        ("Version", ULONG),
        ("VersionDetail", _ANON__ANON__TRACE_LOGFILE_HEADER_SUB_UNION_1_SUB_STRUCTURE_1),
    ]


class _ANON__ANON__TRACE_LOGFILE_HEADER_SUB_UNION_2_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("StartBuffers", ULONG),
        ("PointerSize", ULONG),
        ("EventsLost", ULONG),
        ("CpuSpeedInMHz", ULONG),
    ]

class _ANON__TRACE_LOGFILE_HEADER_SUB_UNION_2(Union):
    _anonymous_ = ("DUMMYSTRUCTNAME",)
    _fields_ = [
        ("LogInstanceGuid", GUID),
        ("DUMMYSTRUCTNAME", _ANON__ANON__TRACE_LOGFILE_HEADER_SUB_UNION_2_SUB_STRUCTURE_1),
    ]

class _TRACE_LOGFILE_HEADER(Structure):
    _anonymous_ = ("DUMMYUNIONNAME","DUMMYUNIONNAME2")
    _fields_ = [
        ("BufferSize", ULONG),
        ("DUMMYUNIONNAME", _ANON__TRACE_LOGFILE_HEADER_SUB_UNION_1),
        ("ProviderVersion", ULONG),
        ("NumberOfProcessors", ULONG),
        ("EndTime", LARGE_INTEGER),
        ("TimerResolution", ULONG),
        ("MaximumFileSize", ULONG),
        ("LogFileMode", ULONG),
        ("BuffersWritten", ULONG),
        ("DUMMYUNIONNAME2", _ANON__TRACE_LOGFILE_HEADER_SUB_UNION_2),
        ("LoggerName", LPWSTR),
        ("LogFileName", LPWSTR),
        ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", LARGE_INTEGER),
        ("PerfFreq", LARGE_INTEGER),
        ("StartTime", LARGE_INTEGER),
        ("ReservedFlags", ULONG),
        ("BuffersLost", ULONG),
    ]
TRACE_LOGFILE_HEADER = _TRACE_LOGFILE_HEADER
PTRACE_LOGFILE_HEADER = POINTER(_TRACE_LOGFILE_HEADER)

class _ANON__EVENT_TRACE_LOGFILEA_SUB_UNION_1(Union):
    _fields_ = [
        ("LogFileMode", ULONG),
        ("ProcessTraceMode", ULONG),
    ]


class _ANON__EVENT_TRACE_LOGFILEA_SUB_UNION_2(Union):
    _fields_ = [
        ("EventCallback", PEVENT_CALLBACK),
        ("EventRecordCallback", PEVENT_RECORD_CALLBACK),
    ]

class _EVENT_TRACE_LOGFILEA(Structure):
    _anonymous_ = ("anon_01","anon_02")
    _fields_ = [
        ("LogFileName", LPSTR),
        ("LoggerName", LPSTR),
        ("CurrentTime", LONGLONG),
        ("BuffersRead", ULONG),
        ("anon_01", _ANON__EVENT_TRACE_LOGFILEA_SUB_UNION_1),
        ("CurrentEvent", EVENT_TRACE),
        ("LogfileHeader", TRACE_LOGFILE_HEADER),
        ("BufferCallback", PEVENT_TRACE_BUFFER_CALLBACKA),
        ("BufferSize", ULONG),
        ("Filled", ULONG),
        ("EventsLost", ULONG),
        ("anon_02", _ANON__EVENT_TRACE_LOGFILEA_SUB_UNION_2),
        ("IsKernelTrace", ULONG),
        ("Context", PVOID),
    ]
EVENT_TRACE_LOGFILEA = _EVENT_TRACE_LOGFILEA
PEVENT_TRACE_LOGFILEA = POINTER(_EVENT_TRACE_LOGFILEA)

class _ANON__EVENT_TRACE_LOGFILEW_SUB_UNION_1(Union):
    _fields_ = [
        ("LogFileMode", ULONG),
        ("ProcessTraceMode", ULONG),
    ]


class _ANON__EVENT_TRACE_LOGFILEW_SUB_UNION_2(Union):
    _fields_ = [
        ("EventCallback", PEVENT_CALLBACK),
        ("EventRecordCallback", PEVENT_RECORD_CALLBACK),
    ]

class _EVENT_TRACE_LOGFILEW(Structure):
    _anonymous_ = ("anon_01","anon_02")
    _fields_ = [
        ("LogFileName", LPWSTR),
        ("LoggerName", LPWSTR),
        ("CurrentTime", LONGLONG),
        ("BuffersRead", ULONG),
        ("anon_01", _ANON__EVENT_TRACE_LOGFILEW_SUB_UNION_1),
        ("CurrentEvent", EVENT_TRACE),
        ("LogfileHeader", TRACE_LOGFILE_HEADER),
        ("BufferCallback", PEVENT_TRACE_BUFFER_CALLBACKW),
        ("BufferSize", ULONG),
        ("Filled", ULONG),
        ("EventsLost", ULONG),
        ("anon_02", _ANON__EVENT_TRACE_LOGFILEW_SUB_UNION_2),
        ("IsKernelTrace", ULONG),
        ("Context", PVOID),
    ]
EVENT_TRACE_LOGFILEW = _EVENT_TRACE_LOGFILEW
PEVENT_TRACE_LOGFILEW = POINTER(_EVENT_TRACE_LOGFILEW)

class _EVENT_FILTER_DESCRIPTOR(Structure):
    _fields_ = [
        ("Ptr", ULONGLONG),
        ("Size", ULONG),
        ("Type", ULONG),
    ]
PEVENT_FILTER_DESCRIPTOR = POINTER(_EVENT_FILTER_DESCRIPTOR)
EVENT_FILTER_DESCRIPTOR = _EVENT_FILTER_DESCRIPTOR

class _ENABLE_TRACE_PARAMETERS(Structure):
    _fields_ = [
        ("Version", ULONG),
        ("EnableProperty", ULONG),
        ("ControlFlags", ULONG),
        ("SourceId", GUID),
        ("EnableFilterDesc", PEVENT_FILTER_DESCRIPTOR),
        ("FilterDescCount", ULONG),
    ]
ENABLE_TRACE_PARAMETERS = _ENABLE_TRACE_PARAMETERS
PENABLE_TRACE_PARAMETERS = POINTER(_ENABLE_TRACE_PARAMETERS)

class _EVENT_DESCRIPTOR(Structure):
    _fields_ = [
        ("Id", USHORT),
        ("Version", BYTE),
        ("Channel", BYTE),
        ("Level", BYTE),
        ("Opcode", BYTE),
        ("Task", USHORT),
        ("Keyword", ULONGLONG),
    ]
EVENT_DESCRIPTOR = _EVENT_DESCRIPTOR
PEVENT_DESCRIPTOR = POINTER(_EVENT_DESCRIPTOR)
PCEVENT_DESCRIPTOR = POINTER(_EVENT_DESCRIPTOR)

class _EVENT_DESCRIPTOR(_EVENT_DESCRIPTOR):
    def __repr__(self):
        return "<{0} Id={self.Id} Opcode={self.Opcode} Version={self.Version} Level={self.Level}>".format(type(self).__name__, self=self)
EVENT_DESCRIPTOR = _EVENT_DESCRIPTOR
PEVENT_DESCRIPTOR = POINTER(_EVENT_DESCRIPTOR)
PCEVENT_DESCRIPTOR = POINTER(_EVENT_DESCRIPTOR)
class _ANON__ANON__EVENT_HEADER_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("KernelTime", ULONG),
        ("UserTime", ULONG),
    ]

class _ANON__EVENT_HEADER_SUB_UNION_1(Union):
    _anonymous_ = ("DUMMYSTRUCTNAME",)
    _fields_ = [
        ("DUMMYSTRUCTNAME", _ANON__ANON__EVENT_HEADER_SUB_UNION_1_SUB_STRUCTURE_1),
        ("ProcessorTime", ULONG64),
    ]

class _EVENT_HEADER(Structure):
    _anonymous_ = ("DUMMYUNIONNAME",)
    _fields_ = [
        ("Size", USHORT),
        ("HeaderType", USHORT),
        ("Flags", USHORT),
        ("EventProperty", USHORT),
        ("ThreadId", ULONG),
        ("ProcessId", ULONG),
        ("TimeStamp", LARGE_INTEGER),
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("DUMMYUNIONNAME", _ANON__EVENT_HEADER_SUB_UNION_1),
        ("ActivityId", GUID),
    ]
EVENT_HEADER = _EVENT_HEADER
PEVENT_HEADER = POINTER(_EVENT_HEADER)

class _ANON__EVENT_HEADER_EXTENDED_DATA_ITEM_SUB_STRUCTURE_1(Structure):
    _fields_ = [
    ("Linkage", USHORT, 1),
    ("Reserved2", USHORT, 15),
    ]

class _EVENT_HEADER_EXTENDED_DATA_ITEM(Structure):
    _anonymous_ = ("anon_01",)
    _fields_ = [
        ("Reserved1", USHORT),
        ("ExtType", USHORT),
        ("anon_01", _ANON__EVENT_HEADER_EXTENDED_DATA_ITEM_SUB_STRUCTURE_1),
        ("DataSize", USHORT),
        ("DataPtr", ULONGLONG),
    ]
EVENT_HEADER_EXTENDED_DATA_ITEM = _EVENT_HEADER_EXTENDED_DATA_ITEM
PEVENT_HEADER_EXTENDED_DATA_ITEM = POINTER(_EVENT_HEADER_EXTENDED_DATA_ITEM)

_OLD_EVENT_HEADER_EXTENDED_DATA_ITEM = _EVENT_HEADER_EXTENDED_DATA_ITEM
class _EVENT_HEADER_EXTENDED_DATA_ITEM(_OLD_EVENT_HEADER_EXTENDED_DATA_ITEM):
    @property
    def data(self):
        bdata = (ctypes.c_char * self.DataSize).from_address(self.DataPtr)
        return bdata[:]
EVENT_HEADER_EXTENDED_DATA_ITEM = _EVENT_HEADER_EXTENDED_DATA_ITEM
PEVENT_HEADER_EXTENDED_DATA_ITEM = POINTER(_EVENT_HEADER_EXTENDED_DATA_ITEM)
class _EVENT_RECORD(Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", USHORT),
        ("UserDataLength", USHORT),
        ("ExtendedData", PEVENT_HEADER_EXTENDED_DATA_ITEM),
        ("UserData", PVOID),
        ("UserContext", PVOID),
    ]
EVENT_RECORD = _EVENT_RECORD
PEVENT_RECORD = POINTER(_EVENT_RECORD)

_OLD_EVENT_RECORD = _EVENT_RECORD
class _EVENT_RECORD(_OLD_EVENT_RECORD):
    pass
EVENT_RECORD = _EVENT_RECORD
PEVENT_RECORD = POINTER(_EVENT_RECORD)
class _TRACE_GUID_REGISTRATION(Structure):
    _fields_ = [
        ("Guid", LPCGUID),
        ("RegHandle", HANDLE),
    ]
TRACE_GUID_REGISTRATION = _TRACE_GUID_REGISTRATION
PTRACE_GUID_REGISTRATION = POINTER(_TRACE_GUID_REGISTRATION)

class _ANON__ANON__EVENT_DATA_DESCRIPTOR_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("Type", UCHAR),
        ("Reserved1", UCHAR),
        ("Reserved2", USHORT),
    ]

class _ANON__EVENT_DATA_DESCRIPTOR_SUB_UNION_1(Union):
    _anonymous_ = ("DUMMYSTRUCTNAME",)
    _fields_ = [
        ("Reserved", ULONG),
        ("DUMMYSTRUCTNAME", _ANON__ANON__EVENT_DATA_DESCRIPTOR_SUB_UNION_1_SUB_STRUCTURE_1),
    ]

class _EVENT_DATA_DESCRIPTOR(Structure):
    _anonymous_ = ("DUMMYUNIONNAME",)
    _fields_ = [
        ("Ptr", ULONGLONG),
        ("Size", ULONG),
        ("DUMMYUNIONNAME", _ANON__EVENT_DATA_DESCRIPTOR_SUB_UNION_1),
    ]
EVENT_DATA_DESCRIPTOR = _EVENT_DATA_DESCRIPTOR
PEVENT_DATA_DESCRIPTOR = POINTER(_EVENT_DATA_DESCRIPTOR)

TokenInvalid = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenInvalid", 0x0)
TokenUser = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenUser", 0x1)
TokenGroups = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenGroups", 0x2)
TokenPrivileges = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenPrivileges", 0x3)
TokenOwner = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenOwner", 0x4)
TokenPrimaryGroup = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenPrimaryGroup", 0x5)
TokenDefaultDacl = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenDefaultDacl", 0x6)
TokenSource = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSource", 0x7)
TokenType = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenType", 0x8)
TokenImpersonationLevel = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenImpersonationLevel", 0x9)
TokenStatistics = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenStatistics", 0xa)
TokenRestrictedSids = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenRestrictedSids", 0xb)
TokenSessionId = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSessionId", 0xc)
TokenGroupsAndPrivileges = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenGroupsAndPrivileges", 0xd)
TokenSessionReference = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSessionReference", 0xe)
TokenSandBoxInert = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSandBoxInert", 0xf)
TokenAuditPolicy = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenAuditPolicy", 0x10)
TokenOrigin = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenOrigin", 0x11)
TokenElevationType = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenElevationType", 0x12)
TokenLinkedToken = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenLinkedToken", 0x13)
TokenElevation = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenElevation", 0x14)
TokenHasRestrictions = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenHasRestrictions", 0x15)
TokenAccessInformation = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenAccessInformation", 0x16)
TokenVirtualizationAllowed = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenVirtualizationAllowed", 0x17)
TokenVirtualizationEnabled = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenVirtualizationEnabled", 0x18)
TokenIntegrityLevel = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenIntegrityLevel", 0x19)
TokenUIAccess = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenUIAccess", 0x1a)
TokenMandatoryPolicy = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenMandatoryPolicy", 0x1b)
TokenLogonSid = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenLogonSid", 0x1c)
TokenIsAppContainer = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenIsAppContainer", 0x1d)
TokenCapabilities = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenCapabilities", 0x1e)
TokenAppContainerSid = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenAppContainerSid", 0x1f)
TokenAppContainerNumber = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenAppContainerNumber", 0x20)
TokenUserClaimAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenUserClaimAttributes", 0x21)
TokenDeviceClaimAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenDeviceClaimAttributes", 0x22)
TokenRestrictedUserClaimAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenRestrictedUserClaimAttributes", 0x23)
TokenRestrictedDeviceClaimAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenRestrictedDeviceClaimAttributes", 0x24)
TokenDeviceGroups = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenDeviceGroups", 0x25)
TokenRestrictedDeviceGroups = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenRestrictedDeviceGroups", 0x26)
TokenSecurityAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSecurityAttributes", 0x27)
TokenIsRestricted = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenIsRestricted", 0x28)
TokenProcessTrustLevel = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenProcessTrustLevel", 0x29)
TokenPrivateNameSpace = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenPrivateNameSpace", 0x2a)
TokenSingletonAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSingletonAttributes", 0x2b)
TokenBnoIsolation = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenBnoIsolation", 0x2c)
TokenChildProcessFlags = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenChildProcessFlags", 0x2d)
MaxTokenInfoClass = EnumValue("_TOKEN_INFORMATION_CLASS", "MaxTokenInfoClass", 0x2e)
class _TOKEN_INFORMATION_CLASS(EnumType):
    values = [TokenInvalid, TokenUser, TokenGroups, TokenPrivileges, TokenOwner, TokenPrimaryGroup, TokenDefaultDacl, TokenSource, TokenType, TokenImpersonationLevel, TokenStatistics, TokenRestrictedSids, TokenSessionId, TokenGroupsAndPrivileges, TokenSessionReference, TokenSandBoxInert, TokenAuditPolicy, TokenOrigin, TokenElevationType, TokenLinkedToken, TokenElevation, TokenHasRestrictions, TokenAccessInformation, TokenVirtualizationAllowed, TokenVirtualizationEnabled, TokenIntegrityLevel, TokenUIAccess, TokenMandatoryPolicy, TokenLogonSid, TokenIsAppContainer, TokenCapabilities, TokenAppContainerSid, TokenAppContainerNumber, TokenUserClaimAttributes, TokenDeviceClaimAttributes, TokenRestrictedUserClaimAttributes, TokenRestrictedDeviceClaimAttributes, TokenDeviceGroups, TokenRestrictedDeviceGroups, TokenSecurityAttributes, TokenIsRestricted, TokenProcessTrustLevel, TokenPrivateNameSpace, TokenSingletonAttributes, TokenBnoIsolation, TokenChildProcessFlags, MaxTokenInfoClass]
    mapper = FlagMapper(*values)
TOKEN_INFORMATION_CLASS = _TOKEN_INFORMATION_CLASS
PTOKEN_INFORMATION_CLASS = POINTER(_TOKEN_INFORMATION_CLASS)


TokenElevationTypeDefault = EnumValue("_TOKEN_ELEVATION_TYPE", "TokenElevationTypeDefault", 0x1)
TokenElevationTypeFull = EnumValue("_TOKEN_ELEVATION_TYPE", "TokenElevationTypeFull", 0x2)
TokenElevationTypeLimited = EnumValue("_TOKEN_ELEVATION_TYPE", "TokenElevationTypeLimited", 0x3)
class _TOKEN_ELEVATION_TYPE(EnumType):
    values = [TokenElevationTypeDefault, TokenElevationTypeFull, TokenElevationTypeLimited]
    mapper = FlagMapper(*values)
TOKEN_ELEVATION_TYPE = _TOKEN_ELEVATION_TYPE
PTOKEN_ELEVATION_TYPE = POINTER(_TOKEN_ELEVATION_TYPE)


class _TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * (ANYSIZE_ARRAY)),
    ]
TOKEN_PRIVILEGES = _TOKEN_PRIVILEGES
PTOKEN_PRIVILEGES = POINTER(_TOKEN_PRIVILEGES)

class _TOKEN_ELEVATION(Structure):
    _fields_ = [
        ("TokenIsElevated", DWORD),
    ]
TOKEN_ELEVATION = _TOKEN_ELEVATION
PTOKEN_ELEVATION = POINTER(_TOKEN_ELEVATION)

class _SID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Sid", PSID),
        ("Attributes", DWORD),
    ]
SID_AND_ATTRIBUTES = _SID_AND_ATTRIBUTES
PSID_AND_ATTRIBUTES = POINTER(_SID_AND_ATTRIBUTES)

_INITIAL_SID_AND_ATTRIBUTES = _SID_AND_ATTRIBUTES
class _SID_AND_ATTRIBUTES(_INITIAL_SID_AND_ATTRIBUTES):
    pass

    # Only in TOKEN_GROUPS
    # attributes = FlagExatractor(_INITIAL_SID_AND_ATTRIBUTES.Attributes,
        # (SE_GROUP_MANDATORY,
        # SE_GROUP_ENABLED_BY_DEFAULT,
        # SE_GROUP_ENABLED,
        # SE_GROUP_OWNER,
        # SE_GROUP_USE_FOR_DENY_ONLY,
        # SE_GROUP_INTEGRITY,
        # SE_GROUP_INTEGRITY_ENABLED,
        # SE_GROUP_LOGON_ID,
        # SE_GROUP_RESOURCE))
SID_AND_ATTRIBUTES = _SID_AND_ATTRIBUTES
PSID_AND_ATTRIBUTES = POINTER(_SID_AND_ATTRIBUTES)
class _TOKEN_MANDATORY_LABEL(Structure):
    _fields_ = [
        ("Label", SID_AND_ATTRIBUTES),
    ]
TOKEN_MANDATORY_LABEL = _TOKEN_MANDATORY_LABEL
PTOKEN_MANDATORY_LABEL = POINTER(_TOKEN_MANDATORY_LABEL)

class _TOKEN_USER(Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES),
    ]
PTOKEN_USER = POINTER(_TOKEN_USER)
TOKEN_USER = _TOKEN_USER

class _TOKEN_DEFAULT_DACL(Structure):
    _fields_ = [
        ("DefaultDacl", PACL),
    ]
TOKEN_DEFAULT_DACL = _TOKEN_DEFAULT_DACL
PTOKEN_DEFAULT_DACL = POINTER(_TOKEN_DEFAULT_DACL)

class _TOKEN_GROUPS(Structure):
    _fields_ = [
        ("GroupCount", DWORD),
        ("Groups", SID_AND_ATTRIBUTES * (ANYSIZE_ARRAY)),
    ]
TOKEN_GROUPS = _TOKEN_GROUPS
PTOKEN_GROUPS = POINTER(_TOKEN_GROUPS)

class _TOKEN_OWNER(Structure):
    _fields_ = [
        ("Owner", PSID),
    ]
TOKEN_OWNER = _TOKEN_OWNER
PTOKEN_OWNER = POINTER(_TOKEN_OWNER)

class _TOKEN_PRIMARY_GROUP(Structure):
    _fields_ = [
        ("PrimaryGroup", PSID),
    ]
PTOKEN_PRIMARY_GROUP = POINTER(_TOKEN_PRIMARY_GROUP)
TOKEN_PRIMARY_GROUP = _TOKEN_PRIMARY_GROUP

class _TOKEN_SOURCE(Structure):
    _fields_ = [
        ("SourceName", CHAR * (TOKEN_SOURCE_LENGTH)),
        ("SourceIdentifier", LUID),
    ]
PTOKEN_SOURCE = POINTER(_TOKEN_SOURCE)
TOKEN_SOURCE = _TOKEN_SOURCE

class _TOKEN_STATISTICS(Structure):
    _fields_ = [
        ("TokenId", LUID),
        ("AuthenticationId", LUID),
        ("ExpirationTime", LARGE_INTEGER),
        ("TokenType", TOKEN_TYPE),
        ("ImpersonationLevel", SECURITY_IMPERSONATION_LEVEL),
        ("DynamicCharged", DWORD),
        ("DynamicAvailable", DWORD),
        ("GroupCount", DWORD),
        ("PrivilegeCount", DWORD),
        ("ModifiedId", LUID),
    ]
PTOKEN_STATISTICS = POINTER(_TOKEN_STATISTICS)
TOKEN_STATISTICS = _TOKEN_STATISTICS

class _TOKEN_ORIGIN(Structure):
    _fields_ = [
        ("OriginatingLogonSession", LUID),
    ]
TOKEN_ORIGIN = _TOKEN_ORIGIN
PTOKEN_ORIGIN = POINTER(_TOKEN_ORIGIN)

class _TOKEN_LINKED_TOKEN(Structure):
    _fields_ = [
        ("LinkedToken", HANDLE),
    ]
PTOKEN_LINKED_TOKEN = POINTER(_TOKEN_LINKED_TOKEN)
TOKEN_LINKED_TOKEN = _TOKEN_LINKED_TOKEN

class _TOKEN_MANDATORY_POLICY(Structure):
    _fields_ = [
        ("Policy", DWORD),
    ]
TOKEN_MANDATORY_POLICY = _TOKEN_MANDATORY_POLICY
PTOKEN_MANDATORY_POLICY = POINTER(_TOKEN_MANDATORY_POLICY)

class _SID_AND_ATTRIBUTES_HASH(Structure):
    _fields_ = [
        ("SidCount", DWORD),
        ("SidAttr", PSID_AND_ATTRIBUTES),
        ("Hash", SID_HASH_ENTRY * (SID_HASH_SIZE)),
    ]
SID_AND_ATTRIBUTES_HASH = _SID_AND_ATTRIBUTES_HASH
PSID_AND_ATTRIBUTES_HASH = POINTER(_SID_AND_ATTRIBUTES_HASH)

class _TOKEN_APPCONTAINER_INFORMATION(Structure):
    _fields_ = [
        ("TokenAppContainer", PSID),
    ]
PTOKEN_APPCONTAINER_INFORMATION = POINTER(_TOKEN_APPCONTAINER_INFORMATION)
TOKEN_APPCONTAINER_INFORMATION = _TOKEN_APPCONTAINER_INFORMATION

class _TOKEN_ACCESS_INFORMATION(Structure):
    _fields_ = [
        ("SidHash", PSID_AND_ATTRIBUTES_HASH),
        ("RestrictedSidHash", PSID_AND_ATTRIBUTES_HASH),
        ("Privileges", PTOKEN_PRIVILEGES),
        ("AuthenticationId", LUID),
        ("TokenType", TOKEN_TYPE),
        ("ImpersonationLevel", SECURITY_IMPERSONATION_LEVEL),
        ("MandatoryPolicy", TOKEN_MANDATORY_POLICY),
        ("Flags", DWORD),
        ("AppContainerNumber", DWORD),
        ("PackageSid", PSID),
        ("CapabilitiesHash", PSID_AND_ATTRIBUTES_HASH),
        ("TrustLevelSid", PSID),
        ("SecurityAttributes", PSECURITY_ATTRIBUTES_OPAQUE),
    ]
PTOKEN_ACCESS_INFORMATION = POINTER(_TOKEN_ACCESS_INFORMATION)
TOKEN_ACCESS_INFORMATION = _TOKEN_ACCESS_INFORMATION

class _TOKEN_GROUPS_AND_PRIVILEGES(Structure):
    _fields_ = [
        ("SidCount", DWORD),
        ("SidLength", DWORD),
        ("Sids", PSID_AND_ATTRIBUTES),
        ("RestrictedSidCount", DWORD),
        ("RestrictedSidLength", DWORD),
        ("RestrictedSids", PSID_AND_ATTRIBUTES),
        ("PrivilegeCount", DWORD),
        ("PrivilegeLength", DWORD),
        ("Privileges", PLUID_AND_ATTRIBUTES),
        ("AuthenticationId", LUID),
    ]
TOKEN_GROUPS_AND_PRIVILEGES = _TOKEN_GROUPS_AND_PRIVILEGES
PTOKEN_GROUPS_AND_PRIVILEGES = POINTER(_TOKEN_GROUPS_AND_PRIVILEGES)

class _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE(Structure):
    _fields_ = [
        ("Version", ULONG64),
        ("Name", UNICODE_STRING),
    ]
PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE = POINTER(_TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE)
TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE = _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE

class _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE(Structure):
    _fields_ = [
        ("pValue", PVOID),
        ("ValueLength", ULONG),
    ]
PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE = POINTER(_TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE)
TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE = _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE

class _TOKEN_SECURITY_ATTRIBUTE_V1_UNION(Union):
    _fields_ = [
        ("pInt64", PLONG64),
        ("pUint64", PULONG64),
        ("pString", PUNICODE_STRING),
        ("pFqbn", PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE),
        ("pOctetString", PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE),
    ]
TOKEN_SECURITY_ATTRIBUTE_V1_UNION = _TOKEN_SECURITY_ATTRIBUTE_V1_UNION

class _TOKEN_SECURITY_ATTRIBUTE_V1(Structure):
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("ValueType", USHORT),
        ("Reserved", USHORT),
        ("Flags", ULONG),
        ("ValueCount", ULONG),
        ("Values", TOKEN_SECURITY_ATTRIBUTE_V1_UNION),
    ]
TOKEN_SECURITY_ATTRIBUTE_V1 = _TOKEN_SECURITY_ATTRIBUTE_V1
PTOKEN_SECURITY_ATTRIBUTE_V1 = POINTER(_TOKEN_SECURITY_ATTRIBUTE_V1)

class _TOKEN_SECURITY_ATTRIBUTES_INFORMATION_UNION(Union):
    _fields_ = [
        ("pAttributeV1", PTOKEN_SECURITY_ATTRIBUTE_V1),
    ]
TOKEN_SECURITY_ATTRIBUTES_INFORMATION_UNION = _TOKEN_SECURITY_ATTRIBUTES_INFORMATION_UNION

class _TOKEN_SECURITY_ATTRIBUTES_INFORMATION(Structure):
    _fields_ = [
        ("Version", USHORT),
        ("Reserved", USHORT),
        ("AttributeCount", ULONG),
        ("Attribute", TOKEN_SECURITY_ATTRIBUTES_INFORMATION_UNION),
    ]
PTOKEN_SECURITY_ATTRIBUTES_INFORMATION = POINTER(_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)
TOKEN_SECURITY_ATTRIBUTES_INFORMATION = _TOKEN_SECURITY_ATTRIBUTES_INFORMATION

class _API_SET_VALUE_ENTRY(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("ValueOffset", ULONG),
        ("ValueLength", ULONG),
    ]
API_SET_VALUE_ENTRY = _API_SET_VALUE_ENTRY
PAPI_SET_VALUE_ENTRY = POINTER(_API_SET_VALUE_ENTRY)

class _API_SET_NAMESPACE_ENTRY(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("AliasOffset", ULONG),
        ("AliasLength", ULONG),
        ("DataOffset", ULONG),
    ]
PAPI_SET_NAMESPACE_ENTRY = POINTER(_API_SET_NAMESPACE_ENTRY)
API_SET_NAMESPACE_ENTRY = _API_SET_NAMESPACE_ENTRY

class _API_SET_NAMESPACE_ARRAY(Structure):
    _fields_ = [
        ("Version", ULONG),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Count", ULONG),
        ("Array", API_SET_NAMESPACE_ENTRY * (ANYSIZE_ARRAY)),
    ]
PAPI_SET_NAMESPACE_ARRAY = POINTER(_API_SET_NAMESPACE_ARRAY)
API_SET_NAMESPACE_ARRAY = _API_SET_NAMESPACE_ARRAY

class _API_SET_VALUE_ENTRY_V2(Structure):
    _fields_ = [
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("ValueOffset", ULONG),
        ("ValueLength", ULONG),
    ]
PAPI_SET_VALUE_ENTRY_V2 = POINTER(_API_SET_VALUE_ENTRY_V2)
API_SET_VALUE_ENTRY_V2 = _API_SET_VALUE_ENTRY_V2

class _API_SET_VALUE_ARRAY_V2(Structure):
    _fields_ = [
        ("Count", ULONG),
        ("Array", API_SET_VALUE_ENTRY_V2 * (ANYSIZE_ARRAY)),
    ]
API_SET_VALUE_ARRAY_V2 = _API_SET_VALUE_ARRAY_V2
PAPI_SET_VALUE_ARRAY_V2 = POINTER(_API_SET_VALUE_ARRAY_V2)

class _API_SET_NAMESPACE_ENTRY_V2(Structure):
    _fields_ = [
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("DataOffset", ULONG),
    ]
PAPI_SET_NAMESPACE_ENTRY_V2 = POINTER(_API_SET_NAMESPACE_ENTRY_V2)
API_SET_NAMESPACE_ENTRY_V2 = _API_SET_NAMESPACE_ENTRY_V2

class _API_SET_NAMESPACE_ARRAY_V2(Structure):
    _fields_ = [
        ("Version", ULONG),
        ("Count", ULONG),
        ("Array", API_SET_NAMESPACE_ENTRY_V2 * (ANYSIZE_ARRAY)),
    ]
API_SET_NAMESPACE_ARRAY_V2 = _API_SET_NAMESPACE_ARRAY_V2
PAPI_SET_NAMESPACE_ARRAY_V2 = POINTER(_API_SET_NAMESPACE_ARRAY_V2)

class _API_SET_VALUE_ARRAY_V4(Structure):
    _fields_ = [
        ("GuessFlags", ULONG),
        ("Count", ULONG),
        ("Array", API_SET_VALUE_ENTRY_V2 * (ANYSIZE_ARRAY)),
    ]
API_SET_VALUE_ARRAY_V4 = _API_SET_VALUE_ARRAY_V4
PAPI_SET_VALUE_ARRAY_V2 = POINTER(_API_SET_VALUE_ARRAY_V4)

class _API_SET_NAMESPACE_ARRAY_V4(Structure):
    _fields_ = [
        ("Version", ULONG),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Count", ULONG),
        ("Array", API_SET_NAMESPACE_ENTRY * (ANYSIZE_ARRAY)),
    ]
API_SET_NAMESPACE_ARRAY_V4 = _API_SET_NAMESPACE_ARRAY_V4
PAPI_SET_NAMESPACE_ARRAY_V4 = POINTER(_API_SET_NAMESPACE_ARRAY_V4)

class _API_SET_NAMESPACE_ENTRY_V4(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("AliasOffset", ULONG),
        ("AliasLength", ULONG),
        ("DataOffset", ULONG),
    ]
PAPI_SET_NAMESPACE_ENTRY_V4 = POINTER(_API_SET_NAMESPACE_ENTRY_V4)
API_SET_NAMESPACE_ENTRY_V4 = _API_SET_NAMESPACE_ENTRY_V4

class _API_SET_NAMESPACE_ENTRY_V6(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("NameOffset", ULONG),
        ("NameLength", ULONG),
        ("HashedLength", ULONG),
        ("ValueOffset", ULONG),
        ("ValueCount", ULONG),
    ]
API_SET_NAMESPACE_ENTRY_V6 = _API_SET_NAMESPACE_ENTRY_V6

class _API_SET_NAMESPACE_V6(Structure):
    _fields_ = [
        ("Version", ULONG),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Count", ULONG),
        ("EntryOffset", ULONG),
        ("HashOffset", ULONG),
        ("HashFactor", ULONG),
    ]
API_SET_NAMESPACE_V6 = _API_SET_NAMESPACE_V6

BG_JOB_STATE_QUEUED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_QUEUED", 0x0)
BG_JOB_STATE_CONNECTING = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_CONNECTING", 0x1)
BG_JOB_STATE_TRANSFERRING = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_TRANSFERRING", 0x2)
BG_JOB_STATE_SUSPENDED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_SUSPENDED", 0x3)
BG_JOB_STATE_ERROR = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_ERROR", 0x4)
BG_JOB_STATE_TRANSIENT_ERROR = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_TRANSIENT_ERROR", 0x5)
BG_JOB_STATE_TRANSFERRED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_TRANSFERRED", 0x6)
BG_JOB_STATE_ACKNOWLEDGED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_ACKNOWLEDGED", 0x7)
BG_JOB_STATE_CANCELLED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_CANCELLED", 0x8)
class _BG_JOB_STATE(EnumType):
    values = [BG_JOB_STATE_QUEUED, BG_JOB_STATE_CONNECTING, BG_JOB_STATE_TRANSFERRING, BG_JOB_STATE_SUSPENDED, BG_JOB_STATE_ERROR, BG_JOB_STATE_TRANSIENT_ERROR, BG_JOB_STATE_TRANSFERRED, BG_JOB_STATE_ACKNOWLEDGED, BG_JOB_STATE_CANCELLED]
    mapper = FlagMapper(*values)
BG_JOB_STATE = _BG_JOB_STATE


BG_JOB_PROXY_USAGE_PRECONFIG = EnumValue("_BG_JOB_PROXY_USAGE", "BG_JOB_PROXY_USAGE_PRECONFIG", 0x0)
BG_JOB_PROXY_USAGE_NO_PROXY = EnumValue("_BG_JOB_PROXY_USAGE", "BG_JOB_PROXY_USAGE_NO_PROXY", 0x1)
BG_JOB_PROXY_USAGE_OVERRIDE = EnumValue("_BG_JOB_PROXY_USAGE", "BG_JOB_PROXY_USAGE_OVERRIDE", 0x2)
BG_JOB_PROXY_USAGE_AUTODETECT = EnumValue("_BG_JOB_PROXY_USAGE", "BG_JOB_PROXY_USAGE_AUTODETECT", 0x3)
class _BG_JOB_PROXY_USAGE(EnumType):
    values = [BG_JOB_PROXY_USAGE_PRECONFIG, BG_JOB_PROXY_USAGE_NO_PROXY, BG_JOB_PROXY_USAGE_OVERRIDE, BG_JOB_PROXY_USAGE_AUTODETECT]
    mapper = FlagMapper(*values)
BG_JOB_PROXY_USAGE = _BG_JOB_PROXY_USAGE


BG_JOB_PRIORITY_FOREGROUND = EnumValue("_BG_JOB_PRIORITY", "BG_JOB_PRIORITY_FOREGROUND", 0x0)
BG_JOB_PRIORITY_HIGH = EnumValue("_BG_JOB_PRIORITY", "BG_JOB_PRIORITY_HIGH", 0x1)
BG_JOB_PRIORITY_NORMAL = EnumValue("_BG_JOB_PRIORITY", "BG_JOB_PRIORITY_NORMAL", 0x2)
BG_JOB_PRIORITY_LOW = EnumValue("_BG_JOB_PRIORITY", "BG_JOB_PRIORITY_LOW", 0x3)
class _BG_JOB_PRIORITY(EnumType):
    values = [BG_JOB_PRIORITY_FOREGROUND, BG_JOB_PRIORITY_HIGH, BG_JOB_PRIORITY_NORMAL, BG_JOB_PRIORITY_LOW]
    mapper = FlagMapper(*values)
BG_JOB_PRIORITY = _BG_JOB_PRIORITY


BG_ERROR_CONTEXT_NONE = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_NONE", 0x0)
BG_ERROR_CONTEXT_UNKNOWN = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_UNKNOWN", 0x1)
BG_ERROR_CONTEXT_GENERAL_QUEUE_MANAGER = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_GENERAL_QUEUE_MANAGER", 0x2)
BG_ERROR_CONTEXT_QUEUE_MANAGER_NOTIFICATION = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_QUEUE_MANAGER_NOTIFICATION", 0x3)
BG_ERROR_CONTEXT_LOCAL_FILE = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_LOCAL_FILE", 0x4)
BG_ERROR_CONTEXT_REMOTE_FILE = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_REMOTE_FILE", 0x5)
BG_ERROR_CONTEXT_GENERAL_TRANSPORT = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_GENERAL_TRANSPORT", 0x6)
BG_ERROR_CONTEXT_REMOTE_APPLICATION = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_REMOTE_APPLICATION", 0x7)
class _BG_ERROR_CONTEXT(EnumType):
    values = [BG_ERROR_CONTEXT_NONE, BG_ERROR_CONTEXT_UNKNOWN, BG_ERROR_CONTEXT_GENERAL_QUEUE_MANAGER, BG_ERROR_CONTEXT_QUEUE_MANAGER_NOTIFICATION, BG_ERROR_CONTEXT_LOCAL_FILE, BG_ERROR_CONTEXT_REMOTE_FILE, BG_ERROR_CONTEXT_GENERAL_TRANSPORT, BG_ERROR_CONTEXT_REMOTE_APPLICATION]
    mapper = FlagMapper(*values)
BG_ERROR_CONTEXT = _BG_ERROR_CONTEXT


BG_JOB_TYPE_DOWNLOAD = EnumValue("_BG_JOB_TYPE", "BG_JOB_TYPE_DOWNLOAD", 0x0)
BG_JOB_TYPE_UPLOAD = EnumValue("_BG_JOB_TYPE", "BG_JOB_TYPE_UPLOAD", 0x1)
BG_JOB_TYPE_UPLOAD_REPLY = EnumValue("_BG_JOB_TYPE", "BG_JOB_TYPE_UPLOAD_REPLY", 0x2)
class _BG_JOB_TYPE(EnumType):
    values = [BG_JOB_TYPE_DOWNLOAD, BG_JOB_TYPE_UPLOAD, BG_JOB_TYPE_UPLOAD_REPLY]
    mapper = FlagMapper(*values)
BG_JOB_TYPE = _BG_JOB_TYPE


class _BG_FILE_PROGRESS(Structure):
    _fields_ = [
        ("BytesTotal", UINT64),
        ("BytesTransferred", UINT64),
        ("Completed", BOOL),
    ]
BG_FILE_PROGRESS = _BG_FILE_PROGRESS

class _BG_JOB_PROGRESS(Structure):
    _fields_ = [
        ("BytesTotal", UINT64),
        ("BytesTransferred", UINT64),
        ("FilesTotal", ULONG),
        ("FilesTransferred", ULONG),
    ]
BG_JOB_PROGRESS = _BG_JOB_PROGRESS

class _BG_FILE_INFO(Structure):
    _fields_ = [
        ("RemoteName", LPWSTR),
        ("LocalName", LPWSTR),
    ]
BG_FILE_INFO = _BG_FILE_INFO

class _BG_JOB_TIMES(Structure):
    _fields_ = [
        ("CreationTime", FILETIME),
        ("ModificationTime", FILETIME),
        ("TransferCompletionTime", FILETIME),
    ]
BG_JOB_TIMES = _BG_JOB_TIMES

WBEM_GENUS_CLASS = EnumValue("tag_WBEM_GENUS_TYPE", "WBEM_GENUS_CLASS", 0x1)
WBEM_GENUS_INSTANCE = EnumValue("tag_WBEM_GENUS_TYPE", "WBEM_GENUS_INSTANCE", 0x2)
class tag_WBEM_GENUS_TYPE(EnumType):
    values = [WBEM_GENUS_CLASS, WBEM_GENUS_INSTANCE]
    mapper = FlagMapper(*values)
WBEM_GENUS_TYPE = tag_WBEM_GENUS_TYPE


WBEM_FLAG_CREATE_OR_UPDATE = EnumValue("tag_WBEM_CHANGE_FLAG_TYPE", "WBEM_FLAG_CREATE_OR_UPDATE", 0x0)
WBEM_FLAG_UPDATE_ONLY = EnumValue("tag_WBEM_CHANGE_FLAG_TYPE", "WBEM_FLAG_UPDATE_ONLY", 0x1)
WBEM_FLAG_CREATE_ONLY = EnumValue("tag_WBEM_CHANGE_FLAG_TYPE", "WBEM_FLAG_CREATE_ONLY", 0x2)
WBEM_FLAG_UPDATE_COMPATIBLE = EnumValue("tag_WBEM_CHANGE_FLAG_TYPE", "WBEM_FLAG_UPDATE_COMPATIBLE", 0x0)
WBEM_FLAG_UPDATE_SAFE_MODE = EnumValue("tag_WBEM_CHANGE_FLAG_TYPE", "WBEM_FLAG_UPDATE_SAFE_MODE", 0x20)
WBEM_FLAG_UPDATE_FORCE_MODE = EnumValue("tag_WBEM_CHANGE_FLAG_TYPE", "WBEM_FLAG_UPDATE_FORCE_MODE", 0x40)
WBEM_MASK_UPDATE_MODE = EnumValue("tag_WBEM_CHANGE_FLAG_TYPE", "WBEM_MASK_UPDATE_MODE", 0x60)
WBEM_FLAG_ADVISORY = EnumValue("tag_WBEM_CHANGE_FLAG_TYPE", "WBEM_FLAG_ADVISORY", 0x10000)
class tag_WBEM_CHANGE_FLAG_TYPE(EnumType):
    values = [WBEM_FLAG_CREATE_OR_UPDATE, WBEM_FLAG_UPDATE_ONLY, WBEM_FLAG_CREATE_ONLY, WBEM_FLAG_UPDATE_COMPATIBLE, WBEM_FLAG_UPDATE_SAFE_MODE, WBEM_FLAG_UPDATE_FORCE_MODE, WBEM_MASK_UPDATE_MODE, WBEM_FLAG_ADVISORY]
    mapper = FlagMapper(*values)
WBEM_CHANGE_FLAG_TYPE = tag_WBEM_CHANGE_FLAG_TYPE


WBEM_NO_ERROR = EnumValue("tag_WBEMSTATUS", "WBEM_NO_ERROR", 0x0)
WBEM_S_NO_ERROR = EnumValue("tag_WBEMSTATUS", "WBEM_S_NO_ERROR", 0x0)
WBEM_S_SAME = EnumValue("tag_WBEMSTATUS", "WBEM_S_SAME", 0x0)
WBEM_S_FALSE = EnumValue("tag_WBEMSTATUS", "WBEM_S_FALSE", 0x1)
WBEM_S_ALREADY_EXISTS = EnumValue("tag_WBEMSTATUS", "WBEM_S_ALREADY_EXISTS", 0x40001)
WBEM_S_RESET_TO_DEFAULT = EnumValue("tag_WBEMSTATUS", "WBEM_S_RESET_TO_DEFAULT", 0x40002)
WBEM_S_DIFFERENT = EnumValue("tag_WBEMSTATUS", "WBEM_S_DIFFERENT", 0x40003)
WBEM_S_TIMEDOUT = EnumValue("tag_WBEMSTATUS", "WBEM_S_TIMEDOUT", 0x40004)
WBEM_S_NO_MORE_DATA = EnumValue("tag_WBEMSTATUS", "WBEM_S_NO_MORE_DATA", 0x40005)
WBEM_S_OPERATION_CANCELLED = EnumValue("tag_WBEMSTATUS", "WBEM_S_OPERATION_CANCELLED", 0x40006)
WBEM_S_PENDING = EnumValue("tag_WBEMSTATUS", "WBEM_S_PENDING", 0x40007)
WBEM_S_DUPLICATE_OBJECTS = EnumValue("tag_WBEMSTATUS", "WBEM_S_DUPLICATE_OBJECTS", 0x40008)
WBEM_S_ACCESS_DENIED = EnumValue("tag_WBEMSTATUS", "WBEM_S_ACCESS_DENIED", 0x40009)
WBEM_S_PARTIAL_RESULTS = EnumValue("tag_WBEMSTATUS", "WBEM_S_PARTIAL_RESULTS", 0x40010)
WBEM_S_SOURCE_NOT_AVAILABLE = EnumValue("tag_WBEMSTATUS", "WBEM_S_SOURCE_NOT_AVAILABLE", 0x40017)
WBEM_E_FAILED = EnumValue("tag_WBEMSTATUS", "WBEM_E_FAILED", 0x80041001)
WBEM_E_NOT_FOUND = EnumValue("tag_WBEMSTATUS", "WBEM_E_NOT_FOUND", 0x80041002)
WBEM_E_ACCESS_DENIED = EnumValue("tag_WBEMSTATUS", "WBEM_E_ACCESS_DENIED", 0x80041003)
WBEM_E_PROVIDER_FAILURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_FAILURE", 0x80041004)
WBEM_E_TYPE_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEM_E_TYPE_MISMATCH", 0x80041005)
WBEM_E_OUT_OF_MEMORY = EnumValue("tag_WBEMSTATUS", "WBEM_E_OUT_OF_MEMORY", 0x80041006)
WBEM_E_INVALID_CONTEXT = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_CONTEXT", 0x80041007)
WBEM_E_INVALID_PARAMETER = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PARAMETER", 0x80041008)
WBEM_E_NOT_AVAILABLE = EnumValue("tag_WBEMSTATUS", "WBEM_E_NOT_AVAILABLE", 0x80041009)
WBEM_E_CRITICAL_ERROR = EnumValue("tag_WBEMSTATUS", "WBEM_E_CRITICAL_ERROR", 0x8004100a)
WBEM_E_INVALID_STREAM = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_STREAM", 0x8004100b)
WBEM_E_NOT_SUPPORTED = EnumValue("tag_WBEMSTATUS", "WBEM_E_NOT_SUPPORTED", 0x8004100c)
WBEM_E_INVALID_SUPERCLASS = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_SUPERCLASS", 0x8004100d)
WBEM_E_INVALID_NAMESPACE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_NAMESPACE", 0x8004100e)
WBEM_E_INVALID_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_OBJECT", 0x8004100f)
WBEM_E_INVALID_CLASS = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_CLASS", 0x80041010)
WBEM_E_PROVIDER_NOT_FOUND = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_NOT_FOUND", 0x80041011)
WBEM_E_INVALID_PROVIDER_REGISTRATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PROVIDER_REGISTRATION", 0x80041012)
WBEM_E_PROVIDER_LOAD_FAILURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_LOAD_FAILURE", 0x80041013)
WBEM_E_INITIALIZATION_FAILURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INITIALIZATION_FAILURE", 0x80041014)
WBEM_E_TRANSPORT_FAILURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_TRANSPORT_FAILURE", 0x80041015)
WBEM_E_INVALID_OPERATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_OPERATION", 0x80041016)
WBEM_E_INVALID_QUERY = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_QUERY", 0x80041017)
WBEM_E_INVALID_QUERY_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_QUERY_TYPE", 0x80041018)
WBEM_E_ALREADY_EXISTS = EnumValue("tag_WBEMSTATUS", "WBEM_E_ALREADY_EXISTS", 0x80041019)
WBEM_E_OVERRIDE_NOT_ALLOWED = EnumValue("tag_WBEMSTATUS", "WBEM_E_OVERRIDE_NOT_ALLOWED", 0x8004101a)
WBEM_E_PROPAGATED_QUALIFIER = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPAGATED_QUALIFIER", 0x8004101b)
WBEM_E_PROPAGATED_PROPERTY = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPAGATED_PROPERTY", 0x8004101c)
WBEM_E_UNEXPECTED = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNEXPECTED", 0x8004101d)
WBEM_E_ILLEGAL_OPERATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_ILLEGAL_OPERATION", 0x8004101e)
WBEM_E_CANNOT_BE_KEY = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_BE_KEY", 0x8004101f)
WBEM_E_INCOMPLETE_CLASS = EnumValue("tag_WBEMSTATUS", "WBEM_E_INCOMPLETE_CLASS", 0x80041020)
WBEM_E_INVALID_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_SYNTAX", 0x80041021)
WBEM_E_NONDECORATED_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_NONDECORATED_OBJECT", 0x80041022)
WBEM_E_READ_ONLY = EnumValue("tag_WBEMSTATUS", "WBEM_E_READ_ONLY", 0x80041023)
WBEM_E_PROVIDER_NOT_CAPABLE = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_NOT_CAPABLE", 0x80041024)
WBEM_E_CLASS_HAS_CHILDREN = EnumValue("tag_WBEMSTATUS", "WBEM_E_CLASS_HAS_CHILDREN", 0x80041025)
WBEM_E_CLASS_HAS_INSTANCES = EnumValue("tag_WBEMSTATUS", "WBEM_E_CLASS_HAS_INSTANCES", 0x80041026)
WBEM_E_QUERY_NOT_IMPLEMENTED = EnumValue("tag_WBEMSTATUS", "WBEM_E_QUERY_NOT_IMPLEMENTED", 0x80041027)
WBEM_E_ILLEGAL_NULL = EnumValue("tag_WBEMSTATUS", "WBEM_E_ILLEGAL_NULL", 0x80041028)
WBEM_E_INVALID_QUALIFIER_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_QUALIFIER_TYPE", 0x80041029)
WBEM_E_INVALID_PROPERTY_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PROPERTY_TYPE", 0x8004102a)
WBEM_E_VALUE_OUT_OF_RANGE = EnumValue("tag_WBEMSTATUS", "WBEM_E_VALUE_OUT_OF_RANGE", 0x8004102b)
WBEM_E_CANNOT_BE_SINGLETON = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_BE_SINGLETON", 0x8004102c)
WBEM_E_INVALID_CIM_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_CIM_TYPE", 0x8004102d)
WBEM_E_INVALID_METHOD = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_METHOD", 0x8004102e)
WBEM_E_INVALID_METHOD_PARAMETERS = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_METHOD_PARAMETERS", 0x8004102f)
WBEM_E_SYSTEM_PROPERTY = EnumValue("tag_WBEMSTATUS", "WBEM_E_SYSTEM_PROPERTY", 0x80041030)
WBEM_E_INVALID_PROPERTY = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PROPERTY", 0x80041031)
WBEM_E_CALL_CANCELLED = EnumValue("tag_WBEMSTATUS", "WBEM_E_CALL_CANCELLED", 0x80041032)
WBEM_E_SHUTTING_DOWN = EnumValue("tag_WBEMSTATUS", "WBEM_E_SHUTTING_DOWN", 0x80041033)
WBEM_E_PROPAGATED_METHOD = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPAGATED_METHOD", 0x80041034)
WBEM_E_UNSUPPORTED_PARAMETER = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNSUPPORTED_PARAMETER", 0x80041035)
WBEM_E_MISSING_PARAMETER_ID = EnumValue("tag_WBEMSTATUS", "WBEM_E_MISSING_PARAMETER_ID", 0x80041036)
WBEM_E_INVALID_PARAMETER_ID = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PARAMETER_ID", 0x80041037)
WBEM_E_NONCONSECUTIVE_PARAMETER_IDS = EnumValue("tag_WBEMSTATUS", "WBEM_E_NONCONSECUTIVE_PARAMETER_IDS", 0x80041038)
WBEM_E_PARAMETER_ID_ON_RETVAL = EnumValue("tag_WBEMSTATUS", "WBEM_E_PARAMETER_ID_ON_RETVAL", 0x80041039)
WBEM_E_INVALID_OBJECT_PATH = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_OBJECT_PATH", 0x8004103a)
WBEM_E_OUT_OF_DISK_SPACE = EnumValue("tag_WBEMSTATUS", "WBEM_E_OUT_OF_DISK_SPACE", 0x8004103b)
WBEM_E_BUFFER_TOO_SMALL = EnumValue("tag_WBEMSTATUS", "WBEM_E_BUFFER_TOO_SMALL", 0x8004103c)
WBEM_E_UNSUPPORTED_PUT_EXTENSION = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNSUPPORTED_PUT_EXTENSION", 0x8004103d)
WBEM_E_UNKNOWN_OBJECT_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNKNOWN_OBJECT_TYPE", 0x8004103e)
WBEM_E_UNKNOWN_PACKET_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNKNOWN_PACKET_TYPE", 0x8004103f)
WBEM_E_MARSHAL_VERSION_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEM_E_MARSHAL_VERSION_MISMATCH", 0x80041040)
WBEM_E_MARSHAL_INVALID_SIGNATURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_MARSHAL_INVALID_SIGNATURE", 0x80041041)
WBEM_E_INVALID_QUALIFIER = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_QUALIFIER", 0x80041042)
WBEM_E_INVALID_DUPLICATE_PARAMETER = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_DUPLICATE_PARAMETER", 0x80041043)
WBEM_E_TOO_MUCH_DATA = EnumValue("tag_WBEMSTATUS", "WBEM_E_TOO_MUCH_DATA", 0x80041044)
WBEM_E_SERVER_TOO_BUSY = EnumValue("tag_WBEMSTATUS", "WBEM_E_SERVER_TOO_BUSY", 0x80041045)
WBEM_E_INVALID_FLAVOR = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_FLAVOR", 0x80041046)
WBEM_E_CIRCULAR_REFERENCE = EnumValue("tag_WBEMSTATUS", "WBEM_E_CIRCULAR_REFERENCE", 0x80041047)
WBEM_E_UNSUPPORTED_CLASS_UPDATE = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNSUPPORTED_CLASS_UPDATE", 0x80041048)
WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE", 0x80041049)
WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE", 0x80041050)
WBEM_E_TOO_MANY_PROPERTIES = EnumValue("tag_WBEMSTATUS", "WBEM_E_TOO_MANY_PROPERTIES", 0x80041051)
WBEM_E_UPDATE_TYPE_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEM_E_UPDATE_TYPE_MISMATCH", 0x80041052)
WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED = EnumValue("tag_WBEMSTATUS", "WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED", 0x80041053)
WBEM_E_UPDATE_PROPAGATED_METHOD = EnumValue("tag_WBEMSTATUS", "WBEM_E_UPDATE_PROPAGATED_METHOD", 0x80041054)
WBEM_E_METHOD_NOT_IMPLEMENTED = EnumValue("tag_WBEMSTATUS", "WBEM_E_METHOD_NOT_IMPLEMENTED", 0x80041055)
WBEM_E_METHOD_DISABLED = EnumValue("tag_WBEMSTATUS", "WBEM_E_METHOD_DISABLED", 0x80041056)
WBEM_E_REFRESHER_BUSY = EnumValue("tag_WBEMSTATUS", "WBEM_E_REFRESHER_BUSY", 0x80041057)
WBEM_E_UNPARSABLE_QUERY = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNPARSABLE_QUERY", 0x80041058)
WBEM_E_NOT_EVENT_CLASS = EnumValue("tag_WBEMSTATUS", "WBEM_E_NOT_EVENT_CLASS", 0x80041059)
WBEM_E_MISSING_GROUP_WITHIN = EnumValue("tag_WBEMSTATUS", "WBEM_E_MISSING_GROUP_WITHIN", 0x8004105a)
WBEM_E_MISSING_AGGREGATION_LIST = EnumValue("tag_WBEMSTATUS", "WBEM_E_MISSING_AGGREGATION_LIST", 0x8004105b)
WBEM_E_PROPERTY_NOT_AN_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPERTY_NOT_AN_OBJECT", 0x8004105c)
WBEM_E_AGGREGATING_BY_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_AGGREGATING_BY_OBJECT", 0x8004105d)
WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY", 0x8004105f)
WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING = EnumValue("tag_WBEMSTATUS", "WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING", 0x80041060)
WBEM_E_QUEUE_OVERFLOW = EnumValue("tag_WBEMSTATUS", "WBEM_E_QUEUE_OVERFLOW", 0x80041061)
WBEM_E_PRIVILEGE_NOT_HELD = EnumValue("tag_WBEMSTATUS", "WBEM_E_PRIVILEGE_NOT_HELD", 0x80041062)
WBEM_E_INVALID_OPERATOR = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_OPERATOR", 0x80041063)
WBEM_E_LOCAL_CREDENTIALS = EnumValue("tag_WBEMSTATUS", "WBEM_E_LOCAL_CREDENTIALS", 0x80041064)
WBEM_E_CANNOT_BE_ABSTRACT = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_BE_ABSTRACT", 0x80041065)
WBEM_E_AMENDED_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_AMENDED_OBJECT", 0x80041066)
WBEM_E_CLIENT_TOO_SLOW = EnumValue("tag_WBEMSTATUS", "WBEM_E_CLIENT_TOO_SLOW", 0x80041067)
WBEM_E_NULL_SECURITY_DESCRIPTOR = EnumValue("tag_WBEMSTATUS", "WBEM_E_NULL_SECURITY_DESCRIPTOR", 0x80041068)
WBEM_E_TIMED_OUT = EnumValue("tag_WBEMSTATUS", "WBEM_E_TIMED_OUT", 0x80041069)
WBEM_E_INVALID_ASSOCIATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_ASSOCIATION", 0x8004106a)
WBEM_E_AMBIGUOUS_OPERATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_AMBIGUOUS_OPERATION", 0x8004106b)
WBEM_E_QUOTA_VIOLATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_QUOTA_VIOLATION", 0x8004106c)
WBEM_E_RESERVED_001 = EnumValue("tag_WBEMSTATUS", "WBEM_E_RESERVED_001", 0x8004106d)
WBEM_E_RESERVED_002 = EnumValue("tag_WBEMSTATUS", "WBEM_E_RESERVED_002", 0x8004106e)
WBEM_E_UNSUPPORTED_LOCALE = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNSUPPORTED_LOCALE", 0x8004106f)
WBEM_E_HANDLE_OUT_OF_DATE = EnumValue("tag_WBEMSTATUS", "WBEM_E_HANDLE_OUT_OF_DATE", 0x80041070)
WBEM_E_CONNECTION_FAILED = EnumValue("tag_WBEMSTATUS", "WBEM_E_CONNECTION_FAILED", 0x80041071)
WBEM_E_INVALID_HANDLE_REQUEST = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_HANDLE_REQUEST", 0x80041072)
WBEM_E_PROPERTY_NAME_TOO_WIDE = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPERTY_NAME_TOO_WIDE", 0x80041073)
WBEM_E_CLASS_NAME_TOO_WIDE = EnumValue("tag_WBEMSTATUS", "WBEM_E_CLASS_NAME_TOO_WIDE", 0x80041074)
WBEM_E_METHOD_NAME_TOO_WIDE = EnumValue("tag_WBEMSTATUS", "WBEM_E_METHOD_NAME_TOO_WIDE", 0x80041075)
WBEM_E_QUALIFIER_NAME_TOO_WIDE = EnumValue("tag_WBEMSTATUS", "WBEM_E_QUALIFIER_NAME_TOO_WIDE", 0x80041076)
WBEM_E_RERUN_COMMAND = EnumValue("tag_WBEMSTATUS", "WBEM_E_RERUN_COMMAND", 0x80041077)
WBEM_E_DATABASE_VER_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEM_E_DATABASE_VER_MISMATCH", 0x80041078)
WBEM_E_VETO_DELETE = EnumValue("tag_WBEMSTATUS", "WBEM_E_VETO_DELETE", 0x80041079)
WBEM_E_VETO_PUT = EnumValue("tag_WBEMSTATUS", "WBEM_E_VETO_PUT", 0x8004107a)
WBEM_E_INVALID_LOCALE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_LOCALE", 0x80041080)
WBEM_E_PROVIDER_SUSPENDED = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_SUSPENDED", 0x80041081)
WBEM_E_SYNCHRONIZATION_REQUIRED = EnumValue("tag_WBEMSTATUS", "WBEM_E_SYNCHRONIZATION_REQUIRED", 0x80041082)
WBEM_E_NO_SCHEMA = EnumValue("tag_WBEMSTATUS", "WBEM_E_NO_SCHEMA", 0x80041083)
WBEM_E_PROVIDER_ALREADY_REGISTERED = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_ALREADY_REGISTERED", 0x80041084)
WBEM_E_PROVIDER_NOT_REGISTERED = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_NOT_REGISTERED", 0x80041085)
WBEM_E_FATAL_TRANSPORT_ERROR = EnumValue("tag_WBEMSTATUS", "WBEM_E_FATAL_TRANSPORT_ERROR", 0x80041086)
WBEM_E_ENCRYPTED_CONNECTION_REQUIRED = EnumValue("tag_WBEMSTATUS", "WBEM_E_ENCRYPTED_CONNECTION_REQUIRED", 0x80041087)
WBEM_E_PROVIDER_TIMED_OUT = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_TIMED_OUT", 0x80041088)
WBEM_E_NO_KEY = EnumValue("tag_WBEMSTATUS", "WBEM_E_NO_KEY", 0x80041089)
WBEM_E_PROVIDER_DISABLED = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_DISABLED", 0x8004108a)
WBEMESS_E_REGISTRATION_TOO_BROAD = EnumValue("tag_WBEMSTATUS", "WBEMESS_E_REGISTRATION_TOO_BROAD", 0x80042001)
WBEMESS_E_REGISTRATION_TOO_PRECISE = EnumValue("tag_WBEMSTATUS", "WBEMESS_E_REGISTRATION_TOO_PRECISE", 0x80042002)
WBEMESS_E_AUTHZ_NOT_PRIVILEGED = EnumValue("tag_WBEMSTATUS", "WBEMESS_E_AUTHZ_NOT_PRIVILEGED", 0x80042003)
WBEMMOF_E_EXPECTED_QUALIFIER_NAME = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_QUALIFIER_NAME", 0x80044001)
WBEMMOF_E_EXPECTED_SEMI = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_SEMI", 0x80044002)
WBEMMOF_E_EXPECTED_OPEN_BRACE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_OPEN_BRACE", 0x80044003)
WBEMMOF_E_EXPECTED_CLOSE_BRACE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_CLOSE_BRACE", 0x80044004)
WBEMMOF_E_EXPECTED_CLOSE_BRACKET = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_CLOSE_BRACKET", 0x80044005)
WBEMMOF_E_EXPECTED_CLOSE_PAREN = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_CLOSE_PAREN", 0x80044006)
WBEMMOF_E_ILLEGAL_CONSTANT_VALUE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_ILLEGAL_CONSTANT_VALUE", 0x80044007)
WBEMMOF_E_EXPECTED_TYPE_IDENTIFIER = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_TYPE_IDENTIFIER", 0x80044008)
WBEMMOF_E_EXPECTED_OPEN_PAREN = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_OPEN_PAREN", 0x80044009)
WBEMMOF_E_UNRECOGNIZED_TOKEN = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNRECOGNIZED_TOKEN", 0x8004400a)
WBEMMOF_E_UNRECOGNIZED_TYPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNRECOGNIZED_TYPE", 0x8004400b)
WBEMMOF_E_EXPECTED_PROPERTY_NAME = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_PROPERTY_NAME", 0x8004400c)
WBEMMOF_E_TYPEDEF_NOT_SUPPORTED = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_TYPEDEF_NOT_SUPPORTED", 0x8004400d)
WBEMMOF_E_UNEXPECTED_ALIAS = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNEXPECTED_ALIAS", 0x8004400e)
WBEMMOF_E_UNEXPECTED_ARRAY_INIT = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNEXPECTED_ARRAY_INIT", 0x8004400f)
WBEMMOF_E_INVALID_AMENDMENT_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_AMENDMENT_SYNTAX", 0x80044010)
WBEMMOF_E_INVALID_DUPLICATE_AMENDMENT = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_DUPLICATE_AMENDMENT", 0x80044011)
WBEMMOF_E_INVALID_PRAGMA = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_PRAGMA", 0x80044012)
WBEMMOF_E_INVALID_NAMESPACE_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_NAMESPACE_SYNTAX", 0x80044013)
WBEMMOF_E_EXPECTED_CLASS_NAME = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_CLASS_NAME", 0x80044014)
WBEMMOF_E_TYPE_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_TYPE_MISMATCH", 0x80044015)
WBEMMOF_E_EXPECTED_ALIAS_NAME = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_ALIAS_NAME", 0x80044016)
WBEMMOF_E_INVALID_CLASS_DECLARATION = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_CLASS_DECLARATION", 0x80044017)
WBEMMOF_E_INVALID_INSTANCE_DECLARATION = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_INSTANCE_DECLARATION", 0x80044018)
WBEMMOF_E_EXPECTED_DOLLAR = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_DOLLAR", 0x80044019)
WBEMMOF_E_CIMTYPE_QUALIFIER = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_CIMTYPE_QUALIFIER", 0x8004401a)
WBEMMOF_E_DUPLICATE_PROPERTY = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_DUPLICATE_PROPERTY", 0x8004401b)
WBEMMOF_E_INVALID_NAMESPACE_SPECIFICATION = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_NAMESPACE_SPECIFICATION", 0x8004401c)
WBEMMOF_E_OUT_OF_RANGE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_OUT_OF_RANGE", 0x8004401d)
WBEMMOF_E_INVALID_FILE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_FILE", 0x8004401e)
WBEMMOF_E_ALIASES_IN_EMBEDDED = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_ALIASES_IN_EMBEDDED", 0x8004401f)
WBEMMOF_E_NULL_ARRAY_ELEM = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_NULL_ARRAY_ELEM", 0x80044020)
WBEMMOF_E_DUPLICATE_QUALIFIER = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_DUPLICATE_QUALIFIER", 0x80044021)
WBEMMOF_E_EXPECTED_FLAVOR_TYPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_FLAVOR_TYPE", 0x80044022)
WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES", 0x80044023)
WBEMMOF_E_MULTIPLE_ALIASES = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_MULTIPLE_ALIASES", 0x80044024)
WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES2 = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES2", 0x80044025)
WBEMMOF_E_NO_ARRAYS_RETURNED = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_NO_ARRAYS_RETURNED", 0x80044026)
WBEMMOF_E_MUST_BE_IN_OR_OUT = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_MUST_BE_IN_OR_OUT", 0x80044027)
WBEMMOF_E_INVALID_FLAGS_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_FLAGS_SYNTAX", 0x80044028)
WBEMMOF_E_EXPECTED_BRACE_OR_BAD_TYPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_BRACE_OR_BAD_TYPE", 0x80044029)
WBEMMOF_E_UNSUPPORTED_CIMV22_QUAL_VALUE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNSUPPORTED_CIMV22_QUAL_VALUE", 0x8004402a)
WBEMMOF_E_UNSUPPORTED_CIMV22_DATA_TYPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNSUPPORTED_CIMV22_DATA_TYPE", 0x8004402b)
WBEMMOF_E_INVALID_DELETEINSTANCE_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_DELETEINSTANCE_SYNTAX", 0x8004402c)
WBEMMOF_E_INVALID_QUALIFIER_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_QUALIFIER_SYNTAX", 0x8004402d)
WBEMMOF_E_QUALIFIER_USED_OUTSIDE_SCOPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_QUALIFIER_USED_OUTSIDE_SCOPE", 0x8004402e)
WBEMMOF_E_ERROR_CREATING_TEMP_FILE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_ERROR_CREATING_TEMP_FILE", 0x8004402f)
WBEMMOF_E_ERROR_INVALID_INCLUDE_FILE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_ERROR_INVALID_INCLUDE_FILE", 0x80044030)
WBEMMOF_E_INVALID_DELETECLASS_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_DELETECLASS_SYNTAX", 0x80044031)
class tag_WBEMSTATUS(EnumType):
    values = [WBEM_NO_ERROR, WBEM_S_NO_ERROR, WBEM_S_SAME, WBEM_S_FALSE, WBEM_S_ALREADY_EXISTS, WBEM_S_RESET_TO_DEFAULT, WBEM_S_DIFFERENT, WBEM_S_TIMEDOUT, WBEM_S_NO_MORE_DATA, WBEM_S_OPERATION_CANCELLED, WBEM_S_PENDING, WBEM_S_DUPLICATE_OBJECTS, WBEM_S_ACCESS_DENIED, WBEM_S_PARTIAL_RESULTS, WBEM_S_SOURCE_NOT_AVAILABLE, WBEM_E_FAILED, WBEM_E_NOT_FOUND, WBEM_E_ACCESS_DENIED, WBEM_E_PROVIDER_FAILURE, WBEM_E_TYPE_MISMATCH, WBEM_E_OUT_OF_MEMORY, WBEM_E_INVALID_CONTEXT, WBEM_E_INVALID_PARAMETER, WBEM_E_NOT_AVAILABLE, WBEM_E_CRITICAL_ERROR, WBEM_E_INVALID_STREAM, WBEM_E_NOT_SUPPORTED, WBEM_E_INVALID_SUPERCLASS, WBEM_E_INVALID_NAMESPACE, WBEM_E_INVALID_OBJECT, WBEM_E_INVALID_CLASS, WBEM_E_PROVIDER_NOT_FOUND, WBEM_E_INVALID_PROVIDER_REGISTRATION, WBEM_E_PROVIDER_LOAD_FAILURE, WBEM_E_INITIALIZATION_FAILURE, WBEM_E_TRANSPORT_FAILURE, WBEM_E_INVALID_OPERATION, WBEM_E_INVALID_QUERY, WBEM_E_INVALID_QUERY_TYPE, WBEM_E_ALREADY_EXISTS, WBEM_E_OVERRIDE_NOT_ALLOWED, WBEM_E_PROPAGATED_QUALIFIER, WBEM_E_PROPAGATED_PROPERTY, WBEM_E_UNEXPECTED, WBEM_E_ILLEGAL_OPERATION, WBEM_E_CANNOT_BE_KEY, WBEM_E_INCOMPLETE_CLASS, WBEM_E_INVALID_SYNTAX, WBEM_E_NONDECORATED_OBJECT, WBEM_E_READ_ONLY, WBEM_E_PROVIDER_NOT_CAPABLE, WBEM_E_CLASS_HAS_CHILDREN, WBEM_E_CLASS_HAS_INSTANCES, WBEM_E_QUERY_NOT_IMPLEMENTED, WBEM_E_ILLEGAL_NULL, WBEM_E_INVALID_QUALIFIER_TYPE, WBEM_E_INVALID_PROPERTY_TYPE, WBEM_E_VALUE_OUT_OF_RANGE, WBEM_E_CANNOT_BE_SINGLETON, WBEM_E_INVALID_CIM_TYPE, WBEM_E_INVALID_METHOD, WBEM_E_INVALID_METHOD_PARAMETERS, WBEM_E_SYSTEM_PROPERTY, WBEM_E_INVALID_PROPERTY, WBEM_E_CALL_CANCELLED, WBEM_E_SHUTTING_DOWN, WBEM_E_PROPAGATED_METHOD, WBEM_E_UNSUPPORTED_PARAMETER, WBEM_E_MISSING_PARAMETER_ID, WBEM_E_INVALID_PARAMETER_ID, WBEM_E_NONCONSECUTIVE_PARAMETER_IDS, WBEM_E_PARAMETER_ID_ON_RETVAL, WBEM_E_INVALID_OBJECT_PATH, WBEM_E_OUT_OF_DISK_SPACE, WBEM_E_BUFFER_TOO_SMALL, WBEM_E_UNSUPPORTED_PUT_EXTENSION, WBEM_E_UNKNOWN_OBJECT_TYPE, WBEM_E_UNKNOWN_PACKET_TYPE, WBEM_E_MARSHAL_VERSION_MISMATCH, WBEM_E_MARSHAL_INVALID_SIGNATURE, WBEM_E_INVALID_QUALIFIER, WBEM_E_INVALID_DUPLICATE_PARAMETER, WBEM_E_TOO_MUCH_DATA, WBEM_E_SERVER_TOO_BUSY, WBEM_E_INVALID_FLAVOR, WBEM_E_CIRCULAR_REFERENCE, WBEM_E_UNSUPPORTED_CLASS_UPDATE, WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE, WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE, WBEM_E_TOO_MANY_PROPERTIES, WBEM_E_UPDATE_TYPE_MISMATCH, WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED, WBEM_E_UPDATE_PROPAGATED_METHOD, WBEM_E_METHOD_NOT_IMPLEMENTED, WBEM_E_METHOD_DISABLED, WBEM_E_REFRESHER_BUSY, WBEM_E_UNPARSABLE_QUERY, WBEM_E_NOT_EVENT_CLASS, WBEM_E_MISSING_GROUP_WITHIN, WBEM_E_MISSING_AGGREGATION_LIST, WBEM_E_PROPERTY_NOT_AN_OBJECT, WBEM_E_AGGREGATING_BY_OBJECT, WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY, WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING, WBEM_E_QUEUE_OVERFLOW, WBEM_E_PRIVILEGE_NOT_HELD, WBEM_E_INVALID_OPERATOR, WBEM_E_LOCAL_CREDENTIALS, WBEM_E_CANNOT_BE_ABSTRACT, WBEM_E_AMENDED_OBJECT, WBEM_E_CLIENT_TOO_SLOW, WBEM_E_NULL_SECURITY_DESCRIPTOR, WBEM_E_TIMED_OUT, WBEM_E_INVALID_ASSOCIATION, WBEM_E_AMBIGUOUS_OPERATION, WBEM_E_QUOTA_VIOLATION, WBEM_E_RESERVED_001, WBEM_E_RESERVED_002, WBEM_E_UNSUPPORTED_LOCALE, WBEM_E_HANDLE_OUT_OF_DATE, WBEM_E_CONNECTION_FAILED, WBEM_E_INVALID_HANDLE_REQUEST, WBEM_E_PROPERTY_NAME_TOO_WIDE, WBEM_E_CLASS_NAME_TOO_WIDE, WBEM_E_METHOD_NAME_TOO_WIDE, WBEM_E_QUALIFIER_NAME_TOO_WIDE, WBEM_E_RERUN_COMMAND, WBEM_E_DATABASE_VER_MISMATCH, WBEM_E_VETO_DELETE, WBEM_E_VETO_PUT, WBEM_E_INVALID_LOCALE, WBEM_E_PROVIDER_SUSPENDED, WBEM_E_SYNCHRONIZATION_REQUIRED, WBEM_E_NO_SCHEMA, WBEM_E_PROVIDER_ALREADY_REGISTERED, WBEM_E_PROVIDER_NOT_REGISTERED, WBEM_E_FATAL_TRANSPORT_ERROR, WBEM_E_ENCRYPTED_CONNECTION_REQUIRED, WBEM_E_PROVIDER_TIMED_OUT, WBEM_E_NO_KEY, WBEM_E_PROVIDER_DISABLED, WBEMESS_E_REGISTRATION_TOO_BROAD, WBEMESS_E_REGISTRATION_TOO_PRECISE, WBEMESS_E_AUTHZ_NOT_PRIVILEGED, WBEMMOF_E_EXPECTED_QUALIFIER_NAME, WBEMMOF_E_EXPECTED_SEMI, WBEMMOF_E_EXPECTED_OPEN_BRACE, WBEMMOF_E_EXPECTED_CLOSE_BRACE, WBEMMOF_E_EXPECTED_CLOSE_BRACKET, WBEMMOF_E_EXPECTED_CLOSE_PAREN, WBEMMOF_E_ILLEGAL_CONSTANT_VALUE, WBEMMOF_E_EXPECTED_TYPE_IDENTIFIER, WBEMMOF_E_EXPECTED_OPEN_PAREN, WBEMMOF_E_UNRECOGNIZED_TOKEN, WBEMMOF_E_UNRECOGNIZED_TYPE, WBEMMOF_E_EXPECTED_PROPERTY_NAME, WBEMMOF_E_TYPEDEF_NOT_SUPPORTED, WBEMMOF_E_UNEXPECTED_ALIAS, WBEMMOF_E_UNEXPECTED_ARRAY_INIT, WBEMMOF_E_INVALID_AMENDMENT_SYNTAX, WBEMMOF_E_INVALID_DUPLICATE_AMENDMENT, WBEMMOF_E_INVALID_PRAGMA, WBEMMOF_E_INVALID_NAMESPACE_SYNTAX, WBEMMOF_E_EXPECTED_CLASS_NAME, WBEMMOF_E_TYPE_MISMATCH, WBEMMOF_E_EXPECTED_ALIAS_NAME, WBEMMOF_E_INVALID_CLASS_DECLARATION, WBEMMOF_E_INVALID_INSTANCE_DECLARATION, WBEMMOF_E_EXPECTED_DOLLAR, WBEMMOF_E_CIMTYPE_QUALIFIER, WBEMMOF_E_DUPLICATE_PROPERTY, WBEMMOF_E_INVALID_NAMESPACE_SPECIFICATION, WBEMMOF_E_OUT_OF_RANGE, WBEMMOF_E_INVALID_FILE, WBEMMOF_E_ALIASES_IN_EMBEDDED, WBEMMOF_E_NULL_ARRAY_ELEM, WBEMMOF_E_DUPLICATE_QUALIFIER, WBEMMOF_E_EXPECTED_FLAVOR_TYPE, WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES, WBEMMOF_E_MULTIPLE_ALIASES, WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES2, WBEMMOF_E_NO_ARRAYS_RETURNED, WBEMMOF_E_MUST_BE_IN_OR_OUT, WBEMMOF_E_INVALID_FLAGS_SYNTAX, WBEMMOF_E_EXPECTED_BRACE_OR_BAD_TYPE, WBEMMOF_E_UNSUPPORTED_CIMV22_QUAL_VALUE, WBEMMOF_E_UNSUPPORTED_CIMV22_DATA_TYPE, WBEMMOF_E_INVALID_DELETEINSTANCE_SYNTAX, WBEMMOF_E_INVALID_QUALIFIER_SYNTAX, WBEMMOF_E_QUALIFIER_USED_OUTSIDE_SCOPE, WBEMMOF_E_ERROR_CREATING_TEMP_FILE, WBEMMOF_E_ERROR_INVALID_INCLUDE_FILE, WBEMMOF_E_INVALID_DELETECLASS_SYNTAX]
    mapper = FlagMapper(*values)
WBEMSTATUS = tag_WBEMSTATUS


WBEM_NO_WAIT = EnumValue("tag_WBEM_TIMEOUT_TYPE", "WBEM_NO_WAIT", 0x0)
WBEM_INFINITE = EnumValue("tag_WBEM_TIMEOUT_TYPE", "WBEM_INFINITE", 0xffffffff)
class tag_WBEM_TIMEOUT_TYPE(EnumType):
    values = [WBEM_NO_WAIT, WBEM_INFINITE]
    mapper = FlagMapper(*values)
WBEM_TIMEOUT_TYPE = tag_WBEM_TIMEOUT_TYPE


WBEM_FLAG_RETURN_IMMEDIATELY = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_RETURN_IMMEDIATELY", 0x10)
WBEM_FLAG_RETURN_WBEM_COMPLETE = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_RETURN_WBEM_COMPLETE", 0x0)
WBEM_FLAG_BIDIRECTIONAL = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_BIDIRECTIONAL", 0x0)
WBEM_FLAG_FORWARD_ONLY = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_FORWARD_ONLY", 0x20)
WBEM_FLAG_NO_ERROR_OBJECT = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_NO_ERROR_OBJECT", 0x40)
WBEM_FLAG_RETURN_ERROR_OBJECT = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_RETURN_ERROR_OBJECT", 0x0)
WBEM_FLAG_SEND_STATUS = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_SEND_STATUS", 0x80)
WBEM_FLAG_DONT_SEND_STATUS = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_DONT_SEND_STATUS", 0x0)
WBEM_FLAG_ENSURE_LOCATABLE = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_ENSURE_LOCATABLE", 0x100)
WBEM_FLAG_DIRECT_READ = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_DIRECT_READ", 0x200)
WBEM_FLAG_SEND_ONLY_SELECTED = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_SEND_ONLY_SELECTED", 0x0)
WBEM_RETURN_WHEN_COMPLETE = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_RETURN_WHEN_COMPLETE", 0x0)
WBEM_RETURN_IMMEDIATELY = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_RETURN_IMMEDIATELY", 0x10)
WBEM_MASK_RESERVED_FLAGS = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_MASK_RESERVED_FLAGS", 0x1f000)
WBEM_FLAG_USE_AMENDED_QUALIFIERS = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_USE_AMENDED_QUALIFIERS", 0x20000)
WBEM_FLAG_STRONG_VALIDATION = EnumValue("tag_WBEM_GENERIC_FLAG_TYPE", "WBEM_FLAG_STRONG_VALIDATION", 0x100000)
class tag_WBEM_GENERIC_FLAG_TYPE(EnumType):
    values = [WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_FLAG_RETURN_WBEM_COMPLETE, WBEM_FLAG_BIDIRECTIONAL, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_NO_ERROR_OBJECT, WBEM_FLAG_RETURN_ERROR_OBJECT, WBEM_FLAG_SEND_STATUS, WBEM_FLAG_DONT_SEND_STATUS, WBEM_FLAG_ENSURE_LOCATABLE, WBEM_FLAG_DIRECT_READ, WBEM_FLAG_SEND_ONLY_SELECTED, WBEM_RETURN_WHEN_COMPLETE, WBEM_RETURN_IMMEDIATELY, WBEM_MASK_RESERVED_FLAGS, WBEM_FLAG_USE_AMENDED_QUALIFIERS, WBEM_FLAG_STRONG_VALIDATION]
    mapper = FlagMapper(*values)
WBEM_GENERIC_FLAG_TYPE = tag_WBEM_GENERIC_FLAG_TYPE


WBEM_FLAG_CONNECT_REPOSITORY_ONLY = EnumValue("tag_WBEM_CONNECT_OPTIONS", "WBEM_FLAG_CONNECT_REPOSITORY_ONLY", 0x40)
WBEM_FLAG_CONNECT_USE_MAX_WAIT = EnumValue("tag_WBEM_CONNECT_OPTIONS", "WBEM_FLAG_CONNECT_USE_MAX_WAIT", 0x80)
WBEM_FLAG_CONNECT_PROVIDERS = EnumValue("tag_WBEM_CONNECT_OPTIONS", "WBEM_FLAG_CONNECT_PROVIDERS", 0x100)
class tag_WBEM_CONNECT_OPTIONS(EnumType):
    values = [WBEM_FLAG_CONNECT_REPOSITORY_ONLY, WBEM_FLAG_CONNECT_USE_MAX_WAIT, WBEM_FLAG_CONNECT_PROVIDERS]
    mapper = FlagMapper(*values)
WBEM_CONNECT_OPTIONS = tag_WBEM_CONNECT_OPTIONS


WBEM_FLAG_DEEP = EnumValue("tag_WBEM_QUERY_FLAG_TYPE", "WBEM_FLAG_DEEP", 0x0)
WBEM_FLAG_SHALLOW = EnumValue("tag_WBEM_QUERY_FLAG_TYPE", "WBEM_FLAG_SHALLOW", 0x1)
WBEM_FLAG_PROTOTYPE = EnumValue("tag_WBEM_QUERY_FLAG_TYPE", "WBEM_FLAG_PROTOTYPE", 0x2)
class tag_WBEM_QUERY_FLAG_TYPE(EnumType):
    values = [WBEM_FLAG_DEEP, WBEM_FLAG_SHALLOW, WBEM_FLAG_PROTOTYPE]
    mapper = FlagMapper(*values)
WBEM_QUERY_FLAG_TYPE = tag_WBEM_QUERY_FLAG_TYPE


WMI_GET_ALL_DATA = EnumValue("WMIDPREQUESTCODE", "WMI_GET_ALL_DATA", 0x0)
WMI_GET_SINGLE_INSTANCE = EnumValue("WMIDPREQUESTCODE", "WMI_GET_SINGLE_INSTANCE", 0x1)
WMI_SET_SINGLE_INSTANCE = EnumValue("WMIDPREQUESTCODE", "WMI_SET_SINGLE_INSTANCE", 0x2)
WMI_SET_SINGLE_ITEM = EnumValue("WMIDPREQUESTCODE", "WMI_SET_SINGLE_ITEM", 0x3)
WMI_ENABLE_EVENTS = EnumValue("WMIDPREQUESTCODE", "WMI_ENABLE_EVENTS", 0x4)
WMI_DISABLE_EVENTS = EnumValue("WMIDPREQUESTCODE", "WMI_DISABLE_EVENTS", 0x5)
WMI_ENABLE_COLLECTION = EnumValue("WMIDPREQUESTCODE", "WMI_ENABLE_COLLECTION", 0x6)
WMI_DISABLE_COLLECTION = EnumValue("WMIDPREQUESTCODE", "WMI_DISABLE_COLLECTION", 0x7)
WMI_REGINFO = EnumValue("WMIDPREQUESTCODE", "WMI_REGINFO", 0x8)
WMI_EXECUTE_METHOD = EnumValue("WMIDPREQUESTCODE", "WMI_EXECUTE_METHOD", 0x9)
class WMIDPREQUESTCODE(EnumType):
    values = [WMI_GET_ALL_DATA, WMI_GET_SINGLE_INSTANCE, WMI_SET_SINGLE_INSTANCE, WMI_SET_SINGLE_ITEM, WMI_ENABLE_EVENTS, WMI_DISABLE_EVENTS, WMI_ENABLE_COLLECTION, WMI_DISABLE_COLLECTION, WMI_REGINFO, WMI_EXECUTE_METHOD]
    mapper = FlagMapper(*values)


class WSAData64(Structure):
    _fields_ = [
        ("wVersion", WORD),
        ("wHighVersion", WORD),
        ("iMaxSockets", USHORT),
        ("iMaxUdpDg", USHORT),
        ("lpVendorInfo", POINTER(CHAR)),
        ("szDescription", CHAR * (WSADESCRIPTION_LEN + 1)),
        ("szSystemStatus", CHAR * (WSASYS_STATUS_LEN + 1)),
    ]
WSADATA64 = WSAData64
LPWSADATA64 = POINTER(WSAData64)

class WSAData32(Structure):
    _fields_ = [
        ("wVersion", WORD),
        ("wHighVersion", WORD),
        ("szDescription", CHAR * (WSADESCRIPTION_LEN + 1)),
        ("szSystemStatus", CHAR * (WSASYS_STATUS_LEN + 1)),
        ("iMaxSockets", USHORT),
        ("iMaxUdpDg", USHORT),
        ("lpVendorInfo", POINTER(CHAR)),
    ]
LPWSADATA32 = POINTER(WSAData32)
WSADATA32 = WSAData32

class _ANON__ANON_IN_ADDR_SUB_UNION_1_SUB_STRUCTURE_1(Structure):
    _fields_ = [
        ("s_b1", UCHAR),
        ("s_b2", UCHAR),
        ("s_b3", UCHAR),
        ("s_b4", UCHAR),
    ]


class _ANON__ANON_IN_ADDR_SUB_UNION_1_SUB_STRUCTURE_2(Structure):
    _fields_ = [
        ("s_w1", USHORT),
        ("s_w2", USHORT),
    ]

class _ANON_IN_ADDR_SUB_UNION_1(Union):
    _anonymous_ = ("S_un_b","S_un_w")
    _fields_ = [
        ("S_un_b", _ANON__ANON_IN_ADDR_SUB_UNION_1_SUB_STRUCTURE_1),
        ("S_un_w", _ANON__ANON_IN_ADDR_SUB_UNION_1_SUB_STRUCTURE_2),
        ("S_addr", ULONG),
    ]

class in_addr(Structure):
    _anonymous_ = ("S_un",)
    _fields_ = [
        ("S_un", _ANON_IN_ADDR_SUB_UNION_1),
    ]


class sockaddr(Structure):
    _fields_ = [
        ("sa_family", USHORT),
        ("sa_data", CHAR * (14)),
    ]


class sockaddr_in(Structure):
    _fields_ = [
        ("sin_family", SHORT),
        ("sin_port", USHORT),
        ("sin_addr", in_addr),
        ("sin_zero", CHAR * (8)),
    ]


# Self referencing struct tricks
class addrinfoW(Structure): pass
ADDRINFOW = addrinfoW
PADDRINFOW = POINTER(addrinfoW)
addrinfoW._fields_ = [
    ("ai_flags", INT),
    ("ai_family", INT),
    ("ai_socktype", INT),
    ("ai_protocol", INT),
    ("ai_addrlen", SIZE_T),
    ("ai_canonname", PWSTR),
    ("ai_addr", POINTER(sockaddr)),
    ("ai_next", POINTER(addrinfoW)),
]

class _WSAPROTOCOLCHAIN(Structure):
    _fields_ = [
        ("ChainLen", INT),
        ("ChainEntries", DWORD * (MAX_PROTOCOL_CHAIN)),
    ]
LPWSAPROTOCOLCHAIN = POINTER(_WSAPROTOCOLCHAIN)
WSAPROTOCOLCHAIN = _WSAPROTOCOLCHAIN

class _WSAPROTOCOL_INFOA(Structure):
    _fields_ = [
        ("dwServiceFlags1", DWORD),
        ("dwServiceFlags2", DWORD),
        ("dwServiceFlags3", DWORD),
        ("dwServiceFlags4", DWORD),
        ("dwProviderFlags", DWORD),
        ("ProviderId", GUID),
        ("dwCatalogEntryId", DWORD),
        ("ProtocolChain", WSAPROTOCOLCHAIN),
        ("iVersion", INT),
        ("iAddressFamily", INT),
        ("iMaxSockAddr", INT),
        ("iMinSockAddr", INT),
        ("iSocketType", INT),
        ("iProtocol", INT),
        ("iProtocolMaxOffset", INT),
        ("iNetworkByteOrder", INT),
        ("iSecurityScheme", INT),
        ("dwMessageSize", DWORD),
        ("dwProviderReserved", DWORD),
        ("szProtocol", CHAR * (WSAPROTOCOL_LEN + 1)),
    ]
WSAPROTOCOL_INFOA = _WSAPROTOCOL_INFOA
LPWSAPROTOCOL_INFOA = POINTER(_WSAPROTOCOL_INFOA)

class _WSAPROTOCOL_INFOW(Structure):
    _fields_ = [
        ("dwServiceFlags1", DWORD),
        ("dwServiceFlags2", DWORD),
        ("dwServiceFlags3", DWORD),
        ("dwServiceFlags4", DWORD),
        ("dwProviderFlags", DWORD),
        ("ProviderId", GUID),
        ("dwCatalogEntryId", DWORD),
        ("ProtocolChain", WSAPROTOCOLCHAIN),
        ("iVersion", INT),
        ("iAddressFamily", INT),
        ("iMaxSockAddr", INT),
        ("iMinSockAddr", INT),
        ("iSocketType", INT),
        ("iProtocol", INT),
        ("iProtocolMaxOffset", INT),
        ("iNetworkByteOrder", INT),
        ("iSecurityScheme", INT),
        ("dwMessageSize", DWORD),
        ("dwProviderReserved", DWORD),
        ("szProtocol", WCHAR * (WSAPROTOCOL_LEN + 1)),
    ]
LPWSAPROTOCOL_INFOW = POINTER(_WSAPROTOCOL_INFOW)
WSAPROTOCOL_INFOW = _WSAPROTOCOL_INFOW

# Self referencing struct tricks
class addrinfo(Structure): pass
PADDRINFOA = POINTER(addrinfo)
ADDRINFOA = addrinfo
addrinfo._fields_ = [
    ("ai_flags", INT),
    ("ai_family", INT),
    ("ai_socktype", INT),
    ("ai_protocol", INT),
    ("ai_addrlen", SIZE_T),
    ("ai_canonname", POINTER(CHAR)),
    ("ai_addr", POINTER(sockaddr)),
    ("ai_next", POINTER(addrinfo)),
]

