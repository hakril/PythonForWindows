import pytest
import windows
import windows.remotectypes as rctypes
import ctypes
import json

from .pfwtest import *

def assert_struct_offset(struct, field, offset):
    assert getattr(struct, field).offset == offset

if windows.current_process.bitness == 32:
    PEB32 = windows.generated_def.PEB
    PEB64 = rctypes.transform_type_to_remote64bits(windows.generated_def.PEB)
    
    TEB32 = windows.generated_def.TEB
    TEB64 = rctypes.transform_type_to_remote64bits(windows.generated_def.TEB)
    
    NT_TIB32 = windows.generated_def.NT_TIB
    NT_TIB64 = rctypes.transform_type_to_remote64bits(windows.generated_def.NT_TIB)
    
    SYSTEM_PROCESS_INFORMATION32 = windows.generated_def.SYSTEM_PROCESS_INFORMATION
    SYSTEM_PROCESS_INFORMATION64 = rctypes.transform_type_to_remote64bits(windows.generated_def.SYSTEM_PROCESS_INFORMATION)
else:
    PEB32 = rctypes.transform_type_to_remote32bits(windows.generated_def.PEB)
    PEB64 = windows.generated_def.PEB
    
    TEB32 = rctypes.transform_type_to_remote32bits(windows.generated_def.TEB)
    TEB64 = windows.generated_def.TEB
    
    NT_TIB32 = rctypes.transform_type_to_remote32bits(windows.generated_def.NT_TIB)
    NT_TIB64 = windows.generated_def.NT_TIB
    
    SYSTEM_PROCESS_INFORMATION32 = rctypes.transform_type_to_remote32bits(windows.generated_def.SYSTEM_PROCESS_INFORMATION)
    SYSTEM_PROCESS_INFORMATION64 = windows.generated_def.SYSTEM_PROCESS_INFORMATION

def test_peb32_fields():
    assert_peb_offset = lambda field, offset: assert_struct_offset(PEB32, field, offset)
    assert_peb_offset("BeingDebugged", 2)
    assert_peb_offset("ImageBaseAddress", 0x8)
    assert_peb_offset("Ldr", 0xc)
    assert_peb_offset("ProcessParameters", 0x10)
    assert_peb_offset("KernelCallbackTable", 0x2c)
    assert_peb_offset("UserSharedInfoPtr", 0x2c)
    assert_peb_offset("ApiSetMap", 0x38)
    assert_peb_offset("NumberOfProcessors", 0x64)
    assert_peb_offset("GdiHandleBuffer", 0xc4)
    assert_peb_offset("PostProcessInitRoutine", 0x14c) # Field just after 'GdiHandleBuffer' allow to also check the 'GdiHandleBuffer' size hack
    assert_peb_offset("SessionId", 0x1d4)
    assert_peb_offset("CSDVersion", 0x01F0)
    assert_peb_offset("MinimumStackCommit", 0x0208)


def test_peb64_fields():
    assert_peb_offset = lambda field, offset: assert_struct_offset(PEB64, field, offset)
    assert_peb_offset("BeingDebugged", 2)
    assert_peb_offset("ImageBaseAddress", 0x10)
    assert_peb_offset("Ldr", 0x18)
    assert_peb_offset("ProcessParameters", 0x20)
    assert_peb_offset("KernelCallbackTable", 0x58)
    assert_peb_offset("UserSharedInfoPtr", 0x58)
    assert_peb_offset("ApiSetMap", 0x68)
    assert_peb_offset("NumberOfProcessors", 0xb8)
    assert_peb_offset("GdiHandleBuffer", 0x140)
    assert_peb_offset("PostProcessInitRoutine", 0x230) # Field just after 'GdiHandleBuffer' allow to also check the 'GdiHandleBuffer' size hack
    assert_peb_offset("SessionId", 0x2c0)
    assert_peb_offset("CSDVersion", 0x02E8)
    assert_peb_offset("MinimumStackCommit", 0x0318)

# Important to the the current TEB via Self
def test_nt_tib32_fields():
    assert_nt_tib_offset = lambda field, offset: assert_struct_offset(NT_TIB32, field, offset)
    assert_nt_tib_offset("ExceptionList", 0)
    assert_nt_tib_offset("StackBase", 4)
    assert_nt_tib_offset("StackLimit", 8)
    assert_nt_tib_offset("SubSystemTib", 0xc)
    assert_nt_tib_offset("FiberData", 0x10)
    # assert_nt_tib_offset("Version", 0x14)
    assert_nt_tib_offset("ArbitraryUserPointer",  0x14)
    assert_nt_tib_offset("Self", 0x18) # Important !

def test_nt_tib64_fields():
    assert_nt_tib_offset = lambda field, offset: assert_struct_offset(NT_TIB64, field, offset)
    assert_nt_tib_offset("ExceptionList", 0)
    assert_nt_tib_offset("StackBase", 8)
    assert_nt_tib_offset("StackLimit", 0x10)
    assert_nt_tib_offset("SubSystemTib", 0x18)
    assert_nt_tib_offset("FiberData", 0x20)
    # assert_nt_tib_offset("Version", 0x28)
    assert_nt_tib_offset("ArbitraryUserPointer",  0x28)
    assert_nt_tib_offset("Self", 0x30) # Important !

def test_system_process_information32_fields():
    assert_spi_offset = lambda field, offset: assert_struct_offset(SYSTEM_PROCESS_INFORMATION32, field, offset)
    # Mainly based on https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm
    # And some symbol files :)
    assert_spi_offset("NextEntryOffset", 0)
    assert_spi_offset('NumberOfThreads', 4)
    assert_spi_offset('CreateTime', 0x20)
    assert_spi_offset('UserTime', 0x28)
    assert_spi_offset('KernelTime', 0x30)
    assert_spi_offset('ImageName', 0x38)
    assert_spi_offset('BasePriority', 0x40)
    assert_spi_offset('UniqueProcessId', 0x44)
    assert_spi_offset('InheritedFromUniqueProcessId', 0x48)
    assert_spi_offset('PeakVirtualSize', 0x58)
    assert_spi_offset('VirtualSize', 0x5C)
    assert_spi_offset('PageFaultCount', 0x60)
    assert_spi_offset('PeakWorkingSetSize', 0x64)
    assert_spi_offset('WorkingSetSize', 0x68)
    assert_spi_offset('PagefileUsage', 0x7C)
    assert_spi_offset('PeakPagefileUsage', 0x80)


def test_system_process_information64_fields():
    assert_spi_offset = lambda field, offset: assert_struct_offset(SYSTEM_PROCESS_INFORMATION64, field, offset)
    # Mainly based on https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm
    # And some symbol files :)
    assert_spi_offset("NextEntryOffset", 0)
    assert_spi_offset('NumberOfThreads', 4)
    assert_spi_offset('CreateTime', 0x20)
    assert_spi_offset('UserTime', 0x28)
    assert_spi_offset('KernelTime', 0x30)
    assert_spi_offset('ImageName', 0x38)
    assert_spi_offset('BasePriority', 0x48)
    assert_spi_offset('UniqueProcessId', 0x50)
    assert_spi_offset('InheritedFromUniqueProcessId', 0x58)
    assert_spi_offset('PeakVirtualSize', 0x70)
    assert_spi_offset('VirtualSize', 0x78)
    assert_spi_offset('PageFaultCount', 0x80)
    assert_spi_offset('PeakWorkingSetSize', 0x88)
    assert_spi_offset('WorkingSetSize', 0x90)
    assert_spi_offset('PagefileUsage', 0xB8)
    assert_spi_offset('PeakPagefileUsage', 0xC0)


def test_cs_custom_define():
    assert windows.generated_def.CS_USER_32B == 0x23
    assert windows.generated_def.CS_USER_64B == 0x33


def test_CTL_CODE_macro():
    """Test that the CTL_CODE() macro, (reimplemented in python in windef.py) returns the correct values"""
    # The hardcoded values are from magnumdb (https://www.magnumdb.com)

    assert gdef.FSCTL_REQUEST_OPLOCK_LEVEL_1 == 0x00090000
    assert gdef.FSCTL_GET_NTFS_VOLUME_DATA == 0x00090064
    assert gdef.FSCTL_REPAIR_COPIES == 0x0009C2B4
    assert gdef.FSCTL_SET_REPARSE_POINT_EX == 0x0009040C
    assert gdef.IOCTL_MOUNTMGR_CREATE_POINT == 0x006DC000
    assert gdef.IOCTL_MOUNTMGR_QUERY_POINTS == 0x006D0008

def test_HRESULT_FACILITY_macro():
    """Test that the HRESULT_FACILITY() macro, (reimplemented in python in windef.py) returns the correct values"""
    assert gdef.HRESULT_FACILITY(0x800706d1) == gdef.FACILITY_WIN32 == 7
    # RPC_E_INVALID_HEADER(0x80010111)
    assert gdef.HRESULT_FACILITY(gdef.RPC_E_INVALID_HEADER) == gdef.FACILITY_RPC == 1


# typedef struct _DnsRecordFlags
# {
#     DWORD   Section     : 2;
#     DWORD   Delete      : 1;
#     DWORD   CharSet     : 2;
#     DWORD   Unused      : 3;
#     DWORD   Reserved    : 24;
# }
# DNS_RECORD_FLAGS;

# Size should be 4 bytes (2+1+2+3+24) == 32 == 4 bytes
def test_dns_record_flags_size():
    assert ctypes.sizeof(gdef.DNS_RECORD_FLAGS) == 4


def test_str_json_serialization():
    # Until dec2019 the __str__ of Flags were that same as __repr__
    # Flag being a int subclasse it would break json encoding as str(x) is used for int & subclasses
    # I do not find this acceptable anymore
    # __str__ of generated_def will now be really different from __repr__ and try to keep good level of compatility
    # with expected output of __str__ by the stdlib

    data = {"code": gdef.CREATE_SUSPENDED, "other": [gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE, gdef.szOID_RSA_RC4]}
    json_data = json.dumps(data)
    newdata = json.loads(json_data) # Will fail if bad Flag.__str__
    assert "CREATE_SUSPENDED" not in json_data
    assert newdata == {"code": gdef.CREATE_SUSPENDED, "other": [gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE, gdef.szOID_RSA_RC4]}
    assert type(newdata["code"]) is int


def test_psid_compare():
    msid = gdef.PSID.from_string
    # Do not reuse the same object as we do not want to fallback on compare based on address
    assert msid("S-1-5-12345") == msid("S-1-5-12345")
    assert msid("S-1-5-123") != msid("S-1-5-42")
    assert not (msid("S-1-5-12345") != msid("S-1-5-12345"))
    assert not (msid("S-1-5-12345") == msid("S-1-5-42"))

def test_psid_from_to_string():
    initial_str = "S-1-5-12345"
    sid = gdef.PSID.from_string(initial_str)
    assert str(sid) == initial_str
    assert gdef.PSID.from_string(str(sid)) == sid

def test_MIDL_XmitDefs_0001_NT_1607():
    # First definition was broken
    # 0:000> dt combase_32!__MIDL_XmitDefs_0001
    # +0x000 asyncOperationId : _GUID
    # +0x010 oxidClientProcessNA : Uint8B
    # +0x018 originalClientLogicalThreadId : _GUID
    # +0x028 uClientCausalityTraceId : Uint8B
    assert gdef.MIDL_XmitDefs_0001_NT_1607.originalClientLogicalThreadId.offset == 0x018
    assert gdef.MIDL_XmitDefs_0001_NT_1607.uClientCausalityTraceId.offset == 0x028