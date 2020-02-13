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
else:
    PEB32 = rctypes.transform_type_to_remote32bits(windows.generated_def.PEB)
    PEB64 = windows.generated_def.PEB

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

def test_cs_custom_define():
    assert windows.generated_def.CS_USER_32B == 0x23
    assert windows.generated_def.CS_USER_64B == 0x33

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
