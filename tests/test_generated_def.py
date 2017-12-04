import pytest
import windows
import windows.remotectypes as rctypes

from pfwtest import *

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