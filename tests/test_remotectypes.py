import ctypes

import pytest

import windows
import windows.generated_def as gdef
import windows.remotectypes as rctypes


def test_remote_struct_same_bitness():
    target = windows.current_process
    struct = gdef.OSVERSIONINFOEXA()
    struct.dwMajorVersion = 42 # DWORD
    struct.dwMinorVersion = 43 # DWORD
    struct.dwPlatformId = 0x11223344 # DWORD
    struct.szCSDVersion = b"LOL" # CHAR * (128)
    struct.wProductType = 0x21 # Byte

    # Create a remote-ctypes-struct that use our process as target
    # Logic will be the same
    remtype = rctypes.transform_type_to_remote(gdef.OSVERSIONINFOEXA)
    remstruct = remtype(ctypes.addressof(struct), target)

    assert struct.dwMajorVersion == remstruct.dwMajorVersion
    assert struct.dwMinorVersion == remstruct.dwMinorVersion
    assert struct.dwPlatformId == remstruct.dwPlatformId
    assert struct.szCSDVersion == remstruct.szCSDVersion
    assert struct.wProductType == remstruct.wProductType

# This test fails for now. (0.6)
# Should I improve remote ctypes to handel this ?
@pytest.mark.known_to_fail
def test_remote_long_ptr():
    # Bug thatwas in retrieving of NtCreateFile arguments
    target = windows.current_process

    large_int = gdef.LARGE_INTEGER(0x1122334455667788)
    large_int_ptr = gdef.PLARGE_INTEGER(large_int)
    assert large_int_ptr[0] == 0x1122334455667788

    # A remote large_int POINTER
    remtype = rctypes.transform_type_to_remote(gdef.PLARGE_INTEGER)
    remstruct = remtype(ctypes.addressof(large_int_ptr), target)

    assert remstruct.value == ctypes.addressof(large_int_ptr)
    assert remstruct.contents == 0x1122334455667788


    import pdb;pdb.set_trace()
    print("LOL")

