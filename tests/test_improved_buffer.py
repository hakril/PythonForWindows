import ctypes

import windows.utils as utils
import windows.generated_def as gdef

from .pfwtest import *


@pytest.mark.parametrize("type, size", [
(gdef.BYTE, 10),
(gdef.DWORD, 12),
(gdef.GUID, 42)])
def test_improved_BUFFER_size(type, size):
    x = utils.BUFFER(type, 1)(size=size)
    assert len(x) == 1
    assert x.real_size == size
    assert len(x._raw_buffer_) == size

@pytest.mark.parametrize("params, expected_type, expected_size", [
(([gdef.DWORD(x) for x in range(10)],), gdef.DWORD, 10), # list
(([gdef.GUID() for x in range(10)],), gdef.GUID, 10), # generator
((range(42), gdef.ULONGLONG), gdef.ULONGLONG, 42), # Explicite type
])
def test_improved_buffer(params, expected_type, expected_size):
    x = utils.buffer(*params)
    assert x._type_ == expected_type
    assert len(x) == expected_size

@pytest.mark.parametrize("c_type, buffer, expected_size", [
(gdef.CHAR, b"12345", 5),
(gdef.WCHAR, b"\x001\x002\x003\x004\x005", 5),
(gdef.DWORD, b"1111222233334444", 4),
])
def test_partial_buffer_size_guess(c_type, buffer, expected_size):
    buf = windows.utils.BUFFER(c_type).from_buffer_copy(buffer)
    assert len(buf) == expected_size


def test_partial_buffer_string_call():
    buffer = windows.utils.BUFFER(gdef.WCHAR)("LOL")
    assert buffer[:] == "LOL"
    assert len(buffer) == 3

