import pytest

import windows
import windows.generated_def as gdef

from windows.native_exec import nativeutils
from windows.pycompat import basestring, int_types

from .pfwtest import *

@check_for_gc_garbage
class TestNativeUtils(object):
    @process_64bit_only
    def test_strlenw64(self):
        strlenw64 = windows.native_exec.create_function(nativeutils.StrlenW64.get_code(), [gdef.UINT, gdef.LPCWSTR])
        assert strlenw64("YOLO") == 4
        assert strlenw64("") == 0

    @process_64bit_only
    def test_strlena64(self):
        strlena64 = windows.native_exec.create_function(nativeutils.StrlenA64.get_code(), [gdef.UINT, gdef.LPCSTR])
        assert strlena64(b"YOLO") == 4
        assert strlena64(b"") == 0

    @process_64bit_only
    def test_getprocaddr64(self):
        getprocaddr64 = windows.native_exec.create_function(nativeutils.GetProcAddress64.get_code(), [gdef.ULONG64, gdef.LPCWSTR, gdef.LPCSTR])
        k32 = [mod for mod in windows.current_process.peb.modules if mod.name == "kernel32.dll"][0]
        exports = [(x,y) for x,y in k32.pe.exports.items() if isinstance(x, basestring) and isinstance(y, int_types)]

        for name, addr in exports:
            name = name.encode()
            compute_addr = getprocaddr64("KERNEL32.DLL", name)
            # Put name in test to know which function caused the assert fails
            assert (name, hex(addr)) == (name, hex(compute_addr))

        assert getprocaddr64("YOLO.DLL", b"whatever") == 0xfffffffffffffffe
        assert getprocaddr64("KERNEL32.DLL", b"YOLOAPI") == 0xffffffffffffffff

    @process_32bit_only
    def test_strlenw32(self):
        strlenw32 = windows.native_exec.create_function(nativeutils.StrlenW32.get_code(), [gdef.UINT, gdef.LPCWSTR])
        assert strlenw32("YOLO") == 4
        assert strlenw32("") == 0

    @process_32bit_only
    def test_strlena32(self):
        strlena32 = windows.native_exec.create_function(nativeutils.StrlenA32.get_code(), [gdef.UINT, gdef.LPCSTR])
        assert strlena32(b"YOLO") == 4
        assert strlena32(b"") == 0

    @process_32bit_only
    def test_getprocaddr32(self):
        getprocaddr32 = windows.native_exec.create_function(nativeutils.GetProcAddress32.get_code(), [gdef.UINT, gdef.LPCWSTR, gdef.LPCSTR])
        k32 = [mod for mod in windows.current_process.peb.modules if mod.name == "kernel32.dll"][0]
        exports = [(x,y) for x,y in k32.pe.exports.items() if isinstance(x, basestring) and isinstance(y, int_types)]

        for name, addr in exports:
            name = name.encode()
            compute_addr = getprocaddr32("KERNEL32.DLL", name)
            # Put name in test to know which function caused the assert fails
            assert (name, hex(addr)) == (name, hex(compute_addr))

        assert getprocaddr32("YOLO.DLL", b"whatever") == 0xfffffffe
        assert getprocaddr32("KERNEL32.DLL", b"YOLOAPI") == 0xffffffff