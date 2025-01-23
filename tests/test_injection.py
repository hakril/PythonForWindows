# -*- coding: utf-8 -*-
import pytest

import os
import sys
import time
import struct
import textwrap
import shutil

import windows
import windows.generated_def as gdef

from .pfwtest import *

# Its really the same test as test_process.test_load_library
def test_dll_injection(proc32_64):
    assert "wintrust.dll" not in [mod.name for mod in proc32_64.peb.modules]
    windows.injection.load_dll_in_remote_process(proc32_64, "wintrust.dll")
    assert "wintrust.dll" in [mod.name for mod in proc32_64.peb.modules]

def test_dll_injection_error_reporting(proc32_64):
    with pytest.raises(windows.injection.InjectionFailedError) as excinfo:
        windows.injection.load_dll_in_remote_process(proc32_64, "NO_A_DLL.dll")
    assert excinfo.value.__cause__.winerror == gdef.ERROR_MOD_NOT_FOUND

def test_dll_injection_access_denied(proc32_64, tmpdir):
        """Emulate injection of MsStore python, were its DLL are not executable by any other append
        See: https://github.com/hakril/PythonForWindows/issues/72
        """
        mybitness = windows.current_process.bitness
        if proc32_64.bitness == mybitness:
            DLLPATH = r"c:\windows\system32\wintrust.dll"
        elif mybitness == 64: # target is 32
            DLLPATH = r"c:\windows\syswow64\wintrust.dll"
        elif mybitness == 32: # target is 64
            DLLPATH = r"c:\windows\sysnative\wintrust.dll"
        else:
            raise Value("WTF ARE THE BITNESS ?")
        targetname = os.path.join(str(tmpdir), "wintrust_noexec.dll")
        shutil.copy(DLLPATH, targetname)
        # Deny Execute; allow read for everyone
        sd = windows.security.SecurityDescriptor.from_string("D:(D;;GXFX;;;WD)(A;;1;;;WD)")
        sd.to_filename(targetname)

        try:
            with pytest.raises(windows.injection.InjectionFailedError) as excinfo:
                windows.injection.load_dll_in_remote_process(proc32_64, targetname)
            assert excinfo.value.__cause__.winerror == gdef.ERROR_ACCESS_DENIED
        finally:
            proc32_64.exit()
            proc32_64.wait()
            time.sleep(0.5) # Fail on Azure CI of no sleep
            os.unlink(targetname)