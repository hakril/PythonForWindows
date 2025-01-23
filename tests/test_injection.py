# -*- coding: utf-8 -*-
import pytest

import weakref
import shutil
import time

import windows
import windows.generated_def as gdef

from .conftest import pop_proc_32, pop_proc_64
from .pfwtest import DEFAULT_CREATION_FLAGS

@pytest.fixture(params=
    [(pop_proc_32, DEFAULT_CREATION_FLAGS),
    (pop_proc_32, gdef.CREATE_SUSPENDED),
    (pop_proc_64, DEFAULT_CREATION_FLAGS),
    (pop_proc_64, gdef.CREATE_SUSPENDED)],
    ids=["proc32", "proc32susp", "proc64", "proc64susp"])
def proc_3264_runsus(request):
    """Fixture for process 32/64 both running & suspended"""
    proc_poper, dwCreationFlags = request.param
    proc = proc_poper(dwCreationFlags=dwCreationFlags)
    time.sleep(0.2) # Give time to the process to load :)
    print("Created {0} ({1}bits) for test".format(proc, proc.bitness))
    yield weakref.proxy(proc)  # provide the fixture value
    try:
        proc.exit(0)
    except WindowsError as e:
        if not proc.is_exit:
            raise
    # print("DEL PROC")
    del proc

# Its really the same test as test_process.test_load_library but with suspended process as well
def test_dll_injection(proc_3264_runsus):
    assert (not proc_3264_runsus.peb.Ldr) or ("wintrust.dll" not in [mod.name for mod in proc_3264_runsus.peb.modules])
    windows.injection.load_dll_in_remote_process(proc_3264_runsus, "wintrust.dll")
    assert "wintrust.dll" in [mod.name for mod in proc_3264_runsus.peb.modules]

def test_dll_injection_error_reporting(proc_3264_runsus):
    with pytest.raises(windows.injection.InjectionFailedError) as excinfo:
        windows.injection.load_dll_in_remote_process(proc_3264_runsus, "NO_A_DLL.dll")
    assert excinfo.value.__cause__.winerror == gdef.ERROR_MOD_NOT_FOUND

def test_dll_injection_access_denied(proc_3264_runsus, tmpdir):
        """Emulate injection of MsStore python, were its DLL are not executable by any other append
        See: https://github.com/hakril/PythonForWindows/issues/72
        """
        mybitness = windows.current_process.bitness
        if proc_3264_runsus.bitness == mybitness:
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
                windows.injection.load_dll_in_remote_process(proc_3264_runsus, targetname)
            assert excinfo.value.__cause__.winerror == gdef.ERROR_ACCESS_DENIED
        finally:
            proc_3264_runsus.exit()
            proc_3264_runsus.wait()
            time.sleep(0.5) # Fail on Azure CI of no sleep
            os.unlink(targetname)