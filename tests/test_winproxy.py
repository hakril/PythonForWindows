import ctypes
import sys
import threading

import pytest

import windows
import windows.generated_def as gdef

from .pfwtest import *

pytestmark = pytest.mark.usefixtures('check_for_gc_garbage')


def test_createfileA_fail():
    with pytest.raises(WindowsError) as ar:
        windows.winproxy.CreateFileA(b"NONEXISTFILE.FILE")


def test_lstrcmpa():
    assert windows.winproxy.lstrcmpA(b"LOL", b"NO-LOL")
    assert not windows.winproxy.lstrcmpA(b"LOL", b"LOL")

def test_getsystemmetrics():
    """Test nothing is raised when GetSystemMetrics() returns 0"""
    # Using a suit of value that may return 0
    windows.winproxy.GetSystemMetrics(gdef.SM_DIGITIZER)
    windows.winproxy.GetSystemMetrics(gdef.SM_CLEANBOOT)
    windows.winproxy.GetSystemMetrics(gdef.SM_MOUSEHORIZONTALWHEELPRESENT)
    windows.winproxy.GetSystemMetrics(gdef.SM_SERVERR2)
    windows.winproxy.GetSystemMetrics(gdef.SM_SLOWMACHINE)
    windows.winproxy.GetSystemMetrics(gdef.SM_SWAPBUTTON)
    windows.winproxy.GetSystemMetrics(gdef.SM_TABLETPC)


def test_NtStatusException_winerror():
    assert gdef.NtStatusException(2).winerror == 2
    assert gdef.NtStatusException(1234).winerror == 1234

def test_resolve():
    ntdll = windows.current_process.peb.modules[1]
    assert ntdll.name == "ntdll.dll"
    assert ntdll.pe.exports["NtCreateFile"] == windows.winproxy.resolve(windows.winproxy.NtCreateFile)


def test_last_error_preserved_during_gil_contention():
    token = windows.current_process.token
    size = gdef.DWORD()
    stop = threading.Event()

    def contend_for_gil():
        while not stop.is_set():
            sum(range(1000))

    worker = threading.Thread(target=contend_for_gil)
    switch_interval = sys.getswitchinterval()
    sys.setswitchinterval(0.00001)
    try:
        worker.start()
        for _ in range(256):
            with pytest.raises(WindowsError) as exc_info:
                windows.winproxy.GetTokenInformation(
                    token.handle,
                    gdef.TokenUser,
                    None,
                    0,
                    ctypes.byref(size),
                )
            assert exc_info.value.winerror == gdef.ERROR_INSUFFICIENT_BUFFER
            assert windows.winproxy.GetLastError() == gdef.ERROR_INSUFFICIENT_BUFFER
    finally:
        stop.set()
        if worker.ident is not None:
            worker.join()
        sys.setswitchinterval(switch_interval)

