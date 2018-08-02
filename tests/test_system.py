import pytest
import windows

from pfwtest import *

@check_for_gc_garbage
class TestSystemWithCheckGarbage(object):
    def test_version(self):
        return windows.system.version

    def test_version_name(self):
        return windows.system.version_name

    def test_computer_name(self):
        return windows.system.computer_name

    def test_services(self):
        return windows.system.services

    def test_logicaldrives(self):
        return windows.system.logicaldrives

    def test_wmi(self):
        # Well, pytest initialize COM with its own parameters
        # It might make our own com.init() in WMI fail and therefore not call
        # CoInitializeSecurity. But looks like pytest/default COM-security parameters
        # does not allow to perform the request we want..
        # So we try & do it ourself here.

        # Do co-reinit in conftest.py ?
        try:
            if windows.com.init(): # if init fail. Call CoInitializeSecurity ourself
                windows.com.initsecurity()
        except Exception as e:
            pass
        return windows.system.wmi.select("Win32_Process", "*")

    def test_handles(self):
        return windows.system.handles

    def test_handle_process(self):
        handle_with_process = [h for h in windows.system.handles if h.dwProcessId]
        handle = handle_with_process[-1]
        proc = handle.process
        assert proc.pid == handle.dwProcessId

    def test_system_modules_ntosk(self):
        assert windows.system.modules[0].name.endswith("ntoskrnl.exe")


@check_for_gc_garbage
class TestSystemWithCheckGarbageAndHandleLeak(object):
    def test_threads(self):
        return windows.system.threads

    def test_processes(self):
        procs = windows.system.processes
        assert windows.current_process.pid in [p.pid for p in procs]

    def test_system_modules(self):
        return windows.system.modules