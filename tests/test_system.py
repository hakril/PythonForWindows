import ctypes
import pytest
import windows
import windows.pycompat
import windows.generated_def as gdef

from .pfwtest import *

@check_for_gc_garbage
class TestSystemWithCheckGarbage(object):
    def test_version(self):
        assert windows.system.version

    def test_version_name(self):
        assert is_unicode(windows.system.version_name)

    def test_version_product_type(self):
        assert windows.system.product_type

    def test_version_edition(self):
       assert windows.system.edition

    def test_version_windir(self):
        assert is_unicode(windows.system.windir)

    def test_version_versionstr(self):
        assert is_unicode(windows.system.windir)


    def test_computer_name(self):
        computer_name = windows.system.computer_name
        assert computer_name
        assert is_unicode(computer_name)

    def test_services(self):
        assert windows.system.services

    def test_logicaldrives(self):
        for ldrive in windows.system.logicaldrives:
            assert ldrive
            assert ldrive.name
            assert ldrive.path
            assert is_unicode(ldrive.path)
            try:
                assert ldrive.volume_info
            except WindowsError as e:
                #handle ERROR_NOT_READY returned by A: in github CI
                if e.winerror != gdef.ERROR_NOT_READY:
                    raise

    def test_wmi(self):
        assert windows.system.wmi is not None

    def test_handles(self):
        assert windows.system.handles

    def test_bitness(self):
        assert windows.system.bitness

    def test_evtlog(self):
        assert windows.system.event_log

    def test_task_scheduler(self):
        assert windows.system.task_scheduler

    def test_task_object_manager(self):
        assert windows.system.object_manager

    def test_system_modules_ntosk(self):
        # NtQuerySystemInformation(gdef.SystemModuleInformation) returns CHAR so not unicode
        # Another Nt API that returns unicode ?
        # assert is_unicode(windows.system.modules[0].name)
        assert windows.system.modules[0].name.endswith(b"ntoskrnl.exe")


@check_for_gc_garbage
class TestSystemWithCheckGarbageAndHandleLeak(object):
    def test_threads(self):
        assert windows.system.threads

    def test_processes(self):
        procs = windows.system.processes
        assert windows.current_process.pid in [p.pid for p in procs]
        assert is_unicode(windows.system.processes[0].name)

    def test_system_modules(self):
        assert windows.system.modules


# Test environement dict
# On py3 this will just test os.environ, but at least we can expect some consistence

UNICODE_STRING_1 = u"\u4e2d\u56fd\u94f6\u884c\u7f51\u94f6\u52a9\u624b" # some chinese
UNICODE_RU_STRING = u"\u0441\u0443\u043a\u0430\u0020\u0431\u043b\u044f\u0442\u044c" # CYKA BLYAT in Cyrillic
UNICODE_UNICORD = u'\U0001f984' # Encoded on 4 char in utf-16
UNICODE_LOIC_ESCAPE = u'lo\xefc' # Loic with trema

def check_env_variable_exist(name):
    buf = ctypes.create_unicode_buffer(0x1000)
    try:
        windows.winproxy.GetEnvironmentVariableW(name, buf, 0x1000)
    except WindowsError as e:
        if e.winerror == gdef.ERROR_ENVVAR_NOT_FOUND:
            return False
        raise
    return True

def test_unicode_environ_dict():
    unicode_environ = windows.system.environ

    unicode_environ["lower"] = "lower"
    unicode_environ[UNICODE_LOIC_ESCAPE] = UNICODE_UNICORD

    assert "LOWER" in unicode_environ
    assert "LOwer" in unicode_environ # Case does not count on __contains__

    assert UNICODE_LOIC_ESCAPE in unicode_environ
    assert unicode_environ[UNICODE_LOIC_ESCAPE] == UNICODE_UNICORD

    assert check_env_variable_exist("lower")
    del unicode_environ["Lower"]
    assert not check_env_variable_exist("lower")

    assert check_env_variable_exist(UNICODE_LOIC_ESCAPE)
    del unicode_environ[UNICODE_LOIC_ESCAPE]
    assert not check_env_variable_exist(UNICODE_LOIC_ESCAPE)

    assert not check_env_variable_exist(UNICODE_STRING_1)
    unicode_environ[UNICODE_STRING_1] = UNICODE_RU_STRING
    assert check_env_variable_exist(UNICODE_STRING_1)

def test_get_file_version():
    assert is_unicode(windows.system.get_file_version(u"ntdll"))
    assert is_unicode(windows.system.get_file_version(u"kernel32"))
