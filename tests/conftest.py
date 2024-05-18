import gc
import time
import pytest
import collections

import windows
import windows.generated_def as gdef

from .pfwtest import is_windows_32_bits, is_process_32_bits, test_binary_name, DEFAULT_CREATION_FLAGS


if is_windows_32_bits:
    def pop_proc_32(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        p = windows.utils.create_process(r"C:\Windows\system32\{0}".format(test_binary_name).encode("ascii"), dwCreationFlags=dwCreationFlags, show_windows=True)
        assert p.bitness == 32
        return p

    def pop_proc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        raise WindowsError("Cannot create calc64 in 32bits system")
else:
    def pop_proc_32(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        p = windows.utils.create_process(r"C:\Windows\syswow64\{0}".format(test_binary_name).encode("ascii"), dwCreationFlags=dwCreationFlags, show_windows=True)
        assert p.bitness == 32
        return p

    if is_process_32_bits:
        def pop_proc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
            with windows.utils.DisableWow64FsRedirection():
                p = windows.utils.create_process(r"C:\Windows\system32\{0}".format(test_binary_name).encode("ascii"), dwCreationFlags=dwCreationFlags, show_windows=True)
                assert p.bitness == 64
                return p
    else:
        def pop_proc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
            p = windows.utils.create_process(r"C:\Windows\system32\{0}".format(test_binary_name).encode("ascii"), dwCreationFlags=dwCreationFlags, show_windows=True)
            assert p.bitness == 64
            return p


import sys
import weakref

def generate_pop_and_exit_fixtures(proc_popers, ids=[], dwCreationFlags=DEFAULT_CREATION_FLAGS):
    @pytest.fixture(params=proc_popers, ids=ids)
    def pop_and_exit_process(request):
        proc_poper = request.param
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
    return pop_and_exit_process

proc32 =  generate_pop_and_exit_fixtures([pop_proc_32], ids=["proc32"])
proc64 =  generate_pop_and_exit_fixtures([pop_proc_64], ids=["proc64"])
if is_windows_32_bits:
    proc32_64 =  generate_pop_and_exit_fixtures([pop_proc_32], ids=["proc32"])
    proc32_64_suspended =  generate_pop_and_exit_fixtures([pop_proc_32], ids=["proc32"],
                                                               dwCreationFlags=gdef.CREATE_SUSPENDED)
else:
    proc32_64 =  generate_pop_and_exit_fixtures([pop_proc_32, pop_proc_64], ids=["proc32", "proc64"])
    proc32_64_suspended =  generate_pop_and_exit_fixtures([pop_proc_32, pop_proc_64], ids=["proc32", "proc64"],
                                                            dwCreationFlags=gdef.CREATE_SUSPENDED)

@pytest.fixture(scope="session")
def init_com_security():
    # Init com security if not done
    try:
        windows.com.init()
        return windows.com.initsecurity()
    except WindowsError:
        pass


class HandleDebugger(object):
    def __init__(self, pid):
        self.pid = pid
        self.handles = []

    def refresh_handles(self):
        self.handles = self.get_handles()

    def get_handles(self):
        tpid = self.pid
        return [h for h in windows.system.handles if h.dwProcessId == tpid]

    def get_new_handle(self, old_handles=None):
        nh = self.get_handles()
        if old_handles is None:
            old_handles = self.handles
        handle_diff = set(h.wValue for h in nh) - set(h.wValue for h in old_handles)
        return [h for h in nh if h.wValue in handle_diff]

    def handles_types(self, hlist):
        return set(h.type for h in hlist)

    def print_new_handle_type(self):
        print(self.handles_types(self.get_new_handle()))


current_process_hdebugger = HandleDebugger(windows.current_process.pid)
current_process_hdebugger.refresh_handles()

class NoLeakAssert(AssertionError):
    pass



@pytest.fixture()
def check_for_handle_leak(request):
    x = current_process_hdebugger.refresh_handles()
    yield None
    leaked_handles = current_process_hdebugger.get_new_handle(x)
    try:
        leaked_handles_types = set(h.type for h in leaked_handles)
    except Exception as e:
        leaked_handles = current_process_hdebugger.get_new_handle(x)
        leaked_handles_types = set(h.type for h in leaked_handles)

    res = collections.defaultdict(list)
    for lh in leaked_handles:
        res[lh.type].append(lh)
    # import pdb;pdb.set_trace()
    for rmt in ['EtwRegistration', 'Key', 'DebugObject', 'Event']:
        if rmt in res:
            del res[rmt]
    # leaked_handles_types -= set(['EtwRegistration', 'Key', 'DebugObject', 'Event'])
    if res:
        raise NoLeakAssert(res)
    # assert not leaked_handles_types, "Test Leaked <{0}> handles of types ({1})".format(len(leaked_handles), leaked_handles_types)


@pytest.fixture()
def check_for_gc_garbage(request):
        # print("GC CHECK")
        garbage_before = set(gc.garbage)
        yield None
        gc.collect()
        new_garbage = set(gc.garbage) - garbage_before
        assert not new_garbage, "Test generated uncollectable object ({0})".format(new_garbage)


## Handle leak 'plugin'

def pytest_addoption(parser):
    parser.addoption("--leaks", action="store_true",
                     default=False, help="Check windows handle leaks")


def pytest_configure(config):
    if not config.getoption("--leaks"):
        return # no leaks check
    config.addinivalue_line("usefixtures", "check_for_handle_leak")


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    # print("Make report {0} | {1}".format(item, call))
    if call.when == "teardown" and call.excinfo and type(call.excinfo.value) == NoLeakAssert:
        x = outcome.get_result()
        x.outcome = "failed"
        # import pdb;pdb.set_trace()
        x.LEAK = call.excinfo.value.args[0]


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_report_teststatus(report):
    outcome = yield
    if getattr(report, "LEAK", None):
        report.outcome = "failed"
        outcome.force_result(('leaked', '0', 'LEAKED'))


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_terminal_summary(terminalreporter, exitstatus):
    outcome = yield
    if terminalreporter.config.option.tbstyle != "no":
        # import pdb;pdb.set_trace()
        reports = terminalreporter.getreports('leaked')
        if not reports:
            return
        terminalreporter.write_sep("=", "Handle leaks")
        for leak_report in reports:
            file, _, test = leak_report.location
            terminalreporter.write_sep("_", "{0}::{1}".format(file, test))
            for type, items in leak_report.LEAK.items():
                terminalreporter.write_line("Leaked handles of type <{0}>".format(type) , Purple=True, bold=True)
                terminalreporter.write_line("* <{0}>".format(items) , Purple=True, bold=True)
                for item in items:
                    try:
                        descr = item.description()
                    except WindowsError as e:
                        descr = None
                    if descr is None:
                        try:
                            descr = item.name
                        except Exception as e:
                            descr = repr(e)
                    terminalreporter.write_line(" * <{0}>".format(descr) , Purple=True, bold=True)
            terminalreporter.write_line("")