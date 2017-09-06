import gc
import pytest

import windows
import windows.generated_def as gdef

from pfwtest import is_windows_32_bits, is_process_32_bits, test_binary_name, DEFAULT_CREATION_FLAGS


if is_windows_32_bits:
    def pop_proc_32(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        return windows.utils.create_process(r"C:\Windows\system32\{0}".format(test_binary_name), dwCreationFlags=dwCreationFlags, show_windows=True)

    def pop_proc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        raise WindowsError("Cannot create calc64 in 32bits system")
else:
    def pop_proc_32(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        return windows.utils.create_process(r"C:\Windows\syswow64\{0}".format(test_binary_name), dwCreationFlags=dwCreationFlags, show_windows=True)

    if is_process_32_bits:
        def pop_proc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
            with windows.utils.DisableWow64FsRedirection():
                return windows.utils.create_process(r"C:\Windows\system32\{0}".format(test_binary_name), dwCreationFlags=dwCreationFlags, show_windows=True)
    else:
        def pop_proc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
            return windows.utils.create_process(r"C:\Windows\system32\{0}".format(test_binary_name), dwCreationFlags=dwCreationFlags, show_windows=True)


import sys

def generate_pop_and_exit_fixtures(proc_popers, ids=[], dwCreationFlags=DEFAULT_CREATION_FLAGS):
    @pytest.fixture(params=proc_popers, ids=ids)
    def pop_and_exit_process(request):
        proc_poper = request.param
        proc = proc_poper(dwCreationFlags=dwCreationFlags)
        yield proc  # provide the fixture value
        try:
            print("EXIT PROC <{0}>".format(sys.getrefcount(proc)))
            # if sys.getrefcount(proc) > 5:
                # import pdb;pdb.set_trace()
            proc.exit(0)
        except WindowsError as e:
            if not proc.is_exit:
                raise
        # import pdb;pdb.set_trace()
        # proc.__del__()
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


@pytest.fixture()
def check_for_gc_garbage(request):
        garbage_before = set(gc.garbage)
        yield
        gc.collect()
        new_garbage = set(gc.garbage) - garbage_before
        assert not new_garbage, "Test generated uncollectable object ({0})".format(new_garbage)

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

# TST = current_process_hdebugger.refresh_handles()

RESULT = {}

@pytest.fixture()
def check_for_handle_leak(request):
    # current_process_hdebugger.refresh_handles()
    yield
    # leaked_handles = current_process_hdebugger.get_new_handle()
    # for lh in leaked_handles:
        # RESULT[lh.wValue] = request.function.__name__
    print("HANDLE LEAK SAVE")
    # assert not leaked_handles, "Test Leaked <{0}> handles of types ({1})".format(len(leaked_handles), set(h.type for h in leaked_handles))


@pytest.fixture(scope='session')
def check_for_handle_leak_final(request):
    # x = current_process_hdebugger.get_handles()
    print("CHECK HANDLE FINAL :D")
    # current_process_hdebugger.refresh_handles()
    yield
    # leaked_handles = current_process_hdebugger.get_new_handle(x)
    # import pdb;pdb.set_trace()
    # print(leaked_handles)

    # leaked_handles = current_process_hdebugger.get_new_handle()
    # import pdb;pdb.set_trace()
    # assert not leaked_handles, "Test Leaked <{0}> handles of types ({1})".format(len(leaked_handles), set(h.type for h in leaked_handles))


def pytest_unconfigure(*args, **kwargs):
    import pdb;pdb.set_trace()
    print(TST)

# pytestmark = pytest.mark.usefixtures('check_for_handle_leak_final')