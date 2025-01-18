import pytest
import textwrap

import windows
import windows.generated_def as gdef
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

from .pfwtest import *

# pytestmark = pytest.mark.usefixtures('check_for_gc_garbage')

def test_print_syswow_state():
    import platform
    print("")
    env = windows.system.environ
    print(f"{platform.machine()=}")
    print(f"{platform.architecture()=}")
    print(f"{windows.system.bitness=}")
    print(f"{windows.current_process.bitness=}")
    print(f"{windows.current_process.is_wow_64=}")
    print(f"{env['PROCESSOR_ARCHITECTURE']=}")
    print(f"{env.get('PROCESSOR_ARCHITEW6432')=}")

    print("")
    print("GetSystemInfo")
    windows.utils.sprint(windows.utils.get_system_info(native=False), name="SystemInfo")
    print("")
    print("GetNativeSystemInfo")
    windows.utils.sprint(windows.utils.get_system_info(native=True), name="NativeSystemInfo")

@process_syswow_only
class TestSyswowCurrentProcess(object):
    def test_exec_syswow(self):
        x64_code = x64.assemble("mov rax, 0x4040404040404040; mov r11, 0x0202020202020202; add rax, r11; ret")
        res = windows.syswow64.execute_64bits_code_from_syswow(x64_code)
        assert res == 0x4242424242424242

    def test_self_pebsyswow(self):
        peb64 = windows.current_process.peb_syswow
        modules_names = [m.name for m in peb64.modules]
        assert "wow64.dll" in modules_names
        # Parsing
        wow64 = [m for m in peb64.modules if m.name == "wow64.dll"][0]
        assert "Wow64LdrpInitialize" in wow64.pe.exports

@python_injection
@windows_64bit_only
class TestSyswowRemoteProcess(object):
    def test_remote_pebsyswow(self, proc32):
        peb64 = proc32.peb_syswow
        modules_names = [m.name for m in peb64.modules]
        assert "wow64.dll" in modules_names
        # Parsing
        wow64 = [m for m in peb64.modules if m.name == "wow64.dll"][0]
        assert "Wow64LdrpInitialize" in wow64.pe.exports


    def test_getset_syswow_context(self, proc32):
        addr = proc32.virtual_alloc(0x1000)
        remote_python_code = """
        import windows
        import windows.native_exec.simple_x64 as x64
        x64_code = x64.assemble("mov r11, 0x1122334455667788; mov rax, 0x8877665544332211; mov [{0}], rax ;label :loop; jmp :loop; nop; nop; ret")
        res = windows.syswow64.execute_64bits_code_from_syswow(x64_code)
        windows.current_process.write_qword({0},  res)
        """.format(addr)

        t = proc32.execute_python_unsafe(textwrap.dedent(remote_python_code))
        # Wait for python execution
        while proc32.read_qword(addr) != 0x8877665544332211:
            pass
        ctx = t.context_syswow
        # Check the get context
        assert ctx.R11 == 0x1122334455667788
        assert proc32.read_memory(ctx.Rip, 2) == x64.assemble("label :loop; jmp :loop")
        t.suspend()
        proc32.write_memory(ctx.Rip, "\x90\x90")
        # Check the set context
        RETURN_VALUE = 0x4041424344454647
        ctx.Rax = RETURN_VALUE
        ctx.Rip += 2
        t.set_syswow_context(ctx)
        t.resume()
        t.wait()
        assert RETURN_VALUE == proc32.read_qword(addr)


import threading
import windows.test

threads_error = {}

def loop_query_ppid(proc, target_ppid):
    assert proc.bitness == 64

    try:
        for i in range(10):
            del proc._ppid # Force requery via syswow API
            assert proc.ppid == target_ppid
            for i in [x for x in proc.memory_state() if x.Protect == gdef.PAGE_EXECUTE_READ][:10]:
                assert proc.read_memory(i.BaseAddress, 0x1000)
            # assert False, "LOL"
    except Exception as e:
        # import traceback; traceback.print(
        threads_error[windows.current_thread.tid] = e
        raise
    return True

@process_syswow_only
def test_syswow_call_multithread():
    all_threads = []
    all_procs = []

    # Create multiple thread that will trigger concurrent call to NtQueryInformationProcess_32_to_64
    # Old version of PFW did not handled that thus generating invalid result / crash
    for tnb in range(10):
        new_proc = windows.test.pop_proc_64()
        new_proc_pid = new_proc.ppid
        all_procs.append(new_proc)
        t = threading.Thread(target=loop_query_ppid, args=(new_proc, new_proc_pid))
        all_threads.append(t)

    # import pdb; pdb.set_trace()
    for t in all_threads:
        t.start()
    for t in all_threads:
        t.join()
    for p in all_procs:
        p.exit()

    assert not threads_error, "syswow call inconsistent with MultiThreading inconsistent"
