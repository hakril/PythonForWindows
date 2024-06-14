import windows
import windows.native_exec.cpuid

def test_native_exec_cpuid():
    assert windows.native_exec.cpuid.do_cpuid(0)
    assert windows.native_exec.cpuid.get_proc_family_model()