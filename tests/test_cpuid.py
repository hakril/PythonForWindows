import pytest

import windows
import windows.generated_def as gdef
import windows.native_exec.cpuid

def test_native_exec_cpuid():
    if windows.current_process.architecture == gdef.IMAGE_FILE_MACHINE_ARM64:
        pytest.skip("CPUID not testable on ARM64")
    assert windows.native_exec.cpuid.do_cpuid(0)
    assert windows.native_exec.cpuid.get_proc_family_model()