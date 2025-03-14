import os.path
import pytest
import base64

import windows
import windows.generated_def as gdef

is_process_32_bits = windows.current_process.bitness == 32
is_process_64_bits = windows.current_process.bitness == 64
is_process_syswow = windows.current_process.is_wow_64

is_windows_32_bits = windows.system.bitness == 32
is_windows_64_bits = windows.system.bitness == 64

is_windows_10 = (windows.system.version[0] == 10)

is_admin = windows.current_process.token.is_elevated

windows_32bit_only = pytest.mark.skipif(not is_windows_32_bits, reason="Test for 32bits Kernel only")
windows_64bit_only = pytest.mark.skipif(not is_windows_64_bits, reason="Test for 64bits Kernel only")

process_32bit_only = pytest.mark.skipif(not is_process_32_bits, reason="Test for 32bits process only")
process_64bit_only = pytest.mark.skipif(not is_process_64_bits, reason="Test for 64bits process only")
process_syswow_only = pytest.mark.skipif((not is_process_syswow) or windows.current_process._is_x86_on_arm64, reason="Test for syswow process only (ARM64 computer not supported)")
require_admin = pytest.mark.skipif(not is_admin, reason="Test must be launched as admin")

def process_architecture_only(target_archi):
    return pytest.mark.skipif(windows.current_process.architecture != target_archi,
                                reason="Test for {0} architecture process only".format(target_archi))

def system_architecture_only(target_archi):
        return pytest.mark.skipif(windows.system.architecture != target_archi,
                                reason="Test for {0} architecture system only".format(target_archi))

@pytest.fixture(scope="function")
def check_cross_heaven_gate_arm64_xfail(request):
    """Mark test crossing the heaven gate as xfail on x86 to arm64"""
    if windows.current_process._is_x86_on_arm64:
        request.applymarker("xfail")

def cross_heaven_gates(tstfunc):
    tstfunc = pytest.mark.usefixtures("check_cross_heaven_gate_arm64_xfail")(tstfunc)
    tstfunc = pytest.mark.cross_heaven_gate(tstfunc)
    return tstfunc

check_for_gc_garbage = pytest.mark.usefixtures("check_for_gc_garbage")
check_for_handle_leak = pytest.mark.usefixtures("check_for_handle_leak")

# msiexec.exe is new best choice:
# - a real process (looking at calc.exe)
# - GUI and wait for a click to close when no param
# - Is ARM64CE on arm -> can be exec as AMD64 or ARM64 with `machine`` param
test_binary_name = "msiexec.exe"
DEFAULT_CREATION_FLAGS = gdef.CREATE_NEW_CONSOLE


# Python Injection check fixture

python_is_installed = {
    windows.current_process.bitness: True
}

if windows.current_process.bitness == 32:
    with windows.utils.DisableWow64FsRedirection():
        python_is_installed[64] = os.path.exists(r"C:\Windows\system32\python27.dll")

if windows.current_process.bitness == 64:
    python_is_installed[32] = os.path.exists(r"C:\Windows\SysWOW64\python27.dll")

@pytest.fixture
def check_injected_python_installed(request):
    # Find the process parameter
    procparams = [argname for argname in request.fixturenames if argname.startswith("proc")]
    if len(procparams) != 1:
        raise ValueError("Could not find the fixture name of the injected python")
    procparam = procparams[0]
    proc = request.getfixturevalue(procparam)
    if not windows.injection.find_python_dll_to_inject(proc.bitness):
        pytest.skip("Python {0}b not installed -> skipping test with python injection into {0}b process".format(proc.bitness))
    return None

@pytest.fixture
def check_dll_injection_target_architecture(request):
    # Find the process parameter
    procparams = [argname for argname in request.fixturenames if argname.startswith("proc")]
    if len(procparams) != 1:
        raise ValueError("Could not find the fixture name of the injected python")
    procparam = procparams[0]
    proc = request.getfixturevalue(procparam)
    # xfail ARM64 injection as its not implemented
    if proc.architecture == gdef.IMAGE_FILE_MACHINE_ARM64:
        request.applymarker("xfail")



dll_injection =  pytest.mark.usefixtures("check_dll_injection_target_architecture", "check_cross_heaven_gate_arm64_xfail")
python_injection =  pytest.mark.usefixtures("check_dll_injection_target_architecture", "check_injected_python_installed", "check_cross_heaven_gate_arm64_xfail")


## P2 VS PY3

if windows.pycompat.is_py3:
    b64decode = base64.decodebytes
else:
    b64decode = base64.decodestring


def is_unicode(data):
    return isinstance(data, windows.pycompat.unicode_type)