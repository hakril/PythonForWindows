import pytest
import windows

import windows.generated_def as gdef

is_process_32_bits = windows.current_process.bitness == 32
is_process_64_bits = windows.current_process.bitness == 64
is_process_syswow = windows.current_process.is_wow_64

is_windows_32_bits = windows.system.bitness == 32
is_windows_64_bits = windows.system.bitness == 64

is_windows_10 = (windows.system.version[0] == 10)

windows_32bit_only = pytest.mark.skipif(not is_windows_32_bits, reason="Test for 32bits Kernel only")
windows_64bit_only = pytest.mark.skipif(not is_windows_64_bits, reason="Test for 64bits Kernel only")

process_32bit_only = pytest.mark.skipif(not is_process_32_bits, reason="Test for 32bits process only")
process_64bit_only = pytest.mark.skipif(not is_process_64_bits, reason="Test for 64bits process only")
process_syswow_only = pytest.mark.skipif(not is_process_syswow, reason="Test for syswow process only")


check_for_gc_garbage = pytest.mark.usefixtures("check_for_gc_garbage")
check_for_handle_leak = pytest.mark.usefixtures("check_for_handle_leak")

test_binary_name = "notepad.exe"
DEFAULT_CREATION_FLAGS = gdef.CREATE_NEW_CONSOLE