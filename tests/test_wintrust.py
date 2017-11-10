import sys
import pytest

import windows
import windows.generated_def as gdef

from pfwtest import *

pytestmark = pytest.mark.usefixtures('check_for_gc_garbage')

def test_script_file_not_signed():
    assert not windows.wintrust.is_signed(__file__)
    assert windows.wintrust.check_signature(__file__) == gdef.TRUST_E_SUBJECT_FORM_UNKNOWN

def test_python_not_signed():
    python_path = sys.executable
    assert not windows.wintrust.is_signed(python_path)
    assert windows.wintrust.check_signature(python_path) == gdef.TRUST_E_NOSIGNATURE

def test_kernel32_signed():
    k32_path = r"C:\windows\system32\kernel32.dll"
    assert windows.wintrust.is_signed(k32_path)
    assert windows.wintrust.check_signature(k32_path) == 0