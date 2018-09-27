import pytest

import windows
import windows.generated_def as gdef

from pfwtest import *

pytestmark = pytest.mark.usefixtures('check_for_gc_garbage')


def test_createfileA_fail():
    with pytest.raises(WindowsError) as ar:
        windows.winproxy.CreateFileA("NONEXISTFILE.FILE")


def test_lstrcmpa():
    assert windows.winproxy.lstrcmpA("LOL", "NO-LOL")
    assert not windows.winproxy.lstrcmpA("LOL", "LOL")