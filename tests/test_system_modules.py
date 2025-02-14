import windows
import ctypes

from pfwtest import *

@cross_heaven_gates
def test_system_module_gc():
    # Test for issue 12 (Py3)
    # https://github.com/hakril/PythonForWindows/issues/12
    mods = windows.system.modules
    first_name = mods[0].ImageName
    import gc; gc.collect()
    # need to do stuff to trigger the bug
    # YOLO LA HEAP
    for i in range(0x1000):
        ctypes.c_buffer(i)
    import gc; gc.collect()
    assert mods[0].ImageName == first_name