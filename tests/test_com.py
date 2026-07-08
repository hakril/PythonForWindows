import ctypes
import gc
import weakref

import pytest

import windows
import windows.com

import windows.generated_def as gdef

# ICallFrameEvents is a good candidate for testing :
# - only 1 fonction (not counting IUnkown())
# - Only 1 param for the function

# class ICallFrameEventsImplem(windows.com.COMImplementation):
#     IMPLEMENT = ICallFrameEvents
#
#     def OnCall(self, This, pFrame):
#         print('ICallFrameEvents.OnCall')
#         return E_NOTIMPL

class ICallFrameEventsImplemIncomplete(windows.com.COMImplementation):
    IMPLEMENT = gdef.ICallFrameEvents


def test_com_implementation_incomplete():
    with pytest.raises(ValueError):
        obj = ICallFrameEventsImplemIncomplete()


class ICallFrameEventsImplemSimple(windows.com.COMImplementation):
    IMPLEMENT = gdef.ICallFrameEvents

    def __init__(self):
        super(ICallFrameEventsImplemSimple, self).__init__()
        self.called = 0

    def OnCall(self, This, pFrame):
        self.called += 1
        return self.called

def test_com_implementation_simple():
    obj = ICallFrameEventsImplemSimple()
    assert obj.com_refcount == 1
    assert obj.AddRef() == 2
    assert obj.Release() == 1
    assert id(obj) in obj._get_keepalive_registry()
    assert obj.Release() == 0
    assert id(obj) not in obj._get_keepalive_registry()

def test_com_implementation_query_interface():
    obj = ICallFrameEventsImplemSimple()
    iunk = gdef.IUnknown()
    # Emulate a call from C code
    obj.QueryInterface(obj._as_parameter_, ctypes.pointer(gdef.IUnknown.IID), ctypes.pointer(iunk))
    assert obj._as_parameter_ == iunk.value
    assert obj.com_refcount == 2 # +1 on QueryInterface
    assert iunk.Release() == 1 # We are now working via ctypes/vtable call

def test_com_implementation_keep_alive():
    obj = ICallFrameEventsImplemSimple()
    # Create a C-like pointer from the interface
    objcom = gdef.ICallFrameEvents(obj._as_parameter_)
    assert objcom.AddRef() == 2
    wref = weakref.ref(obj)
    assert wref() is obj # Check object is still alive in python world
    del obj # No more python-side direct reference
    gc.collect() # Force gc : code below would crash without keep-alive logic
    assert objcom.Release() == 1
    assert objcom.OnCall(None) == 1 # Count the number of call : proof of correct python-side execution
    assert objcom.OnCall(None) == 2
    gc.collect()
    assert objcom.OnCall(None) == 3
    assert objcom.Release() == 0 # trigger Revoke / free !
    gc.collect()
    assert wref() is None # Check object is dead in python world
