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
        self.oncall = 0

    def OnCall(self, This, pFrame):
        self.oncall += 1
        return self.oncall

def test_com_implementation_simple():
    obj = ICallFrameEventsImplemSimple()
    assert obj._com_refcount == 1
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
    assert obj._com_refcount == 2 # +1 on QueryInterface
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


# Test multiple interface code

class SimpleMultipleInterfaceImplem(windows.com.COMImplementation):
    IMPLEMENT = [
        gdef.ICallFrameEvents, # OnCall
        gdef.IPersist # GetClassID
    ]

    def __init__(self):
        super(SimpleMultipleInterfaceImplem, self).__init__()
        self.oncall = 0
        self.getclassid = 0
        self.global_call = 0 # Proof this is the same object

    def OnCall(self, This, pFrame):
        self.oncall += 1
        self.global_call += 1
        return self.oncall

    def GetClassID(self, This, pClassID):
        self.getclassid += 1
        self.global_call += 1
        return self.getclassid

def test_com_multiple_implementation_no_collision():
    obj = SimpleMultipleInterfaceImplem()
    with pytest.raises(ValueError):
        x = obj._as_parameter_ # _as_parameter_ cannot be ask directly on object implementing multiple interfaces

    # Create a C-like pointer from the interface
    objcom = gdef.ICallFrameEvents(obj.as_interface(gdef.ICallFrameEvents))
    assert objcom.OnCall(None) == 1 # Count the number of call : proof of correct python-side execution
    assert objcom.OnCall(None) == 2
    assert obj.global_call == 2

    objcom2 = gdef.IPersist(obj.as_interface(gdef.IPersist))
    assert objcom2.GetClassID(None) == 1 # Count the number of call : proof of correct python-side execution
    assert objcom2.GetClassID(None) == 2
    assert obj.global_call == 4



def test_com_multiple_implementation_query_interface():
    obj = SimpleMultipleInterfaceImplem()
    iunk = gdef.IUnknown()
    # Emulate a call from C code
    obj.QueryInterface(obj.as_interface(gdef.ICallFrameEvents), ctypes.pointer(gdef.IUnknown.IID), ctypes.pointer(iunk))
    assert obj._com_refcount == 2
    assert iunk.value
    assert iunk.value in obj._vtables_ptr.values()
    # Use the standard C/ctypes Iunknown pointer to query other types and verify pointer/refcount
    assert iunk.query(gdef.ICallFrameEvents).value == obj._vtables_ptr[str(gdef.ICallFrameEvents.IID)]
    assert obj._com_refcount == 3
    assert iunk.query(gdef.IPersist).value == obj._vtables_ptr[str(gdef.IPersist.IID)]
    assert obj._com_refcount == 4


class CollisionMultipleInterfaceImplem(windows.com.COMImplementation):
    # Both share the same root & have "Invoke"
    IMPLEMENT = [
        gdef.IIdleSettings, # Invoke
        gdef.ITaskFolderCollection, # Invoke
    ]

    def __init__(self):
        super(CollisionMultipleInterfaceImplem, self).__init__()
        self.iidlesettings_invoke = 0
        self.itaskfoldercollection_invoke = 0

    def IIdleSettings_Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
        print('IIdleSettings.Invoke')
        self.iidlesettings_invoke += 1
        return self.iidlesettings_invoke

    def ITaskFolderCollection_Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
        print('ITaskFolderCollection.Invoke')
        self.itaskfoldercollection_invoke += 1
        return self.itaskfoldercollection_invoke

    def not_implemented(self, *args):
        return gdef.E_NOTIMPL

    # IIdleSettings

    IIdleSettings_GetTypeInfoCount = not_implemented
    IIdleSettings_GetTypeInfo = not_implemented
    IIdleSettings_GetIDsOfNames = not_implemented
    get_IdleDuration = not_implemented
    put_IdleDuration = not_implemented
    get_WaitTimeout = not_implemented
    put_WaitTimeout = not_implemented
    get_StopOnIdleEnd = not_implemented
    put_StopOnIdleEnd = not_implemented
    get_RestartOnIdle = not_implemented
    put_RestartOnIdle = not_implemented

    # ITaskFolderCollection

    ITaskFolderCollection_GetTypeInfoCount = not_implemented
    ITaskFolderCollection_GetTypeInfo = not_implemented
    ITaskFolderCollection_GetIDsOfNames = not_implemented
    get_Count = not_implemented
    get_Item = not_implemented
    get__NewEnum = not_implemented


def test_com_multiple_implementation_with_collision():
    obj = CollisionMultipleInterfaceImplem()
    assert obj

    # Emulate a call from C code : check that as_interface() indeed return an COMInterface subclasse of correct type
    iunk = obj.as_interface(gdef.IUnknown)
    assert isinstance(iunk, gdef.IUnknown)
    assert isinstance(obj.as_interface(gdef.ITaskFolderCollection), gdef.ITaskFolderCollection)

    # If we only give an IID: return a Iunknown for simple pvoid casting
    assert isinstance(obj.as_interface(iid=gdef.ITaskFolderCollection.IID), gdef.IUnknown)

    idlesetting = iunk.query(gdef.IIdleSettings)
    taskfoldercollection = iunk.query(gdef.ITaskFolderCollection)
    taskfoldercollection.Invoke(0, None, 0, 0, None, None, None, None)
    assert obj.itaskfoldercollection_invoke == 1
    assert obj.iidlesettings_invoke == 0
    taskfoldercollection.Invoke(0, None, 0, 0, None, None, None, None)
    assert obj.itaskfoldercollection_invoke == 2
    assert obj.iidlesettings_invoke == 0
    idlesetting.Invoke(0, None, 0, 0, None, None, None, None)
    assert obj.itaskfoldercollection_invoke == 2
    assert obj.iidlesettings_invoke == 1