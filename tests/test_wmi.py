import pytest

import windows
import windows.generated_def as gdef
from windows.pycompat import basestring

from .pfwtest import *

## This comment was in test_system.py: still revelant ?
# Well, pytest initialize COM with its own parameters
# It might make our own com.init() in WMI fail and therefore not call
# CoInitializeSecurity. But looks like pytest/default COM-security parameters
# does not allow to perform the request we want..
# So we try & do it ourself here.

pytestmark = pytest.mark.usefixtures("init_com_security")

@pytest.mark.parametrize("name, expected_cls", [
    ("root\\cimv2", "Win32_Process"),
    ("root\\subscription", "__EventFilter"),
    ])
def test_wmimanager_getnamespace(name, expected_cls):
    namespace = windows.system.wmi[name]
    assert namespace.name == name
    assert namespace.get_object(expected_cls)


def test_wmimanager_subnamespaces():
    subnamespaces = windows.system.wmi.get_subnamespaces("root")
    subnamespaces = [x.lower() for x in subnamespaces]
    assert "cimv2" in subnamespaces
    assert "security" in subnamespaces
    assert "subscription" in subnamespaces

# Test WmiNamespace

@pytest.mark.parametrize("name, query",[
    ("root\\cimv2", "select * from Win32_Process"),
    ("root\\subscription", "select * from __EventFilter"),
    ])
def test_query_select(name, query):
    namespace = windows.system.wmi[name]
    x = namespace.query(query)
    assert x
    assert isinstance(x, list)


def test_bad_query_raise():
    namespace = windows.system.wmi["root\\cimv2"]
    with pytest.raises(WindowsError) as e:
        x = namespace.query("BADSELECT QUERY BAD")
    assert (e.value.winerror & 0xffffffff) == gdef.WBEM_E_INVALID_QUERY

def test_create_class_enum():
    namespace = windows.system.wmi["root\\cimv2"]
    enum = namespace.create_class_enum(None)
    assert enum
    classes = list(enum)
    cls_names = [cls["__CLASS"].lower() for cls in classes]
    assert "win32_process" in cls_names
    assert "win32_shortcutfile" in cls_names
    assert "__win32provider" in cls_names

@pytest.mark.parametrize("name, cls", [
    ("root\\cimv2", "Win32_Process"),
    ("root\\subscription", "__EventFilter"),
    ])
def test_get_object(name, cls):
    namespace = windows.system.wmi[name]
    assert namespace.name == name
    obj = namespace.get_object(cls)
    assert obj["__CLASS"] == cls
    assert obj["__PATH"]

# Todo: test
#   - put_instance

@pytest.mark.parametrize("cmdline", [r"winver.exe test_string_pfw"])
def test_exec_method_Win32_Process_create(cmdline):
    namespace = windows.system.wmi["root\\cimv2"]
    win32_process_cls = namespace.get_object("Win32_Process")
    inparam = win32_process_cls.get_method("Create").inparam.spawn_instance()
    inparam["CommandLine"] = cmdline
    result = namespace.exec_method(win32_process_cls, "Create", inparam)
    assert result
    assert not result["ReturnValue"]
    assert result["ProcessId"]
    proc = windows.WinProcess(pid=result["ProcessId"])
    assert proc.peb.commandline.str == cmdline
    proc.exit(0)


## Test enum
def test_enumeration_iteration_no_timeout():
    namespace = windows.system.wmi["root\\cimv2"]
    processes = namespace.exec_query("select * from Win32_Process").all()
    assert isinstance(processes, list)
    assert processes
    processes = list(namespace.exec_query("select * from Win32_Process"))
    assert processes
    assert isinstance(processes, list)
    proc = namespace.exec_query("select * from Win32_Process").next()
    assert proc
    assert proc["__CLASS"].lower() == "win32_process"

def test_enumeration_iteration_timeout():
    namespace = windows.system.wmi["root\\cimv2"]
    timegen = namespace.exec_query("select * from Win32_Process").iter_timeout(0)
    # Iter on Win32_Process should not be immediat
    # so itering on timegen should trigger a timeout
    with pytest.raises(WindowsError) as e:
        x = list(timegen)
    assert (e.value.winerror & 0xffffffff) == gdef.WBEM_S_TIMEDOUT


@pytest.fixture
def wmi_cls():
    # Test expect the cls to have a "Name" attribute & "Create" method
    # Maybe doing something more generic
    namespace = windows.system.wmi["root\\cimv2"]
    yield namespace.get_object("Win32_Process")

def test_wmiobject_spawn(wmi_cls):
    assert wmi_cls["__Genus"] == wmi_cls.genus == gdef.WBEM_GENUS_CLASS
    wmi_obj = wmi_cls()
    assert wmi_obj["__Genus"] == wmi_obj.genus == gdef.WBEM_GENUS_INSTANCE
    assert wmi_obj["__CLASS"] == wmi_cls["__CLASS"]

def test_wmiobject_getitem(wmi_cls):
    assert wmi_cls["Name"] is None
    wmi_obj = wmi_cls()
    assert wmi_obj["Name"] is None
    with pytest.raises(WindowsError) as e:
        wmi_obj["BAD_NAME"]
    assert (e.value.winerror & 0xffffffff) == gdef.WBEM_E_NOT_FOUND
    # Complexe type
    assert isinstance(wmi_obj["__CLASS"], basestring)
    assert isinstance(wmi_obj["__PROPERTY_COUNT"], int)
    assert isinstance(wmi_obj["__DERIVATION"], list)

    props = wmi_obj.get_properties()
    assert isinstance(props, list)
    assert len(props) == wmi_obj["__PROPERTY_COUNT"]
    # Check that other dict-like methods exists
    assert wmi_obj.keys()
    assert wmi_obj.values()
    assert wmi_obj.items()


def test_wmiobject_getmethod(wmi_cls):
    wmi_method = wmi_cls.get_method("Create")
    # Wmi method is a custom PFW object (namedtuple)
    assert wmi_method
    assert wmi_method.inparam
    inparam_attrs = wmi_method.inparam.keys()
    assert "CommandLine" in inparam_attrs
    assert wmi_method.outparam
    outparam_attrs = wmi_method.outparam.keys()
    assert "ProcessId" in outparam_attrs

def test_wmiobject_setitem(wmi_cls):
    wmi_obj = wmi_cls()
    assert wmi_obj["Name"] is None
    wmi_obj["Name"] = "Test"
    assert wmi_obj["Name"] == "Test"
    # Strange but that how WMI api works with variant :D
    wmi_obj["Name"] = 2
    assert wmi_obj["Name"] == "2"
    with pytest.raises(WindowsError) as e:
        wmi_obj["PageFaults"] = "ERROR_BAD_INT"
    assert (e.value.winerror & 0xffffffff) == gdef.WBEM_E_TYPE_MISMATCH
    with pytest.raises(WindowsError) as e:
        wmi_obj["__PROPERTY_COUNT"] = 42
    assert (e.value.winerror & 0xffffffff) == gdef.WBEM_E_READ_ONLY




