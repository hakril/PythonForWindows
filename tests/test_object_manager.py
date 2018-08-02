import pytest
import windows

from pfwtest import *


KNOWN_DIRECTORY_OBJECT = ("KnownDLLs", "\\KnownDLLs")

objmanager = windows.system.object_manager

@pytest.mark.parametrize("objname", KNOWN_DIRECTORY_OBJECT)
def test_directory_object(objname):
    obj = objmanager[objname]
    if "\\" not in objname:
        assert obj.name == objname
    else:
        assert obj.fullname == objname
    assert obj.type == "Directory"
    assert obj.target is None
    assert list(obj)
    assert obj["kernel32.dll"]
    assert obj.items()
    assert obj.keys()
    assert obj.values()

@pytest.mark.parametrize("objname", KNOWN_DIRECTORY_OBJECT)
def test_multiple_access_type(objname):
    assert objmanager[objname]
    assert objmanager.root[objname]


def test_complex_object_path():
    obj = objmanager["\\KnownDLLs\\kernel32.dll"]
    assert obj.name == "kernel32.dll"
    assert obj.fullname == "\\KnownDLLs\\kernel32.dll"
    assert obj.path == "\\KnownDLLs"
    assert obj.type == "Section"
    assert obj.target is None


def test_link_object():
    obj = objmanager["\\KnownDLLs\\KnownDLLPath"]
    assert obj.type == "SymbolicLink"
    assert obj.target.lower() == "c:\windows\system32"