# -*- coding: utf-8 -*-

import pytest
import windows

from .pfwtest import *


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

# Test unicode string in Kernel object using an ALPC port

UNICODE_PORT_NAME = u"こんにちは、世界！"
UNICODE_PORT_PATH = u"\\RPC Control\\" + UNICODE_PORT_NAME

def test_unicode_kernel_object():
    alpc_port = windows.alpc.AlpcServer(UNICODE_PORT_PATH)
    assert UNICODE_PORT_NAME in objmanager[u"\\RPC Control"].keys()
    assert objmanager[UNICODE_PORT_PATH]
    assert objmanager[UNICODE_PORT_PATH].fullname == UNICODE_PORT_PATH
    import pdb;pdb.set_trace()
    alpc_port.disconnect()