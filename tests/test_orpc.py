import sys
import pytest
import os.path
import time

import windows.rpc.stubborn
import windows.rpc as rpc
from windows.rpc import ndr
import windows.generated_def as gdef

from .pfwtest import *

# Test ORPC capabilities by manually connecting to a DCOM Object and querying a simple method
# The server choosen is 0002DF01-0000-0000-C000-000000000046 (Internet Explorer)
#   Target is IWebBrowser2->get_FullName which should return a path to iexplorer
#   A second check about in parameters can be done with put_Left / get_Left or put_Visible
def test_orpc_iexplore():
    iid = gdef.IWebBrowser2.IID
    client, ipid = windows.rpc.stubborn.stubborn_create_instance("0002DF01-0000-0000-C000-000000000046", iid)

    # get_FullName
    addrep = client.call(iid, 38, b"", ipid=ipid)
    assert addrep.startswith(b"User") # NdrUserMarshalMarshall setup 'User' as first DWORD
    fullname = addrep[4 * 4:].decode("utf-16-le").rstrip("\x00") # User | Size | Flags | Size of NDR BSTR
    assert fullname.lower().endswith("iexplore.exe")

    # put_Visible
    # addrep = client.call(iid, 41, b"\x01\x00\x00\x00", ipid=ipid)

    # put_Left
    addrep = client.call(iid, 22, b"\x42\x00\x00\x00", ipid=ipid)

    # get_Left
    addrep = client.call(iid, 21, b"0", ipid=ipid)
    # py2/py3
    assert addrep[0] in (b"B", 66) # Check that put_Left worked and this LOCALTHIS is correct of send

    # Quit
    client.call(iid, 32, b"", ipid=ipid)

# Test ORPC capabilities by manually connecting to a DCOM Object and querying a simple method
# The server choosen is A47979D2-C419-11D9-A5B4-001185AD2B89 (Service C:\Windows\System32\netprofmsvc.dll)
#   Target is INetWorkListManager->GetConnectivity (17) which should return a simple byte about network state
#   IsConnectedToInternet(15) / IsConnected(16) should works too
def test_orpc_network_manager():
    """ORPC: Testing ORPCTHAT size using a method that takes no arguments and returns a single bytes"""
    iid = gdef.GUID.from_string("D0074FFD-570F-4A9B-8D69-199FDBA5723B")
    client, ipid = windows.rpc.stubborn.stubborn_create_instance("A47979D2-C419-11D9-A5B4-001185AD2B89", iid)
    response = client.call(iid, 17, b"", ipid=ipid)
    assert response[0] not in (b"\x00", 0)

