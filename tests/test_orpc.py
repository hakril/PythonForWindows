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



# Test ORPC capabilities by manually connecting to a DCOM Object and querying a simple method
# The server choosen is A47979D2-C419-11D9-A5B4-001185AD2B89 (Service C:\Windows\System32\netprofmsvc.dll)
#   Target is INetWorkListManager->17 which should return a simple byte about network state
def test_orpc_network_manager():
    iid = gdef.GUID.from_string("D0074FFD-570F-4A9B-8D69-199FDBA5723B")
    client, ipid = windows.rpc.stubborn.stubborn_create_instance("A47979D2-C419-11D9-A5B4-001185AD2B89", iid)
    response = client.call(iid, 17, b"", ipid=ipid)
    import pdb;pdb.set_trace()
    assert response[0] not in (b"\x00", 0)

