import sys
import pytest
import os.path
import time

import windows.rpc as rpc
from windows.rpc import ndr
import windows.generated_def as gdef

from .pfwtest import *



UAC_UIID = "201ef99a-7fa0-444c-9399-19ba84f12a1a"

def start_uac_service():
    appinfo_service = windows.system.services["AppInfo"]
    if appinfo_service.status.state == gdef.SERVICE_RUNNING:
        return False
    if appinfo_service.status.state != gdef.SERVICE_START_PENDING:
        appinfo_service.start()
    time.sleep(1) # Wait if just started or not marked as running yet
    return True



def test_rpc_epmapper():
    start_uac_service()
    endpoints = windows.rpc.find_alpc_endpoints(UAC_UIID)
    assert endpoints
    endpoint = endpoints[0]
    assert endpoint.protseq == "ncalrpc"
    assert endpoint.endpoint
    assert endpoint.object.Uuid.to_string().lower() == UAC_UIID


# NDR Descriptions
class NDRPoint(ndr.NdrStructure):
    MEMBERS = [ndr.NdrLong, ndr.NdrLong]

class NdrUACStartupInfo(ndr.NdrStructure):
    MEMBERS = [ndr.NdrUniquePTR(ndr.NdrWString),
                ndr.NdrLong,
                ndr.NdrLong,
                ndr.NdrLong,
                ndr.NdrLong,
                ndr.NdrLong,
                ndr.NdrLong,
                ndr.NdrLong,
                ndr.NdrLong,
                ndr.NdrLong,
                NDRPoint]

class UACParameters(ndr.NdrParameters):
    MEMBERS = [ndr.NdrUniquePTR(ndr.NdrWString),
                ndr.NdrUniquePTR(ndr.NdrWString),
                ndr.NdrLong,
                ndr.NdrLong,
                ndr.NdrWString,
                ndr.NdrWString,
                NdrUACStartupInfo,
                ndr.NdrLong,
                ndr.NdrLong]

class NdrProcessInformation(ndr.NdrParameters):
    MEMBERS = [ndr.NdrLong] * 4


def test_rpc_uac_call():
    start_uac_service()
    client = windows.rpc.find_alpc_endpoint_and_connect(UAC_UIID)
    iid = client.bind(UAC_UIID)

    python_path = sys.executable
    python_name = os.path.basename(python_path)

    # Marshalling parameters.
    parameters = UACParameters.pack([
        python_path + "\x00", # Application Path
        python_path + "\x00", # Commandline
        0, # UAC-Request Flag
        gdef.CREATE_UNICODE_ENVIRONMENT, # dwCreationFlags
        "\x00", # StartDirectory
        "WinSta0\\Default\x00", # Station
            # Startup Info
            (None, # Title
            0, # dwX
            0, # dwY
            0, # dwXSize
            0, # dwYSize
            0, # dwXCountChars
            0, # dwYCountChars
            0, # dwFillAttribute
            0, # dwFlags
            5, # wShowWindow
            # Point structure: Use MonitorFromPoint to setup StartupInfo.hStdOutput
            (0, 0)),
        0, # Window-Handle to know if UAC can steal focus
        0xffffffff]) # UAC Timeout


    result = client.call(iid, 0, parameters)
    stream = ndr.NdrStream(result)

    ph, th, pid, tid = NdrProcessInformation.unpack(stream)
    return_value = ndr.NdrLong.unpack(stream)
    assert ph
    assert pid
    assert th
    assert tid
    windows.winproxy.CloseHandle(th) # NoLeak
    proc = windows.WinProcess(handle=ph)
    assert proc.name == python_name
    assert proc.pid == pid
    proc.exit(0)


class DbgRpcClient(windows.rpc.RPCClient):
    def __init__(self, *args, **kwargs):
        super(DbgRpcClient, self).__init__(*args, **kwargs)
        self.last_response_was_view = False

    def _get_response_effective_data(self, response):
        self.last_response_was_view = response.view_is_valid
        return super(DbgRpcClient, self)._get_response_effective_data(response)


FIREWALL_RPC_IID = "2fb92682-6599-42dc-ae13-bd2ca89bd11c"

Proc0_RPC_FWOpenPolicyStore = 0
Proc9_RPC_FWEnumFirewallRules = 9

def test_rpc_response_as_view():
    """Check that parsing response as view in RPC Client works. Testing after a bug in 32b RPCCLient"""
    # We test what by using a RPC endpoint that returns a lot of info : forcing a response in a view
    # In this case we use the Firewall RPC and we list all Firerules.
    # We use a custom RPCClient subclasse to track if last response was a view
    client = windows.rpc.find_alpc_endpoint_and_connect(FIREWALL_RPC_IID, sid=gdef.WinLocalSid)
    client.__class__ = DbgRpcClient
    iid = client.bind(FIREWALL_RPC_IID)

    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/230d1ae7-b42e-4d9c-b997-b1463aaa0ded
    # !\x02\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00
    # Binaryversion : 0x022f
    # FW_STORE_TYPE_LOCAL
    # FW_POLICY_ACCESS_RIGHT_READ
    # Flags = 0
    resp1 = client.call(iid, Proc0_RPC_FWOpenPolicyStore, params=b"!\x02\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00")
    rawpolstore = resp1[:20]
    assert not client.last_response_was_view

    # Proc9_RPC_FWEnumFirewallRules
    # \x00\x00\x03\x00\xff\xff\xff\x7f\x07\x00
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/36cddff4-c427-4863-a58d-3d913a12b221
    # FW_PROFILE_TYPE_ALL : 0x7FFFFFFF
    # FW_RULE_STATUS_CLASS_OK +  FW_RULE_STATUS_PARTIALLY_IGNORED = 0x00010000 + 0x00020000
    # Flags = 7 ?
    resp2 = client.call(iid, Proc9_RPC_FWEnumFirewallRules, params=rawpolstore + b"\x00\x00\x03\x00\xff\xff\xff\x7f\x07\x00")
    assert client.last_response_was_view
