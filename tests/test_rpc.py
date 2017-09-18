import pytest
import os.path

import windows.rpc as rpc
from windows.rpc import ndr
import windows.generated_def as gdef

from pfwtest import *



UAC_UIID = "201ef99a-7fa0-444c-9399-19ba84f12a1a"



def test_rpc_epmapper():
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
    client = windows.rpc.find_alpc_endpoint_and_connect(UAC_UIID)
    iid = client.bind(UAC_UIID)

    python_path = 'C:\\Python27\\python.exe'
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
    proc.exit(0)

