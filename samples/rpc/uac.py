import argparse
import sys

import windows.rpc
import windows.generated_def as gdef
from windows.rpc import ndr

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

class RAiLaunchAdminProcessParameters(ndr.NdrParameters):
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

# Parsing args
parser = argparse.ArgumentParser(prog=__file__)
parser.add_argument('--target', default=sys.executable, help='Executable to launch')
parser.add_argument('--cmdline', default="", help='The commandline for the process')
parser.add_argument('--uacflags', type=lambda x: int(x, 0), default=0x11)
parser.add_argument('--creationflags', type=lambda x: int(x, 0), default=gdef.CREATE_UNICODE_ENVIRONMENT)
params = parser.parse_args()
print(params)

# Connecting to RPC Interface.
UAC_UIID = "201ef99a-7fa0-444c-9399-19ba84f12a1a"
client = windows.rpc.find_alpc_endpoint_and_connect(UAC_UIID)
iid = client.bind(UAC_UIID)

# Marshalling parameters.
parameters = RAiLaunchAdminProcessParameters.pack([
    params.target, # Application Path
    params.cmdline, # Commandline
    params.uacflags, # UAC-Request Flag
    params.creationflags, # dwCreationFlags
    "", # StartDirectory
    "WinSta0\\Default", # Station
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
print("Return value = {0:#x}".format(return_value))
target = windows.winobject.process.WinProcess(handle=ph)
print("Created process is {0}".format(target))
print(" * bitness is {0}".format(target.bitness))
print(" * integrity: {0}".format(target.token.integrity))
print(" * elevated: {0}".format(target.token.is_elevated))