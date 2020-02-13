import struct
from collections import namedtuple

import windows
import windows.generated_def as gdef
from windows.rpc import ndr
from windows.dbgprint import dbgprint
from windows.pycompat import basestring



class NdrTower(ndr.NdrStructure):
    MEMBERS = [ndr.NdrLong, ndr.NdrByteConformantArray]

    @classmethod
    def post_unpack(cls, data):
        size = data[0]
        tower = data[1]
        return bytearray(struct.pack("<I", size)) + bytearray(tower)


class NdrContext(ndr.NdrStructure):
    MEMBERS = [ndr.NdrLong, ndr.NdrLong, ndr.NdrLong, ndr.NdrLong, ndr.NdrLong]


class NDRIID(ndr.NdrStructure):
    MEMBERS = [ndr.NdrByte] * 16


class EptMapAuthParameters(ndr.NdrParameters):
    MEMBERS = [NDRIID,
                NdrTower,
                ndr.NdrUniquePTR(ndr.NdrSID),
                NdrContext,
                ndr.NdrLong]


class Towers(ndr.NdrConformantVaryingArrays):
    MEMBER_TYPE = ndr.NdrUniquePTR(NdrTower)


class EptMapAuthResults(ndr.NdrParameters):
    MEMBERS = [NdrContext,
                ndr.NdrLong,
                Towers]

UnpackTower = namedtuple("UnpackTower", ["protseq", "endpoint", "address", "object", "syntax"])

def parse_floor(stream):
    lhs_size = stream.partial_unpack("<H")[0]
    lhs = stream.read(lhs_size)
    rhs_size = stream.partial_unpack("<H")[0]
    rhs = stream.read(rhs_size)
    return lhs, rhs

def craft_floor(lhs, rhs):
    return struct.pack("<H", len(lhs)) + lhs + struct.pack("<H", len(rhs))  + rhs

def explode_alpc_tower(tower):
    stream = ndr.NdrStream(bytearray(tower))
    size = stream.partial_unpack("<I")[0]
    if size != len(stream.data):
        raise ValueError("Invalid tower size: indicate {0}, tower size {1}".format(size, len(stream.data)))
    floor_count = stream.partial_unpack("<H")[0]
    if floor_count != 4:
        raise ValueError("ALPC Tower are expected to have 4 floors ({0} instead)".format(floor_count))

    # Floor 0
    lhs, rhs = parse_floor(stream)
    if not (lhs[0] == 0xd):
        raise ValueError("Floor 0: IID expected")
    iid =  gdef.IID.from_buffer_copy(lhs[1:17])
    object = gdef.RPC_IF_ID(iid, lhs[17], lhs[18])

    # Floor 1
    lhs, rhs = parse_floor(stream)
    if not (lhs[0] == 0xd):
        raise ValueError("Floor 0: IID expected")
    iid =  gdef.IID.from_buffer_copy(lhs[1:17])
    syntax = gdef.RPC_IF_ID(iid, lhs[17], lhs[18])

    # Floor 2
    lhs, rhs = parse_floor(stream)
    if (len(lhs) != 1 or lhs[0] != 0x0c):
        raise ValueError("Alpc Tower expects 0xc as Floor2 LHS (got {0:#x})".format(lhs[0]))

    lhs, rhs = parse_floor(stream)
    if not (rhs[-1] == 0):
        rhs = rhs[:rhs.find("\x00")]
        # raise ValueError("ALPC Port name doest not end by \\x00")
    return UnpackTower("ncalrpc", bytes(rhs[:-1]), None, object, syntax)

# http://pubs.opengroup.org/onlinepubs/9629399/apdxi.htm#tagcjh_28
# Octet 0 contains the hexadecimal value 0d. This is a reserved protocol identifier prefix that indicates that the protocol ID is UUID derived
TOWER_PROTOCOL_IS_UUID = b"\x0d"
TOWER_EMPTY_RHS = b"\x00\x00"
TOWER_PROTOCOL_ID_ALPC = b"\x0c" # From RE

def construct_alpc_tower(object, syntax, protseq, endpoint, address):
    if address is not None:
        raise NotImplementedError("Construct ALPC Tower with address != None")
    if protseq != "ncalrpc":
        raise NotImplementedError("Construct ALPC Tower with protseq != 'ncalrpc'")
    # Floor 0
    floor_0_lsh = TOWER_PROTOCOL_IS_UUID + bytearray(object.Uuid) + struct.pack("<BB", object.VersMajor, object.VersMinor)
    floor_0_rsh = TOWER_EMPTY_RHS
    floor_0 = craft_floor(floor_0_lsh, floor_0_rsh)
    # Floor 1
    floor_1_lsh = TOWER_PROTOCOL_IS_UUID + bytearray(syntax.Uuid) + struct.pack("<BB", syntax.VersMajor, syntax.VersMinor)
    floor_1_rsh = TOWER_EMPTY_RHS
    floor_1 = craft_floor(floor_1_lsh, floor_1_rsh)
    # Floor 2
    floor_2_lsh = TOWER_PROTOCOL_ID_ALPC
    floor_2_rsh = TOWER_EMPTY_RHS
    floor_2 = craft_floor(floor_2_lsh, floor_2_rsh)
    # Floor 3
    if endpoint is None:
        floor_3_lsh = b"\xff"
        floor_3_rsh = TOWER_EMPTY_RHS
        floor_3 = craft_floor(floor_3_lsh, floor_3_rsh)
    else:
        floor_3_lsh = b"\x10"
        floor_3_rsh = endpoint
        floor_3 = craft_floor(floor_3_lsh, floor_3_rsh)
    towerarray = struct.pack("<H", 4) +  floor_0 + floor_1 + floor_2 + floor_3
    return len(towerarray), bytearray(towerarray)

def find_alpc_endpoints(targetiid, version=(1,0), nb_response=1, sid=gdef.WinLocalSystemSid):
    """Ask the EPMapper for ALPC endpoints of ``targetiid:version`` (maximum of ``nb_response``)

        :param str targetiid: The IID of the requested interface
        :param (int,int) version: The version requested interface
        :param int nb_response: The maximum number of response
        :param WELL_KNOWN_SID_TYPE sid: The SID used to request the EPMapper

        :returns: [:class:`~windows.rpc.epmapper.UnpackTower`] -- A list of :class:`~windows.rpc.epmapper.UnpackTower`
    """

    if isinstance(targetiid, basestring):
        targetiid = gdef.IID.from_string(targetiid)
    # Connect to epmapper
    client = windows.rpc.RPCClient(r"\RPC Control\epmapper")
    epmapperiid = client.bind("e1af8308-5d1f-11c9-91a4-08002b14a0fa", version=(3,0))

    # Compute request tower
    ## object
    rpc_object = gdef.RPC_IF_ID(targetiid, *version)
    ## Syntax
    syntax_iid = gdef.IID.from_string("8a885d04-1ceb-11c9-9fe8-08002b104860")
    rpc_syntax = gdef.RPC_IF_ID(syntax_iid, 2, 0)
    ## Forge tower
    tower_array_size, towerarray = construct_alpc_tower(rpc_object, rpc_syntax, "ncalrpc", b"", None)

    # parameters
    local_system_psid = windows.utils.get_known_sid(sid)
    context = (0, 0, 0, 0, 0)

    # Pack request
    fullreq = EptMapAuthParameters.pack([bytearray(targetiid),
                                            (tower_array_size, towerarray),
                                            local_system_psid,
                                            context,
                                            nb_response])
    # RPC Call
    response = client.call(epmapperiid, 7, fullreq)
    # Unpack response
    stream = ndr.NdrStream(response)
    unpacked = EptMapAuthResults.unpack(stream)
    # Looks like there is a memory leak here (in stream.data) if nb_response > len(unpacked[2])
    # Parse towers
    return [explode_alpc_tower(obj) for obj in unpacked[2]]


def find_alpc_endpoint_and_connect(targetiid, version=(1,0), sid=gdef.WinLocalSystemSid):
    """Ask the EPMapper for ALPC endpoints of ``targetiid:version`` and connect to one of them.

        :param str targetiid: The IID of the requested interface
        :param (int,int) version: The version requested interface
        :param WELL_KNOWN_SID_TYPE sid: The SID used to request the EPMapper

        :returns: A connected :class:`~windows.rpc.RPCClient`
    """
    dbgprint("Finding ALPC endpoints for  <{0}>".format(targetiid), "RPC")
    alpctowers = find_alpc_endpoints(targetiid, version, nb_response=50, sid=sid)
    dbgprint("ALPC endpoints list: <{0}>".format(alpctowers), "RPC")
    for tower in alpctowers:
        dbgprint("Trying to connect to endpoint <{0}>".format(tower.endpoint), "RPC")
        alpc_port = r"\RPC Control\{0}".format(tower.endpoint.decode())
        try:
            client = windows.rpc.RPCClient(alpc_port)
        except Exception as e:
            dbgprint("Could not connect to endpoint <{0}>: {1}".format(tower.endpoint, e), "RPC")
            continue
        break
    else:
        raise ValueError("Could not find a valid endpoint for target <{0}> version <{1}>".format(targetiid, version))
    dbgprint('Connected to ALPC port "{0}"'.format(alpc_port), "RPC")
    return client

