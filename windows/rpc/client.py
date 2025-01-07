import ctypes
import struct

import windows.alpc as alpc
import windows.com
import windows.generated_def as gdef

if windows.pycompat.is_py3:
    buffer = bytes


KNOW_REQUEST_TYPE = gdef.FlagMapper(gdef.RPC_REQUEST_TYPE_CALL, gdef.RPC_REQUEST_TYPE_BIND)
KNOW_RESPONSE_TYPE = gdef.FlagMapper(gdef.RPC_RESPONSE_TYPE_FAIL, gdef.RPC_RESPONSE_TYPE_SUCCESS, gdef.RPC_RESPONSE_TYPE_BIND_OK)
KNOWN_RPC_ERROR_CODE = gdef.FlagMapper(
        gdef.ERROR_INVALID_HANDLE,
        gdef.RPC_X_BAD_STUB_DATA,
        gdef.RPC_E_INVALID_HEADER,
        gdef.RPC_E_DISCONNECTED,
        gdef.RPC_S_UNKNOWN_IF,
        gdef.RPC_S_PROTOCOL_ERROR,
        gdef.RPC_S_UNSUPPORTED_TRANS_SYN,
        gdef.RPC_S_PROCNUM_OUT_OF_RANGE)

NOT_USED = 0xBAADF00D

class ALPC_RPC_BIND(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("request_type", gdef.DWORD),
        ("UNK1", gdef.DWORD),
        ("UNK2", gdef.DWORD),
        ("target", gdef.RPC_IF_ID),
        ("flags", gdef.DWORD),
        ("if_nb_ndr32", gdef.USHORT),
        ("if_nb_ndr64", gdef.USHORT),
        ("if_nb_unkn", gdef.USHORT),
        ("PAD", gdef.USHORT),
        ("register_multiple_syntax", gdef.DWORD),
        ("use_flow", gdef.DWORD),
        ("UNK5", gdef.DWORD),
        ("maybe_flow_id", gdef.DWORD),
        ("UNK7", gdef.DWORD),
        ("some_context_id", gdef.DWORD),
        ("UNK9", gdef.DWORD),
    ]

class ALPC_RPC_CALL(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("request_type", gdef.DWORD),
        ("UNK1", gdef.DWORD),
        ("flags",gdef.DWORD),
        ("request_id", gdef.DWORD),
        ("if_nb", gdef.DWORD),
        ("method_offset", gdef.DWORD),
        ("UNK2", gdef.DWORD),
        ("UNK3", gdef.DWORD),
        ("UNK4", gdef.DWORD),
        ("UNK5", gdef.DWORD),
        ("UNK6", gdef.DWORD),
        ("UNK7", gdef.DWORD),
        ("orpc_ipid", gdef.GUID)
    ]

# Was an array of 6 DWORD, new class inspired by :
# https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/main/NtCoreLib/Win32/Rpc/Transport/Alpc/LRPC_IMMEDIATE_RESPONSE_MESSAGE.cs#L22

class ALPC_RPC_RESPONSE(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("request_type", gdef.DWORD),
        ("UNK1", gdef.DWORD),
        ("flags",gdef.DWORD),
        ("request_id", gdef.DWORD),
        ("UNK2", gdef.DWORD),
        ("UNK3", gdef.DWORD),
    ]

class RPCClient(object):
    """A client for RPC-over-ALPC able to bind to interface and perform calls using NDR32 marshalling"""
    REQUEST_IDENTIFIER = 0x42424242
    # Used to recognize ORPC call we made
    # thus we know the response contains a orpcthat & localthat
    REQUEST_IDENTIFIER_ORPC = 0x43434343

    def __init__(self, port):
        self.alpc_client = alpc.AlpcClient(port) #: The :class:`windows.alpc.AlpcClient` used to communicate with the server
        self.number_of_bind_if = 0 # if -> interface
        self.if_bind_number = {}

    def bind(self, iid, version=(1,0)):
        """Bind to the ``IID`` with the given ``version``

            :returns: :class:`windows.generated_def.IID`
        """
        if not isinstance(iid, gdef.GUID):
            iid = windows.com.IID.from_string(iid)
        request = self._forge_bind_request(iid, version, self.number_of_bind_if)
        response = self._send_request(request)
        # Parse reponse
        request_type = self._get_request_type(response)
        if request_type != gdef.RPC_RESPONSE_TYPE_BIND_OK:
            raise ValueError("Unexpected reponse type. Expected RESPONSE_TYPE_BIND_OK got {0}".format(KNOW_RESPONSE_TYPE[request_type]))
        iid_hash = hash(buffer(iid)[:]) # TODO: add __hash__ to IID
        self.if_bind_number[iid_hash] = self.number_of_bind_if
        self.number_of_bind_if += 1
        #TODO: attach version information to IID
        return iid

    def forge_alpc_request(self, IID, method_offset, params, ipid=None):
        """Craft an ALPC message containing an RPC request to call ``method_offset`` of interface ``IID`
        with ``params``.
        Can be used to craft request without directly sending it
        """
        iid_hash = hash(buffer(IID)[:])
        interface_nb = self.if_bind_number[iid_hash] # TODO: add __hash__ to IID
        if len(params) > 0x900: # 0x1000 - size of meta-data
            request = self._forge_call_request_in_view(interface_nb, method_offset, params, ipid=ipid)
        else:
            request = self._forge_call_request(interface_nb, method_offset, params, ipid=ipid)
        return request

    def call(self, IID, method_offset, params, ipid=None):
        """Call method number ``method_offset`` of interface ``IID`` with mashalled ``params``.
        Handle `ORPC calls <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/db1d5ce1-a783-4f3d-854c-dc44308e78fb>`_ via the `ipid` parameter.
            :param IID IID: An IID previously returned by :func:`bind`
            :param int method_offset:
            :param str params: The mashalled parameters (NDR32)
            :param GUID ipid: The IPID for `ORPC calls <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/db1d5ce1-a783-4f3d-854c-dc44308e78fb>`_
            :returns: :class:`str`

        .. note::

            Since `1.0.3` if the call is an ORPC call, the `ORPCTHAT` & `LOCALTHAT` present in the response are parsed and striped from the result.
        """
        request = self.forge_alpc_request(IID, method_offset, params, ipid=ipid)
        response = self._send_request(request)
        # Parse reponse
        request_type = self._get_request_type(response)
        if request_type != gdef.RPC_RESPONSE_TYPE_SUCCESS:
            raise ValueError("Unexpected reponse type. Expected RESPONSE_SUCCESS got {0}".format(KNOW_RESPONSE_TYPE[request_type]))
        return self._get_response_effective_data(response)
        # windows.utils.sprint(ALPC_RPC_CALL.from_buffer_copy(response + "\x00" * 12))
        # data = struct.unpack("<6I", response[:6 * 4])
        # assert data[3] == self.REQUEST_IDENTIFIER
        # return response[4 * 6:] # Should be the return value (not completly verified)

    def _send_request(self, request):
        return self.alpc_client.send_receive(request)

    def _forge_call_request(self, interface_nb, method_offset, params, ipid=None):
        # TODO: differents REQUEST_IDENTIFIER for each req ? Use REQUEST_IDENTIFIER to identify ORPC calls ?
        # TODO: what is this '0' ? (1 is also accepted) (flags ?)
        # request = struct.pack("<16I", gdef.RPC_REQUEST_TYPE_CALL, NOT_USED, 1, self.REQUEST_IDENTIFIER, interface_nb, method_offset, *[NOT_USED] * 10)
        req = ALPC_RPC_CALL()
        req.request_type = gdef.RPC_REQUEST_TYPE_CALL
        req.flags = 0
        req.request_id = self.REQUEST_IDENTIFIER
        req.if_nb = interface_nb
        req.method_offset = method_offset
        if ipid:
            req.request_id = self.REQUEST_IDENTIFIER_ORPC
            req.flags = 1 # We have a IPID
            req.orpc_ipid = ipid
            this = gdef.ORPCTHIS32() # we use NDR32
            this.version = (5,7)
            this.flags = gdef.ORPCF_LOCAL
            # Returned correct type with mandatory fields filed
            lthis = find_correct_localthis_for_version()
            return buffer(req)[:] + buffer(this)[:] + buffer(lthis)[:] + params
        return buffer(req)[:] + params

    def _forge_call_request_in_view(self, interface_nb, method_offset, params, ipid=None):
        # Version crade qui clean rien pour POC. GROS DOUTES :D
        if ipid:
            raise NotImplementedError("RpcClient._forge_call_request_in_view() with ipid")
        raw_request = self._forge_call_request(interface_nb, method_offset, b"")
        p = windows.alpc.AlpcMessage(0x2000)
        section = self.alpc_client.create_port_section(0x40000, 0, len(params))
        view = self.alpc_client.map_section(section[0], len(params))
        p.port_message.data = raw_request + windows.rpc.ndr.NdrLong.pack(len(params) + 0x200) + b"\x00" * 40
        p.attributes.ValidAttributes |= gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE
        p.view_attribute.Flags = 0x40000
        p.view_attribute.ViewBase = view.ViewBase
        p.view_attribute.SectionHandle = view.SectionHandle
        p.view_attribute.ViewSize = len(params)
        windows.current_process.write_memory(view.ViewBase, params) # Write NDR to view
        return p

    def _forge_bind_request(self, uuid, syntaxversion, requested_if_nb):
        version_major, version_minor = syntaxversion
        req = ALPC_RPC_BIND()
        req.request_type = gdef.RPC_REQUEST_TYPE_BIND
        req.target = gdef.RPC_IF_ID(uuid, *syntaxversion)
        req.flags = gdef.BIND_IF_SYNTAX_NDR32
        req.if_nb_ndr32 = requested_if_nb
        req.if_nb_ndr64 = 0
        req.if_nb_unkn = 0
        req.register_multiple_syntax = False
        req.some_context_id = 0xB00B00B
        return buffer(req)[:]

    def _get_request_type(self, response):
        """Response is a `AlpcMessage`"""
        "raise if request_type == RESPONSE_TYPE_FAIL"
        request_type = struct.unpack("<I", response.data[:4])[0]
        if request_type == gdef.RPC_RESPONSE_TYPE_FAIL:
            error_code = struct.unpack("<5I", response.data)[2]
            raise ValueError("RPC Response error {0} ({1!r})".format(error_code, KNOWN_RPC_ERROR_CODE.get(error_code, error_code)))
        return request_type

    def _get_response_effective_data(self, response):
        """Response is a `AlpcMessage` needed to handle response in message vs response in view"""
        response_header = ALPC_RPC_RESPONSE.from_buffer_copy(response.data)
        if not response.view_is_valid:
            # Reponse directly in PORT_MESSAGE
            data = response.data[ctypes.sizeof(ALPC_RPC_RESPONSE):]
        else:
            # Response in view M extract size from PORT_MESSAGE & read data from view
            assert response.port_message.u1.s1.TotalLength >= 0x48 # At least 0x20 of data
            rpcdatasize = struct.unpack("<I", response.data[0x18:0x1c])[0] # ctypes.sizeof(ALPC_RPC_RESPONSE)
            viewattr = response.view_attribute
            assert viewattr.ViewSize >= rpcdatasize
            data = windows.current_process.read_memory(viewattr.ViewBase, rpcdatasize)
        if response_header.request_id == self.REQUEST_IDENTIFIER_ORPC:
            # Parse & remove ORPC headers (orpcthat + LocalThat)
            orpcthat = gdef.ORPCTHAT32.from_buffer_copy(data)
            data = data[ctypes.sizeof(orpcthat):]
            if orpcthat.extensions != 0:
                print("Parsing extension !")
                # Parse extension : code have not been tested a lot
                write_array_extend = gdef.WireExtentArray.from_buffer_copy(data)
                data = data[ctypes.sizeof(gdef.WireExtentArray):]
                if write_array_extend.rounded_size != 2:
                    raise NotImplementedError("orpcthat.extensions: WireExtentArray.rounded_size != 2")
                for value in write_array_extend.unique_flag:
                    if value != 0:
                        data = self._pass_wire_extend(data)
            localthat_type = find_correct_localthat_for_version()
            if localthat_type is not None:
                localthat = localthat_type.from_buffer_copy(data)
                # Check localthat pointers are empty
                for field in ("pAsyncResponseBlock", "containerErrorInformation", "containerPassthroughData"):
                    if getattr(localthat, field, 0) != 0:
                        raise NotImplementedError("ORPC Response with localthat.{0} != 0".format(field))
                data = data[ctypes.sizeof(localthat):]
        return data

    def _pass_wire_extend(self, data):
        wire_extend = gdef.WireExtent.from_buffer_copy(data)
        # We don't care -> jump over the size only
        return data[ctypes.sizeof(gdef.WireExtent) + wire_extend.rounded_size:]

# Based on combase.dll analysis

# LOCALTHIS
# Nb fields:  2
# 6.1.7601.17514 -> 6.2.9200.22376
#  * 6.1.7601.17514
#  * 6.1.7601.17514
#  * 6.2.9200.22376
# Nb fields:  4
# 6.3.9600.17031 -> 6.3.9600.20772
#  * 6.3.9600.17031
#  * 6.3.9600.20772
# Nb fields:  5
# 10.0.10240.16384 -> 10.0.15063.2679
# Nb fields:  7
# 10.0.16299.1 -> 10.0.26100.2454

def find_correct_localthis_for_version():
    vmaj, vmin = windows.system.version
    if (vmaj, vmin) < (6, 1):
        return None
    if (vmaj, vmin) in ((6, 1), (6, 2)):
        return gdef.LOCALTHIS32_NT_62(dwClientThread = windows.current_thread.tid)
    elif (vmaj, vmin) == (6,3):
        return gdef.LOCALTHIS32_NT_63(dwClientThread = windows.current_thread.tid)
    assert vmaj == 10
    vnumber = windows.system.get_file_version(r"C:\windows\system32\combase.dll")
    # Extract version number from combase
    # as it was used to find the struct per version
    build_number = int(vnumber.split(".")[2])
    if build_number <= 15063:
        return gdef.LOCALTHIS32_NT_1607(dwClientThread = windows.current_thread.tid)
    return gdef.LOCALTHIS32(callTraceActivity=gdef.GUID.from_string("42424242-4242-4242-4242-424242424242"),
                        dwClientThread = windows.current_thread.tid)


# LOCALTHAT
# Nb fields:  2
# 6.3.9600.17031 -> 6.3.9600.20772
#  * 6.3.9600.17031
#  * 6.3.9600.17031
#  * 6.3.9600.17031
#  * 6.3.9600.20772
# Nb fields:  3
# 10.0.18362.900 -> 10.0.18362.1916
#  * 10.0.18362.900
#  * 10.0.18362.900
#  * 10.0.18362.1016
#  * 10.0.18362.1916
# Nb fields:  4
# 10.0.10240.16384 -> 10.0.17763.6040
#  * 10.0.10240.16384
#  * 10.0.10240.16384
#  * 10.0.10240.20747
#  * 10.0.10586.0
#  * 10.0.14393.576
#  * 10.0.14393.6451
#  * 10.0.14393.7426
#  * 10.0.15063.251
#  * 10.0.15063.1563
#  * 10.0.15063.2500
#  * 10.0.15063.2679
#  * 10.0.16299.1
#  * 10.0.16299.15
#  * 10.0.17134.1
#  * 10.0.17134.48
#  * 10.0.17134.2145
#  * 10.0.17134.2145
#  * 10.0.17763.1
#  * 10.0.17763.2931
#  * 10.0.17763.6040
# Nb fields:  5
# 10.0.19039.1 -> 10.0.26100.2454
#  * 10.0.19039.1
#  * 10.0.19041.84
#  * 10.0.19041.4894
#  * 10.0.22000.65
#  * 10.0.22621.2792
#  * 10.0.22621.3958
#  * 10.0.22621.4111
#  * 10.0.22621.4541
#  * 10.0.26100.2454
#  * 10.0.26100.2454

def find_correct_localthat_for_version():
    vmaj, vmin = windows.system.version
    if (vmaj, vmin) < (6, 3):
        return None
    elif (vmaj, vmin) == (6,3):
        return gdef.LOCALTHAT32_NT_63
    assert vmaj == 10
    vnumber = windows.system.get_file_version(r"C:\windows\system32\combase.dll")
    # Extract version number from combase
    # as it was used to find the struct per version
    build_number = int(vnumber.split(".")[2])
    if build_number <= 17763:
        return gdef.LOCALTHAT32_NT_1607
    elif build_number == 18362:
        return gdef.LOCALTHAT32_10_1903
    elif build_number >= 19039:
        return gdef.LOCALTHAT32
    raise NotImplementedError("Unknown LOCALTHAT32 structure for version {0}, please share me your combase.dll file".format(windows.system.versionstr))