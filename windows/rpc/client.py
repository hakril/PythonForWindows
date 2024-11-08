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

class RPCClient(object):
    """A client for RPC-over-ALPC able to bind to interface and perform calls using NDR32 marshalling"""
    REQUEST_IDENTIFIER = 0x11223344

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
            req.flags = 1 # We have a IPID
            req.orpc_ipid = ipid
            this = gdef.ORPCTHIS32() # we use NDR32
            this.version = (5,7)
            this.flags = gdef.ORPCF_LOCAL
            # Not mandatory
            # this.cid = gdef.GUID.from_string("42424242-4242-4242-4242-424242424242")
            lthis = gdef.LOCALTHIS32() # we use NDR32
            # RPC_E_INVALID_HEADER is NULL
            lthis.callTraceActivity = gdef.GUID.from_string("42424242-4242-4242-4242-424242424242")
            lthis.dwClientThread = windows.current_thread.tid
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
            raise ValueError("RPC Response error {0} ({1})".format(error_code, KNOWN_RPC_ERROR_CODE.get(error_code, error_code)))
        return request_type

    def _get_response_effective_data(self, response):
        """Response is a `AlpcMessage` needed to handle response in message vs response in view"""
        if not response.view_is_valid:
            # Reponse directly in PORT_MESSAGE
            return response.data[0x18:] # 4 * 6
        # Response in view M extract size from PORT_MESSAGE & read data from view
        assert response.port_message.u1.s1.TotalLength >= 0x48 # At least 0x20 of data
        rpcdatasize = struct.unpack("<I", response.data[0x18:0x1c])[0]
        viewattr = response.view_attribute
        assert viewattr.ViewSize >= rpcdatasize
        return windows.current_process.read_memory(viewattr.ViewBase, rpcdatasize)