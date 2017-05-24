import windows.alpc as alpc
import windows.com
from windows.generated_def import USHORT
import ctypes
import struct


class _RPC_SYNTAX_IDENTIFIER(ctypes.Structure):
    _fields_ = [
        ("SyntaxGUID", windows.com.IID),
        ("MajorVersion", USHORT),
        ("MinorVersion", USHORT),
    ]

    def __repr__(self):
        return '<RPC_SYNTAX_IDENTIFIER "{0}" ({1}, {2})>'.format(self.SyntaxGUID.to_string(), self.MajorVersion, self.MinorVersion)
RPC_SYNTAX_IDENTIFIER = _RPC_SYNTAX_IDENTIFIER

# DEFINES

REQUEST_TYPE_CALL = 0
REQUEST_TYPE_BIND = 1

KNOW_REQUEST_TYPE = {
    REQUEST_TYPE_CALL : "REQUEST_CALL",
    REQUEST_TYPE_BIND : "REQUEST_BIND",
    }


RESPONSE_TYPE_BIND_OK = 1
RESPONSE_TYPE_FAIL = 2
RESPONSE_TYPE_SUCESS = 3


KNOW_RESPONSE_TYPE = {
    RESPONSE_TYPE_FAIL : "RESPONSE_FAIL",
    RESPONSE_TYPE_SUCESS : "RESPONSE_SUCESS",
    RESPONSE_TYPE_BIND_OK: "RESPONSE_BIND_OK",
    }


KNOWN_RPC_ERROR_CODE = {
    1783 : "RPC_X_BAD_STUB_DATA",
    1717 : "RPC_S_UNKNOWN_IF",
    1745 : "RPC_S_PROCNUM_OUT_OF_RANGE"

}

NOT_USED = 0xBAADF00D

# def dword_pack(*args):
#     return "".join(struct.pack("<I", x) for x in args)

class RPCClient(object):
    REQUEST_IDENTIFIER = 0x11223344
    def __init__(self, port):
        self.aplc_client = alpc.AlpcClient()
        self.aplc_client.connect_to_port(port)
        self.number_of_bind_if = 0 # if -> interface
        self.if_bind_number = {}

    def bind(self, IID_str, version=(1,0)):
        IID = windows.com.IID.from_string(IID_str)
        request = self._forge_bind_request(buffer(IID)[:], version, self.number_of_bind_if)
        response = self._send_request(request)
        # Parse reponse
        request_type = self._get_request_type(response)
        if request_type != RESPONSE_TYPE_BIND_OK:
            raise ValueError("Unexpected reponse type. Expected RESPONSE_TYPE_BIND_OK got {0}".format(KNOW_RESPONSE_TYPE.get(request_type, request_type)))
        iid_hash = hash(buffer(IID)[:]) # TODO: add __hash__ to IID
        self.if_bind_number[iid_hash] = self.number_of_bind_if
        self.number_of_bind_if += 1
        #TODO: attach version information to IID
        return IID

    def call(self, IID, method_offset, params):
        iid_hash = hash(buffer(IID)[:])
        interface_nb = self.if_bind_number[iid_hash] # TODO: add __hash__ to IID
        request = self._forge_call_request(interface_nb, method_offset, params)
        response = self._send_request(request)
        # Parse reponse
        request_type = self._get_request_type(response)
        if request_type != RESPONSE_TYPE_SUCESS:
            raise ValueError("Unexpected reponse type. Expected RESPONSE_SUCESS got {0}".format(KNOW_RESPONSE_TYPE.get(request_type, request_type)))

        data = struct.unpack("<6I", response[:6 * 4])
        assert data[3] == self.REQUEST_IDENTIFIER
        return response[4 * 6:] # Should be the return value (not completly verified)

    def _send_request(self, request):
        resp_attr, resp = self.aplc_client.send_receive(request)
        return resp.data

    def _forge_bind_request(self, rawuuid, syntaxversion, requested_if_nb):
        version_major, version_minor = syntaxversion
        # TODO: flags
        data = struct.pack("III16sHHIIIIIIIIII", REQUEST_TYPE_BIND, NOT_USED, NOT_USED, rawuuid, version_major, version_minor, NOT_USED, requested_if_nb, NOT_USED, NOT_USED ,NOT_USED, NOT_USED, NOT_USED, NOT_USED, NOT_USED, NOT_USED) # Fonctionne pour le BIND :D
        return data

    def _forge_call_request(self, interface_nb, method_offset, params):
        # TODO: differents REQUEST_IDENTIFIER for each req ?
        request = struct.pack("<16I", REQUEST_TYPE_CALL, NOT_USED, 0, self.REQUEST_IDENTIFIER, interface_nb, method_offset, NOT_USED, NOT_USED, NOT_USED, NOT_USED, NOT_USED, NOT_USED, NOT_USED, NOT_USED, NOT_USED, NOT_USED)
        request += params
        return request

    def _get_request_type(self, response):
        "raise if request_type == RESPONSE_TYPE_FAIL"
        request_type = struct.unpack("<I", response[:4])[0]
        if request_type == RESPONSE_TYPE_FAIL:
            error_code = struct.unpack("<5I", response)[2]
            raise ValueError("RPC Response error {0} ({1})".format(error_code, KNOWN_RPC_ERROR_CODE.get(error_code, error_code)))
        return request_type
