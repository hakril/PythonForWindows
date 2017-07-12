import ndr
from client import (RPC_SYNTAX_IDENTIFIER, RPCClient,
                        REQUEST_TYPE_CALL, REQUEST_TYPE_BIND,
                        RESPONSE_TYPE_BIND_OK, RESPONSE_TYPE_FAIL, RESPONSE_TYPE_SUCESS)
from epmapper import find_alpc_endpoint_and_connect, endpoint_map_alpc, construct_alpc_tower