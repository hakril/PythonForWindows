import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter

from ..error import WinproxyError, succeed_on_zero, no_error_check, fail_on_minus_one

len_ = len

class Ws2_32Proxy(ApiProxy):
    APIDLL = "ws2_32"
    default_error_check = staticmethod(succeed_on_zero)

def check_invalid_socket(func_name, result, func, args):
    if result == gdef.INVALID_SOCKET:
        raise WinproxyError(func_name, error_code=WSAGetLastError())
    return args

@Ws2_32Proxy()
def WSAStartup(wVersionRequested, lpWSAData):
    if isinstance(lpWSAData, gdef.WSADATA):
        lpWSAData = ctypes.byref(lpWSAData) #  Not naturally done as lpWSAData is defined as a PVOID due to WSADATA32/WSADATA64 types
    return WSAStartup.ctypes_function(wVersionRequested, lpWSAData)


@Ws2_32Proxy()
def WSACleanup():
    return WSACleanup.ctypes_function()

@Ws2_32Proxy(error_check=no_error_check)
def WSAGetLastError():
    return WSAGetLastError.ctypes_function()

@Ws2_32Proxy()
def getaddrinfo(pNodeName, pServiceName, pHints, ppResult):
    return getaddrinfo.ctypes_function(pNodeName, pServiceName, pHints, ppResult)

@Ws2_32Proxy()
def GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult):
    return GetAddrInfoW.ctypes_function(pNodeName, pServiceName, pHints, ppResult)

@Ws2_32Proxy(error_check=check_invalid_socket)
def WSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags):
    return WSASocketA.ctypes_function(af, type, protocol, lpProtocolInfo, g, dwFlags)

@Ws2_32Proxy(error_check=check_invalid_socket)
def WSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags):
    return WSASocketW.ctypes_function(af, type, protocol, lpProtocolInfo, g, dwFlags)

@Ws2_32Proxy(error_check=check_invalid_socket)
def socket(af, type, protocol):
    return socket.ctypes_function(af, type, protocol)

@Ws2_32Proxy(error_check=fail_on_minus_one) # SOCKET_ERROR
def connect(s, name, namelen):
    return connect.ctypes_function(s, name, namelen)

@Ws2_32Proxy(error_check=fail_on_minus_one) # SOCKET_ERROR
def send(s, buf, len=None, flags=0):
    if len is None:
        len = len_(buf)
    return send.ctypes_function(s, buf, len, flags)

@Ws2_32Proxy(error_check=fail_on_minus_one) # SOCKET_ERROR
def recv(s, buf, len=None, flags=0):
    if len is None:
        len = len_(buf)
    return recv.ctypes_function(s, buf, len, flags)

@Ws2_32Proxy(error_check=fail_on_minus_one) # SOCKET_ERROR
def shutdown(s, how):
    return shutdown.ctypes_function(s, how)

@Ws2_32Proxy(error_check=fail_on_minus_one) # SOCKET_ERROR
def closesocket(s):
    return closesocket.ctypes_function(s)
