import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter

from ..error import (fail_on_zero)


class WinHTTPProxy(ApiProxy):
    APIDLL = "winhttp"
    default_error_check = staticmethod(fail_on_zero)

@WinHTTPProxy()
def WinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags):
    return WinHttpOpen.ctypes_function(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags)

@WinHTTPProxy()
def WinHttpCloseHandle(hInternet):
    return WinHttpCloseHandle.ctypes_function(hInternet)

@WinHTTPProxy()
def WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved):
    return WinHttpConnect.ctypes_function(hSession, pswzServerName, nServerPort, dwReserved)

@WinHTTPProxy()
def WinHttpQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable):
    return WinHttpQueryDataAvailable.ctypes_function(hRequest, lpdwNumberOfBytesAvailable)

@WinHTTPProxy()
def WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead):
    return WinHttpReadData.ctypes_function(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)

@WinHTTPProxy()
def WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags):
    return WinHttpOpenRequest.ctypes_function(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags)

@WinHTTPProxy()
def WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext):
    return WinHttpSendRequest.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext)

@WinHTTPProxy()
def WinHttpReceiveResponse(hRequest, lpReserved):
    return WinHttpReceiveResponse.ctypes_function(hRequest, lpReserved)

@WinHTTPProxy()
def WinHttpAddRequestHeaders(hRequest, lpszHeaders, dwHeadersLength, dwModifiers):
    return WinHttpAddRequestHeaders.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, dwModifiers)

@WinHTTPProxy()
def WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex):
    return WinHttpQueryHeaders.ctypes_function(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex)
