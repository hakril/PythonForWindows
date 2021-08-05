import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter

from ..error import (fail_on_zero)


class WinInetProxy(ApiProxy):
    APIDLL = "wininet"
    default_error_check = staticmethod(fail_on_zero)

@WinInetProxy()
def InternetCheckConnectionA(lpszUrl, dwFlags, dwReserved):
    return InternetCheckConnectionA.ctypes_function(lpszUrl, dwFlags, dwReserved)

@WinInetProxy()
def InternetCheckConnectionW(lpszUrl, dwFlags, dwReserved):
    return InternetCheckConnectionW.ctypes_function(lpszUrl, dwFlags, dwReserved)

@WinInetProxy()
def InternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags):
    return InternetOpenA.ctypes_function(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags)

@WinInetProxy()
def InternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags):
    return InternetOpenW.ctypes_function(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags)

@WinInetProxy()
def InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
    return InternetOpenUrlA.ctypes_function(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext)

@WinInetProxy()
def InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
    return InternetOpenUrlW.ctypes_function(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext)

@WinInetProxy()
def InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
    return InternetConnectA.ctypes_function(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)

@WinInetProxy()
def InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
    return InternetConnectW.ctypes_function(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)

@WinInetProxy()
def HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
    return HttpOpenRequestA.ctypes_function(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)

@WinInetProxy()
def HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
    return HttpOpenRequestW.ctypes_function(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)

@WinInetProxy()
def InternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength):
    return InternetSetOptionA.ctypes_function(hInternet, dwOption, lpBuffer, dwBufferLength)

@WinInetProxy()
def InternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength):
    return InternetSetOptionW.ctypes_function(hInternet, dwOption, lpBuffer, dwBufferLength)

@WinInetProxy()
def HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
    return HttpSendRequestA.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)

@WinInetProxy()
def HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
    return HttpSendRequestW.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)

@WinInetProxy()
def InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead):
    return InternetReadFile.ctypes_function(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)

@WinInetProxy()
def InternetReadFileExA(hFile, lpBuffersOut, dwFlags, dwContext):
    return InternetReadFileExA.ctypes_function(hFile, lpBuffersOut, dwFlags, dwContext)

@WinInetProxy()
def InternetReadFileExW(hFile, lpBuffersOut, dwFlags, dwContext):
    return InternetReadFileExW.ctypes_function(hFile, lpBuffersOut, dwFlags, dwContext)

@WinInetProxy()
def HttpQueryInfoA(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex):
    return HttpQueryInfoA.ctypes_function(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex)

@WinInetProxy()
def HttpQueryInfoW(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex):
    return HttpQueryInfoW.ctypes_function(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex)

@WinInetProxy()
def HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
    return HttpSendRequestA.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)

@WinInetProxy()
def HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
    return HttpSendRequestW.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
