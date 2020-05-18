import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero

class VersionProxy(ApiProxy):
    APIDLL = "version"
    default_error_check = staticmethod(fail_on_zero)


@VersionProxy()
def GetFileVersionInfoA(lptstrFilename, dwHandle=0, dwLen=None, lpData=NeededParameter):
    if dwLen is None and lpData is not None:
        dwLen = len(lpData)
    return GetFileVersionInfoA.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)


@VersionProxy()
def GetFileVersionInfoW(lptstrFilename, dwHandle=0, dwLen=None, lpData=NeededParameter):
    if dwLen is None and lpData is not None:
        dwLen = len(lpData)
    return GetFileVersionInfoW.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)


@VersionProxy()
def GetFileVersionInfoExA(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData):
    return GetFileVersionInfoExA.ctypes_function(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData)


@VersionProxy()
def GetFileVersionInfoExW(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData):
    return GetFileVersionInfoExW.ctypes_function(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData)


@VersionProxy()
def GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle=None):
    if lpdwHandle is None:
        lpdwHandle = ctypes.byref(gdef.DWORD())
    return GetFileVersionInfoSizeA.ctypes_function(lptstrFilename, lpdwHandle)


@VersionProxy()
def GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle=None):
    if lpdwHandle is None:
        lpdwHandle = ctypes.byref(gdef.DWORD())
    return GetFileVersionInfoSizeW.ctypes_function(lptstrFilename, lpdwHandle)


@VersionProxy()
def GetFileVersionInfoSizeExA(dwFlags, lpwstrFilename, lpdwHandle=None):
    return GetFileVersionInfoSizeExA.ctypes_function(dwFlags, lpwstrFilename, lpdwHandle)


@VersionProxy()
def GetFileVersionInfoSizeExW(dwFlags, lpwstrFilename, lpdwHandle=None):
    return GetFileVersionInfoSizeExW.ctypes_function(dwFlags, lpwstrFilename, lpdwHandle)


@VersionProxy()
def VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen):
    return VerQueryValueA.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)


@VersionProxy()
def VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen):
    return VerQueryValueW.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)
