import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero

class PsapiProxy(ApiProxy):
    APIDLL = "psapi"
    default_error_check = staticmethod(fail_on_zero)


@PsapiProxy()
def GetMappedFileNameW(hProcess, lpv, lpFilename, nSize=None):
    if nSize is None:
        nSize = ctypes.sizeof(lpFilename)
    return GetMappedFileNameW.ctypes_function(hProcess, lpv, lpFilename, nSize)

@PsapiProxy()
def GetMappedFileNameA(hProcess, lpv, lpFilename, nSize=None):
    if nSize is None:
        nSize = ctypes.sizeof(lpFilename)
    return GetMappedFileNameA.ctypes_function(hProcess, lpv, lpFilename, nSize)

@PsapiProxy()
def QueryWorkingSet(hProcess, pv, cb):
    return QueryWorkingSet.ctypes_function(hProcess, pv, cb)

@PsapiProxy()
def QueryWorkingSetEx(hProcess, pv, cb):
    return QueryWorkingSetEx.ctypes_function(hProcess, pv, cb)

@PsapiProxy()
def GetModuleBaseNameA(hProcess, hModule, lpBaseName, nSize=None):
    if nSize is None:
        nSize = len(lpBaseName)
    return GetModuleBaseNameA.ctypes_function(hProcess, hModule, lpBaseName, nSize)

@PsapiProxy()
def GetModuleBaseNameW(hProcess, hModule, lpBaseName, nSize=None):
    if nSize is None:
        nSize = len(lpBaseName)
    return GetModuleBaseNameW.ctypes_function(hProcess, hModule, lpBaseName, nSize)

@PsapiProxy()
def GetProcessImageFileNameA(hProcess, lpImageFileName, nSize=None):
    if nSize is None:
        nSize = len(lpImageFileName)
    return GetProcessImageFileNameA.ctypes_function(hProcess, lpImageFileName, nSize)

@PsapiProxy()
def GetProcessImageFileNameW(hProcess, lpImageFileName, nSize=None):
    if nSize is None:
        nSize = len(lpImageFileName)
    return GetProcessImageFileNameW.ctypes_function(hProcess, lpImageFileName, nSize)

@PsapiProxy()
def GetProcessMemoryInfo(Process, ppsmemCounters, cb):
    return GetProcessMemoryInfo.ctypes_function(Process, ppsmemCounters, cb)