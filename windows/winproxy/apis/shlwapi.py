import ctypes
import windows
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter, is_implemented
from ..error import fail_on_zero

class ShlwapiProxy(ApiProxy):
    APIDLL = "Shlwapi"
    default_error_check = staticmethod(fail_on_zero)

@ShlwapiProxy()
def StrStrIW(pszFirst, pszSrch):
    return StrStrIW.ctypes_function(pszFirst, pszSrch)

@ShlwapiProxy()
def StrStrIA(pszFirst, pszSrch):
    return StrStrIA.ctypes_function(pszFirst, pszSrch)

@ShlwapiProxy()
def IsOS(dwOS):
    if not is_implemented(IsOS) and windows.system.version[0] < 6:
        # Before Vista:
        # If so use ordinal 437 from DOCUMENTATION
        # https://docs.microsoft.com/en-us/windows/desktop/api/shlwapi/nf-shlwapi-isos#remarks
        IsOS.proxy.func_name = 437
    return IsOS.ctypes_function(dwOS)
