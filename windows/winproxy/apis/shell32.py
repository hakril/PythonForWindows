import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero

class Shell32Proxy(ApiProxy):
    APIDLL = "shell32"
    default_error_check = staticmethod(fail_on_zero)

@Shell32Proxy()
def ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd):
    return ShellExecuteA.ctypes_function(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)

@Shell32Proxy()
def ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd):
    return ShellExecuteW.ctypes_function(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
