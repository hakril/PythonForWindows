import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero, succeed_on_zero

class Shell32Proxy(ApiProxy):
    APIDLL = "shell32"
    default_error_check = staticmethod(fail_on_zero)

@Shell32Proxy()
def ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd):
    return ShellExecuteA.ctypes_function(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)

@Shell32Proxy()
def ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd):
    return ShellExecuteW.ctypes_function(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)

@Shell32Proxy()
def SHGetPathFromIDListA(pidl, pszPath):
    return SHGetPathFromIDListA.ctypes_function(pidl, pszPath)

@Shell32Proxy()
def SHGetPathFromIDListW(pidl, pszPath):
    return SHGetPathFromIDListW.ctypes_function(pidl, pszPath)

@Shell32Proxy(error_check=succeed_on_zero)
def SHFileOperationA(lpFileOp):
    return SHFileOperationA.ctypes_function(lpFileOp)