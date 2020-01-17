import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero, no_error_check

class User32Proxy(ApiProxy):
    APIDLL = "user32"
    default_error_check = staticmethod(fail_on_zero)


# Window

@User32Proxy()
def EnumWindows(lpEnumFunc, lParam):
    return EnumWindows.ctypes_function(lpEnumFunc, lParam)

@User32Proxy()
def GetParent(hWnd):
    return GetParent.ctypes_function(hWnd)

@User32Proxy(error_check=no_error_check)
def GetWindowTextA(hWnd, lpString, nMaxCount):
    return GetWindowTextA.ctypes_function(hWnd, lpString, nMaxCount)

@User32Proxy()
def GetWindowTextW(hWnd, lpString, nMaxCount):
    return GetWindowTextW.ctypes_function(hWnd, lpString, nMaxCount)

@User32Proxy()
def FindWindowA(lpClassName, lpWindowName):
    return FindWindowA.ctypes_function(lpClassName, lpWindowName)

@User32Proxy()
def FindWindowW(lpClassName, lpWindowName):
    return FindWindowW.ctypes_function(lpClassName, lpWindowName)

@User32Proxy()
def GetWindowModuleFileNameA(hwnd, pszFileName, cchFileNameMax):
    return GetWindowModuleFileNameA.ctypes_function(hwnd, pszFileName, cchFileNameMax)

@User32Proxy()
def GetWindowModuleFileNameW(hwnd, pszFileName, cchFileNameMax):
    return GetWindowModuleFileNameW.ctypes_function(hwnd, pszFileName, cchFileNameMax)

@User32Proxy()
def EnumChildWindows(hWndParent, lpEnumFunc, lParam):
    return EnumChildWindows.ctypes_function(hWndParent, lpEnumFunc, lParam)

@User32Proxy()
def GetClassInfoExA(hinst, lpszClass, lpwcx):
    return GetClassInfoExA.ctypes_function(hinst, lpszClass, lpwcx)

@User32Proxy()
def GetClassInfoExW(hinst, lpszClass, lpwcx):
    return GetClassInfoExW.ctypes_function(hinst, lpszClass, lpwcx)

@User32Proxy()
def GetWindowThreadProcessId(hWnd, lpdwProcessId):
    return GetWindowThreadProcessId.ctypes_function(hWnd, lpdwProcessId)

@User32Proxy()
def WindowFromPoint(Point):
    return WindowFromPoint.ctypes_function(Point)

@User32Proxy()
def GetWindowRect(hWnd, lpRect):
    return GetWindowRect.ctypes_function(hWnd, lpRect)

@User32Proxy("RealGetWindowClassA")
def RealGetWindowClassA(hwnd, pszType, cchType=None):
    if cchType is None:
        cchType = len(pszType)
    return RealGetWindowClassA.ctypes_function(hwnd, pszType, cchType)

@User32Proxy("RealGetWindowClassW")
def RealGetWindowClassW(hwnd, pszType, cchType=None):
    if cchType is None:
        cchType = len(pszType)
    return RealGetWindowClassW.ctypes_function(hwnd, pszType, cchType)

@User32Proxy("GetClassNameA")
def GetClassNameA (hwnd, pszType, cchType=None):
    if cchType is None:
        cchType = len(pszType)
    return GetClassNameA .ctypes_function(hwnd, pszType, cchType)

@User32Proxy("GetClassNameW")
def GetClassNameW (hwnd, pszType, cchType=None):
    if cchType is None:
        cchType = len(pszType)
    return GetClassNameW .ctypes_function(hwnd, pszType, cchType)

## Windows Message

@User32Proxy()
def MessageBoxA(hWnd=0, lpText=NeededParameter, lpCaption=None, uType=0):
    return MessageBoxA.ctypes_function(hWnd, lpText, lpCaption, uType)

@User32Proxy()
def MessageBoxW(hWnd=0, lpText=NeededParameter, lpCaption=None, uType=0):
    return MessageBoxW.ctypes_function(hWnd, lpText, lpCaption, uType)

# Cursor

@User32Proxy()
def GetCursorPos(lpPoint):
    return GetCursorPos.ctypes_function(lpPoint)

# System


# If the function succeeds, the return value is the requested system metric or configuration setting.
# If the function fails, the return value is 0. GetLastError does not provide extended error information.
# And 0 is also a valid return value.. Thanks a lot..

@User32Proxy(error_check=no_error_check)
def GetSystemMetrics(nIndex):
    return GetSystemMetrics.ctypes_function(nIndex)
