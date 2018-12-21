import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero

class DbgHelpProxy(ApiProxy):
    APIDLL = "dbghelp"
    default_error_check = staticmethod(fail_on_zero)


@DbgHelpProxy()
def SymInitialize(hProcess, UserSearchPath, fInvadeProcess):
    return SymInitialize.ctypes_function(hProcess, UserSearchPath, fInvadeProcess)

@DbgHelpProxy()
def SymLoadModuleExA(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
    return SymLoadModuleExA.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)

@DbgHelpProxy()
def SymLoadModuleExW(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
    return SymLoadModuleExW.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)

@DbgHelpProxy()
def SymFromAddr(hProcess, Address, Displacement, Symbol):
    return SymFromAddr.ctypes_function(hProcess, Address, Displacement, Symbol)

@DbgHelpProxy()
def SymGetModuleInfo64(hProcess, dwAddr, ModuleInfo):
    return SymGetModuleInfo64.ctypes_function(hProcess, dwAddr, ModuleInfo)