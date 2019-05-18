import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero

class DbgHelpProxy(ApiProxy):
    APIDLL = "dbghelp"
    default_error_check = staticmethod(fail_on_zero)

# We keep the simple definition where callback UserContext are PVOID
# Be we want to be able to pass arbitrary python object (list/dict)
# So ctypes magic to make the py_object->pvoid transformation
# !! this code loose a ref to obj.
# Should still work as our calling-caller method keep a ref
def transform_pyobject_to_pvoid(obj):
    if obj is None or isinstance(obj, (int, long)):
        return obj
    return ctypes.POINTER(gdef.PVOID)(ctypes.py_object(obj))[0]

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

@DbgHelpProxy()
def SymFromName(hProcess, Name, Symbol):
    return SymFromName.ctypes_function(hProcess, Name, Symbol)

@DbgHelpProxy()
def SymLoadModuleEx(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
    return SymLoadModuleEx.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)

@DbgHelpProxy()
def SymSetOptions(SymOptions):
    return SymSetOptions.ctypes_function(SymOptions)

@DbgHelpProxy()
def SymGetTypeInfo(hProcess, ModBase, TypeId, GetType, pInfo):
    return SymGetTypeInfo.ctypes_function(hProcess, ModBase, TypeId, GetType, pInfo)

@DbgHelpProxy()
def SymEnumSymbols(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext):
    if UserContext is not None and not isinstance(UserContext, (int, long)):
        UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumSymbols.ctypes_function(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext)

@DbgHelpProxy()
def SymEnumSymbolsEx(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext, Options):
    if UserContext is not None and not isinstance(UserContext, (int, long)):
        UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumSymbolsEx.ctypes_function(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext, Options)

@DbgHelpProxy()
def SymEnumTypes(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext):
    if UserContext is not None and not isinstance(UserContext, (int, long)):
        UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumTypes.ctypes_function(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)

@DbgHelpProxy()
def SymEnumTypesByName(hProcess, BaseOfDll, mask, EnumSymbolsCallback, UserContext):
    if UserContext is not None and not isinstance(UserContext, (int, long)):
        UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumTypesByName.ctypes_function(hProcess, BaseOfDll, mask, EnumSymbolsCallback, UserContext)

@DbgHelpProxy()
def SymEnumerateModules64(hProcess, EnumModulesCallback, UserContext):
    if UserContext is not None and not isinstance(UserContext, (int, long)):
        UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumerateModules64.ctypes_function(hProcess, EnumModulesCallback, UserContext)

@DbgHelpProxy()
def SymGetTypeFromName(hProcess, BaseOfDll, Name, Symbol):
    return SymGetTypeFromName.ctypes_function(hProcess, BaseOfDll, Name, Symbol)

@DbgHelpProxy()
def SymSearch(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options):
    UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymSearch.ctypes_function(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options)

@DbgHelpProxy()
def SymSearchW(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options):
    return SymSearchW.ctypes_function(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options)
