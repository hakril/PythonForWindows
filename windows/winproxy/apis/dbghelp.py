import ctypes
import windows.generated_def as gdef
from windows.pycompat import int_types

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
    if obj is None or isinstance(obj, int_types):
        return obj
    return ctypes.POINTER(gdef.PVOID)(ctypes.py_object(obj))[0]

@DbgHelpProxy()
def SymInitialize(hProcess, UserSearchPath, fInvadeProcess):
    return SymInitialize.ctypes_function(hProcess, UserSearchPath, fInvadeProcess)

@DbgHelpProxy()
def SymCleanup(hProcess):
    return SymCleanup.ctypes_function(hProcess)

@DbgHelpProxy()
def SymLoadModuleExA(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
    return SymLoadModuleExA.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)

@DbgHelpProxy()
def SymLoadModuleExW(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
    return SymLoadModuleExW.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)

@DbgHelpProxy()
def SymUnloadModule64(hProcess, BaseOfDll):
    return SymUnloadModule64.ctypes_function(hProcess, BaseOfDll)

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

@DbgHelpProxy(error_check=None)
def SymSetOptions(SymOptions):
    return SymSetOptions.ctypes_function(SymOptions)

@DbgHelpProxy(error_check=None)
def SymGetOptions():
    return SymGetOptions.ctypes_function()

@DbgHelpProxy()
def SymGetSearchPath(hProcess, SearchPath, SearchPathLength=None):
    if SearchPath and SearchPathLength is None:
        SearchPathLength = len(SearchPath)
    return SymGetSearchPath.ctypes_function(hProcess, SearchPath, SearchPathLength)

@DbgHelpProxy()
def SymGetSearchPathW(hProcess, SearchPath, SearchPathLength=None):
    if SearchPath and SearchPathLength is None:
        SearchPathLength = len(SearchPath)
    return SymGetSearchPathW.ctypes_function(hProcess, SearchPath, SearchPathLength)

@DbgHelpProxy()
def SymSetSearchPath(hProcess, SearchPath):
    return SymSetSearchPath.ctypes_function(hProcess, SearchPath)

@DbgHelpProxy()
def SymSetSearchPathW(hProcess, SearchPath):
    return SymSetSearchPathW.ctypes_function(hProcess, SearchPath)


@DbgHelpProxy()
def SymGetTypeInfo(hProcess, ModBase, TypeId, GetType, pInfo):
    return SymGetTypeInfo.ctypes_function(hProcess, ModBase, TypeId, GetType, pInfo)

@DbgHelpProxy()
def SymEnumSymbols(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext=None):
    UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumSymbols.ctypes_function(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext)

@DbgHelpProxy()
def SymEnumSymbolsEx(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext=None, Options=NeededParameter):
    UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumSymbolsEx.ctypes_function(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext, Options)

@DbgHelpProxy()
def SymEnumSymbolsForAddr(hProcess, Address, EnumSymbolsCallback, UserContext=None):
    UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumSymbolsForAddr.ctypes_function(hProcess, Address, EnumSymbolsCallback, UserContext)

@DbgHelpProxy()
def SymEnumSymbolsForAddrW(hProcess, Address, EnumSymbolsCallback, UserContext=None):
    UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumSymbolsForAddrW.ctypes_function(hProcess, Address, EnumSymbolsCallback, UserContext)

@DbgHelpProxy()
def SymEnumTypes(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext=None):
    UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumTypes.ctypes_function(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)

@DbgHelpProxy()
def SymEnumTypesByName(hProcess, BaseOfDll, mask, EnumSymbolsCallback, UserContext=None):
    UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymEnumTypesByName.ctypes_function(hProcess, BaseOfDll, mask, EnumSymbolsCallback, UserContext)

@DbgHelpProxy()
def SymEnumerateModules64(hProcess, EnumModulesCallback, UserContext=None):
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
    UserContext = transform_pyobject_to_pvoid(UserContext)
    return SymSearchW.ctypes_function(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options)

@DbgHelpProxy()
def SymRefreshModuleList(hProcess):
    return SymRefreshModuleList.ctypes_function(hProcess)

# Helpers

@DbgHelpProxy()
def SymFunctionTableAccess(hProcess, AddrBase):
    return SymFunctionTableAccess.ctypes_function(hProcess, AddrBase)

@DbgHelpProxy()
def SymFunctionTableAccess64(hProcess, AddrBase):
    return SymFunctionTableAccess64.ctypes_function(hProcess, AddrBase)

@DbgHelpProxy()
def SymGetModuleBase(hProcess, dwAddr):
    return SymGetModuleBase.ctypes_function(hProcess, dwAddr)

@DbgHelpProxy()
def SymGetModuleBase64(hProcess, qwAddr):
    return SymGetModuleBase64.ctypes_function(hProcess, qwAddr)

@DbgHelpProxy()
def SymEnumProcesses(EnumProcessesCallback, UserContext=None):
    return SymEnumProcesses.ctypes_function(EnumProcessesCallback, UserContext)

## Sym callback

@DbgHelpProxy()
def SymRegisterCallback(hProcess, CallbackFunction, UserContext=None):
    return SymRegisterCallback.ctypes_function(hProcess, CallbackFunction, UserContext)

@DbgHelpProxy()
def SymRegisterCallback64(hProcess, CallbackFunction, UserContext=0):
    return SymRegisterCallback64.ctypes_function(hProcess, CallbackFunction, UserContext)

@DbgHelpProxy()
def SymRegisterCallbackW64(hProcess, CallbackFunction, UserContext=0):
    return SymRegisterCallbackW64.ctypes_function(hProcess, CallbackFunction, UserContext)


# Stack walk

@DbgHelpProxy()
def StackWalk64(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress):
    return StackWalk64.ctypes_function(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress)

@DbgHelpProxy()
def StackWalkEx(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress, Flags):
    return StackWalkEx.ctypes_function(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress, Flags)

@DbgHelpProxy()
def StackWalk(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress):
    return StackWalk.ctypes_function(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress)
