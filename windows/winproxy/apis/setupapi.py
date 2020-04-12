import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter, is_implemented
from ..error import succeed_on_zero

class SetupApiProxy(ApiProxy):
    APIDLL = "SetupApi"
    default_error_check = staticmethod(succeed_on_zero)


# @SetupApiProxy()
# def SetupDiClassNameFromGuidA(Guid):
#     return SetupDiClassNameFromGuidA.ctypes_function()

# @SetupApiProxy()
# def SetupDiClassNameFromGuidW(Guid):
#     return SetupDiClassNameFromGuidW.ctypes_function()

# @SetupApiProxy()
# def SetupDiGetClassDevsA(Guid):
#     return SetupDiGetClassDevsA.ctypes_function()

# @SetupApiProxy()
# def SetupDiEnumDeviceInfo(hDevInfo, NumDevice):
#     return SetupDiEnumDeviceInfo.ctypes_function()

# @SetupApiProxy()
# def SetupDiGetDeviceRegistryPropertyA(hDevInfo, DevData, Property, PropertyType):
#     return SetupDiGetDeviceRegistryPropertyA.ctypes_function()


# @SetupApiProxy()
# def SetupDiGetDeviceRegistryPropertyW(hDevInfo, DevData, Property, PropertyType):
#     return SetupDiGetDeviceRegistryPropertyW.ctypes_function()


# @SetupApiProxy()
# def SetupDiDestroyDeviceInfoList(hDevInfo):
#     return SetupDiDestroyDeviceInfoList.ctypes_function(hDevInfo)