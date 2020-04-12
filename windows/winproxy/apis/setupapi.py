import ctypes
from ctypes import wintypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter, is_implemented
from ..error import succeed_on_zero, fail_on_zero


MAX_CLASS_NAME_LEN = 32

class SetupApiProxy(ApiProxy):
    APIDLL = "SetupApi"
    default_error_check = staticmethod(succeed_on_zero)


@SetupApiProxy()
def SetupDiClassNameFromGuidA(Guid):
    """ 
        Given a class Guid, return the name associated or raise an Exception
    """

    class_name = ctypes.create_string_buffer(MAX_CLASS_NAME_LEN)

    success = SetupDiClassNameFromGuidA.ctypes_function(
        ctypes.byref(Guid),
        ctypes.cast(ctypes.byref(class_name), wintypes.LPCSTR),
        MAX_CLASS_NAME_LEN,
        None
    )

    raw_class_name = bytes(class_name)
    return raw_class_name.decode("utf-8").rstrip("\x00")

@SetupApiProxy(error_check=fail_on_zero)
def SetupDiClassNameFromGuidW(Guid):

    """ 
        Given a class Guid, return the name associated or raise an Exception
    """

    class_name = ctypes.create_unicode_buffer(MAX_CLASS_NAME_LEN)

    success = SetupDiClassNameFromGuidW.ctypes_function(
        ctypes.byref(Guid),
        ctypes.cast(ctypes.byref(class_name), wintypes.LPCWSTR),
        MAX_CLASS_NAME_LEN,
        None
    )

    raw_class_name = bytes(class_name)
    return raw_class_name.decode("utf-16-le").rstrip("\x00")

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