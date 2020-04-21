import ctypes
from ctypes import wintypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter, is_implemented
from ..error import succeed_on_zero, fail_on_zero, result_is_handle, no_error_check


MAX_CLASS_NAME_LEN = 32
MAX_DEV_LEN = 1000


class SetupApiProxy(ApiProxy):
    APIDLL = "SetupApi"
    default_error_check = staticmethod(fail_on_zero)


@SetupApiProxy()
def SetupDiClassNameFromGuidA(ClassGuid, ClassName, ClassNameSize=None, RequiredSize=None):
    """
        Given a class Guid, return the name associated or raise an Exception
    """
    if ClassNameSize is None:
        ClassNameSize = ctypes.sizeof(ClassName)
    return SetupDiClassNameFromGuidA.ctypes_function(ClassGuid, ClassName, ClassNameSize, RequiredSize)


@SetupApiProxy()
def SetupDiClassNameFromGuidW(Guid):

    """
        Given a class Guid, return the name associated or raise an Exception
    """
    if ClassNameSize is None:
        ClassNameSize = ctypes.sizeof(ClassName)
    return SetupDiClassNameFromGuidW.ctypes_function(ClassGuid, ClassName, ClassNameSize, RequiredSize)


@SetupApiProxy(error_check=result_is_handle)
def SetupDiGetClassDevsA(Guid, Enumerator=None, hwndParent=None, Flags=0):
    """
        Given a class GUID, return a HANDLE to the device's information set or raise an Exception
    """
    return SetupDiGetClassDevsA.ctypes_function(Guid, Enumerator, hwndParent, Flags)

@SetupApiProxy(error_check=result_is_handle)
def SetupDiGetClassDevsW(Guid, Enumerator=None, hwndParent=None, Flags=0):
    """
        Given a class GUID, return a HANDLE to the device's information set or raise an Exception
    """
    return SetupDiGetClassDevsW.ctypes_function(Guid, Enumerator, hwndParent, Flags)

@SetupApiProxy()
def SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData):
    """
        Given a device information set, return the info associated with the index
        or raise ERROR_NO_MORE_ITEMS if there is none anymore.
    """
    return SetupDiEnumDeviceInfo.ctypes_function(DeviceInfoSet, MemberIndex, DeviceInfoData)

@SetupApiProxy()
def SetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData):
    return SetupDiEnumDeviceInterfaces.ctypes_function(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData)

@SetupApiProxy()
def SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize):
    return SetupDiGetDeviceRegistryPropertyA.ctypes_function(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize)

@SetupApiProxy()
def SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize):
    return SetupDiGetDeviceRegistryPropertyW.ctypes_function(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize)




@SetupApiProxy()
def SetupDiDestroyDeviceInfoList(hDevInfo):
    return SetupDiDestroyDeviceInfoList.ctypes_function(hDevInfo)