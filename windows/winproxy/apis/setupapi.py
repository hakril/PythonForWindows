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

@SetupApiProxy()
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

@SetupApiProxy(error_check=result_is_handle)
def SetupDiGetClassDevsA(Guid, Enumerator = None, hwndParent = None, Flags=0):
    """ 
        Given a class GUID, return a HANDLE to the device's information set or raise an Exception
    """

    return SetupDiGetClassDevsA.ctypes_function(
        ctypes.byref(Guid),
        Enumerator,
        hwndParent,
        Flags
    )

@SetupApiProxy(error_check=result_is_handle)
def SetupDiGetClassDevsW(Guid, Enumerator = None, hwndParent = None, Flags=0):
    """ 
        Given a class GUID, return a HANDLE to the device's information set or raise an Exception
    """

    return SetupDiGetClassDevsW.ctypes_function(
        ctypes.byref(Guid),
        Enumerator,
        hwndParent,
        Flags
    )

@SetupApiProxy()
def SetupDiEnumDeviceInfo(hDevInfo, MemberIndex):
    """
        Given a device information set, return the info associated with the index
        or raise ERROR_NO_MORE_ITEMS if there is none anymore.
    """

    data = gdef.winstructs.SP_DEVINFO_DATA()
    data.cbSize = ctypes.sizeof(gdef.winstructs.SP_DEVINFO_DATA)

    success = SetupDiEnumDeviceInfo.ctypes_function(
        hDevInfo,
        MemberIndex,
        ctypes.byref(data)
    )

    return data

@SetupApiProxy()
def SetupDiGetDeviceRegistryPropertyA(hDevInfo, DevData, Property, PropertyType, PropertySize = MAX_DEV_LEN*ctypes.sizeof(wintypes.CHAR)):
    
    property_buffer = ctypes.create_string_buffer(PropertySize)
    bytes_written = wintypes.DWORD(0)

    success = SetupDiGetDeviceRegistryPropertyA.ctypes_function(
        hDevInfo,
        ctypes.byref(DevData),
        Property,
        PropertyType,
        ctypes.cast(ctypes.byref(property_buffer), gdef.winstructs.PBYTE),
        wintypes.DWORD(PropertySize),
        ctypes.byref(bytes_written),
    )

    if not success:
        return None

    # Truncate read data
    registry_data = bytes(property_buffer)
    registry_data = registry_data[0:bytes_written.value]

    return registry_data


@SetupApiProxy()
def SetupDiGetDeviceRegistryPropertyW(hDevInfo, DevData, Property, PropertyType, PropertySize = MAX_DEV_LEN*ctypes.sizeof(wintypes.WCHAR)):
    
    property_buffer = ctypes.create_unicode_buffer(PropertySize)
    bytes_written = wintypes.DWORD(0)
    
    success = SetupDiGetDeviceRegistryPropertyW.ctypes_function(
        hDevInfo,
        ctypes.byref(DevData),
        Property,
        PropertyType,
        ctypes.cast(ctypes.byref(property_buffer), gdef.winstructs.PBYTE),
        wintypes.DWORD(PropertySize),
        ctypes.byref(bytes_written),
    )

    if not success:
        return None

    # Truncate read data
    registry_data = bytes(property_buffer)
    registry_data = registry_data[0:bytes_written.value]
    
    return registry_data



@SetupApiProxy()
def SetupDiDestroyDeviceInfoList(hDevInfo):
    return SetupDiDestroyDeviceInfoList.ctypes_function(hDevInfo)