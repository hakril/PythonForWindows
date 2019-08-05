import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import no_error_check, result_is_error_code

class VirtDiskProxy(ApiProxy):
    APIDLL = "virtdisk"
    default_error_check = staticmethod(result_is_error_code)


@VirtDiskProxy()
def OpenVirtualDisk(VirtualStorageType, Path, VirtualDiskAccessMask, Flags, Parameters, Handle):
    return OpenVirtualDisk.ctypes_function(VirtualStorageType, Path, VirtualDiskAccessMask, Flags, Parameters, Handle)

@VirtDiskProxy()
def AttachVirtualDisk(VirtualDiskHandle, SecurityDescriptor, Flags, ProviderSpecificFlags, Parameters, Overlapped):
    return AttachVirtualDisk.ctypes_function(VirtualDiskHandle, SecurityDescriptor, Flags, ProviderSpecificFlags, Parameters, Overlapped)
