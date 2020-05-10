import ctypes
import itertools

import windows
from windows import winproxy
import windows.generated_def as gdef
from windows.security import SecurityDescriptor
from windows.utils import fixedproperty


class DeviceManager(object):
    """Represent the device manager"""


    @property
    def classes(self):
        """The list of installed device classes.

        :return: [:class:`DeviceClass`] -- A list of :class:`DeviceClass`
        """
        return list(self._classes_generator())

    def _classes_generator(self):
        for index in itertools.count():
            try:
                yield self._enumerate_classes(index, 0)
            except WindowsError as e:
                if e.winerror == gdef.CR_NO_SUCH_VALUE:
                    break
                # Some index values might represent list entries containing invalid class data,
                # in which case the function returns CR_INVALID_DATA.
                # This return value can be ignored.
                if e.winerror == gdef.CR_INVALID_DATA:
                    continue
                raise


    def _enumerate_classes(self, index, flags=0):
        res = DeviceClass()
        x = winproxy.CM_Enumerate_Classes(index, res, flags)
        return res


class DeviceClass(gdef.GUID):
    """A Device class, which is mainly a :class:`GUID` with additional attributes"""
    def __init__(self):
        # Bypass GUID __init__ that is not revelant here
        pass

    @fixedproperty
    def name(self):
        """The name of the device class"""
        return self._get_device_class_name()

    @property
    def devices(self):
        """The set of devices of the current class.

        :type: :class:`DeviceInformationSet`
        """
        return self.enumerate_devices()

    def enumerate_devices(self, flags=0):
        handle = winproxy.SetupDiGetClassDevsA(self, Flags=flags)
        return DeviceInformationSet(handle)

    def _get_device_class_name(self):
        name = ctypes.create_string_buffer(gdef.MAX_CLASS_NAME_LEN)
        winproxy.SetupDiClassNameFromGuidA(self, name)
        return name.value

    def __repr__(self):
        guid_cls = self.to_string()
        return """<{0} name="{1}" guid={2}>""".format(type(self).__name__, self.name, guid_cls)

    __str__ = __repr__ # Overwrite default GUID str

class DeviceInformationSet(gdef.HDEVINFO):
    """A device instances, can be itered to retrieve the underliyings :class:`DeviceInstance`"""

    def all_device_infos(self):
        for index in itertools.count():
            try:
                yield self.enum_device_info(index)
            except WindowsError as e:
                if e.winerror == gdef.ERROR_NO_MORE_ITEMS:
                    return
                raise

    __iter__ = all_device_infos

    def enum_device_info(self, index):
        res = DeviceInstance(self)
        res.cbSize = ctypes.sizeof(res)
        winproxy.SetupDiEnumDeviceInfo(self, index, res)
        return res

    def enum_device_interface(self, index):
        """Not Implemented Yet"""
        raise NotImplementedError("enum_device_interface")

    def all(self):
        return list(self)


class DeviceInstance(gdef.SP_DEVINFO_DATA):
    """An instance of a Device.

    The properties are from the page https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertya#spdrp_address
    """
    def __init__(self, information_set=None):
        self.information_set = information_set

    # make a .device_class ? that return the DeviceClass ased in ClassGuid ?
    def get_property(self, property):
        datatype = gdef.DWORD()
        buffer_size = 0x1000
        buffer = windows.utils.BUFFER(gdef.BYTE, nbelt=buffer_size)()
        required_size = gdef.DWORD()
        # Registry parsing code expect W stuff, so use W function
        try:
            winproxy.SetupDiGetDeviceRegistryPropertyW(self.information_set, self, property, datatype, buffer.cast(gdef.LPBYTE), buffer_size, required_size)
        except WindowsError as e:
            if e.winerror == gdef.ERROR_INVALID_DATA:
                return None
            raise
        # PropertyRegDataType
        # A pointer to a variable that receives the data type of the property
        # that is being retrieved.
        # This is one of the standard registry data types
        # Look like its registry based, so use the registry decoders :)
        return windows.winobject.registry.decode_registry_buffer(datatype.value, buffer, required_size.value)


    def _generate_property_getter(prop):
        def getter(self):
            return self.get_property(prop)
        return property(getter)

    name = _generate_property_getter(gdef.SPDRP_FRIENDLYNAME)
    """The name of the device"""
    description = _generate_property_getter(gdef.SPDRP_DEVICEDESC)
    """The description of the device"""
    hardware_id = _generate_property_getter(gdef.SPDRP_HARDWAREID)
    """The list of hardware IDs for the device.
    (https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertya#spdrp_hardwareid)
    """
    enumerator_name = _generate_property_getter(gdef.SPDRP_ENUMERATOR_NAME)
    """The enumerator name of the devices
    (https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertya#spdrp_enumerator_name)
    """
    driver = _generate_property_getter(gdef.SPDRP_DRIVER)
    """The driver of the device
    https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertya#spdrp_driver
    """
    # Map on Device type ?
    # https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/specifying-device-types
    type = _generate_property_getter(gdef.SPDRP_DEVTYPE)
    """The type of device
    (https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/specifying-device-types)
    """
    upper_filters = _generate_property_getter(gdef.SPDRP_UPPERFILTERS)
    """A list of string that contains the names of a device's upper filter drivers."""
    lower_filters = _generate_property_getter(gdef.SPDRP_LOWERFILTERS)
    """A list of string that contains the names of a device's lower filter drivers."""
    raw_security_descriptor = _generate_property_getter(gdef.SPDRP_SECURITY)
    """The raw (binary) security descriptor of the device"""
    # I would prefer to use the security_descriptor sddl
    # ssdl = _generate_property_getter(gdef.SPDRP_SECURITY_SDS)
    service_name = _generate_property_getter(gdef.SPDRP_SERVICE)
    """The name of the service for the device
    (https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertya#spdrp_service)
    """
    manufacturer = _generate_property_getter(gdef.SPDRP_MFG)
    """The name of the device manufacturer."""
    location_information = _generate_property_getter(gdef.SPDRP_LOCATION_INFORMATION)
    """The hardware location of a device."""
    location_paths = _generate_property_getter(gdef.SPDRP_LOCATION_PATHS)
    """A list of strings that represents the location of the device in the device tree."""
    # Looks like it can raise ERROR_NO_SUCH_DEVINST
    # install_date = _generate_property_getter(gdef.SPDRP_INSTALL_STATE)
    capabilites = _generate_property_getter(gdef.SPDRP_CAPABILITIES)
    """The device capabilites
    (https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertya#spdrp_capabilities)
    """
    bus_type = _generate_property_getter(gdef.SPDRP_BUSTYPEGUID)
    """The function retrieves the GUID for the device's bus type."""
    bus_number = _generate_property_getter(gdef.SPDRP_BUSNUMBER)
    """The device's bus number."""
    address = _generate_property_getter(gdef.SPDRP_ADDRESS)
    """The device's address."""
    ui_number = _generate_property_getter(gdef.SPDRP_UI_NUMBER)
    """Retrieves a DWORD value set to the value of the UINumber member of the device's"""
    ui_number_desc_format = _generate_property_getter(gdef.SPDRP_UI_NUMBER_DESC_FORMAT)

    # Getter with special error handling
    @property
    def device_object_name(self):
        """The function retrieves a string that contains the name that is associated with the device's PDO."""
        try:
            return self.get_property(gdef.SPDRP_PHYSICAL_DEVICE_OBJECT_NAME)
        except WindowsError as e:
            if e.winerror not in (gdef.ERROR_INVALID_DATA, gdef.ERROR_NO_SUCH_DEVINST):
                raise


    # https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/hardware-resources
    # Explanation of types:
        # - https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/hardware-resources#logical-configuration-types-for-resource-requirements-lists
    def get_first_logical_configuration(self, type):
        res = LogicalConfiguration()
        try:
            winproxy.CM_Get_First_Log_Conf(res, self.DevInst, type)
        except WindowsError as e:
            if e.winerror == gdef.CR_CALL_NOT_IMPLEMENTED:
                e.strerror += " (Cannot be called from Wow64 process since Win8)"
                raise
        return res

    def get_next_logical_configuration(self, logconf):
        res = gdef.HANDLE(0)
        winproxy.CM_Get_Next_Log_Conf(res, logconf)
        return res

    def _logical_configuration_generator(self, type):
        x = self.get_first_logical_configuration(type)
        while x:
            yield x
            try:
                x = self.get_next_logical_configuration(x)
            except WindowsError as e:
                if e.winerror == gdef.CR_NO_MORE_LOG_CONF:
                    return
                raise

    def get_logical_configuration(self, type):
        return list(self._logical_configuration_generator(type))


    # Allocated Configuration
    # From https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/hardware-resources#logical-configuration-types-for-resource-lists
    # A resource list identifying resources currently in use by a device instance.
    # !!! Only one allocated configuration can exist for each device instance.
    @property
    def allocated_configuration(self):
        """The allocated configuration of the device.
        (https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/hardware-resources#logical-configuration-types-for-resource-lists)

        :type: :class:`LogicalConfiguration`
        """

        allocconfs = self.get_logical_configuration(gdef.ALLOC_LOG_CONF)
        if not allocconfs:
            return allocconfs
        assert len(allocconfs) == 1 # Only one allocated configuration can exist for each device instance.
        return allocconfs[0]

    # Boot Configuration
    # From https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/hardware-resources#logical-configuration-types-for-resource-lists
    # A resource list identifying the resources assigned to a device instance when the system is booted
    # Only one boot configuration can exist for each device instance.

    @property
    def boot_configuration(self):
        """The boot configuration of the device.
        (https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/hardware-resources#logical-configuration-types-for-resource-lists)

        :type: :class:`LogicalConfiguration`
        """
        bootconfs = self.get_logical_configuration(gdef.BOOT_LOG_CONF)
        if not bootconfs:
            return bootconfs
        assert len(bootconfs) == 1 # Only one boot configuration can exist for each device instance.
        return bootconfs[0]



    # Make properties for Each type of logical configuration ?

    # 'advanced' attributes extrapolated from properties
    @property
    def security_descriptor(self):
        """The security descriptor of the device.

        :type: :class:`~windows.security.SecurityDescriptor`
        """

        return SecurityDescriptor.from_binary(self.raw_security_descriptor)

    def __repr__(self):
        return """<{0} "{1}" (id={2})>""".format(type(self).__name__, self.description, self.DevInst)


class LogicalConfiguration(gdef.HANDLE):
    """Logical Configuration of a Device instance"""

    def get_next_resource_descriptor(self, resource, resdes=None):
        if resdes is None:
            # Using logical-conf as resdes will retrieve the first one
            # https://docs.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_next_res_des#remarks
            resdes = self
        resid = None
        if resource == gdef.ResType_All:
            resid = gdef.RESOURCEID()
        res = gdef.HANDLE()
        winproxy.CM_Get_Next_Res_Des(res, resdes, resource, resid, 0)
        resdes_type = resid.value if resid is not None else resource
        return ResourceDescriptor.from_handle_and_type(res.value, resdes_type)

    def get_resources_for_type(self, type):
        try:
            current = self.get_next_resource_descriptor(type)
            yield current
            while True:
                current = self.get_next_resource_descriptor(type, current)
                yield current
        except WindowsError as e:
            if e.winerror == gdef.CR_NO_MORE_RES_DES:
                return
            raise

    @property
    def resources(self):
        """The list of resources in the current logical configuration

        :type: [:class:`ResourceDescriptor`] -- A list of [:class:`ResourceDescriptor`]
        """
        return list(self.get_resources_for_type(gdef.ResType_All))

    def __repr__(self):
        return "<{0}>".format(type(self).__name__)


ResType_Mapper = gdef.FlagMapper(
    gdef.ResType_None,
    gdef.ResType_Mem,
    gdef.ResType_IO,
    gdef.ResType_DMA,
    gdef.ResType_IRQ,
    gdef.ResType_BusNumber,
    gdef.ResType_MemLarge,
    gdef.ResType_ClassSpecific,
    gdef.ResType_DevicePrivate,
    gdef.ResType_MfCardConfig,
    gdef.ResType_PcCardConfig,

)

class ResourceDescriptor(gdef.HANDLE):
    """Describe a resource allocated or reserved by a device instance.
    This class is a base class, all resources returned by :class:`LogicalConfiguration` should be one of the following:

        * :class:`ResourceNoType`
        * :class:`MemoryResource`
        * :class:`IoResource`
        * :class:`DmaResource`
        * :class:`IrqResource`
        * :class:`BusNumberResource`
        * :class:`MemLargeResource`
        * :class:`ClassSpecificResource`
        * :class:`DevicePrivateResource`
        * :class:`MfCardConfigResource`
        * :class:`PcCardConfigResource`
    """
    SUBCLASSES = {}

    def __init__(self, handle, type):
        super(ResourceDescriptor, self).__init__(handle)
        self.type = ResType_Mapper[type]

    @classmethod
    def from_handle_and_type(cls, handle, type):
        ecls = cls.SUBCLASSES[type]
        return ecls(handle, type)

    @property
    def rawdata(self):
        """The raw data describing the resource"""
        data_size = gdef.ULONG()
        winproxy.CM_Get_Res_Des_Data_Size(data_size, self)
        if not self:
            return None
        data_size = data_size.value
        buffer = ctypes.create_string_buffer(data_size)
        winproxy.CM_Get_Res_Des_Data(self, buffer, data_size)
        return bytearray(buffer[:data_size])

    def __repr__(self):
        return "<{0} type={1!r}>".format(type(self).__name__, self.type)


class ResourceDescriptorWithHeader(ResourceDescriptor):
    # Assert the header is the first field
    @property
    def header_type(self):
        # Type of first field
        return self.DATA_TYPE._fields_[0][1]

    @property
    def header(self):
        return self.header_type.from_buffer(self.rawdata)

    @property
    def data(self):
        return None

class ResourceDescriptorWithHeaderAndRanges(ResourceDescriptorWithHeader):
    def count_field_name(self):
        # Assert (manyally checked) that the first field of the
        # header is a field containing the size of the data array
        # Return name of the first field of the header
        return self.header_type._fields_[0][0]

    @property
    def data(self):
        count_field_name = self.count_field_name()
        count = getattr(self.header, count_field_name)
        # No entry:
        if not count:
            return []
        raise NotImplementedError("Resource descriptor with non-zero entry in range array")


class ResourceNoType(ResourceDescriptor):
    @property
    def data(self):
        return self.rawdata

class MemoryResource(ResourceDescriptorWithHeaderAndRanges):
    """A resource of type MEM_RESOURCE"""
    DATA_TYPE = gdef.MEM_RESOURCE

    def __str__(self):
        return "<{0} : [{1:#016x}-{2:#016x}]>".format(type(self).__name__, self.header.MD_Alloc_Base, self.header.MD_Alloc_End)

class IoResource(ResourceDescriptorWithHeaderAndRanges):
    """A resource of type IO_RESOURCE"""
    DATA_TYPE = gdef.IO_RESOURCE

    def __str__(self):
        return "<{0} : [{1:#016x}-{2:#016x}]>".format(type(self).__name__, self.header.IOD_Alloc_Base, self.header.IOD_Alloc_End)

class DmaResource(ResourceDescriptorWithHeaderAndRanges):
    """A resource of type DMA_RESOURCE"""
    DATA_TYPE = gdef.DMA_RESOURCE

    def __str__(self):
        return "<{0} : [{1:#016x}]>".format(type(self).__name__, self.header.DD_Alloc_Chan)


class IrqResource(ResourceDescriptorWithHeaderAndRanges):
    """A resource of type IRQ_RESOURCE"""
    # 32/64 based on current process bitness
    # Cross bitness cannot be implemented as >=Win8 block it
    DATA_TYPE = gdef.IRQ_RESOURCE

    def __str__(self):
        return "<{0} : [{1:#016x}]>".format(type(self).__name__, self.header.IRQD_Alloc_Num)


class BusNumberResource(ResourceDescriptorWithHeaderAndRanges):
    """A resource of type BUSNUMBER_RESOURCE"""
    DATA_TYPE = gdef.BUSNUMBER_RESOURCE

    def __str__(self):
        return "<{0} : [{1:#016x}-{2:#016x}]>".format(type(self).__name__, self.header.BUSD_Alloc_Base, self.header.BUSD_Alloc_End)


class MemLargeResource(ResourceDescriptor):
    """A resource of type MEM_LARGE_RESOURCE"""
    DATA_TYPE = gdef.MEM_LARGE_RESOURCE

    def __str__(self):
        return "<{0} : [{1:#016x}-{2:#016x}]>".format(type(self).__name__, self.header.MLD_Alloc_Base, self.header.MLD_Alloc_End)

class ClassSpecificResource(ResourceDescriptorWithHeader):
    """A resource of type CS_RESOURCE"""
    DATA_TYPE = gdef.CS_RESOURCE
    # Any idea for __str__ ?

class DevicePrivateResource(ResourceDescriptor):
    """A device private resource
    (https://docs.microsoft.com/en-us/windows-hardware/drivers/install/devprivate-resource)
    """

    @property
    def header(self):
        return None

    # Any idea for __str__ ?

class MfCardConfigResource(ResourceDescriptorWithHeader):
    """A resource of type MFCARD_RESOURCE"""
    DATA_TYPE = gdef.MFCARD_RESOURCE
    # Any idea for __str__ ?

class PcCardConfigResource(ResourceDescriptorWithHeader):
    """A resource of type PCCARD_RESOURCE"""
    DATA_TYPE = gdef.PCCARD_RESOURCE
    # Any idea for __str__ ?

# Flemme de faire une meta-classe pour ca..
ResourceDescriptor.SUBCLASSES.update({
    gdef.ResType_None: ResourceNoType,
    gdef.ResType_Mem: MemoryResource,
    gdef.ResType_IO: IoResource,
    gdef.ResType_DMA: DmaResource,
    gdef.ResType_IRQ: IrqResource,
    gdef.ResType_BusNumber: BusNumberResource,
    gdef.ResType_MemLarge: MemLargeResource,
    gdef.ResType_ClassSpecific: ClassSpecificResource,
    gdef.ResType_DevicePrivate: DevicePrivateResource,
    gdef.ResType_MfCardConfig: MfCardConfigResource,
    gdef.ResType_PcCardConfig: PcCardConfigResource,
})