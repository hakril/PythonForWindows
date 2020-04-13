
import windows
from windows import winproxy
from windows.generated_def import windef
import windows.generated_def as gdef

SPDRP_DEVICEDESC    = 0x0000000
SPDRP_FRIENDLYNAME  = 0x000000C

# Resource types
# source : 
ResourceType_All = 0x00000000       # query every resource available
ResourceType_Mem = 0x00000001       # Physical address resource
ResourceType_IO  = 0x00000002       # Physical I/O address resource
ResourceType_DMA = 0x00000003       # DMA channels resource
ResourceType_IRQ = 0x00000004       # IRQ resource
ResourceType_DoNotUse = 0x00000005  # Do not use it, idiot
ResourceType_BusNumber = 0x00000006 # (PCI) bus number
ResourceType_MAX = 0x00000007 

# Log conf
# source : https://docs.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_first_log_conf
BASIC_LOG_CONF      = 0x00000000 # basic configuration information.
FILTERED_LOG_CONF   = 0x00000001 # filtered configuration information.
ALLOC_LOG_CONF      = 0x00000002 # allocated configuration information.
BOOT_LOG_CONF       = 0x00000003 # boot configuration information.
FORCED_LOG_CONF     = 0x00000004 # forced configuration information.
OVERRIDE_LOG_CONF   = 0x00000005 # override configuration information. 

class AbstractDeviceResource(object):
    """ An abstract Python object representing a setup device resource. """
    pass

class MmioDeviceResource(AbstractDeviceResource):
    """ A Python object representing a setup device MMIO resource. """
    
    def __init__(self, data):
        pass

class IoDeviceResource(AbstractDeviceResource):
    """ A Python object representing a setup device IO port resource. """
    
    def __init__(self, data):
        pass

class DmaDeviceResource(AbstractDeviceResource):
    """ A Python object representing a setup device DMA resource. """
    
    def __init__(self, data):
        pass

class IrqDeviceResource(AbstractDeviceResource):
    """ A Python object representing a setup device Irq resource. """
    
    def __init__(self, data):
        pass

class DeviceResource(object):
    """ A Python object representing a setup device resource. """
    
    @classmethod
    def parse(cls, resource_type, data):
        
        subclasses = {
            ResourceType_Mem : MmioDeviceResource,
            ResourceType_IO  : IoDeviceResource,
            ResourceType_DMA : DmaDeviceResource,
            ResourceType_IRQ : IrqDeviceResource,
        }

        return subclasses[resource_type](data)


class DeviceObject(object):
    """ A Python object representing a setup device instance. """

    def __init__(self, dev_data, device_name):

        # gdef.winstructs.SP_DEVINFO_DATA: associated device info
        self.dev_data = dev_data

        # str: Device instance name (optional)
        self._name = device_name

        # list(AbstractDeviceResource): list of resources registered by the device
        self._resources = None

    @property
    def name(self):
        return self._name

    @property
    def resources(self):
        if not self._resources:
            self._resources = list(res for res in self.get_resources()) 

        return self._resources


    @classmethod
    def from_device_info(cls, h_devs, device_data):

        # DO NOT STORE h_devs since it may be invalidated in the future
        try:
            device_name = winproxy.SetupDiGetDeviceRegistryPropertyW(h_devs, device_data, SPDRP_FRIENDLYNAME, None)
            if device_name:
                device_name = device_name.decode('utf-16-le').rstrip('\x00')
            else:
                device_name = winproxy.SetupDiGetDeviceRegistryPropertyW(h_devs, device_data, SPDRP_DEVICEDESC, None)
                if device_name:
                    device_name = device_name.decode('utf-16-le').rstrip('\x00')
                else:
                    device_name = None

        except WindowsError as e:
            if e.winerror == gdef.ERROR_INVALID_DATA:
                return cls(device_data,  None)
            raise
                

        return cls(device_data, device_name)

    def get_resources(self, resource_type = None):

        conf = self._get_first_log_conf()
        if conf is None: 
            return

        if resource_type:
            yield from self._get_resources_by_type(conf, resource_type)
        else:
            yield from self._get_resources_by_type(conf, ResourceType_Mem)
            yield from self._get_resources_by_type(conf, ResourceType_IO)
            yield from self._get_resources_by_type(conf, ResourceType_DMA)
            yield from self._get_resources_by_type(conf, ResourceType_IRQ)

        # TODO : free "conf" automagically

    def _get_first_log_conf(self):
        """ Try to retrieve the first log conf by using several flags """

        conf = winproxy.CM_Get_First_Log_Conf(self.dev_data.DevInst, ALLOC_LOG_CONF )
        if conf != None:
            return conf

        conf = winproxy.CM_Get_First_Log_Conf(self.dev_data.DevInst, BOOT_LOG_CONF )
        if conf != None:
            return conf




    def _get_resources_by_type(self, conf, resource_type):

        h_res = winproxy.CM_Get_Next_Res_Des(conf, resource_type)
        
        while h_res != None:

            # open resource
            resource_size = winproxy.CM_Get_Res_Des_Data_Size(h_res)
            if resource_size:
                resource_data = winproxy.CM_Get_Res_Des_Data(h_res, resource_size)
                yield DeviceResource.parse(resource_type, resource_data)

            # goto next resource
            h_res = winproxy.CM_Get_Next_Res_Des(h_res, resource_type)

        # TODO : free "h_res" automagically

class DeviceClass(object):
    """ A Python object representing a setup device class. """
    
    def __init__(self, guid):

        # gdef.winstructs.GUID: class GUID
        self._guid = guid

        # str: associated class name
        self._name = None 

        # list(DeviceObject): list of devices registered under the class        
        self._devices = None 

    @property
    def name(self):
        if not self._name:
            self._name = self._get_class_name()

        return self._name

    @property
    def guid(self):
        return self._guid

    @property
    def devices(self):
        if not self._devices:

            try:
                h_devs = winproxy.SetupDiGetClassDevsA(self.guid)
                self._devices = list(do for do in self._get_devices(h_devs))
            finally:
                winproxy.SetupDiDestroyDeviceInfoList(h_devs)

        return self._devices
    
    def _get_devices(self, h_devs):

        if not h_devs:
            return

        device_index = 0
            
        while True:

            try:
                device_data = winproxy.SetupDiEnumDeviceInfo(h_devs, device_index)
            except WindowsError as e:
                if e.winerror == gdef.ERROR_NO_MORE_ITEMS:
                    return # stop iterating
                raise 

            device_index+=1
            yield DeviceObject.from_device_info(h_devs, device_data)


    def _get_class_name(self):
        return winproxy.SetupDiClassNameFromGuidW(self.guid)
        

class DeviceManager(object):

    @staticmethod
    def enumerate_active_class():
        return list(DeviceManager.enumerate_class())
        # return list(filter(lambda dc: len(dc.devices) > 0, DeviceManager.enumerate_class()))

    @staticmethod
    def enumerate_class():

        def _gen_all_class_guid():
            """
                Return every registered device classes in the system, generator-style
            """

            class_index = 0
            
            while True:
                class_guid = winproxy.CM_Enumerate_Classes(class_index, 0)
                class_index+=1

                if not class_guid:
                    return # stop iterating

                yield DeviceClass(class_guid)



        return (dc for dc in _gen_all_class_guid())