import struct
import ctypes
from ctypes import wintypes

import windows
from windows import winproxy
from windows.generated_def import windef
import windows.generated_def as gdef

SPDRP_DEVICEDESC                    = 0x00000000
SPDRP_HARDWAREID                    = 0x00000001
SPDRP_COMPATIBLEIDS                 = 0x00000002
SPDRP_UNUSED0                       = 0x00000003
SPDRP_SERVICE                       = 0x00000004
SPDRP_UNUSED1                       = 0x00000005
SPDRP_UNUSED2                       = 0x00000006
SPDRP_CLASS                         = 0x00000007
SPDRP_CLASSGUID                     = 0x00000008
SPDRP_DRIVER                        = 0x00000009
SPDRP_CONFIGFLAGS                   = 0x0000000A
SPDRP_MFG                           = 0x0000000B
SPDRP_FRIENDLYNAME                  = 0x0000000C
SPDRP_LOCATION_INFORMATION          = 0x0000000D
SPDRP_PHYSICAL_DEVICE_OBJECT_NAME   = 0x0000000E
SPDRP_CAPABILITIES                  = 0x0000000F
SPDRP_UI_NUMBER                     = 0x00000010
SPDRP_UPPERFILTERS                  = 0x00000011
SPDRP_LOWERFILTERS                  = 0x00000012
SPDRP_BUSTYPEGUID                   = 0x00000013
SPDRP_LEGACYBUSTYPE                 = 0x00000014
SPDRP_BUSNUMBER                     = 0x00000015
SPDRP_ENUMERATOR_NAME               = 0x00000016
SPDRP_SECURITY                      = 0x00000017
SPDRP_SECURITY_SDS                  = 0x00000018
SPDRP_DEVTYPE                       = 0x00000019
SPDRP_EXCLUSIVE                     = 0x0000001a
SPDRP_CHARACTERISTICS               = 0x0000001b
SPDRP_ADDRESS                       = 0x0000001c
SPDRP_UI_NUMBER_DESC_FORMAT         = 0x0000001d
SPDRP_DEVICE_POWER_DATA             = 0x0000001e
SPDRP_REMOVAL_POLICY                = 0x0000001f
SPDRP_REMOVAL_POLICY_HW_DEFAULT     = 0x00000020
SPDRP_REMOVAL_POLICY_OVERRIDE       = 0x00000021
SPDRP_INSTALL_STATE                 = 0x00000022
SPDRP_LOCATION_PATHS                = 0x00000023
SPDRP_BASE_CONTAINERID              = 0x00000024
SPDRP_MAXIMUM_PROPERTY              = 0x00000025


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

class _IO_DES(ctypes.Structure):
    """ 
        The IO_DES structure is used for specifying either a resource list or a resource requirements list that describes I/O port usage for a device instance. 
        Source : https://docs.microsoft.com/en-gb/windows/win32/api/cfgmgr32/ns-cfgmgr32-io_des
    """

    _fields_ = [
        ('IOD_Count', gdef.DWORD),     
        ('IOD_Type', gdef.DWORD),     
        ('IOD_Alloc_Base', gdef.UINT64), 
        ('IOD_Alloc_End', gdef.UINT64), 
        ('IOD_DesFlags', gdef.DWORD),     
    ]
IO_DES = _IO_DES
PIO_DES = ctypes.POINTER(_IO_DES)

class _IO_RANGE(ctypes.Structure):
    """ 
        The IO_RANGE structure specifies a resource requirements list that describes I/O port usage for a device instance. 
        Source : https://docs.microsoft.com/en-gb/windows/win32/api/cfgmgr32/ns-cfgmgr32-io_range
    """

    _fields_ = [
        ('IOR_Align', gdef.UINT64),
        ('IOR_nPorts', gdef.DWORD),
        ('IOR_Min', gdef.UINT64),
        ('IOR_Max', gdef.UINT64),
        ('IOR_RangeFlags', gdef.DWORD),
        ('IOR_Alias', gdef.UINT64),
    ]
IO_RANGE = _IO_RANGE
PIO_RANGE = ctypes.POINTER(_IO_RANGE)

class _MEM_DES(ctypes.Structure):
    """ 
        The MEM_DES structure is used for specifying either a resource list or a resource requirements list that describes memory usage for a device instance.
        Source : https://docs.microsoft.com/en-gb/windows/win32/api/cfgmgr32/ns-cfgmgr32-mem_des
    """

    _fields_ = [
        ('MD_Count', gdef.DWORD),     
        ('MD_Type', gdef.DWORD),     
        ('MD_Alloc_Base', gdef.UINT64), 
        ('MD_Alloc_End', gdef.UINT64), 
        ('MD_DesFlags', gdef.DWORD),     
    ]
MEM_DES = _MEM_DES
PMEM_DES = ctypes.POINTER(_MEM_DES)


class _MEM_RANGE(ctypes.Structure):
    """ 
        The MEM_RANGE structure specifies a resource requirements list that describes memory usage for a device instance. 
        Source : https://docs.microsoft.com/en-gb/windows/win32/api/cfgmgr32/ns-cfgmgr32-mem_range
    """

    _fields_ = [
        ('MR_Align', gdef.UINT64),
        ('MR_nBytes', gdef.ULONG),
        ('MR_Min', gdef.UINT64),
        ('MR_Max', gdef.UINT64),
        ('MR_Flags', gdef.DWORD),
        ('MR_Reserved', gdef.DWORD),
    ]

MEM_RANGE = _MEM_RANGE
PMEM_RANGE = ctypes.POINTER(_MEM_RANGE)

class _DMA_DES(ctypes.Structure):
    """ 
        The DMA_DES structure is used for specifying either a resource list or a resource requirements list that describes direct memory access (DMA) channel usage for a device instance.
        Source : https://docs.microsoft.com/en-gb/windows/win32/api/cfgmgr32/ns-cfgmgr32-dma_des
    """

    _fields_ = [
        ('DD_Count', gdef.DWORD),     
        ('DD_Type', gdef.DWORD),     
        ('DD_Flags', gdef.DWORD),     
        ('DD_Alloc_Chan', gdef.ULONG),     
    ]
DMA_DES = _DMA_DES
PDMA_DES = ctypes.POINTER(_DMA_DES)


class _DMA_RANGE(ctypes.Structure):
    """ 
        The MEM_RANGE structure specifies a resource requirements list that describes memory usage for a device instance. 
        Source : https://docs.microsoft.com/en-gb/windows/win32/api/cfgmgr32/ns-cfgmgr32-dma_range
    """

    _fields_ = [
        ('DR_Min', gdef.ULONG),
        ('DR_Max', gdef.ULONG),
        ('DR_Flags', gdef.ULONG),
    ]

DMA_RANGE = _DMA_RANGE
PDMA_RANGE = ctypes.POINTER(_DMA_RANGE)

class _IRQ_DES_64(ctypes.Structure):
    """ 
        The IRQ_DES structure is used for specifying either a resource list or a resource requirements list that describes IRQ line usage for a device instance.
        Source : https://docs.microsoft.com/en-gb/windows/win32/api/cfgmgr32/ns-cfgmgr32-irq_des_64
    """

    _fields_ = [
        ('IRQD_Count', gdef.DWORD),     
        ('IRQD_Type', gdef.DWORD),     
        ('IRQD_Flags', gdef.DWORD),     
        ('IRQD_Alloc_Num', gdef.ULONG),     
        ('IRQD_Affinity', gdef.ULONG64),     
    ]
IRQ_DES_64 = _IRQ_DES_64
PIRQ_DES_64 = ctypes.POINTER(_IRQ_DES_64)

class _IRQ_DES_32(ctypes.Structure):
    """ 
        The IRQ_DES structure is used for specifying either a resource list or a resource requirements list that describes IRQ line usage for a device instance.
        Source : https://docs.microsoft.com/en-gb/windows/win32/api/cfgmgr32/ns-cfgmgr32-irq_des_32
    """

    _fields_ = [
        ('IRQD_Count', gdef.DWORD),     
        ('IRQD_Type', gdef.DWORD),     
        ('IRQD_Flags', gdef.DWORD),     
        ('IRQD_Alloc_Num', gdef.ULONG),     
        ('IRQD_Affinity', gdef.DWORD),     
    ]
IRQ_DES_32 = _IRQ_DES_32
PIRQ_DES_32 = ctypes.POINTER(_IRQ_DES_32)


class _IRQ_RANGE(ctypes.Structure):
    """ 
        The IRQ_RANGE structure specifies a resource requirements list that describes IRQ line usage for a device instance. 
        Source : https://docs.microsoft.com/en-gb/windows/win32/api/cfgmgr32/ns-cfgmgr32-irq_range
    """

    _fields_ = [
        ('IRQR_Min', gdef.ULONG),
        ('IRQR_Max', gdef.ULONG),
        ('IRQR_Flags', gdef.ULONG),
    ]

IRQ_RANGE = _IRQ_RANGE
PIRQ_RANGE = ctypes.POINTER(_IRQ_RANGE)

class AbstractDeviceResource(object):
    """ An abstract Python object representing a setup device resource. """
    pass

class MmioDeviceResource(AbstractDeviceResource):
    """ A Python object representing a setup device MMIO resource. """
    
    def __init__(self, data):     

        # check before casting into MEM_DES
        assert (len(data) >= ctypes.sizeof(MEM_DES))

        self.header = MEM_DES()   
        ctypes.memmove(ctypes.byref(self.header), data, ctypes.sizeof(MEM_DES))

        # check before casting into MEM_RANGES
        assert (len(data) >= ctypes.sizeof(MEM_DES) + self.header.MD_Count*ctypes.sizeof(MEM_RANGE))

        # only for requirements list (not our case)
        self.ranges = ()
        for i in range(self.header.MD_Count):
            mem_range = MEM_RANGE()
            ctypes.memmove(ctypes.byref(mem_range), data + ctypes.sizeof(MEM_DES) + i*ctypes.sizeof(MEM_RANGE), ctypes.sizeof(MEM_RANGE))
            self.ranges.append(mem_range)

    def __str__(self):
        return 'MmioDeviceResource : [%016x-%016x]' % (self.header.MD_Alloc_Base, self.header.MD_Alloc_End)


class IoDeviceResource(AbstractDeviceResource):
    """ A Python object representing a setup device IO port resource. """
    
    def __init__(self, data):     

        # check before casting into IO_DES
        assert (len(data) >= ctypes.sizeof(IO_DES))

        self.header = IO_DES()   
        ctypes.memmove(ctypes.byref(self.header), data, ctypes.sizeof(IO_DES))

        # check before casting into IO_RANGES
        assert (len(data) >= ctypes.sizeof(IO_DES) + self.header.IOD_Count*ctypes.sizeof(IO_RANGE))

        # only for requirements list (not our case)
        self.ranges = ()
        for i in range(self.header.IOD_Count):
            io_range = IO_RANGE()
            ctypes.memmove(ctypes.byref(io_range), data + ctypes.sizeof(IO_DES) + i*ctypes.sizeof(IO_RANGE), ctypes.sizeof(IO_RANGE))
            self.ranges.append(io_range)


    def __str__(self):
        return 'IoDeviceResource   : [%016x-%016x]' % (self.header.IOD_Alloc_Base, self.header.IOD_Alloc_End)


class DmaDeviceResource(AbstractDeviceResource):
    """ A Python object representing a setup device DMA resource. """
    
    def __init__(self, data):     

        # check before casting into DMA_DES
        assert (len(data) >= ctypes.sizeof(DMA_DES))

        self.header = DMA_DES()   
        ctypes.memmove(ctypes.byref(self.header), data, ctypes.sizeof(DMA_DES))

        # check before casting into MEM_RANGES
        assert (len(data) >= ctypes.sizeof(DMA_DES) + self.header.DD_Count*ctypes.sizeof(DMA_RANGE))

        # only for requirements list (not our case)
        self.ranges = ()
        for i in range(self.header.DD_Count):
            dma_range = DMA_RANGE()
            ctypes.memmove(ctypes.byref(mem_range), data + ctypes.sizeof(DMA_DES) + i*ctypes.sizeof(DMA_RANGE), ctypes.sizeof(DMA_RANGE))
            self.ranges.append(dma_range)

    def __str__(self):
        return 'DmaDeviceResource  : [%016x]' % (self.header.DD_Alloc_Chan)

class IrqDeviceResource(AbstractDeviceResource):
    """ A Python object representing a setup device Irq resource. """
    
    def __init__(self, data):

        # TODO : check 32/64 bitness before casting
        
        # check before casting into IRQ_DES_64
        assert (len(data) >= ctypes.sizeof(IRQ_DES_64))

        self.header = IRQ_DES_64()   
        ctypes.memmove(ctypes.byref(self.header), data, ctypes.sizeof(IRQ_DES_64))

        # check before casting into MEM_RANGES
        assert (len(data) >= ctypes.sizeof(IRQ_DES_64) + self.header.IRQD_Count*ctypes.sizeof(IRQ_RANGE))

        # only for requirements list (not our case)
        self.ranges = ()
        for i in range(self.header.IRQD_Count):
            irq_range = IRQ_RANGE()
            ctypes.memmove(ctypes.byref(mem_range), data + ctypes.sizeof(IRQ_DES_64) + i*ctypes.sizeof(IRQ_RANGE), ctypes.sizeof(DMA_RANGE))
            self.ranges.append(irq_range)

    def __str__(self):
        return 'IrqDeviceResource  : [%016x]' % (self.header.IRQD_Alloc_Num)

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
        device_name = None

        for name_params in [SPDRP_FRIENDLYNAME, SPDRP_DEVICEDESC, SPDRP_PHYSICAL_DEVICE_OBJECT_NAME]:
                
            try:
                device_name = winproxy.SetupDiGetDeviceRegistryPropertyW(h_devs, device_data, name_params, None)
                if device_name:
                    device_name = device_name.decode('utf-16-le').rstrip('\x00')
                    break        

            except WindowsError as e:
                if e.winerror == gdef.ERROR_INVALID_DATA:
                    continue
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