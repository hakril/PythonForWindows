
import windows
from windows import winproxy
from windows.generated_def import windef
import windows.generated_def as gdef

SPDRP_DEVICEDESC    = 0x0000000
SPDRP_FRIENDLYNAME  = 0x000000C


class DeviceObject(object):
    

    def __init__(self, dev_data, device_name):

        self.dev_data = dev_data
        self._name = device_name

    @property
    def name(self):
        return self._name

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
                    device_name = "N/A"

        except WindowsError as e:
            if e.winerror == gdef.ERROR_INVALID_DATA:
                return cls(device_data,  "N/A")
            raise
                

        return cls(device_data, device_name)

class DeviceClass(object):
    
    def __init__(self, guid):

        # class GUID
        self._guid = guid

        # associated class name
        self._name = None 

        # List of devices registered under the class        
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