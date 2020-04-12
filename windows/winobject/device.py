import windows
from windows import winproxy
from windows.generated_def import windef
import windows.generated_def as gdef


class DeviceClass(object):
    
    def __init__(self, guid):

        self._guid = guid

        self._name = None 
        
        # self._devices = None 
        # self._h_devs = None

    @property
    def name(self):
        if not self._name:
            self._name = self._get_class_name()

        return self._name

    @property
    def guid(self):
    	return self._guid

    # @property
    # def devices(self):
    #     if not self._devices:

    #         with OpenDeviceClass(self):
    #             self._devices = list(do for do in self._get_devices())

    #     return self._devices
    
    # def _get_devices(self):

    #     if not self._h_devs:
    #         return

    #     device_index = 0
            
    #     while True:

    #         device_data = winproxy.SetupDiEnumDeviceInfo(self._h_devs, device_index)
    #         if not device_data:
    #             return # stop iterating


    #         device_index+=1
    #         yield DeviceObject.from_device_info(self._h_devs, device_data)


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