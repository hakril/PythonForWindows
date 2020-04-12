import windows
from windows import winproxy
from windows.generated_def import windef
import windows.generated_def as gdef


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

                #yield DeviceClass(class_guid)
                yield class_guid



        return (dc for dc in _gen_all_class_guid())