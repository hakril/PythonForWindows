import windows
from windows.winobject.device import DeviceManager

def main():

    for device_class in DeviceManager.enumerate_active_class():
        print("-Class : %s" % (device_class))

        # for device in device_class.devices:
        #     print("  -Device : %s" % (device.name))
        
        #     for resource in device.resources:
        #         print('    -%s : [0x%08x - 0x%08x] (0x%04x)' % (resource.type, resource.start, resource.end, resource.flags))



if __name__ == '__main__':
    main()