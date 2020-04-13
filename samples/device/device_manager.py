import windows
from windows.winobject.device import DeviceManager

def main():

    for device_class in DeviceManager.enumerate_active_class():
        print("-Class %s  %s  [%s]" % (device_class.name, " "*(60 - min(60,len(device_class.name))), device_class.guid))

        for device in device_class.devices:
            if device.name != "N/A":
                print("  -Device : %s" % (device.name))
        
        #     for resource in device.resources:
        #         print('    -%s : [0x%08x - 0x%08x] (0x%04x)' % (resource.type, resource.start, resource.end, resource.flags))



if __name__ == '__main__':
    main()