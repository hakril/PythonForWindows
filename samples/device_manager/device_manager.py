import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.pipe
import windows.generated_def as gdef

devmgr = windows.system.device_manager
print("Device manager is {0}".format(devmgr))

print("Enumerating the first 3 device classes")
for cls in devmgr.classes[:3]:
    print(" * {0}".format(cls))

print("Finding device class 'System'")
# Allow devmgr.classes["name"] ?
system_cls = [cls for cls in devmgr.classes if cls.name == "System"][0]
print("  * {0}".format(system_cls))
print("  Enumerating some devices of 'System'")
devices = system_cls.devices.all()

for devinst in (devices[0], devices[25], devices[35]): # Some "random" devices to have interesting ones
    print("    * {0}".format(devinst))
    devconf = devinst.allocated_configuration
    if not devconf:
        continue
    print("        Enumerating allocated resources:")
    for resource in devconf.resources:
        print("          * {0}".format(resource))


# python64  samples\device\device_manager.py

# Device manager is <windows.winobject.device_manager.DeviceManager object at 0x0000000003669908>
# Enumerating the first 3 device classes
#  * <DeviceClass name="XboxComposite" guid=05F5CFE2-4733-4950-A6BB-07AAD01A3A84>
#  * <DeviceClass name="DXGKrnl" guid=1264760F-A5C8-4BFE-B314-D56A7B44A362>
#  * <DeviceClass name="RemotePosDevice" guid=13E42DFA-85D9-424D-8646-28A70F864F9C>
# Finding device class 'System'
#   * <DeviceClass name="System" guid=4D36E97D-E325-11CE-BFC1-08002BE10318>
#   Enumerating some devices of 'System'
#     * <DeviceInstance "Motherboard resources" (id=1)>
#     * <DeviceInstance "Microsoft ACPI-Compliant Embedded Controller" (id=26)>
#         Enumerating allocated resources:
#           * <IoResource : [0x00000000000062-0x00000000000062]>
#           * <IoResource : [0x00000000000066-0x00000000000066]>
#     * <DeviceInstance "High Definition Audio Controller" (id=36)>
#         Enumerating allocated resources:
#           * <MemoryResource : [0x000000f7080000-0x000000f7083fff]>
#           * <DevicePrivateResource type=ResType_DevicePrivate(0x8001)>
#           * <IrqResource : [0x00000000000011]>
