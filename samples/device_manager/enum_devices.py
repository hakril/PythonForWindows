import argparse

import windows
import windows.generated_def as gdef

devmgr = windows.system.device_manager

def class_generator(filter=None):
    for cls in devmgr.classes:
        if filter and cls.name != filter:
            continue
        yield cls


def main(clsfilter, enumerate_devices, print_devinst_resources, attributes):
    for devcls in class_generator(clsfilter):
        print(devcls)
        if not enumerate_devices:
            continue
        # Enumerate devices
        for devinst in devcls.devices:
            print("  * {0}".format(devinst))

            # Print attributes
            if attributes:
                print("    Attributes:")
                for attr in attributes:
                    value = getattr(devinst, attr)
                    print("    * {0}={1}".format(attr, value))

            if not print_devinst_resources:
                continue
            # Device resources
            devconf = devinst.allocated_configuration
            if not devconf:
                # No allocated configuration
                # Check boot conf ?
                continue

            for resource in devconf.resources:
                print("    * {0}".format(resource))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog=__file__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--class", dest="clsfilter", default=None, help="The classe to list: default all")
    parser.add_argument("--no-print-devices", action="store_true", help="Prevent the listing of devices in the matching classes")
    parser.add_argument("--print-resources", action="store_true", help="Print the resources allocated to the device instance")
    parser.add_argument("--attributes", nargs="+", help="The list of attributes to print for each discovered device instance")

    args = parser.parse_args()
    print(args)
    main(args.clsfilter,
            enumerate_devices=not args.no_print_devices,
            print_devinst_resources=args.print_resources,
            attributes=args.attributes)



