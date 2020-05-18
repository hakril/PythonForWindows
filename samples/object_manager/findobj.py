import argparse

import windows
import windows.generated_def as gdef

def obj_with_link(obj):
    target = obj.target
    if target is None:
        return str(obj)
    return "{0} -> <{1}>".format(obj, target)


def find_name(root, findname):
    TODO = [root]
    while TODO:
        try:
            for name, obj in TODO.pop().items():
                if findname in name or findname in obj.type:
                    print("* {0}".format(obj_with_link(obj)))
                if obj.type == "Directory":
                    TODO.append(obj)
        except gdef.NtStatusException as e:
            print("<{0}> -> {1}".format(obj.fullname, e.name))



parser = argparse.ArgumentParser(prog=__file__)
parser.add_argument('name', nargs='?', default="ls", help='The name of the object to find')
res = parser.parse_args()

objmanag = windows.system.object_manager
print("Looking for object name containing <{0}>".format(res.name))
find_name(objmanag.root, res.name)


