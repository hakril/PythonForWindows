import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.generated_def as gdef

object_manager = windows.system.object_manager
print("Object manager is {0}".format(object_manager))
root = object_manager.root
print("Root object is {0}".format(root))

print("")
print("Listing some of root-subobject:")
# Kernel object of type 'Directory' are iterable
for i, (name, obj) in enumerate(root.items()):
    print("  * {0}: {1}".format(name, obj))
    if i == 3:
        break

print("")
print(r"Retrieving <\Rpc Control\lsasspirpc>:")
# You can retrieve this value in one request
x1 = root[r"\Rpc Control\lsasspirpc"]
# Sub-directory also allow __getitem__
x2 = root["Rpc Control"]["lsasspirpc"]
# You can directly request the object manager that will request `root`
x3 = object_manager[r"\Rpc Control\lsasspirpc"]
assert x1.fullname == x2.fullname == x3.fullname

lsasspirpc = x1
print("Object is: {0}".format(lsasspirpc))
print("   * name: <{0}>".format(lsasspirpc.name))
print("   * path: <{0}>".format(lsasspirpc.path))
print("   * fullname: <{0}>".format(lsasspirpc.fullname))
print("   * type: <{0}>".format(lsasspirpc.type))
print("   * target: <{0}>".format(lsasspirpc.target)) # None on non-symlink

print("")
print("Looking for a SymbolicLink in <ArcName>")
slo = [o for o in root["ArcName"].values() if o.type == "SymbolicLink"][0]
print("Object is: {0}".format(slo))
print("   * name: <{0}>".format(slo.name))
print("   * target: <{0}>".format(slo.target))
