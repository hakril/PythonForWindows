import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows

registry = windows.system.registry
print("Registry is <{0}>".format(registry))

current_user = registry["HKEY_CURRENT_USER"]
print("HKEY_CURRENT_USER is <{0}>".format(current_user))
subkeys_name = [s.name for s in current_user.subkeys]
print("HKEY_CURRENT_USER subkeys names are:")
pprint.pprint(subkeys_name)

print("Opening 'Software' in HKEY_CURRENT_USER: {0}".format(current_user["Software"]))
print("We can also open it in one access: {0}".format(registry[r"HKEY_CURRENT_USER\Sofware"]))
print("Looking at CurrentVersion")

windows_info = registry["HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"]
print("Key is {0}".format(windows_info))

print("values are:")
pprint.pprint(windows_info.values)

registered_owner = windows_info.get("RegisteredOwner")
print("registered owner = <{0}>".format(registered_owner))