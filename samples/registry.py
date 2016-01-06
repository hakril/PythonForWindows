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
print("HKEY_CURRENT_USER subkeys names are is <{0}>".format(pprint.pprint(subkeys_name)))

print("Opening 'Software' in HKEY_CURRENT_USER: {0}".format(current_user["Software"]))

print("We can also open it in one access: {0}".format(registry[r"HKEY_CURRENT_USER\Sofware"]))

print("Looking for the JIT Debugger")

jit_debug_key = registry["HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"]

print("Key is {0}".format(jit_debug_key))

print("values are: {0}".format(pprint.pprint(jit_debug_key.values)))

print()