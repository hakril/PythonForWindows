import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import _winreg
import windows

# Here is a demo of IAT hooking in python
# We will hook the 'RegOpenKeyExA' entry of Python27.dll because it is easy to trigger !

# First: let's create our hook
# windows.hooks.RegOpenKeyExACallback is generated based on windows.generated_def.winfuncs
@windows.hooks.RegOpenKeyExACallback
def open_reg_hook(hKey, lpSubKey, ulOptions, samDesired, phkResult, real_function):
    print("<in hook> Hook called | hKey = {0} | lpSubKey = <{1}>".format(hex(hKey), lpSubKey.value))
    # Out hook can choose to call the real_function or not
    if "SECRET" in lpSubKey.value:
        print("<in hook> Secret key asked, returning magic handle 0x12345678")
        # We must respect the hooked method return-value interface
        phkResult[0] = 0x12345678
        return 0
    if "FAIL" in lpSubKey.value:
        print("<in hook> Asked for a failing key: returning 0x2a")
        return 42
    print("<in hook> Non-secret key : calling normal function")
    return real_function()
    
    
# Get the peb of our process
peb = windows.current_process.peb

# Get the pythonxx.dll module
pythondll_module = [m for m in peb.modules if m.name.startswith("python") and m.name.endswith(".dll")][0]

# Get the iat entries for DLL advapi32.dll
adv_imports = pythondll_module.pe.imports['advapi32.dll']

# Get RegOpenKeyExA iat entry
RegOpenKeyExA_iat = [n for n in adv_imports if n.name == "RegOpenKeyExA"][0]

# Setup our hook 

RegOpenKeyExA_iat.set_hook(open_reg_hook)

# Use python native module _winreg that call 'RegOpenKeyExA'

print("Asking for <MY_SECRET_KEY>")
v = _winreg.OpenKey(1234567, "MY_SECRET_KEY")
print("Result = " + hex(v.handle))

print("Asking for <MY_FAIL_KEY>")
try:
    v = _winreg.OpenKey(1234567, "MY_FAIL_KEY")
    print("Result = " + hex(v.handle))
except WindowsError as e:
    print(repr(e))

print("Asking for <HKEY_CURRENT_USER/Software>")
try:
    v = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, "Software")
    print("Result = " + hex(v.handle))
except WindowsError as e:
    print(repr(e))