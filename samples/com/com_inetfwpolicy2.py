import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.generated_def as gdef
from windows.generated_def import interfaces

# This code is a simple version of the firewall code in windows.winoject.network
print("Initialisation of COM")
windows.com.init()
print("Creating INetFwPolicy2 variable")
firewall = interfaces.INetFwPolicy2()
print("{0} (value = {1})".format(firewall, firewall.value))
print("")

print("Generating CLSID")
NetFwPolicy2CLSID = windows.com.IID.from_string("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD")
print(repr(NetFwPolicy2CLSID))
print("")

print("Creating COM instance")
windows.com.create_instance(NetFwPolicy2CLSID, firewall)
print("{0} (value = 0x{1:0})".format(firewall, firewall.value))
print("")

print("Checking for enabled profiles")
for profile in [gdef.NET_FW_PROFILE2_DOMAIN, gdef.NET_FW_PROFILE2_PRIVATE, gdef.NET_FW_PROFILE2_PUBLIC]:
    enabled = gdef.VARIANT_BOOL()
    firewall.get_FirewallEnabled(profile, enabled)
    print("   * {0} -> {1}".format(profile, enabled.value))
