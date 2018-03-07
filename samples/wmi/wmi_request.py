import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows

print("WMI requester is {0}".format(windows.system.wmi))
print("Selecting * from 'Win32_Process'")
result = windows.system.wmi.select("Win32_Process")

print("They are <{0}> processes".format(len(result)))
print("Looking for ourself via pid")
us = [p for p in result if int(p["ProcessId"]) == windows.current_process.pid][0]

print("Some info about our process:")
print("    * {0} -> {1}".format("Name", us["Name"]))
print("    * {0} -> {1}".format("ProcessId", us["ProcessId"]))
print("    * {0} -> {1}".format("OSName", us["OSName"]))
print("    * {0} -> {1}".format("UserModeTime", us["UserModeTime"]))
print("    * {0} -> {1}".format("WindowsVersion", us["WindowsVersion"]))
print("    * {0} -> {1}".format("CommandLine", us["CommandLine"]))

print("<Select Caption,FileSystem,FreeSpace from Win32_LogicalDisk>:")
for vol in windows.system.wmi.select("Win32_LogicalDisk", ["Caption", "FileSystem", "FreeSpace"]):
    print("    * " + str(vol))

print("\n ==== Advanced use ====")
print("Listing some namespaces:")
for namespace in [ns for ns in windows.system.wmi.namespaces if "2" in ns]:
    print("    * {0}".format(namespace))

security2 = windows.system.wmi["root\\SecurityCenter2"]
print("Querying non-default namespace: {0}".format(security2))
print("Listing some available classes:")
for clsname in [x for x in security2.classes if x.endswith("Product")]:
    print("    * {0}".format(clsname))

print("Listing <AntiVirusProduct>:")
for av in security2.select("AntiVirusProduct"):
    print("    * {0}".format(av["displayName"]))



