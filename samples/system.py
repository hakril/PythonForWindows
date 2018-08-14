import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
system = windows.system

print("Basic system infos:")
print("    version = {0}".format(system.version))
print("    bitness = {0}".format(system.bitness))
print("    computer_name = {0}".format(system.computer_name))
print("    product_type = {0}".format(system.product_type))
print("    version_name = {0}".format(system.version_name))
print("")
print("There is {0} processes".format(len(system.processes)))
print("There is {0} threads".format(len(system.threads)))
print("")

print("Dumping first logical drive:")
drive = system.logicaldrives[0]
print("    " + str(drive))
print((" " * 8) + "name = {0}".format(drive.name))
print((" " * 8) + "type = {0}".format(drive.type))
print((" " * 8) + "path = {0}".format(drive.path))
print("")

print("Dumping first service:")
serv = windows.system.services[0]
print("    " + str(serv))
print((" " * 8) + "name = {0}".format(serv.name))
print((" " * 8) + "description = {0}".format(serv.description))
print((" " * 8) + "status = {0}".format(serv.status))
print((" " * 8) + "process = {0}".format(repr(serv.process)))
print("")

print("Finding a service in a user process:")
serv = [s for s in windows.system.services if s.process][0]
print("    " + str(serv))
print((" " * 8) + "name = {0}".format(serv.name))
print((" " * 8) + "description = {0}".format(serv.description))
print((" " * 8) + "status = {0}".format(serv.status))
print((" " * 8) + "process = {0}".format(repr(serv.process)))
print("")

print("Enumerating handles:")
handles = system.handles
print("    There are {0} handles:".format(len(handles)))
print("    First handle is: " + str(handles[0]))

print("    Enumerating handles of the current process:")
cp_handles = [h for h in system.handles if h.dwProcessId == windows.current_process.pid]
print("        There are {0} handles for this process".format(len(cp_handles)))
print("    Looking for a File handle:")
file_h = [h for h in cp_handles if h.type == "File"][0]
print("        Handle is {0}".format(file_h))
print("        Name is <{0}>".format(file_h.name))
print("")


print("Dumping the first system module")
kmod = windows.system.modules[0]
print("    " + str(kmod))
print((" " * 8) + "ImageName = {0}".format(kmod.ImageName))
print((" " * 8) + "Base = {0:#x}".format(kmod.Base))
print((" " * 8) + "Size = {0:#x}".format(kmod.Size))
print((" " * 8) + "Flags = {0:#x}".format(kmod.Flags))
print((" " * 8) + "LoadCount = {0}".format(kmod.LoadCount))
