import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows

print("Exploring the current process PEB")
peb = windows.current_process.peb
print("PEB is <{0}>".format(peb))
commandline = peb.commandline
print("Commandline object is {0}".format(commandline))
print("Commandline string is {0}".format(repr(commandline.Buffer)))

imagepath = peb.imagepath
print("Imagepath  {0}".format(imagepath))

modules = peb.modules
print("Printing some modules: {0}".format("\n".join(str(m) for m in modules[:6])))

print("=== K32  ===")
print("Looking for kernel32.dll")
k32 = [m for m in modules if m.name == "kernel32.dll"][0]
print("Kernel32 module: {0}".format(k32))

print("Module name = <{0}> | Fullname = <{1}>".format(k32.name, k32.fullname))
print("Kernel32 is loaded at address {0}".format(hex(k32.baseaddr)))

print("=== K32 PE ===")
k32pe = k32.pe
print("PE Representation of k32: {0}".format(k32pe))
exports = k32pe.exports
some_exports = dict((k,v) for k,v in exports.items() if k in [0, 42, "VirtualAlloc", "CreateFileA"])
print("Here are some exports {0}".format(some_exports))

imports = k32pe.imports
print("Import DLL dependancies are (without api-*): {0}".format([x for x in imports.keys() if not x.startswith("api-")]))

NtCreateFile_iat = [x for x in imports["ntdll.dll"] if x.name == "NtCreateFile"][0]
print("IAT Entry for ntdll!NtCreateFile = {0} | addr = {1}".format(NtCreateFile_iat, hex(NtCreateFile_iat.addr)))
print("Sections: {0}".format(k32pe.sections))