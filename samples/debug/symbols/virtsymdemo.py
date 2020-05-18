import os
import windows
import windows.generated_def as gdef
from windows.debug import symbols
import argparse


parser = argparse.ArgumentParser(prog=__file__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--dbghelp', help='The path of DBG help to use (default use env:PFW_DBGHELP_PATH)')
args = parser.parse_args()
print(args)

if args.dbghelp:
    symbols.set_dbghelp_path(args.dbghelp)
else:
    if "PFW_DBGHELP_PATH" not in os.environ:
        print("Not dbghelp path given and no environ var 'PFW_DBGHELP_PATH' sample may fail")


symbols.engine.options = 0 # Disable defered load
sh = symbols.VirtualSymbolHandler()

ntmod = sh.load_file(r"c:\windows\system32\ntdll.dll", addr=0x420000)

print("Ntdll module is: {0}".format(ntmod))
print("  * name = {0}".format(ntmod.name))
print("  * addr = {0:#x}".format(ntmod.addr))
print("  * path = {0:}".format(ntmod.path))
print("  * type = {0:}".format(ntmod.type))
print("  * pdb = {0:}".format(ntmod.pdb))

print("")
TEST_FUNCTION = "LdrLoadDll"
print("Resolving function <{0}>".format(TEST_FUNCTION))
loaddll = sh["ntdll!" + TEST_FUNCTION]
print("Symbol found !")
print("  * __repr__: {0!r}".format(loaddll))
print("  * __str__: {0}".format(loaddll))
print("  * addr: {0:#x}".format(loaddll.addr))
print("  * name: {0}".format(loaddll.name))
print("  * fullname: {0}".format(loaddll.fullname))
print("  * module: {0}".format(loaddll.module))

print("")
print("Loading kernelbase")
kbasemod = sh.load_file(r"c:\windows\system32\kernelbase.dll", addr=0x1230000)
print("Loaded modules are: {0}".format(sh.modules))
LOOKUP_ADDR = 0x1231242
print("Looking up address: {0:#x}".format(LOOKUP_ADDR))
lookupsym = sh[LOOKUP_ADDR]
print("Symbol resolved !")
print("  * __repr__: {0!r}".format(lookupsym))
print("  * __str__: {0}".format(lookupsym))
print("  * start: {0:#x}".format(lookupsym.start))
print("  * addr: {0:#x}".format(lookupsym.addr))
print("  * displacement: {0:#x}".format(lookupsym.displacement))
print("  * name: {0}".format(lookupsym.name))
print("  * fullname: {0}".format(lookupsym.fullname))
print("  * module: {0}".format(lookupsym.module))
