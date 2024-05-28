import os
import argparse

import windows
import windows.generated_def as gdef
from windows.debug import symbols


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

# Let's explore some types

print("")
stype = sh.get_type("ntdll!_CURDIR")
print(stype)
print("  - name: {0}".format(stype.name))
print("  - size: {0}".format(stype.size))
print("  - tag: {0!r}".format(stype.tag))
print("  - udtkind: {0!r}".format(stype.udtkind))

print("Exploring children: ")
for child in stype.children:
    print("    {0}".format(child))
    print("        - name: {0}".format(child.name))
    print("        - tag: {0!r}".format(child.tag))
    print("        - datakind: {0!r}".format(child.datakind))
    print("        - type: {0!r}".format(child.type))
    print("        - parent: {0!r}".format(child.parent))

print("")
print("Exploring Array member:")
## Exploring Array type
rupp_type = sh.get_type("ntdll!_RTL_USER_PROCESS_PARAMETERS")
print(rupp_type)
child = [x for x in rupp_type.children if x.name == "CurrentDirectores"][0]
print("ntdll!_RTL_USER_PROCESS_PARAMETERS CurrentDirectores is an Array:")
print("  {0}".format(child))
print("      - name: {0}".format(child.name))
print("      - tag: {0!r}".format(child.tag))
print("      - datakind: {0!r}".format(child.datakind))
print("      - count: {0!r}".format(child.count))
print("      - type: {0!r}".format(child.type))
print("      - parent: {0!r}".format(child.parent))

print("")
print("Exploring an enum:")
prodt_type = sh.get_type("ntdll!_NT_PRODUCT_TYPE")
print(prodt_type)
for child in prodt_type.children:
    print("    {0}".format(child))
    print("        - name: {0}".format(child.name))
    print("        - value: {0}".format(child.value))
    print("        - tag: {0!r}".format(child.tag))
    print("        - datakind: {0!r}".format(child.datakind))
    print("        - type: {0!r}".format(child.type))
    print("        - parent: {0!r}".format(child.parent))

print("")
print("Exploring a function:")
func_inc = sh.get_type("ntdll!_inc")
print(func_inc)
print("  - tag: {0!r}".format(func_inc.tag))
print("  - type: {0}".format(func_inc.type))
print("  - children:")
for child in func_inc.children:
    print("    {0}".format(child))
    print("        - tag: {0!r}".format(child.tag))
    print("        - address: {0!r}".format(child.address))