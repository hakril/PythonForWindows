import os
import argparse

import windows
import windows.test
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


if windows.current_process.bitness == 32:
    target = windows.test.pop_proc_32()
else:
    target = windows.test.pop_proc_64()

print("Target is {0}".format(target))
sh = symbols.ProcessSymbolHandler(target)
import time;time.sleep(0.1) # Just wait for the process initialisation
sh.refresh() # Refresh symbol list (Only meaningful for ProcessSymbolHandler)

print("Some loaded modules are:".format())
for sm in sh.modules[:3]:
    print(" * {0}".format(sm))

createserv = sh["advapi32!CreateServiceEx"]

print("")
TEST_FUNCTION = "advapi32!CreateServiceEx"
print("Resolving function <{0}>".format(TEST_FUNCTION))
createserv = sh[TEST_FUNCTION]
print("Symbol found !")
print("  * __repr__: {0!r}".format(createserv))
print("  * __str__: {0}".format(createserv))
print("  * addr: {0:#x}".format(createserv.addr))
print("  * name: {0}".format(createserv.name))
print("  * fullname: {0}".format(createserv.fullname))
print("  * module: {0}".format(createserv.module))

target.exit()