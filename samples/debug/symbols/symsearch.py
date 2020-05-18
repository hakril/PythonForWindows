import argparse
import os

import windows
import windows.debug.symbols as symbols


parser = argparse.ArgumentParser(prog=__file__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('pattern')
parser.add_argument('file', help="The PE file to load")
parser.add_argument('--addr', type=lambda x: int(x, 0), default=0, help="The load address of the PE")
parser.add_argument('--tag', type=lambda x: int(x, 0), default=0)
parser.add_argument('--dbghelp', help='The path of DBG help to use (default use env:PFW_DBGHELP_PATH)')

args = parser.parse_args()
if args.dbghelp:
    symbols.set_dbghelp_path(args.dbghelp)
else:
    if "PFW_DBGHELP_PATH" not in os.environ:
        print("Not dbghelp path given and no environ var 'PFW_DBGHELP_PATH' sample may fail")


sh = symbols.VirtualSymbolHandler()
mod = sh.load_file(path=args.file, addr=args.addr)
res = sh.search(args.pattern, mod=mod, tag=args.tag)
print("{0} symbols found:".format(len(res)))
for sym in res:
    print(" * {0!r}".format(sym))
