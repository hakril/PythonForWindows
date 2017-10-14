import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.test
import windows.debug

from windows.generated_def.winstructs import *

# Just a debugger that follow NtCreateFile and print filename & handler
from debug_functionbp import FollowNtCreateFile


def follow_create_file(pid):
    print("Finding process with pid <{0}>".format(pid))
    target = [p for p in windows.system.processes if p.pid == pid][0]
    print("Target is {0}".format(target))
    dbg = windows.debug.Debugger.attach(target)
    print("Debugger attached: {0}".format(dbg))
    print("")
    dbg.add_bp(FollowNtCreateFile())
    dbg.loop()

if __name__ == "__main__":
    # Create a non-debugged process safe to debug
    calc = windows.test.pop_proc_32(dwCreationFlags=0)
    # Give ovnly the PID to follow_create_file
    follow_create_file(calc.pid)
