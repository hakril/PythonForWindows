import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.test
import windows.debug

from windows.generated_def.winstructs import *

class FollowNtCreateFile(windows.debug.FunctionBP):
    TARGET = windows.winproxy.NtCreateFile
    COUNTER = 3

    def trigger(self, dbg, exc):
        if not self.COUNTER:
            print("Exiting process")
            dbg.current_process.exit()
            return
        params = self.extract_arguments(dbg.current_process, dbg.current_thread)
        filename = params["ObjectAttributes"].contents.ObjectName.contents.Buffer
        handle_addr = params["FileHandle"].value
        self.data = (filename, handle_addr)
        self.break_on_ret(dbg, exc)

    def ret_trigger(self, dbg, exc):
        filename, handle_addr = self.data
        ret_value = dbg.current_thread.context.func_result # EAX / RAX depending of bitness
        handle_value = dbg.current_process.read_ptr(handle_addr)
        if ret_value:
            print("NtCreateFile of <{0}> FAILED (result={1:#x})".format(filename, ret_value))
            return
        print("NtCreateFile of <{0}>: handle = {1:#x}".format(filename, handle_value))
        # Manual verification
        fhandle = [h for h in windows.system.handles if h.dwProcessId == dbg.current_process.pid and h.wValue == handle_value]
        if not fhandle:
            raise ValueError("handle not found!")
        fhandle = fhandle[0]
        print("Handle manually found! typename=<{0}>, name=<{1}>".format(fhandle.type, fhandle.name))
        print("")
        self.COUNTER -= 1

if __name__ == "__main__":
    calc = windows.test.pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
    d = windows.debug.Debugger(calc)
    d.add_bp(FollowNtCreateFile())
    d.loop()