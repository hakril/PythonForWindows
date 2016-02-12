import ctypes
import windows
import windows.test

from windows.generated_def.winstructs import *

remote_code = """
import windows
from windows.generated_def.winstructs import *

windows.utils.create_console()

class YOLOHXBP(windows.debug.HXBreakpoint):
    def trigger(self, dbg, exc):
        p = windows.current_process
        arg_pos = 2
        context = dbg.get_exception_context()
        esp = context.Esp
        unicode_string_addr = p.read_ptr(esp + (arg_pos + 1) * 4)
        wstring_addr = p.read_ptr(unicode_string_addr + 4)
        dll_loaded = p.read_wstring(wstring_addr)
        print("I AM LOADING <{0}>".format(dll_loaded))

d = windows.debug.LocalDebugger()

exp = windows.current_process.peb.modules[1].pe.exports
#windows.utils.FixedInteractiveConsole(locals()).interact()
ldr = exp["LdrLoadDll"]
d.add_bp(YOLOHXBP(ldr))
print("By from {0}".format(windows.current_thread.tid))

"""

c = windows.test.pop_calc_32(dwCreationFlags=CREATE_SUSPENDED)
c.execute_python(remote_code)
c.threads[0].resume()

import time
time.sleep(2)
c.exit()
