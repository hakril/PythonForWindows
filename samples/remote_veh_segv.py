import windows
import windows.test

from windows.generated_def.winstructs import *

python_code = """
import windows
import ctypes
import windows
from windows.exception import VectoredException
import windows.generated_def.windef as windef
from windows.generated_def.winstructs import *

windows.utils.create_console()

module_to_trace = "gdi32.dll"
nb_repeat = [5]

@VectoredException
def handler(exc):
    if exc[0].ExceptionRecord[0].ExceptionCode == EXCEPTION_ACCESS_VIOLATION:
        print("")
        target_addr = ctypes.cast(exc[0].ExceptionRecord[0].ExceptionInformation[1], ctypes.c_void_p).value
        print("Instr at {0} accessed to addr {1} ({2})".format(hex(exc[0].ExceptionRecord[0].ExceptionAddress), hex(target_addr), module_to_trace))
        windows.winproxy.VirtualProtect(target_page, code_size, windef.PAGE_EXECUTE_READWRITE)
        nb_repeat[0] -= 1
        if nb_repeat[0]:
            exc[0].ContextRecord[0].EEFlags.TF = 1
        else:
            print("No more tracing !")
        return windef.EXCEPTION_CONTINUE_EXECUTION
    else:
        print("Exception of type {0}".format(exc[0].ExceptionRecord[0].ExceptionCode))
        print("Resetting page protection to <PAGE_READWRITE>")
        windows.winproxy.VirtualProtect(target_page, code_size, windef.PAGE_READWRITE)
        return windef.EXCEPTION_CONTINUE_EXECUTION


windows.winproxy.AddVectoredExceptionHandler(0, handler)

print("Tracing execution in module: <{0}>".format(module_to_trace))

module = [x for x in windows.current_process.peb.modules if x.name == module_to_trace][0]
target_page = module.baseaddr
code_size = module.pe.get_OptionalHeader().SizeOfCode

print("Protected page is at {0}".format(hex(target_page)))
windows.winproxy.VirtualProtect(target_page, code_size, windef.PAGE_READWRITE)
"""

c = windows.test.pop_calc_64(dwCreationFlags=CREATE_SUSPENDED)
x = c.execute_python(python_code)

c.threads[0].resume()

import time
time.sleep(0.1)

for t in c.threads:
    t.suspend()

time.sleep(1)
c.exit()

