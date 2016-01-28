import windows
import windows.test

from windows.generated_def.winstructs import *

#c = windows.test.pop_calc_64()


c = windows.test.pop_calc_64(dwCreationFlags=CREATE_SUSPENDED)


python_code = """
import windows
import ctypes
import windows
from windows.vectored_exception import VectoredException
import windows.generated_def.windef as windef
from windows.generated_def.winstructs import *

windows.utils.create_console()

@VectoredException
def handler(exc):
    print("POUET")
    if exc[0].ExceptionRecord[0].ExceptionCode == EXCEPTION_ACCESS_VIOLATION:
        target_addr = ctypes.cast(exc[0].ExceptionRecord[0].ExceptionInformation[1], ctypes.c_void_p).value
        print("Instr at {0} accessed to addr {1}".format(hex(exc[0].ExceptionRecord[0].ExceptionAddress), hex(target_addr)))
        #return windef.EXCEPTION_CONTINUE_EXECUTION
    return windef.EXCEPTION_CONTINUE_SEARCH


windows.winproxy.AddVectoredExceptionHandler(0, handler)
print("YOLO<3")
print(ctypes.c_uint.from_address(0x42424242).value)
"""


x = c.execute_python(python_code)