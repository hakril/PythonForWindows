import ctypes
import windows
from windows.vectored_exception import VectoredException
import windows.generated_def.windef as windef
from windows.generated_def.winstructs import *


@VectoredException
def handler(exc):
    print("POUET")
    if exc[0].ExceptionRecord[0].ExceptionCode == EXCEPTION_ACCESS_VIOLATION:
        target_addr = ctypes.cast(exc[0].ExceptionRecord[0].ExceptionInformation[1], ctypes.c_void_p).value
        print("Instr at {0} accessed to addr {1}".format(hex(exc[0].ExceptionRecord[0].ExceptionAddress), hex(target_addr)))
        windows.winproxy.VirtualProtect(target_page, 0x1000, windef.PAGE_READWRITE)
        exc[0].ContextRecord[0].EEFlags.TF = 1
        return windef.EXCEPTION_CONTINUE_EXECUTION
    else:
        print("HAHAH {0}".format(exc[0].ExceptionRecord[0].ExceptionCode))
        windows.winproxy.VirtualProtect(target_page, 0x1000, windef.PAGE_NOACCESS)
        return windef.EXCEPTION_CONTINUE_EXECUTION


windows.winproxy.AddVectoredExceptionHandler(0, handler)

target_page = windows.current_process.virtual_alloc(0x1000)
print("Protected page is at {0}".format(hex(target_page)))
windows.winproxy.VirtualProtect(target_page, 0x1000, windef.PAGE_NOACCESS)

v = ctypes.c_uint.from_address(target_page).value
print("POINT1")
v = ctypes.c_uint.from_address(target_page + 0x10).value
print("POINT2")



# (cmd) python.exe samples\veh_segv.py
#Protected page is at 0x3f0000
#POUET
#Instr at 0x1d1ab5f4 accessed to addr 0x3f0000
#POUET
#HAHAH EXCEPTION_SINGLE_STEP(0x80000004L)
#POINT1
#POUET
#Instr at 0x1d1ab5f4 accessed to addr 0x3f0010
#POUET
#HAHAH EXCEPTION_SINGLE_STEP(0x80000004L)
#POINT2