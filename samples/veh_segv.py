import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import ctypes
import windows
from windows.winobject.exception import VectoredException
import windows.generated_def.windef as windef
from windows.generated_def.winstructs import *


@VectoredException
def handler(exc):
    print("==Entry of VEH handler==")
    if exc[0].ExceptionRecord[0].ExceptionCode == EXCEPTION_ACCESS_VIOLATION:
        target_addr = ctypes.cast(exc[0].ExceptionRecord[0].ExceptionInformation[1], ctypes.c_void_p).value
        print("Instr at {0} accessed to addr {1}".format(hex(exc[0].ExceptionRecord[0].ExceptionAddress), hex(target_addr)))
        print("Resetting page protection to <PAGE_READWRITE>")
        windows.winproxy.VirtualProtect(target_page, 0x1000, windef.PAGE_READWRITE)
        exc[0].ContextRecord[0].EEFlags.TF = 1
        return windef.EXCEPTION_CONTINUE_EXECUTION
    else:
        print("Exception of type {0}".format(exc[0].ExceptionRecord[0].ExceptionCode))
        print("Resetting page protection to <PAGE_NOACCESS>")
        windows.winproxy.VirtualProtect(target_page, 0x1000, windef.PAGE_NOACCESS)
        return windef.EXCEPTION_CONTINUE_EXECUTION


windows.winproxy.AddVectoredExceptionHandler(0, handler)

target_page = windows.current_process.virtual_alloc(0x1000)
print("Protected page is at <{0}>".format(hex(target_page)))
print("Setting page protection to <PAGE_NOACCESS>")
windows.winproxy.VirtualProtect(target_page, 0x1000, windef.PAGE_NOACCESS)

print("")
v = ctypes.c_uint.from_address(target_page).value
print("Value 1 read")

print("")
v = ctypes.c_uint.from_address(target_page + 0x10).value
print("Value 2 read")
