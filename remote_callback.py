import ctypes
import ctypes.wintypes
from windows.hooks import *

# Example of callback for IAT hooks

@Callback(ctypes.c_ulong, ctypes.c_ulong)
def exit_callback(x, real_function):
    print("Try to quit with {0} | {1}".format(x, type(x)))
    if x == 3:
        print("TRYING TO REAL EXIT")
        return real_function(1234)
    return 0

@CreateFileACallback
def createfile_callback(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, real_function):
    print("Trying to open {0}".format(lpFileName))
    if "dick" in lpFileName:
        return 0x4242
    return real_function()
    