import windows
from . import winstructs

def bitness():
    """Return 32 or 64"""
    import platform
    bits = platform.architecture()[0]
    return int(bits[:2])

# Use windows.current_process.bitness ? need to fix problem of this imported before the creation of windows.current_process
if bitness() == 32:
    winstructs.CONTEXT = winstructs.CONTEXT32
    winstructs.PCONTEXT = winstructs.PCONTEXT32
    winstructs.LPCONTEXT = winstructs.LPCONTEXT32

    winstructs.EXCEPTION_POINTERS = winstructs.EXCEPTION_POINTERS32
    winstructs.PEXCEPTION_POINTERS = winstructs.PEXCEPTION_POINTERS32

    winstructs.SYSTEM_MODULE = winstructs.SYSTEM_MODULE32
    winstructs.SYSTEM_MODULE_INFORMATION = winstructs.SYSTEM_MODULE_INFORMATION32
else:
    winstructs.CONTEXT = winstructs.CONTEXT64
    winstructs.PCONTEXT = winstructs.PCONTEXT64
    winstructs.LPCONTEXT = winstructs.LPCONTEXT64

    winstructs.EXCEPTION_POINTERS = winstructs.EXCEPTION_POINTERS64
    winstructs.PEXCEPTION_POINTERS = winstructs.PEXCEPTION_POINTERS64

    winstructs.SYSTEM_MODULE = winstructs.SYSTEM_MODULE64
    winstructs.SYSTEM_MODULE_INFORMATION = winstructs.SYSTEM_MODULE_INFORMATION64

from . import winfuncs



