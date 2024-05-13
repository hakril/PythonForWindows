from . import windef
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

    winstructs.PALPC_PORT_ATTRIBUTES = winstructs.PALPC_PORT_ATTRIBUTES32
    winstructs.ALPC_PORT_ATTRIBUTES = winstructs.ALPC_PORT_ATTRIBUTES32

    winstructs.PORT_MESSAGE = winstructs.PORT_MESSAGE32
    winstructs.PPORT_MESSAGE = winstructs.PPORT_MESSAGE32

    # CFGMGR32
    winstructs.IRQ_RESOURCE = winstructs.IRQ_RESOURCE_32

    # Socket
    windef.WSADATA = winstructs.WSADATA32
    windef.INVALID_SOCKET = windef.INVALID_SOCKET32


else:
    winstructs.CONTEXT = winstructs.CONTEXT64
    winstructs.PCONTEXT = winstructs.PCONTEXT64
    winstructs.LPCONTEXT = winstructs.LPCONTEXT64

    winstructs.EXCEPTION_POINTERS = winstructs.EXCEPTION_POINTERS64
    winstructs.PEXCEPTION_POINTERS = winstructs.PEXCEPTION_POINTERS64

    winstructs.SYSTEM_MODULE = winstructs.SYSTEM_MODULE64
    winstructs.SYSTEM_MODULE_INFORMATION = winstructs.SYSTEM_MODULE_INFORMATION64

    winstructs.PALPC_PORT_ATTRIBUTES = winstructs.PALPC_PORT_ATTRIBUTES64
    winstructs.ALPC_PORT_ATTRIBUTES = winstructs.ALPC_PORT_ATTRIBUTES64

    winstructs.PORT_MESSAGE = winstructs.PORT_MESSAGE64
    winstructs.PPORT_MESSAGE = winstructs.PPORT_MESSAGE64

    # CFGMGR32
    winstructs.IRQ_RESOURCE = winstructs.IRQ_RESOURCE_64

    # Socket
    windef.WSADATA = winstructs.WSADATA64
    windef.INVALID_SOCKET = windef.INVALID_SOCKET64

from . import winfuncs
from . import windef
from . import interfaces

# Fuck it
from .winstructs import *
from .winfuncs import *
from .windef import *
from .interfaces import *



