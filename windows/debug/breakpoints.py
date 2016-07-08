from windows.generated_def.winstructs import *
from windows.generated_def import windef

from windows.winobject.process import WinProcess, WinThread


STANDARD_BP = "BP"
HARDWARE_EXEC_BP = "HXBP"
MEMORY_BREAKPOINT = "MEMBP"

class Breakpoint(object):
    """An standard (Int3) breakpoint (type == ``STANDARD_BP``)"""
    type = STANDARD_BP # REAL BP
    def __init__(self, addr):
        self.addr = addr

    def apply_to_target(self, target):
        return isinstance(target, WinProcess)

    def trigger(self, dbg, exception):
        """Called when breakpoint is hit"""
        pass


class ProxyBreakpoint(Breakpoint):
    def __init__(self, target, addr, type):
        self.target = target
        self.addr = addr
        self.type = type

    def trigger(self, dbg, exception):
        return self.target(dbg, exception)


class HXBreakpoint(Breakpoint):
    """An hardware-execution breakpoint (type == ``HARDWARE_EXEC_BP``)"""
    type = HARDWARE_EXEC_BP

    def apply_to_target(self, target):
        return isinstance(target, WinThread)

class MemoryBreakpoint(Breakpoint):
    type = MEMORY_BREAKPOINT

    DEFAULT_PROTECT = PAGE_READONLY
    DEFAULT_SIZE = 0x1000
    def __init__(self, addr, size=None, prot=None):
        super(MemoryBreakpoint, self).__init__(addr)
        self.size = size if size is not None else self.DEFAULT_SIZE
        self.protect = size if prot is not None else self.DEFAULT_PROTECT


    def trigger(self, dbg, exception):
        """Called when breakpoint is hit"""
        pass