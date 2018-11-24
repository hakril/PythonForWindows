import ctypes
import mmap
import platform
import sys

import windows
import windows.winproxy

from . import simple_x86 as x86
from . import simple_x64 as x64


class PyObj(ctypes.Structure):
    _fields_ = [("ob_refcnt", ctypes.c_size_t),
                ("ob_type", ctypes.c_void_p)]  # must be cast


class PyMmap(PyObj):
    _fields_ = [("ob_addr", ctypes.c_size_t), ("ob_size", ctypes.c_size_t)]


# Specific mmap class for code injection
class MyMap(mmap.mmap):
    """ A mmap that is never unmapped and that contains the page address """
    def __init__(self, *args, **kwarg):
        # Get the page address by 'introspection' of the C struct
        m = PyMmap.from_address(id(self))
        self.addr = m.ob_addr
        # Prevent garbage collection (so unmaping) of the page
        m.ob_refcnt += 1

    @classmethod
    def get_map(cls, size):
        """ Dispatch to the good mmap implem depending on the current system """
        systems = {'windows': Win32MyMap,
                   'linux': UnixMyMap}
        x = platform.system().lower()
        if x not in systems:
            raise ValueError("Unknow system {0}".format(x))
        return systems[x].get_map(size)


class Win32MyMap(MyMap):
    @classmethod
    def get_map(cls, size):
        addr = windows.winproxy.VirtualAlloc(0, size, 0x1000, 0x40)
        new_map = (ctypes.c_char * size).from_address(addr)
        new_map.addr = addr
        if new_map.addr == 0:
            raise ctypes.WinError()
        return new_map


class UnixMyMap(MyMap):
    @classmethod
    def get_map(cls, size):
        prot = mmap.PROT_EXEC | mmap.PROT_WRITE | mmap.PROT_READ
        return cls(-1, size, prot=prot)


class CustomAllocator(object):
    int_size = {'32bit': 4, '64bit': 8}

    def __init__(self):
        self.maps = []
        self.cur_offset = 0
        self.cur_page_size = 0 # Force get_new_page on first request
        self.names = []

    @classmethod
    def get_int_size(cls):
        bits = platform.architecture()[0]
        if bits not in cls.int_size:
            raise ValueError("Unknow platform bits <{0}>".format(bits))
        return cls.int_size[bits]

    def get_new_page(self, size):
        self.maps.append(MyMap.get_map(size))
        self.cur_offset = 0
        self.cur_page_size = size

    def reserve_size(self, size):
        if size + self.cur_offset > self.cur_page_size:
            self.get_new_page((size + 0x1000) & ~0xfff)
        addr = self.maps[-1].addr + self.cur_offset
        self.cur_offset += size
        return addr

    def reserve_int(self, nb_int=1):
        int_size = self.get_int_size()
        return self.reserve_size(int_size * nb_int)

    def write_code(self, code):
        size = len(code)
        if size + self.cur_offset > self.cur_page_size:
            self.get_new_page((size + 0x1000) & ~0xfff)
        self.maps[-1][self.cur_offset: self.cur_offset + size] = code
        addr = self.maps[-1].addr + self.cur_offset
        self.cur_offset += size
        return addr

allocator = CustomAllocator()


def create_function(code, types):
    """Create a python function that call raw machine code

   :param str code: Raw machine code that will be called
   :param list types: Return type and parameters type (see :mod:`ctypes`)
   :return: the created function
   :rtype: function
     """
    func_type = ctypes.CFUNCTYPE(*types)
    addr = allocator.write_code(code)
    res = func_type(addr)
    res.code_addr = addr
    return res
