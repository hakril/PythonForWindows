import ctypes
import mmap
import platform
import sys

import windows
import windows.winproxy
import windows.generated_def as gdef

from . import simple_x86 as x86
from . import simple_x64 as x64


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
        addr = windows.winproxy.VirtualAlloc(0, size, 0x1000, gdef.PAGE_EXECUTE_READWRITE)
        mymap = (ctypes.c_char * size).from_address(addr)
        mymap.addr = addr
        self.maps.append(mymap)
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

    def close(self):
        maps = self.maps
        self.maps = []
        self.cur_offset = 0
        self.cur_page_size = 0
        if getattr(sys, "path", None) is None:
            # Path is None -> Python shutdown
            return
        for mymap in maps:
            windows.winproxy.VirtualFree(mymap.addr, dwFreeType=gdef.MEM_RELEASE)

    def __del__(self):
        self.close()

allocator = CustomAllocator()


def create_function(code, types, calling_convention=ctypes.CFUNCTYPE):
    """Create a python function that call raw machine code

   :param str code: Raw machine code that will be called
   :param list types: Return type and parameters type (see :mod:`ctypes`)
   :return: the created function
   :rtype: function
     """
    func_type = calling_convention(*types)
    addr = allocator.write_code(code)
    res = func_type(addr)
    res.code_addr = addr
    return res
