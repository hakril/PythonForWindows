import sys
import ctypes
from .flag import Flag

is_py3 = (sys.version_info.major >= 3)

class NtStatusException(WindowsError):
    ALL_STATUS = {}
    def __init__(self , code):
        try:
            x = self.ALL_STATUS[code]
        except KeyError:
            x = (code, 'UNKNOW_ERROR', 'Error non documented in ntstatus.py')
        self.code = x[0]
        self.name = x[1]
        self.descr = x[2]
        code_as_long = ctypes.c_long(x[0]).value
        if is_py3:
            vals =  code_as_long, x[1], x[2], code_as_long
        else:
            vals =  code_as_long, x[1], x[2]
        return super(NtStatusException, self).__init__(*vals)

    def __str__(self):
        return "{e.name}(0x{e.code:x}): {e.descr}".format(e=self)

    def __repr__(self):
        return "{0}(0x{1:08x}, {2})".format(type(self).__name__, self.code, self.name)

    @classmethod
    def register_ntstatus(cls, code, name, descr):
        if code in cls.ALL_STATUS:
            return # Use the first def
        cls.ALL_STATUS[code] = (code, name, descr)
        return Flag(name, code)

