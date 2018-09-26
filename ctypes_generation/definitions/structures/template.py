import windows # Allow extended-struct to use windows/winproxy/...
from ctypes import *
from ctypes.wintypes import *

from flag import Flag, FlagMapper, FlagExatractor

class EnumValue(Flag):
    def __new__(cls, enum_name, name, value):
        return super(EnumValue, cls).__new__(cls, name, value)

    def __init__(self, enum_name, name, value):
        self.enum_name = enum_name
        self.name = name

    def __repr__(self):
        return "{0}.{1}({2})".format(self.enum_name, self.name, hex(self))

    # Fix pickling with protocol 2
    def __getnewargs__(self, *args):
        return self.enum_name, self.name, int(self)


class EnumType(DWORD):
    values = ()
    mapper = {}

    @property
    def value(self):
        raw_value = super(EnumType, self).value
        return self.mapper.get(raw_value, raw_value)

    def __repr__(self):
        raw_value = super(EnumType, self).value
        if raw_value in self.values:
            value = self.value
            return "<{0} {1}({2})>".format(type(self).__name__, value.name, hex(raw_value))
        return "<{0}({1})>".format(type(self).__name__, hex(self.value))
