import windows # Allow extended-struct to use windows/winproxy/...
import windows.pycompat

from ctypes import *
from ctypes.wintypes import *

from .flag import Flag, FlagMapper, FlagExatractor

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

# Bypass bug https://bugs.python.org/issue29270

super_noissue = super

class EnumType(DWORD):
    values = ()
    mapper = {}

    @property
    def value(self):
        raw_value = super_noissue(EnumType, self).value
        return self.mapper.get(raw_value, raw_value)

    def __repr__(self):
        raw_value = super_noissue(EnumType, self).value
        if raw_value in self.values:
            value = self.value
            return "<{0} {1}({2})>".format(type(self).__name__, value.name, hex(raw_value))
        return "<{0}({1})>".format(type(self).__name__, hex(self.value))

# Sale: windef is hardcoded
from . import windef
SZOID_MAPPER = FlagMapper(*(getattr(windef, x) for x in dir(windef) if x.startswith("szOID")))
