import sys

if sys.version_info.major == 3:
    long = int

class Flag(long):
    def __new__(cls, name, value):
        return super(Flag, cls).__new__(cls, value)

    def __init__(self, name, value):
        self.name = name

    def __repr__(self):
        return "{0}({1})".format(self.name, hex(self))

    __str__ = __repr__

   # Fix pickling with protocol 2
    def __getnewargs__(self, *args):
        return self.name, long(self)

class StrFlag(str):
    def __new__(cls, name, value):
        if isinstance(value, cls):
            return value
        return super(StrFlag, cls).__new__(cls, value)

    def __init__(self, name, value):
        self.name = name

    def __repr__(self):
        return "{0}({1})".format(self.name, str.__repr__(self))

    # __str__ = __repr__

    # Fix pickling with protocol 2
    def __getnewargs__(self, *args):
        return self.name, str.__str__(self)

def make_flag(name, value):
    if isinstance(value, (int, long)):
        return Flag(name, value)
    return StrFlag(name, value)

class FlagMapper(dict):
    def __init__(self, *values):
        self.update({x:x for x in values})

    def __missing__(self, key):
        return key