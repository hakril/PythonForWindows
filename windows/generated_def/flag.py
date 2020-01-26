import sys

if sys.version_info.major >= 3:
    long = int


class Flag(long):
    def __new__(cls, name, value):
        return super(Flag, cls).__new__(cls, value)

    def __init__(self, name, value):
        self.name = name

    def __repr__(self):
        return "{0}({1:#x})".format(self.name, self)

    # Custom __str__ removed for multiple reason
    # Main one -> it breaks the json encoding of structure with flags :)
    # Moving to a new politic -> if people want the name in a string use {x!r}
    # The __str__ of security descriptor & guid will change soon as well :)

    # __str__ = __repr__

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


class FlagExatractor(object):
    def __init__(self, attr, values):
        self.attr = attr
        self.attrsize = attr.size * 8
        self.mapper = FlagMapper(*values)

    def __get__(self, obj, type):
        if obj is None:
            return self
        # Retrieve the real value
        value = self.attr.__get__(obj)
        generator = (1 << i for i in range(self.attrsize))
        return [self.mapper[f] for f in generator if value & f]
