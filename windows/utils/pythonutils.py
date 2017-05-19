"""utils fonctions non windows-related"""
import ctypes
import _ctypes
from windows.generated_def import Flag


def fixedpropety(f):
    cache_name = "_" + f.__name__

    def prop(self):
        try:
            return getattr(self, cache_name)
        except AttributeError:
            setattr(self, cache_name, f(self))
            return getattr(self, cache_name)
    return property(prop, doc=f.__doc__)


def swallow_ctypes_copy(ctypes_object):
    new_copy = type(ctypes_object)()
    ctypes.memmove(ctypes.byref(new_copy), ctypes.byref(ctypes_object), ctypes.sizeof(new_copy))
    return new_copy


# type replacement based on name
def transform_ctypes_fields(struct, replacement):
    return [(name, replacement.get(name, type)) for name, type in struct._fields_]


def print_ctypes_struct(struct, name="", ident=0, hexa=False):
    if isinstance(struct, _ctypes._Pointer):
        if ctypes.cast(struct, ctypes.c_void_p).value is None:
            print("{0} -> NULL".format(name))
            return
        return print_ctypes_struct(struct[0], name + "<deref>", hexa=hexa)

    if not hasattr(struct, "_fields_"):
        value = struct
        if hasattr(struct, "value"):
            value = struct.value

        if isinstance(value, basestring):
            value = repr(value)
        if hexa and not isinstance(value, Flag):
            try:
                print("{0} -> {1}".format(name, hex(value)))
                return
            except TypeError:
                pass
        print("{0} -> {1}".format(name, value))
        return

    for fname, ftype in struct._fields_:
        try:
            value = getattr(struct, fname)
        except Exception as e:
            print("Error while printing <{0}> : {1}".format(fname, e))
            continue
        print_ctypes_struct(value, "{0}.{1}".format(name, fname), hexa=hexa)