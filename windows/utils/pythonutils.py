"""utils fonctions non windows-related"""
import ctypes
import _ctypes
from windows.generated_def import Flag, LPCSTR, LPWSTR


def buffer(size): # Test
    buf = ctypes.create_string_buffer(size)
    buf.size = size
    buf.address = ctypes.addressof(buf)

    class ImprovedCtypesBufferImpl(ctypes.Array):
        _length_ = size
        _type_ = ctypes.c_char
        def lol(self):
            return "lol"

        def as_string(self):
            return ctypes.cast(self, LPCSTR).value

        def as_wstring(self):
            return ctypes.cast(self, LPWSTR).value

    return ImprovedCtypesBufferImpl()


def fixedpropety(f):
    cache_name = "_" + f.__name__

    def prop(self):
        try:
            return getattr(self, cache_name)
        except AttributeError:
            setattr(self, cache_name, f(self))
            return getattr(self, cache_name)
    return property(prop, doc=f.__doc__)


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


def sprint(struct, name="struct", hexa=True):
    return print_ctypes_struct(struct, name=name, hexa=hexa)