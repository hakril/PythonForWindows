import sys
import ctypes
import _ctypes
import windows.generated_def as gdef
from windows.pycompat import basestring

## TESTING Improved Buffer code ###
## This code is not stable and WILL CHANGE ##
## Do not use for now :) ##

# Uses cases:
    # Simple buffer
        # String / Wstring / Bytes
    # Resize array in struct
    # Typed buffer : filed call & contains X struct S
    # Having a ptr on struct with a buffer > sizeof(struct)
    # Autocreate a good-typed buffer from a tuple of ctypes objects

    # On peut vouloir creer un buffer avec 12 elts de type X
    # Ou creer un buffer avec 12 elt de type X mais une sub-size de 1000

if sys.version_info.major >= 3:
    long = int

class ImprovedCtypesBufferBase(object):
    def cast(self, type):
        return ctypes.cast(self, type)

    def as_string(self):
        return ctypes.cast(self, gdef.LPCSTR).value

    def as_wstring(self):
        return ctypes.cast(self, gdef.LPWSTR).value

    def as_pvoid(self):
        return self.cast(gdef.PVOID)

    # Constructor
    @classmethod
    def from_size(cls, size):
        raw_buffer = ctypes.c_buffer(size)
        buffer = cls.from_buffer(raw_buffer)
        buffer._raw_buffer_ = raw_buffer
        return buffer

    @property
    def real_size(self):
        real_buffer = getattr(self, "_raw_buffer_", self)
        return ctypes.sizeof(real_buffer)

    def __new__(cls, *args, **kwargs):
        if "size" in kwargs:
            buff =  ctypes.create_string_buffer(kwargs["size"])
            self = cls.from_buffer(buff)
            self._raw_buffer_ = buff
            return self
        # Add a '_raw_buffer_' even when no explicit size ?
        return super(ImprovedCtypesBufferBase, cls).__new__(cls, *args, **kwargs)


# Used in windows.crypto.sign_verify for test
class PartialBufferType(object):
    def __init__(self, type, nbelt=None):
        self.type = type
        self.nbelt = None

    @staticmethod
    def create_real_implem(item_type, nbelt):
        if isinstance(nbelt, long):
            nbelt = int(nbelt)
            assert isinstance(nbelt, int)
        cls_name = "TypedBuffer<{0}><{1}>".format(item_type.__name__, nbelt)

        class TmpImplemArrayName(ImprovedCtypesBufferBase, ctypes.Array):
            _type_ = item_type
            _length_ = nbelt

        TmpImplemArrayName.__name__ = cls_name
        return TmpImplemArrayName

    def from_buffer(self, buffer): # size as kwargs ?
        if  len(buffer) % ctypes.sizeof(self.type):
            raise NotImplementedError("Buffer size of not a multiple of sizeof({0})".format(self.type.__name__))
        nbelt = int(len(buffer) / ctypes.sizeof(self.type))
        return self.create_real_implem(self.type, nbelt).from_buffer(buffer)

    def from_buffer_copy(self, buffer): # size as kwargs ?
        if  len(buffer) % ctypes.sizeof(self.type):
            raise NotImplementedError("Buffer size of not a multiple of sizeof({0})".format(self.type.__name__))
        nbelt = int(len(buffer) / ctypes.sizeof(self.type))
        return self.create_real_implem(self.type, nbelt).from_buffer_copy(buffer)

    def create(self, nbelt):
        return self.create_real_implem(self.type, nbelt)

    def __mul__(self, nbelt):
        return self.create_real_implem(self.type, nbelt)

    def __call__(self, *args, **kwargs):
        if len(args) == 1: # String magic: explode string as arg
            if isinstance(args[0], basestring):
                args = args[0]
        nbelt = kwargs.get("nbelt", max(len(args), 1))
        return self.create_real_implem(self.type, nbelt)(*args, **kwargs)

# # Expose these predefined types ?
# CharBuffer = PartialBufferType(gdef.CHAR)
# WCharBuffer = PartialBufferType(gdef.WCHAR)
# ByteBuffer = PartialBufferType(gdef.BYTE)


def BUFFER(type, nbelt=None):
    if nbelt is None:
        return PartialBufferType(type) # Allow user to create custom sized buffer
    return PartialBufferType.create_real_implem(type, int(nbelt))

def buffer(obj, eltclass=None):
    if eltclass is None: # Guess
        obj = list(obj)
        item = obj[0]
        eltclass = type(item) # All object must have the same type
    dlen = len(obj)
    return BUFFER(eltclass, dlen)(*obj)

def resized_array(array, newnbelt, newtype=None):
    if newtype is None:
        newtype = array._type_
    btype = BUFFER(newtype, newnbelt)
    new_array = btype.from_address(ctypes.addressof(array))
    new_array._base_array_ = array # Keep a ref to prevent some gc
    return new_array



