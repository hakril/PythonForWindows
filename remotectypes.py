import _ctypes
import ctypes
import ctypes.wintypes
import itertools
from _ctypes import _SimpleCData


# ## Utils ### #
def is_pointer(x):
    return isinstance(x, _ctypes._Pointer)


def is_pointer_type(x):
    return issubclass(x, _ctypes._Pointer)


def is_array(x):
    return isinstance(x, _ctypes.Array)


def is_array_type(x):
    return issubclass(x, _ctypes.Array)


def is_structure_type(x):
    return issubclass(x, ctypes.Structure)


def is_union_type(x):
    return issubclass(x, ctypes.Union)

# ### My types ### #

# # 64bits pointer types # #

# I know direct inheritance from _SimpleCData seems bad
# But it seems to be the only way to have the normal
# ctypes.Structure way of working (need to investigate)


class c_void_p64(_SimpleCData):
    _type_ = "Q"


class c_char_p64(_SimpleCData):
    _type_ = "Q"


class c_wchar_p64(_SimpleCData):
    _type_ = "Q"

# standard type translation
# don't know how to handle size_t since it's non-distinguable from c_ulong
# maybe force import before ctypes and modif stuff into ctypes ?


# # Remote Value
# Used by the RemoteStructure to access the target memory

class RemoteValue(object):
    @classmethod
    def from_buffer_with_target(cls, buffer, offset=0, target=None):
        x = cls.from_buffer(buffer)
        x.target = target
        return x


class RemotePtr(RemoteValue):
    @property
    def raw_value(self):
        return ctypes.cast(self, ctypes.c_void_p).value


class RemoteCCharP(RemotePtr, ctypes.c_char_p):
    @property
    def value(self):
        base = self.raw_value
        res = []
        for i in itertools.count():
            x = self.target.read_memory(base + (i * 0x100), 0x100)
            if "\x00" in x:
                res.append(x.split("\x00", 1)[0])
                break
            res.append(x)
        return "".join(res)


class RemoteWCharP(RemotePtr, ctypes.c_char_p):
    @property
    def value(self):
        base = self.raw_value
        res = []
        for i in itertools.count():
            x = self.target.read_memory(base + (i * 0x100), 0x100)
            utf16_chars = ["".join(c) for c in zip(*[iter(x)] * 2)]
            if "\x00\x00" in utf16_chars:
                res.extend(utf16_chars[:utf16_chars.index("\x00\x00")])
                break
            res.extend(x)
        return "".join(res).decode('utf16')


class RemoteStructurePointer(RemotePtr, ctypes.c_void_p):
    @classmethod
    def from_buffer_with_target_and_ptr_type(cls, buffer, offset=0, target=None, ptr_type=None):
        x = cls.from_buffer(buffer)
        x.target = target
        x.real_pointer_type = ptr_type
        return x

    @property
    def contents(self):
        remote_pointed_type = RemoteStructure.from_structure(self.real_pointer_type._type_)
        return remote_pointed_type(self.raw_value, self.target)

    def __repr__(self):
        return "<RemoteStructurePointer to {0}>".format(self.real_pointer_type._type_.__name__)


def create_remote_array(subtype, len):

    class RemoteArray(_ctypes.Array):
        _length_ = len
        _type_ = subtype

        def __init__(self, addr, target):
            self._base_addr = addr
            self.target = target

        def __getitem__(self, slice):
            if not isinstance(slice, (int, long)):
                raise NotImplementedError("RemoteArray slice __getitem__")
            if slice >= len:
                raise IndexError("Access to {0} for a RemoteArray of size {1}".format(slice, len))
            item_addr = self._base_addr + (ctypes.sizeof(subtype) * slice)

            # TODO: do better ?
            class TST(ctypes.Structure):
                _fields_ = [("TST", subtype)]
            return RemoteStructure.from_structure(TST)(item_addr, target=self.target).TST
    return RemoteArray


# 64bits pointers
class RemotePtr64(RemoteValue):
    def __init__(self, value, target):
        self.target = target
        super(RemotePtr64, self).__init__(value)

    @property
    def raw_value(self):
        # Bypass our own 'value' implementation
        # Even if we are a subclass of c_ulonglong
        my_addr = ctypes.addressof(self)
        return ctypes.c_ulonglong.from_address(my_addr).value


class Remote_c_void_p64(RemotePtr64, c_void_p64):
    pass


# base explanation:
# RemotePtr64 for the good `raw_value` implem
# RemoteCCharP for the good `value` implem
# c_char_p64 for the good _type_ (ctypes size)
class Remote_c_char_p64(c_char_p64, RemotePtr64, RemoteCCharP):
    def __repr__(self):
        return "<Remote_c_char_p64({0})>".format(self.raw_value)


class Remote_w_char_p64(c_wchar_p64, RemotePtr64, RemoteWCharP):
    def __repr__(self):
        return "<Remote_c_char_p64({0})>".format(self.raw_value)


class RemoteStructurePointer64(Remote_c_void_p64):
    @property
    def raw_value(self):
        return self.value

    @classmethod
    def from_buffer_with_target_and_ptr_type(cls, buffer, offset=0, target=None, ptr_type=None):
        x = cls.from_buffer(buffer)
        x.target = target
        x.real_pointer_type = ptr_type
        return x

    @property
    def contents(self):
        remote_pointed_type = transform_type_to_remote64bits(self.real_pointer_type._sub_ctypes_)
        return remote_pointed_type(self.raw_value, self.target)


type_32_64_translation_table = {
    ctypes.c_void_p: Remote_c_void_p64,
    ctypes.c_char_p: Remote_c_char_p64,
    ctypes.c_wchar_p: Remote_w_char_p64,
}


class RemoteStructureUnion(object):
    """Target is a process object"""
    _reserved_name = ["_target", "_fields_", "_fields_dict_", "_base_addr", "_get_field_by_name",
                      "_get_field_descrptor_by_name", "_handle_field_getattr", "_field_type_to_remote_type",
                      "__getattribute__", "_fields_"]

    _field_type_to_remote_type = {
        ctypes.c_char_p: RemoteCCharP,
        ctypes.c_wchar_p: RemoteWCharP,
        Remote_c_void_p64: Remote_c_void_p64,
        Remote_c_char_p64: Remote_c_char_p64,
        Remote_w_char_p64: Remote_w_char_p64
    }

    def __init__(self, base_addr, target):
        self._target = target
        self._base_addr = base_addr
        self._fields_dict_ = dict(self._fields_)

    def _get_field_by_name(self, fieldname):
        try:
            return self._fields_dict_[fieldname]
        except KeyError:
            raise AttributeError(fieldname + "is not a field of {0}".format(type(self)))

    def _get_field_descrptor_by_name(self, fieldname):
        return getattr(type(self), fieldname)  # ctypes metaclass fill this for us

    def _handle_field_getattr(self, ftype, fosset, fsize):
        s = self._target.read_memory(self._base_addr + fosset, fsize)
        if ftype in self._field_type_to_remote_type:
            return self._field_type_to_remote_type[ftype].from_buffer_with_target(bytearray(s), target=self._target).value
        if issubclass(ftype, _ctypes._Pointer):  # Pointer
            return RemoteStructurePointer.from_buffer_with_target_and_ptr_type(bytearray(s), target=self._target, ptr_type=ftype)
        if issubclass(ftype, RemotePtr64):  # Pointer to remote64 bits process
            return RemoteStructurePointer64.from_buffer_with_target_and_ptr_type(bytearray(s), target=self._target, ptr_type=ftype)
        if issubclass(ftype, RemoteStructureUnion):  # Structure|Union already transfomed in remote
            return ftype(self._base_addr + fosset, self._target)
        if issubclass(ftype, ctypes.Structure):  # Structure that must be transfomed
            return RemoteStructure.from_structure(ftype)(self._base_addr + fosset, self._target)
        if issubclass(ftype, ctypes.Union):  # Union that must be transfomed
            return RemoteUnion.from_structure(ftype)(self._base_addr + fosset, self._target)
        if issubclass(ftype, _ctypes.Array):  # Arrays
            return create_remote_array(ftype._type_, ftype._length_)(self._base_addr + fosset, self._target)
        # Normal types
        # Follow the ctypes usage: if it's not directly inherited from _SimpleCData
        # We do not apply the .value
        # Seems weird but it's mandatory AND useful :D (in pe_parse)
        if _SimpleCData not in ftype.__bases__:
            return ftype.from_buffer(bytearray(s))
        return ftype.from_buffer(bytearray(s)).value

    def __getattribute__(self, fieldname):
        if fieldname in type(self)._reserved_name:  # Prevent recursion !
            return super(RemoteStructureUnion, self).__getattribute__(fieldname)
        try:
            t = self._get_field_by_name(fieldname)
        except AttributeError:  # Not a real attribute
            return super(RemoteStructureUnion, self).__getattribute__(fieldname)
        descr = self._get_field_descrptor_by_name(fieldname)
        return self._handle_field_getattr(t, descr.offset, descr.size)

    @classmethod
    def from_structure(cls, structcls):
        class MyStruct(cls, structcls):  # inherit of structcls to keep property (see winobject.LoadedModule)
            _fields_ = structcls._fields_

        MyStruct.__name__ = "Remote" + structcls.__name__
        return MyStruct

    @classmethod
    def from_fields(cls, fields, base_cls=None):
        bases = [cls]
        if base_cls:
            bases.append(base_cls)
        # inherit of structcls to keep property (see winobject.LoadedModule)
        RemoteStruct = type("RemoteStruct", tuple(bases), {"_fields_": fields})
        if base_cls:
            RemoteStruct.__name__ = "Remote" + base_cls.__name__
        return RemoteStruct


class RemoteStructure(RemoteStructureUnion, ctypes.Structure):
    pass


class RemoteUnion(RemoteStructureUnion, ctypes.Union):
    pass


remote_struct = RemoteStructure.from_structure

if ctypes.sizeof(ctypes.c_void_p) == 4:
    # ctypes 32 -> 64 methods
    def MakePtr(type):
        class PointerToStruct64(Remote_c_void_p64):
            _sub_ctypes_ = (type)
        return PointerToStruct64

    def transform_structure_to_remote64bits(structcls):
        """Create a remote structure for a 64bits target process"""
        new_fields = []
        for fname, ftype in structcls._fields_:
            ftype = transform_type_to_remote64bits(ftype)
            new_fields.append((fname, ftype))
        return RemoteStructure.from_fields(new_fields, base_cls=structcls)

    def transform_union_to_remote64bits(structcls):
        """Create a remote structure for a 64bits target process"""
        new_fields = []
        for fname, ftype in structcls._fields_:
            ftype = transform_type_to_remote64bits(ftype)
            new_fields.append((fname, ftype))
        return RemoteUnion.from_fields(new_fields, base_cls=structcls)

    def transform_type_to_remote64bits(ftype):
        if is_pointer_type(ftype):
            return MakePtr(ftype._type_)
        if is_array_type(ftype):
            return create_remote_array(transform_type_to_remote64bits(ftype._type_), ftype._length_)
        if is_structure_type(ftype):
            return transform_structure_to_remote64bits(ftype)
        if is_union_type(ftype):
            return transform_union_to_remote64bits(ftype)
        # Normal types
        return type_32_64_translation_table.get(ftype, ftype)
