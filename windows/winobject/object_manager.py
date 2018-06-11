import os.path
import ctypes
from collections import namedtuple

import windows
from windows import winproxy
# from windows.generated_def.winstructs import *
import windows.generated_def as gdef


def query_link(linkpath):
    obj_attr = gdef.OBJECT_ATTRIBUTES()
    obj_attr.Length = ctypes.sizeof(obj_attr)
    obj_attr.RootDirectory = 0
    obj_attr.ObjectName = ctypes.pointer(gdef.LSA_UNICODE_STRING.from_string(linkpath))
    obj_attr.Attributes = gdef.OBJ_CASE_INSENSITIVE
    obj_attr.SecurityDescriptor = 0
    obj_attr.SecurityQualityOfService = 0
    res = gdef.HANDLE()
    x = winproxy.NtOpenSymbolicLinkObject(res, gdef.DIRECTORY_QUERY | gdef.READ_CONTROL , obj_attr)
    v = gdef.LSA_UNICODE_STRING.from_string("\x00" * 1000)
    s = gdef.ULONG()
    winproxy.NtQuerySymbolicLinkObject(res, v, s)
    return v.str


class KernelObject(object):
    def __init__(self, path, name, type):
        self.path = path
        self.name = name
        if path and not path.endswith("\\"):
            path += "\\"
        self.fullname = path + name
        self.type = type

    @property
    def target(self):
        try:
            return query_link(self.fullname)
        except windows.generated_def.ntstatus.NtStatusException as e:
            return None

    def items(self):
        """Todo: better name ?"""
        path = self.fullname
        return [(name, KernelObject(path, name, typename)) for name, typename in self._directory_query_generator()]

    def keys(self):
        return list(self)

    def values(self):
        path = self.fullname
        return [KernelObject(path, name, typename) for name, typename in self._directory_query_generator()]

    def _open_directory(self):
        path = self.fullname
        utf16_len = len(path) * 2
        obj_attr = gdef.OBJECT_ATTRIBUTES()
        obj_attr.Length = ctypes.sizeof(obj_attr)
        obj_attr.RootDirectory = None
        obj_attr.ObjectName = ctypes.pointer(gdef.LSA_UNICODE_STRING.from_string(path))
        obj_attr.Attributes = gdef.OBJ_CASE_INSENSITIVE
        obj_attr.SecurityDescriptor = 0
        obj_attr.SecurityQualityOfService = 0
        res = gdef.HANDLE()
        winproxy.NtOpenDirectoryObject(res, gdef.DIRECTORY_QUERY | gdef.READ_CONTROL , obj_attr)
        return res.value

    def _directory_query_generator(self):
        handle = self._open_directory()
        size = 0x1000
        buf = ctypes.c_buffer(size)
        rres = gdef.ULONG()
        ctx = gdef.ULONG()
        while True:
            try:
                # Restart == True has we don't save the buffer when resizing it for next call
                winproxy.NtQueryDirectoryObject(handle, buf, size, False, True, ctypes.byref(ctx), rres)
                break
            except gdef.NtStatusException as e:
                if e.code == gdef.STATUS_NO_MORE_ENTRIES:
                    return
                if e.code == gdef.STATUS_MORE_ENTRIES:
                    # If the call did not extrack all data: retry with bigger buffer
                    size *= 2
                    buf = ctypes.c_buffer(size)
                    continue
                raise
        # Function -> _extract_objects ?
        t = gdef.OBJECT_DIRECTORY_INFORMATION.from_buffer(buf)
        t = gdef.POBJECT_DIRECTORY_INFORMATION(t)
        res = {}
        for v in t:
            if v.Name.Buffer is None:
                break
            yield v.Name.str, v.TypeName.str

    def __iter__(self):
        return (name for name, type in self._directory_query_generator())

    def __repr__(self):
        return """<{0} "{1}" (type="{2}")>""".format(type(self).__name__, self.fullname, self.type)

    def get(self, name):
        """Retrieve the object ``name`` in the current directory.

        :rtype: :class:`KernelObject`
        """
        for objname, objtype in self._directory_query_generator():
            if objname.lower() == name.lower():
                return KernelObject(self.fullname, name, objtype)
        raise KeyError("Could not find WinObject <{0}> under <{1}>".format(name, self.fullname))

    def __getitem__(self, value):
        print(self, value)
        if value.startswith("\\"):
            # Are we the root directory ?
            if not self.fullname == "\\" :
                raise ValueError("Cannot query an object path begining by '\\' from an object other than '\\'")
            elif value == "\\": # Ask for root ? return ourself
                return self
            else:
                value = value[1:]

        obj = self
        print(value.split("\\"))
        for part in value.split("\\"):
            try:
                obj = obj.get(part)
            except gdef.NtStatusException as e:
                if e.code == gdef.STATUS_OBJECT_TYPE_MISMATCH:
                    raise KeyError("Could not find object <{0}> under <{1}> because it is a <{2}>".format(
                                    part, obj.name, obj.type))
        return obj


class ObjectManager(object):
    """Represent the object manager.

    .. note::

        For now, it only offers the ``root`` :class:`KernelObject`. But I want a ``manager`` object accessible
        from ``windows.system`` just like other API and not directly the ``root`` directory.
    """

    @property
    def root(self):
        """The root ``\\`` Directory

        :type: :class:`KernelObject` -- The root :class:`KernelObject`
        """
        return KernelObject("", "\\", "Directory")

    def __getitem__(self, name):
        """Query ``name`` from the root ``\\`` directory::

            object_manager["RPC Control"]["lsasspirpc"]
            object_manager[r"\\RPC Control\\lsasspirpc"]

        :rtype: :class:`KernelObject`
        """
        return self.root[name]