import os.path
import ctypes
from collections import namedtuple

import windows
from windows import winproxy
from windows.generated_def.winstructs import *


def query_link(linkpath):
    utf16_len = len(linkpath) * 2
    obj_attr = OBJECT_ATTRIBUTES()
    obj_attr.Length = ctypes.sizeof(obj_attr)
    obj_attr.RootDirectory = 0
    obj_attr.ObjectName = pointer(LSA_UNICODE_STRING(utf16_len, utf16_len, linkpath))
    obj_attr.Attributes = OBJ_CASE_INSENSITIVE
    obj_attr.SecurityDescriptor = 0
    obj_attr.SecurityQualityOfService = 0

    res = HANDLE()
    x = winproxy.NtOpenSymbolicLinkObject(res, DIRECTORY_QUERY | READ_CONTROL , obj_attr)
    v = LSA_UNICODE_STRING(0x1000, 0x1000, ctypes.cast(ctypes.c_buffer(0x1000), ctypes.c_wchar_p))
    s = ULONG()
    winproxy.NtQuerySymbolicLinkObject(res, v, s)
    return v.Buffer


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

    @property
    def entries(self):
        """Todo: better name ?"""
        path = self.fullname
        utf16_len = len(path) * 2
        obj_attr = OBJECT_ATTRIBUTES()
        obj_attr.Length = ctypes.sizeof(obj_attr)
        obj_attr.RootDirectory = None
        obj_attr.ObjectName = pointer(LSA_UNICODE_STRING(utf16_len, utf16_len, path))
        obj_attr.Attributes = OBJ_CASE_INSENSITIVE
        obj_attr.SecurityDescriptor = 0
        obj_attr.SecurityQualityOfService = 0

        res = HANDLE()
        x = winproxy.NtOpenDirectoryObject(res, DIRECTORY_QUERY | READ_CONTROL , obj_attr)
        size = 0x1000
        buf = ctypes.c_buffer(size)
        rres = ULONG()
        ctx = ULONG()
        while True:
            try:
                winproxy.NtQueryDirectoryObject(res, buf, size, False, False, ctx, rres)
                break
            except windows.generated_def.ntstatus.NtStatusException as e:
                if e.code == STATUS_NO_MORE_ENTRIES:
                    return {}
                if e.code == STATUS_MORE_ENTRIES:
                    size *= 2
                    buf = ctypes.c_buffer(size)
                    continue
                raise

        t = OBJECT_DIRECTORY_INFORMATION.from_buffer(buf)
        t = POBJECT_DIRECTORY_INFORMATION(t)
        res = {}
        for v in t:
            if v.Name.Buffer is None:
                break
            x = KernelObject(path, v.Name.Buffer, v.TypeName.Buffer)
            res[x.name] = x
        return res

    def __repr__(self):
        return """<{0} "{1}" (type="{2}")>""".format(type(self).__name__, self.fullname, self.type)


root = KernelObject("", "\\", "Directory")

#def full_explore(start):
#    TODO = [start]
#    while TODO:
#        path = TODO.pop()
#        print("Explore <{0}>".format(path))
#        try:
#            for obj in path.subobjects.values():
#                print("{0} -> {1}".format(obj.fullname, obj.type))
#                if obj.type == "Directory":
#                    TODO.append(obj)
#                if obj.type == "SymbolicLink":
#                    print("* Symblink target -> {0}".format(obj.target))
#        except windows.generated_def.ntstatus.NtStatusException as e:
#            print(repr(e))
#full_explore(yolo)