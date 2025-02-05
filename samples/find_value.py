import sys
import argparse

import windows
import windows.generated_def as gdef
import windows.generated_def.meta as meta

def match(s1, s2):
    # return s1 in s2
    return s1.lower() in s2.lower()

def search_name_in_function(target):
    for funcname in meta.functions:
        if match(target, funcname):
            print(funcname)

def search_name_in_enum(target):
    for name, enum in meta.enums_walker():
        if match(target, name):
            print(name, enum)
        if not issubclass(enum, gdef.EnumType):
                continue
        for enumvalue in enum.values:
            if match(target, enumvalue.name):
                print("Enum <{0!r}>".format(enumvalue))

def search_name_in_struct(target):
    for name, struct in meta.structs_walker():
        if match(target, name):
            print(name, struct)
        if hasattr(struct, "_fields_"):
            # import pdb;pdb.set_trace()
            for finfo in struct._fields_:
                if match(target, finfo[0]):
                    print("Field <{0}> in <{1}>: {2}".format(finfo[0], name, struct))

def search_name_in_windef(target):
    for name, windef in meta.windef_walker():
        if match(target, name):
            print(repr(windef))

def search_name_in_winerror(target):
    for name, windef in meta.errors_walker():
        if match(target, name):
            print(repr(windef))


def search_name_in_interface(target):
    for name, interface in meta.interfaces_walker():
        if not issubclass(interface, windows.generated_def.interfaces.COMInterface):
            continue
        if match(target, name):
            print(name, interface)
        for mname, mvalue in interface._functions_.items():
            if match(target, mname):
                print("Method <{0}> of <{1}>: {2}".format(mname, name, mvalue))


def search_name(target):
    print("== Functions ==")
    search_name_in_function(target)
    print("== Enums ==")
    search_name_in_enum(target)
    print("== Structs ==")
    search_name_in_struct(target)
    print("== Windef ==")
    search_name_in_windef(target)
    print("== Winerror ==")
    search_name_in_winerror(target)
    print("== Interfaces ==")
    search_name_in_interface(target)

def search_value(target):
    for name, windef in meta.windef_walker():
        if target == windef:
            print(repr(windef))

    for status in gdef.ntstatus.NtStatusException.ALL_STATUS.values():
        if target == status[0]:
            print(repr(windef))

    for name, windef in meta.errors_walker():
        if target == windef:
            print(repr(windef))

    for name, enum in meta.enums_walker():
        if not issubclass(enum, gdef.EnumType):
                continue
        for enumvalue in enum.values:
            if target == enumvalue:
                print("Enum <{0!r}>".format(enumvalue))

parser = argparse.ArgumentParser(prog=__file__)
parser.add_argument('target', help='The name or value to research in PythonForWindows generated definition')
res = parser.parse_args()
target = res.target
try:
    itarget = int(target, 0)
except ValueError:
    print("Searching name <{0}>".format(target))
    search_name(target)
else:
    print("== Searching value <{0:#x}> ==".format(itarget))
    search_value(itarget)