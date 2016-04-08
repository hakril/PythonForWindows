import sys
import os
import os.path
import re
import glob

import dummy_wintypes
import struct_parser
import func_parser
import def_parser
import com_parser



TYPE_EQUIVALENCE = [
    ('PWSTR', 'LPWSTR'),
    ('SIZE_T', 'c_ulong'),
    ('PSIZE_T', 'POINTER(SIZE_T)'),
    ('PVOID', 'c_void_p'),
    ('PPS_POST_PROCESS_INIT_ROUTINE', 'PVOID'),
    ('NTSTATUS', 'DWORD'),
    ('PULONG', 'POINTER(ULONG)'),
    ('PDWORD', 'POINTER(DWORD)'),
    ('LPDWORD', 'POINTER(DWORD)'),
    ('LPTHREAD_START_ROUTINE', 'PVOID'),
    ('WNDENUMPROC', 'PVOID'),
    ('PHANDLER_ROUTINE', 'PVOID'),
    ('LPBYTE', 'POINTER(BYTE)'),
    ('ULONG_PTR','PVOID'),
    ('CHAR', 'c_char'),
    ('INT', 'c_int'),
    ('UCHAR', 'c_char'),
    ('CSHORT', 'c_short'),
    ('VARTYPE', 'c_ushort'),
    ('BSTR', 'c_wchar_p'),
    ('OLECHAR', 'c_wchar'),
    ('POLECHAR', 'c_wchar_p'),
    ('PUCHAR', 'POINTER(UCHAR)'),
    ('double', 'c_double'),
    ('FARPROC', 'PVOID'),
    ('HGLOBAL', 'PVOID'),
    ('PSID', 'PVOID'),
    ('PVECTORED_EXCEPTION_HANDLER', 'PVOID'),
    #('HRESULT', 'c_long'), # VERY BAD : real HRESULT raise by itself -> way better
    ('ULONGLONG', 'c_ulonglong'),
    ('LONGLONG', 'c_longlong'),
    ('ULONG64', 'c_ulonglong'),
    ('LARGE_INTEGER', 'LONGLONG'),
    ('PLARGE_INTEGER', 'POINTER(LARGE_INTEGER)'),
    ('DWORD64', 'ULONG64'),
    ('SCODE', 'LONG'),
    ('CIMTYPE', 'LONG'),
    ('NET_IFINDEX', 'ULONG'),
    ('IF_INDEX', 'NET_IFINDEX'),
    ('IFTYPE', 'ULONG'),
    ('PULONG64', 'POINTER(ULONG64)'),
    ('PUINT', 'POINTER(UINT)'),
    ('PHANDLE', 'POINTER(HANDLE)'),
    ('HKEY', 'HANDLE'),
    ('HCATADMIN', 'HANDLE'),
    ('HCATINFO', 'HANDLE'),
    ('SC_HANDLE', 'HANDLE'),
    ('LPHANDLE', 'POINTER(HANDLE)'),
    ('PHKEY', 'POINTER(HKEY)'),
    ('ACCESS_MASK', 'DWORD'),
    ('REGSAM', 'ACCESS_MASK'),
    ('SECURITY_CONTEXT_TRACKING_MODE', 'BOOLEAN'),
    ("DISPID", "LONG"),
    ("MEMBERID", "DISPID"),
    ('PSECURITY_DESCRIPTOR', 'PVOID'),
    ('LPUNKNOWN', 'POINTER(PVOID)'),
    # Will be changed at import time
    ('LPCONTEXT', 'PVOID'),
    ('HCERTSTORE', 'PVOID'),
    ('HCRYPTMSG', 'PVOID'),
    ('PALPC_PORT_ATTRIBUTES', 'PVOID'),
    ]

# For functions returning void
TYPE_EQUIVALENCE.append(('VOID', 'DWORD'))
# TRICHE
TYPE_EQUIVALENCE.append(('ITypeInfo', 'PVOID'))


known_type = dummy_wintypes.names + list([x[0] for x in TYPE_EQUIVALENCE])
known_type += ["void"]


FUNC_FILE = "winfunc.txt"
STRUCT_FILE = "winstruct.txt"
DEF_FILE = "windef.txt"
NTSTATUS_FILE = "ntstatus.txt"
NAME_TO_IID_FILE = "interface_to_iid.txt"
COM_INTERFACE_DIR_GLOB = "com/*.txt"

GENERATED_STRUCT_FILE = "winstructs"
GENERATED_FUNC_FILE = "winfuncs"
GENERATED_DEF_FILE = "windef"
GENERATED_NTSTATUS_FILE = "ntstatus"
GENERATED_COM_FILE = "interfaces"
#GENERATED_NAME_TO_IID_FILE = "com_iid"

OUT_DIRS = ["..\windows\generated_def"]
if len(sys.argv) > 1:
    OUT_DIRS.append(sys.argv[1])

def get_all_struct_name(structs, enums):
    res = []
    for s in structs + enums:
        res.append(s.name)
        res.extend(s.typedef)
    return res

def generate_type_equiv_code(type_equiv):
    ctypes_str = ""
    for type_equiv in type_equiv:
        ctypes_str += "{0} = {1}\n".format(*type_equiv)
    ctypes_str += "\n"
    return ctypes_str

def verif_funcs_type(funcs, structs, enums):
    all_struct_name = get_all_struct_name(structs, enums)
    for f in funcs:
        ret_type = f.return_type
        if ret_type not in known_type and ret_type not in all_struct_name:
            raise ValueError("UNKNOW RET TYPE {0}".format(ret_type))

        for param_type, _ in f.params:
            # Crappy but fuck it !
            if param_type.startswith("POINTER(") and param_type.endswith(")"):
                param_type = param_type[len("POINTER("): -1]
            if param_type not in known_type and param_type not in all_struct_name:
                raise ValueError("UNKNOW PARAM TYPE {0}".format(param_type))


try:
    yolo_struct = [x[:-4] for x in  os.listdir(r"C:\Users\hakril\Documents\Work\COM\dump")]
except WindowsError:
    yolo_struct = []

def verif_com_interface_type(vtbls, struc, enum):
    all_struct_name = get_all_struct_name(structs, enums)
    all_interface_name = [vtbl.name for vtbl in vtbls]

    for vtbl in vtbls:
        #print(vtbl)
        for method in vtbl.methods:
            #print("Checking ret type <{0}>".format(method.ret_type))
            ret_type = method.ret_type
            if ret_type not in known_type and ret_type not in all_struct_name + all_interface_name:
                raise ValueError("UNKNOW RET TYPE {0}".format(ret_type))
            for arg in method.args:
                #print("Checking arg type <{0}>".format(arg.type))
                param_type = arg.type
                if param_type not in known_type and param_type not in all_struct_name + all_interface_name:
                    #if param_type != "ITypeInfo":
                    if param_type in yolo_struct:
                        import pdb;pdb.set_trace()
                        print("Ned to extract <{0}> from dump".format(param_type))
                        import shutil
                        #shutil.copy(r"C:\Users\hakril\Documents\Work\COM\dump\{0}.txt".format(param_type), "com")
                        continue
                    raise ValueError("UNKNOW PARAM TYPE {0}".format(param_type))


def check_in_define(name, defs):
    return any(name == d.name for d in defs)

def validate_structs(structs, enums, defs):
    all_struct_name = get_all_struct_name(structs, enums)
    for struct in structs:
        for field_type, field_name, nb_rep in struct.fields:
            if field_type.name not in known_type + all_struct_name:
                raise ValueError("UNKNOW TYPE {0}".format(field_type))
            try:
                int(nb_rep)
            except ValueError:
                if not check_in_define(nb_rep, defs):
                    raise ValueError("UNKNOW DEFINE {0}".format(nb_rep))

common_header = "#Generated file\n"

defs_header = common_header + """
import sys
import platform
if sys.version_info.major == 3:
    long = int

bits = platform.architecture()[0]
bitness =  int(bits[:2])

NATIVE_WORD_MAX_VALUE = 0xffffffff if bitness == 32 else 0xffffffffffffffff

class Flag(long):
    def __new__(cls, name, value):
        return super(Flag, cls).__new__(cls, value)

    def __init__(self, name, value):
        self.name = name

    def __repr__(self):
        return "{0}({1})".format(self.name, hex(self))

    __str__ = __repr__
"""

def generate_defs_ctypes(defs):
    ctypes_lines = [defs_header] + [d.generate_ctypes() for d in defs]
    ctypes_code = "\n".join(ctypes_lines)
    return ctypes_code


funcs_header = common_header + """
from ctypes import *
from ctypes.wintypes import *
from .{0} import *

"""[1:].format(GENERATED_STRUCT_FILE)

def generate_funcs_ctypes(funcs):
    ctypes_code = funcs_header

    all_funcs_name = [f.name for f in funcs]
    ctypes_code += "functions = {0}\n\n".format(str(all_funcs_name))
    for func in funcs:
        ctypes_code += func.generate_ctypes() + "\n"
    return ctypes_code

structs_header = common_header + """
from ctypes import *
from ctypes.wintypes import *
from .windef import *

class EnumValue(Flag):
    def __new__(cls, enum_name, name, value):
        return super(EnumValue, cls).__new__(cls, name, value)

    def __init__(self, enum_name, name, value):
        self.enum_name = enum_name
        self.name = name

    def __repr__(self):
        return "{0}.{1}({2})".format(self.enum_name, self.name, hex(self))


class EnumType(DWORD):
    values = ()
    mapper = {}

    @property
    def value(self):
        raw_value = super(EnumType, self).value
        return self.mapper.get(raw_value, raw_value)

    def __repr__(self):
        raw_value = super(EnumType, self).value
        if raw_value in self.values:
            value = self.value
            return "<{0} {1}({2})>".format(type(self).__name__, value.name, hex(raw_value))
        return "<{0}({1})>".format(type(self).__name__, hex(self.value))

"""[1:]

def generate_struct_ctypes(structs, enums):
    ctypes_str  = structs_header
    ctypes_str += generate_type_equiv_code(TYPE_EQUIVALENCE)

    all_struct_name = [s.name for s in structs]
    ctypes_str += "structs = {0}\n\n".format(str(all_struct_name))

    all_enum_name = [e.name for e in enums]
    ctypes_str += "enums = {0}\n\n".format(str(all_enum_name))

    # Enums declarations
    for enum in enums:
        ctypes_str += "# Enum {0} definitions\n".format(enum.name)
        ctypes_str += enum.generate_ctypes() + "\n"

    # Struct declarations
    for struct in structs:
        ctypes_str += "# Struct {0} definitions\n".format(struct.name)
        ctypes_str += struct.generate_ctypes() + "\n"

    return ctypes_str


data = open(NAME_TO_IID_FILE).read()
iids_def = {}
for line in data.split("\n"):
    name, iid = line.split("|")
    part_iid = iid.split("-")
    str_iid = []
    str_iid.append("0x" + part_iid[0])
    str_iid.append("0x" + part_iid[1])
    str_iid.append("0x" + part_iid[2])
    str_iid.append("0x" + part_iid[3][:2])
    str_iid.append("0x" + part_iid[3][2:])
    for i in range(6): str_iid.append("0x" + part_iid[4][i * 2:(i + 1) * 2])
    iids_def[name] = ", ".join(str_iid), iid
#full_name_to_iid = name_to_iid_header + "\n".join(iids_def)


com_interface_header = """
import functools
import ctypes
from winstructs import *

class IID(IID):
    def __init__(self, Data1, Data2, Data3, Data4, name=None, strid=None):
        self.name = name
        self.strid = strid
        super(IID, self).__init__(Data1, Data2, Data3, Data4)

    def __repr__(self):
        if self.strid is None:
            return super(IID, self).__repr__()
        if self.name is None:
            return '<IID "{0}">'.format(self.strid.upper())
        return '<IID "{0}({1})">'.format(self.strid.upper(), self.name)

    @classmethod
    def from_string(cls, iid):
        part_iid = iid.split("-")
        datas = [int(x, 16) for x in part_iid[:3]]
        datas.append(int(part_iid[3][:2], 16))
        datas.append(int(part_iid[3][2:], 16))
        for i in range(6):
            datas.append(int(part_iid[4][i * 2:(i + 1) * 2], 16))
        return cls.from_raw(*datas, strid=iid)

    @classmethod
    def from_raw(cls, Data1, Data2, Data3, Data41, Data42, Data43, Data44, Data45, Data46, Data47, Data48, **kwargs):
        return cls(Data1, Data2, Data3,  (BYTE*8)(Data41, Data42, Data43, Data44, Data45, Data46, Data47, Data48), **kwargs)

generate_IID = IID.from_raw


class COMInterface(ctypes.c_void_p):
    _functions_ = {
    }

    def __getattr__(self, name):
        if name in self._functions_:
            return functools.partial(self._functions_[name], self)
        return super(COMInterface, self).__getattribute__(name)
"""

com_interface_template = """
class {0}(COMInterface):
    IID = generate_IID({2}, name="{0}", strid="{3}")

    _functions_ = {{
{1}
    }}
"""

com_interface_comment_template = """ #{0} -> {1}"""
com_interface_method_template = """ "{0}": ctypes.WINFUNCTYPE({1})({2}, "{0}"),"""

def generate_com_interface_ctype(vtbls):
    define = []
    all_name = [vtbl.name for vtbl in vtbls]
    for vtbl in vtbls:
        methods_string = []
        for method_nb, method in enumerate(vtbl.methods):
            args_to_define = method.args[1:] #ctypes doesnt not need the This
            #import pdb;pdb.set_trace()
            str_args = []
            methods_string.append(com_interface_comment_template.format(method.name, ", ".join([arg.name +":"+ ("*"* arg.byreflevel) +arg.type for arg in args_to_define])))
            for arg in args_to_define:
                type = arg.type
                byreflevel = arg.byreflevel
                if type in all_name:
                    type = "PVOID"
                    byreflevel -= 1
                if type == "void":
                    type = "PVOID"
                    if byreflevel == 0:
                        raise ValueError("{0}.{1} take a parameter <void>".format(vtbl.name, method.name))
                    byreflevel -= 1
                for i in range(byreflevel):
                    type = "POINTER({0})".format(type)
                str_args.append(type)
            methods_string.append(com_interface_method_template.format(method.name, ", ".join([method.ret_type] + str_args), method_nb))
        #import pdb;pdb.set_trace()
        iid_python, iid_str = iids_def[vtbl.name]
        define.append((com_interface_template.format(vtbl.name, "\n".join(methods_string), iid_python, iid_str)))
    return com_interface_header + "\n".join(define)

def write_to_out_file(name, data):
    for out_dir in OUT_DIRS:
        f = open("{0}/{1}.py".format(out_dir, name), 'w')
        f.write(data)
        f.close()


def parse_com_interfaces(filenames):
    res = []
    for filename in filenames:
        print("Parsing COM from <{0}>".format(filename))
        data = open(filename).read()
        vtbl = com_parser.WinComParser(data).parse()
        res.append(vtbl)
    return res


def_code  = open(DEF_FILE, 'r').read()
funcs_code = open(FUNC_FILE, 'r').read()
structs_code = open(STRUCT_FILE, 'r').read()

defs = def_parser.WinDefParser(def_code).parse()
funcs = func_parser.WinFuncParser(funcs_code).parse()
structs, enums = struct_parser.WinStructParser(structs_code).parse()
vtbls = parse_com_interfaces(glob.glob(COM_INTERFACE_DIR_GLOB))

validate_structs(structs, enums, defs)
verif_funcs_type(funcs, structs, enums)
verif_com_interface_type(vtbls, structs, enums)


# Create Flags for ntstatus
nt_status_defs = []
for line in open(NTSTATUS_FILE):
    code, name, descr = line.split("|", 2)
    nt_status_defs.append(def_parser.WinDef(name, code))
defs = nt_status_defs + defs

defs_ctypes = generate_defs_ctypes(defs)
funcs_ctypes = generate_funcs_ctypes(funcs)
structs_ctypes = generate_struct_ctypes(structs, enums)
com_interface_ctypes = generate_com_interface_ctype(vtbls)

# Create name -> IID file

name_to_iid_header = """
from winstructs import IID, BYTE

"""


#f = open("yolo.py", "w")
#f.write(com_interface_ctypes)
#f.close()

for out_dir in OUT_DIRS:
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)

write_to_out_file(GENERATED_DEF_FILE, defs_ctypes)
write_to_out_file(GENERATED_FUNC_FILE, funcs_ctypes)
write_to_out_file(GENERATED_STRUCT_FILE, structs_ctypes)
write_to_out_file(GENERATED_COM_FILE, com_interface_ctypes)
#write_to_out_file(GENERATED_NAME_TO_IID_FILE, full_name_to_iid)

NTSTATUS_HEAD = """
class NtStatusException(Exception):
    ALL_STATUS = {}
    def __init__(self , code):
        try:
            x = self.ALL_STATUS[code]
        except KeyError:
            x = (code, 'UNKNOW_ERROR', 'Error non documented in ntstatus.py')
        self.code = x[0]
        self.name = x[1]
        self.descr = x[2]

        return super(NtStatusException, self).__init__(*x)

    def __str__(self):
        return "{e.name}(0x{e.code:x}): {e.descr}".format(e=self)

    @classmethod
    def register_ntstatus(cls, code, name, descr):
        if code in cls.ALL_STATUS:
            return # Use the first def
        cls.ALL_STATUS[code] = (code, name, descr)
"""

nt_status_exceptions = [NTSTATUS_HEAD]
for line in open(NTSTATUS_FILE):
    code, name, descr = line.split("|", 2)
    code = int(code, 0)
    b = descr
    descr = re.sub(" +", " ", descr[:-1]) # remove \n
    descr = descr.replace('"', "'")
    nt_status_exceptions.append('NtStatusException.register_ntstatus({0}, "{1}", "{2}")'.format(hex(code), name, descr))


write_to_out_file(GENERATED_NTSTATUS_FILE, "\n".join(nt_status_exceptions))

for out_dir in OUT_DIRS:
    print("Files generated in <{0}>".format(os.path.abspath(out_dir)))
