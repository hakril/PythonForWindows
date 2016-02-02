import sys
import os
import os.path
import re

import dummy_wintypes
import struct_parser
import func_parser
import def_parser



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
    ('PHANDLER_ROUTINE', 'PVOID'),
    ('LPBYTE', 'POINTER(BYTE)'),
    ('ULONG_PTR','PULONG'),
    ('CHAR', 'c_char'),
    ('UCHAR', 'c_char'),
    ('PUCHAR', 'POINTER(UCHAR)'),
    ('FARPROC', 'PVOID'),
    ('HGLOBAL', 'PVOID'),
    ('PSID', 'PVOID'),
    ('PVECTORED_EXCEPTION_HANDLER', 'PVOID'),
    #('HRESULT', 'c_long'), # VERY BAD : real HRESULT raise by itself -> way better
    ('ULONGLONG', 'c_ulonglong'),
    ('LONGLONG', 'c_longlong'),
    ('ULONG64', 'c_ulonglong'),
    ('DWORD64', 'ULONG64'),
    ('PULONG64', 'POINTER(ULONG64)'),
    ('PHANDLE', 'POINTER(HANDLE)'),
    ('HKEY', 'HANDLE'),
    ('PHKEY', 'POINTER(HKEY)'),
    ('ACCESS_MASK', 'DWORD'),
    ('REGSAM', 'ACCESS_MASK'),
    # Will be changed at import time
    ('LPCONTEXT', 'PVOID'),
    ('HCERTSTORE', 'PVOID'),
    ('HCRYPTMSG', 'PVOID'),
    ]

# For functions returning void
TYPE_EQUIVALENCE.append(('VOID', 'DWORD'))

known_type = dummy_wintypes.names + list([x[0] for x in TYPE_EQUIVALENCE])

FUNC_FILE = "winfunc.txt"
STRUCT_FILE = "winstruct.txt"
DEF_FILE = "windef.txt"
NTSTATUS_FILE = "ntstatus.txt"

GENERATED_STRUCT_FILE = "winstructs"
GENERATED_FUNC_FILE = "winfuncs"
GENERATED_DEF_FILE = "windef"
GENERATED_NTSTATUS_FILE = "ntstatus"

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
            import pdb; pdb.set_trace()
            raise ValueError("UNKNOW RET TYPE {0}".format(ret_type))

        for param_type, _ in f.params:
            # Crappy but fuck it !
            if param_type.startswith("POINTER(") and param_type.endswith(")"):
                param_type = param_type[len("POINTER("): -1]
            if param_type not in known_type and param_type not in all_struct_name:
                import pdb; pdb.set_trace()
                raise ValueError("UNKNOW PARAM TYPE {0}".format(param_type))

def check_in_define(name, defs):
    return any(name == d.name for d in defs)

def validate_structs(structs, enums, defs):
    all_struct_name = get_all_struct_name(structs, enums)
    for struct in structs:
        for field_type, field_name, nb_rep in struct.fields:
            if field_type.name not in known_type + all_struct_name:
                import pdb; pdb.set_trace()
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

def write_to_out_file(name, data):
    for out_dir in OUT_DIRS:
        f = open("{0}/{1}.py".format(out_dir, name), 'w')
        f.write(data)
        f.close()

def_code  = open(DEF_FILE, 'r').read()
funcs_code = open(FUNC_FILE, 'r').read()
structs_code = open(STRUCT_FILE, 'r').read()

defs = def_parser.WinDefParser(def_code).parse()
funcs = func_parser.WinFuncParser(funcs_code).parse()
structs, enums = struct_parser.WinStructParser(structs_code).parse()


validate_structs(structs, enums, defs)
verif_funcs_type(funcs, structs, enums)


# Create Flags for ntstatus
nt_status_defs = []
for line in open(NTSTATUS_FILE):
    code, name, descr = line.split("|", 2)
    nt_status_defs.append(def_parser.WinDef(name, code))
defs = nt_status_defs + defs

defs_ctypes = generate_defs_ctypes(defs)
funcs_ctypes = generate_funcs_ctypes(funcs)
structs_ctypes = generate_struct_ctypes(structs, enums)

for out_dir in OUT_DIRS:
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)

write_to_out_file(GENERATED_DEF_FILE, defs_ctypes)
write_to_out_file(GENERATED_FUNC_FILE, funcs_ctypes)
write_to_out_file(GENERATED_STRUCT_FILE, structs_ctypes)


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
