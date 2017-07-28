import sys
import os
import os.path
import re
import glob
import textwrap

import dummy_wintypes
import struct_parser
import func_parser
import def_parser
import com_parser

pjoin = os.path.join
pexists = os.path.exists
dedent = textwrap.dedent


TYPE_EQUIVALENCE = [
    # BYTE is defined in ctypes.wintypes as c_byte but who wants
    # BYTE to be signed ? (from MSDN: <typedef unsigned char BYTE;>)
    ('BYTE', 'c_ubyte'),
    ('PWSTR', 'LPWSTR'),
    ('PCWSTR', 'LPWSTR'),
    ('SIZE_T', 'c_size_t'),
    ('PSIZE_T', 'POINTER(SIZE_T)'),
    ('PVOID', 'c_void_p'),
    ('PPS_POST_PROCESS_INIT_ROUTINE', 'PVOID'),
    ('NTSTATUS', 'DWORD'),
    ('SECURITY_INFORMATION', 'DWORD'),
    ('PSECURITY_INFORMATION', 'POINTER(SECURITY_INFORMATION)'),
    ('PULONG', 'POINTER(ULONG)'),
    ('PDWORD', 'POINTER(DWORD)'),
    ('LPDWORD', 'POINTER(DWORD)'),
    ('LPTHREAD_START_ROUTINE', 'PVOID'),
    ('WNDENUMPROC', 'PVOID'),
    ('PHANDLER_ROUTINE', 'PVOID'),
    ('LPBYTE', 'POINTER(BYTE)'),
    ('ULONG_PTR','PVOID'),
    ('DWORD_PTR','ULONG_PTR'),
    ('KAFFINITY','ULONG_PTR'),
    ('KPRIORITY','LONG'),
    ('CHAR', 'c_char'),
    ('INT', 'c_int'),
    ('UCHAR', 'c_char'),
    ('CSHORT', 'c_short'),
    ('VARTYPE', 'c_ushort'),
    ('PBOOL', 'POINTER(BOOL)'),
    ('PSTR', 'LPSTR'),
    ('PCSTR', 'LPSTR'),
    ('va_list', 'c_char_p'),
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
    ('UINT64', 'ULONG64'),
    ('LONG64', 'c_longlong'),
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
    ('HDC', 'HANDLE'),
    ('HBITMAP', 'HANDLE'),
    ('SC_HANDLE', 'HANDLE'),
    ('HCERTCHAINENGINE', 'HANDLE'),
    ('LPHANDLE', 'POINTER(HANDLE)'),
    ('ALPC_HANDLE', 'HANDLE'),
    ('PALPC_HANDLE', 'POINTER(ALPC_HANDLE)'),
    ('PHKEY', 'POINTER(HKEY)'),
    ('ACCESS_MASK', 'DWORD'),
    ('REGSAM', 'ACCESS_MASK'),
    ('SECURITY_CONTEXT_TRACKING_MODE', 'BOOLEAN'),
    ('HCRYPTPROV_OR_NCRYPT_KEY_HANDLE', 'PULONG'),
    ('HCRYPTPROV_LEGACY', 'PULONG'),
    ('HCRYPTKEY', 'PULONG'),
    ('HCRYPTPROV', 'PULONG'),
    ('HCRYPTHASH', 'PULONG'),
    ('ALG_ID', 'UINT'),
    ("DISPID", "LONG"),
    ("MEMBERID", "DISPID"),
    ('PSECURITY_DESCRIPTOR', 'PVOID'),
    ('LPPROC_THREAD_ATTRIBUTE_LIST', 'PVOID'),
    ('LPUNKNOWN', 'POINTER(PVOID)'),
    ('SPC_UUID', 'BYTE * 16'),
    #STUFF FOR COM (will be replace at runtime
    # real def in com_interface_header
    # ('GUID', 'PVOID'),
    #('REFGUID', 'PVOID'),
    #('LPGUID', 'PVOID'),
    # STUFF FOR DBGENGINE
    ('PWINDBG_EXTENSION_APIS32', 'PVOID'),
    ('PWINDBG_EXTENSION_APIS64', 'PVOID'),
    #('PDEBUG_SYMBOL_PARAMETERS', 'PVOID'),
    # Will be changed at import time
    ('LPCONTEXT', 'PVOID'),
    ('HCERTSTORE', 'PVOID'),
    ('HCRYPTMSG', 'PVOID'),
    ('PALPC_PORT_ATTRIBUTES', 'PVOID'),
    ]

TYPE_EQUIVALENCE.append(('VOID', 'DWORD'))
# TRICHE
BASIC_TYPE = dummy_wintypes.names + list([x[0] for x in TYPE_EQUIVALENCE])

class CtypesGenerator(object):
    common_header = "#Generated file\n"

    PARSER = None
    IMPORT_HEADER = "{deps}"

    def __init__(self, infilename, outfilename, dependances=()):
        self.infilename = infilename
        self.outfilename = outfilename
        self.infile = open(self.infilename)
        self.data = None
        self.dependances = dependances

        self.exports = set([])
        self.imports = set([])

        self.parse()
        self.analyse(self.data)
        self.check_dependances()

    def parse(self):
        if self.data is None:
            print("Parsing <{0}>".format(self.infilename))
            self.data = self.PARSER(self.infile.read()).parse()
        return self.data

    def analyse(self, data):
        raise NotImplementedError("<{0}> doest not implement <analyse>".format(type(self).__name__))

    def check_dependances(self):
        missing = self.imports
        for dep in self.dependances:
            missing -= dep.exports
        if missing:
            raise ValueError("Missing dependance <{0}> in <{1}>".format(missing, self.infilename))

    def generate_import(self):
        deps = "\n".join(["from {0} import *".format(os.path.basename(dep.outfilename).rsplit(".")[0]) for dep in self.dependances])
        return self.IMPORT_HEADER.format(deps = deps)

    def add_imports(self, *names):
        self.imports.update(names)

    def add_exports(self, *names):
        self.exports.update(names)

    def generate(self):
        raise NotImplementedError("<{0}> doest not implement <generate>".format(type(self).__name__))

    def append_input_file(self, filename):
        print("Adding file <{0}>".format(filename))
        self.parse()
        self.data +=  self.PARSER(open(filename).read()).parse()
        self.analyse(self.data)
        self.check_dependances()

class InitialDefGenerator(CtypesGenerator):
    PARSER = def_parser.WinDefParser
    HEADER = dedent("""
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

           # Fix pickling with protocol 2
            def __getnewargs__(self, *args):
                return self.name, long(self)

        class StrFlags(str):
            def __new__(cls, name, value):
                if isinstance(value, cls):
                    return value
                return super(StrFlags, cls).__new__(cls, value)

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
            return StrFlags(name, value)


        """)

    IMPORT_HEADER = "{deps}"

    def analyse(self, data):
        self.add_exports("Flag")
        self.add_exports("NATIVE_WORD_MAX_VALUE")
        for defin in data:
            self.add_exports(defin.name)

    def generate(self):
        ctypes_lines = [self.common_header, self.HEADER]
        #deps = "\n".join(["from {0} import *".format(os.path.basename(dep.outfilename).rsplit(".")[0]) for dep in self.dependances])
        ctypes_lines += [self.generate_import()]
        ctypes_lines += [d.generate_ctypes() for d in self.parse()]
        ctypes_code = "\n".join(ctypes_lines)
        with open(self.outfilename, "w") as f:
            f.write(ctypes_code)
        print("<{0}> generated".format(self.outfilename))
        return ctypes_code

class StructGenerator(CtypesGenerator):
    PARSER = struct_parser.WinStructParser
    IMPORT_HEADER = dedent ("""
        from ctypes import *
        from ctypes.wintypes import *
        {deps}
    """)
    TYPES_HEADER = dedent("""
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

        """)

    def analyse(self, data):
        structs, enums = data
        for btype in BASIC_TYPE:
            self.add_exports(btype)
        for enum in enums:
            self.add_exports(enum.name)
            self.add_exports(*enum.typedef)
        for struct in structs:
            self.add_exports(struct.name)
            self.add_exports(*struct.typedef)
            for field_type, field_name, nb_rep in struct.fields:
                if field_type.name not in self.exports:
                    self.add_imports(field_type.name)
                try:
                    int(nb_rep)
                except:
                    self.add_imports(nb_rep)

        # We have PPORT_MESSAGE32 and PPORT_MESSAGE64 and PPORT_MESSAGE is choosed at runtime
        self.add_exports("PPORT_MESSAGE")


    def generate(self):
        type_equivalences = "\n".join(["{0} = {1}".format(*x) for x in TYPE_EQUIVALENCE])
        HEADER = self.generate_import()
        HEADER += type_equivalences
        HEADER += self.TYPES_HEADER

        structs, enums = self.data
        ctypes_lines = [self.common_header, HEADER] + [d.generate_ctypes() for l in (enums, structs) for d in l]
        ctypes_code = "\n".join(ctypes_lines)
        with open(self.outfilename, "w") as f:
            f.write(ctypes_code)
        print("<{0}> generated".format(self.outfilename))
        return ctypes_code

    def append_input_file(self, filename):
        print("Adding file <{0}>".format(filename))
        self.parse()
        new_data = self.PARSER(open(filename).read()).parse()
        self.data[0].extend(new_data[0])
        self.data[1].extend(new_data[1])
        self.analyse(self.data)
        self.check_dependances()

class FuncGenerator(CtypesGenerator):
    PARSER = func_parser.WinFuncParser
    IMPORT_HEADER = dedent ("""
        from ctypes import *
        from ctypes.wintypes import *
        {deps}

        """)

    def analyse(self, data):
        for func in data:
            self.add_imports(func.return_type)
            for param_type, _ in func.params:
                if param_type.startswith("POINTER(") and param_type.endswith(")"):
                    param_type = param_type[len("POINTER("): -1]
                self.add_imports(param_type)

    def generate(self):
        deps = "\n".join(["from {0} import *".format(os.path.basename(dep.outfilename).rsplit(".")[0]) for dep in self.dependances])
        HEADER = self.generate_import()

        func_list = "functions = {0}\n\n".format(str([f.name for f in self.data]))

        ctypes_lines = [self.common_header, HEADER, func_list] + [d.generate_ctypes() for d in self.parse()]
        ctypes_code = "\n".join(ctypes_lines)
        with open(self.outfilename, "w") as f:
            f.write(ctypes_code)
        print("<{0}> generated".format(self.outfilename))
        return ctypes_code

class NtStatusGenerator(CtypesGenerator):
    IMPORT_HEADER = dedent("""
    import ctypes
    {deps}
    """)
    HEADER = dedent("""
    class NtStatusException(WindowsError):
        ALL_STATUS = {}
        def __init__(self , code):
            try:
                x = self.ALL_STATUS[code]
            except KeyError:
                x = (code, 'UNKNOW_ERROR', 'Error non documented in ntstatus.py')
            self.code = x[0]
            self.name = x[1]
            self.descr = x[2]
            x =  ctypes.c_long(x[0]).value, x[1], x[2]
            return super(NtStatusException, self).__init__(*x)

        def __str__(self):
            return "{e.name}(0x{e.code:x}): {e.descr}".format(e=self)

        def __repr__(self):
            return "{0}(0x{1:08x}, {2})".format(type(self).__name__, self.code, self.name)

        @classmethod
        def register_ntstatus(cls, code, name, descr):
            if code in cls.ALL_STATUS:
                return # Use the first def
            cls.ALL_STATUS[code] = (code, name, descr)
            return Flag(name, code)
    """)

    def parse_ntstatus(self, content):
        nt_status_defs = []
        for line in content.split("\n"):
            if not line:
                continue
            code, name, descr = line.split("|", 2)
            code = int(code, 0)
            descr = re.sub(" +", " ", descr[:-1]) # remove \n
            descr = descr.replace('"', "'")
            nt_status_defs.append((code, name, descr))
        self.data = nt_status_defs
        return self

    # Hack for PARSER
    def parse(self):
        if self.data is None:
            print("Parsing <{0}>".format(self.infilename))
            self.parse_ntstatus(self.infile.read())
        return self.data

    def analyse(self, data):
        self.add_imports("Flag")

    def generate(self):
        #deps = "\n".join(["from {0} import *".format(os.path.basename(dep.outfilename).rsplit(".")[0]) for dep in self.dependances])
        HEADER = self.generate_import() + self.HEADER
        ctypes_lines = [HEADER]
        for code, name, descr in self.parse():
            ctypes_lines.append('{1} = NtStatusException.register_ntstatus({0}, "{1}", "{2}")'.format(hex(code).strip("L"), name, descr))
        ctypes_code = "\n".join(ctypes_lines)
        with open(self.outfilename, "w") as f:
            f.write(ctypes_code)
        print("<{0}> generated".format(self.outfilename))
        return ctypes_code


class InitialCOMGenerator(CtypesGenerator):
    PARSER = com_parser.WinComParser
    IGNORE_INTERFACE = ["ITypeInfo"]
    IMPORT_HEADER = dedent("""
    import functools
    import ctypes


    {deps}

    """)
    HEADER = dedent("""
    _GUID = IID
    class IID(IID):
        def __init__(self, Data1=None, Data2=None, Data3=None, Data4=None, name=None, strid=None):
            data_tuple = (Data1, Data2, Data3, Data4)
            self.name = name
            self.strid = strid
            if all(data is None for data in data_tuple):
                return super(IID, self).__init__()
            if any(data is None for data in data_tuple):
                raise ValueError("All or none of (Data1, Data2, Data3, Data4) should be None")
            super(IID, self).__init__(Data1, Data2, Data3, Data4)

        def __repr__(self):
            notpresent = object()
            # Handle IID created without '__init__' (like ctypes-ptr deref)
            if getattr(self, "strid", notpresent) is notpresent:
                self.strid = self.to_string()
            if self.strid is None:
                return super(IID, self).__repr__()

            if getattr(self, "name", notpresent) is notpresent:
                self.name = None
            if self.name is None:
                return '<IID "{0}">'.format(self.strid.upper())
            return '<IID "{0}({1})">'.format(self.strid.upper(), self.name)

        def to_string(self):
            data4_format = "{0:02X}{1:02X}-" + "".join("{{{i}:02X}}".format(i=i + 2) for i in range(6))
            data4_str = data4_format.format(*self.Data4)
            return "{0:08X}-{1:04X}-{2:04X}-".format(self.Data1, self.Data2, self.Data3) + data4_str

        def update_strid(self):
           new_strid = self.to_string()
           self.strid = new_strid

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

        def __eq__(self, other):
            if not isinstance(other, (IID, _GUID)):
                return NotImplemented
            return (self.Data1, self.Data2, self.Data3, self.Data4[:]) == (other.Data1, other.Data2, other.Data3, other.Data4[:])

    generate_IID = IID.from_raw

    GUID = IID
    LPGUID = POINTER(GUID)
    REFGUID = POINTER(GUID)
    REFCLSID = POINTER(GUID)
    REFIID = POINTER(GUID)

    class COMInterface(ctypes.c_void_p):
        _functions_ = {
        }

        def __getattr__(self, name):
            if name in self._functions_:
                return functools.partial(self._functions_[name], self)
            return super(COMInterface, self).__getattribute__(name)

    class COMImplementation(object):
        IMPLEMENT = None

        def get_index_of_method(self, method):
            # This code is horrible but not totally my fault
            # the PyCFuncPtrObject->index is not exposed to Python..
            # repr is: '<COM method offset 2: WinFunctionType at 0x035DDBE8>'
            rpr = repr(method)
            if not rpr.startswith("<COM method offset ") or ":" not in rpr:
                raise ValueError("Could not extract offset of {0}".format(rpr))
            return int(rpr[len("<COM method offset "): rpr.index(":")])

        def extract_methods_order(self, interface):
            index_and_method = sorted((self.get_index_of_method(m),name, m) for name, m in interface._functions_.items())
            return index_and_method

        def verify_implem(self, interface):
            for func_name in interface._functions_:
                implem = getattr(self, func_name, None)
                if implem is None:
                    raise ValueError("<{0}> implementing <{1}> has no method <{2}>".format(type(self).__name__, self.IMPLEMENT.__name__, func_name))
                if not callable(implem):
                    raise ValueError("{0} implementing <{1}>: <{2}> is not callable".format(type(self).__name__, self.IMPLEMENT.__name__, func_name))
            return True

        def _create_vtable(self, interface):
            implems = []
            names = []
            for index, name, method in self.extract_methods_order(interface):
                func_implem = getattr(self, name)
                #PVOID is 'this'
                types = [method.restype, PVOID] + list(method.argtypes)
                implems.append(ctypes.WINFUNCTYPE(*types)(func_implem))
                names.append(name)
            class Vtable(ctypes.Structure):
                _fields_ = [(name, ctypes.c_void_p) for name in names]
            return Vtable(*[ctypes.cast(x, ctypes.c_void_p) for x in implems]), implems

        def __init__(self):
            self.verify_implem(self.IMPLEMENT)
            vtable, implems = self._create_vtable(self.IMPLEMENT)
            self.vtable = vtable
            self.implems = implems
            self.vtable_pointer = ctypes.pointer(self.vtable)
            self._as_parameter_ = ctypes.addressof(self.vtable_pointer)

        def QueryInterface(self, this, piid, result):
            if piid[0] in (IUnknown.IID, self.IMPLEMENT.IID):
                result[0] = this
                return 1
            return E_NOINTERFACE

        def AddRef(self, *args):
            return 1

        def Release(self, *args):
            return 0
    """)

    def __init__(self, indirname, iiddef, outfilename, dependances=()):
        self.indirname = indirname
        self.infilename = indirname
        self.outfilename = outfilename
        self.data = None
        self.dependances = dependances

        data = open(iiddef).read()
        self.iids_def = {}
        for line in data.split("\n"):
            name, iid = line.split("|")
            self.iids_def[name] = self.parse_iid(iid), iid

        self.exports = set([])
        self.imports = set([])

        self.parse()
        self.analyse(self.data)
        self.check_dependances()

    def parse(self):
        if self.data is not None:
            return self.data
        data = []
        for filename in glob.glob(self.indirname):
            print("Parsing <{0}>".format(filename))
            data.append(self.PARSER(open(filename).read()).parse())
        self.data = data
        return data

    def analyse(self, data):
        self.real_type = {}
        self.add_exports("IID")
        self.add_exports("GUID")
        self.add_exports("LPGUID")  # setup in InitialCOMGenerator.HEADER
        self.add_exports("REFGUID") # setup in InitialCOMGenerator.HEADER
        self.add_exports("COMInterface")
        self.add_exports("COMImplementation")
        for cominterface in data:
            #import pdb;pdb.set_trace()
            self.add_exports(cominterface.name)
            if cominterface.typedefptr:
                self.add_exports(cominterface.typedefptr)
        for cominterface in data:
            for method in cominterface.methods:
                self.add_imports(method.ret_type)
                for pos, arg in enumerate(method.args):
                    initial_arg = arg
                    if arg.type in self.exports or arg.type in self.IGNORE_INTERFACE:
                        # GUID type ?
                        if arg.type in ["GUID", "REFGUID", "LPGUID", "IID"]:
                            continue
                        # COM Interface ? -> PVOID !
                        atype = "PVOID"
                        byreflevel = arg.byreflevel - 1
                        method.args[pos] = arg = type(arg)(atype, byreflevel, arg.name)
                        self.real_type[arg] = initial_arg

                    elif arg.type == "void" and arg.byreflevel > 0:
                        # **void -> *PVOID
                        atype = "PVOID"
                        byreflevel = arg.byreflevel - 1
                        method.args[pos] = arg = type(arg)(atype, byreflevel, arg.name)
                        self.real_type[arg] = initial_arg

                    self.add_imports(arg.type)

    com_interface_comment_template = """ #{0} -> {1}"""
    com_interface_method_template = """ "{0}": ctypes.WINFUNCTYPE({1})({2}, "{0}"),"""
    com_interface_template = dedent("""
    class {0}(COMInterface):
        IID = generate_IID({2}, name="{0}", strid="{3}")

        _functions_ = {{
    {1}
        }}
    """)

    def generate(self):
        define = []
        for cominterface in self.data:
            methods_string = []
            for method_nb, method in enumerate(cominterface.methods):
                args_to_define = method.args[1:] #ctypes doesnt not need the This
                args_for_comment = [self.real_type.get(arg, arg) for arg in args_to_define]
                #import pdb;pdb.set_trace()
                str_args = []
                methods_string.append(self.com_interface_comment_template.format(method.name, ", ".join([arg.name +":"+ ("*"* arg.byreflevel) +arg.type for arg in args_for_comment])))
                for arg in args_to_define:
                    type = arg.type
                    for i in range(arg.byreflevel):
                        type = "POINTER({0})".format(type)
                    str_args.append(type)

                methods_string.append(self.com_interface_method_template.format(method.name, ", ".join([method.ret_type] + str_args), method_nb))
            #import pdb;pdb.set_trace()
            if cominterface.iid is not None:
                iid_str = cominterface.iid
                iid_python = self.parse_iid(iid_str)
            else:
                print("Lookup of IID for <{0}>".format(cominterface.name))
                iid_python, iid_str = self.iids_def[cominterface.name]
            define.append((self.com_interface_template.format(cominterface.name, "\n".join(methods_string), iid_python, iid_str)))

        deps = "\n".join(["from {0} import *".format(os.path.basename(dep.outfilename).rsplit(".")[0]) for dep in self.dependances])

        ctypes_code =  self.generate_import() + "\n" + self.HEADER + "\n".join(define)
        with open(self.outfilename, "w") as f:
            f.write(ctypes_code)
        print("<{0}> generated".format(self.outfilename))
        return ctypes_code

    def parse_iid(self, iid_str):
        part_iid = iid_str.split("-")
        str_iid = []
        str_iid.append("0x" + part_iid[0])
        str_iid.append("0x" + part_iid[1])
        str_iid.append("0x" + part_iid[2])
        str_iid.append("0x" + part_iid[3][:2])
        str_iid.append("0x" + part_iid[3][2:])
        for i in range(6): str_iid.append("0x" + part_iid[4][i * 2:(i + 1) * 2])
        return ", ".join(str_iid)


class COMGenerator(InitialCOMGenerator):
    IMPORT_HEADER = "{deps}"
    HEADER = ""

class DefGenerator(InitialDefGenerator):
    IMPORT_HEADER = "{deps}"
    HEADER = ""



SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
print(SCRIPT_DIR)
from_here = lambda path: pjoin(SCRIPT_DIR, path)

DEFAULT_INTERFACE_TO_IID = from_here("definitions\\interface_to_iid.txt")

# A partial define without the dependance to ntstatus defintion
# BOOTSTRAP!!
non_generated_def = InitialDefGenerator(from_here("definitions\\windef.txt"), from_here(r"..\windows\generated_def\\windef.py"))
ntstatus = NtStatusGenerator(from_here("definitions\\ntstatus.txt"), from_here(r"..\windows\generated_def\\ntstatus.py"), dependances=[non_generated_def])
# Not a real circular def (import not at the begin of file
defs_with_ntstatus = InitialDefGenerator(from_here("definitions\\windef.txt"), from_here(r"..\windows\generated_def\\windef.py"), dependances=[ntstatus])

# YOLO HACK FOR NOW :DD
defs_with_ntstatus.append_input_file(from_here("definitions\\wintrust_crypt_def.txt"))
defs_with_ntstatus.append_input_file(from_here("definitions\\windef_error.txt"))
defs_with_ntstatus.append_input_file(from_here("definitions\\custom_rpc_windef.txt"))


structs = StructGenerator(from_here("definitions\\winstruct.txt"), from_here(r"..\windows\generated_def\\winstructs.py"), dependances=[defs_with_ntstatus])
structs.append_input_file(from_here("definitions\\display_struct.txt"))
structs.append_input_file(from_here("definitions\\winstruct_bits.txt"))
structs.append_input_file(from_here("definitions\\winstruct_alpc.txt"))

functions = FuncGenerator(from_here("definitions\\winfunc.txt"), from_here(r"..\windows\generated_def\\winfuncs.py"), dependances=[structs])
functions.append_input_file(from_here("definitions\\wintrust_crypt_func.txt"))

com = InitialCOMGenerator(from_here("definitions\\com\\*.txt"), DEFAULT_INTERFACE_TO_IID, from_here(r"..\windows\generated_def\\interfaces.py"), dependances=[structs, defs_with_ntstatus])


if __name__ == "__main__":
    ntstatus.generate()
    defs_with_ntstatus.generate()
    structs.generate()
    functions.generate()
    com.generate()