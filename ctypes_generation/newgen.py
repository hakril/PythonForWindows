import sys
import os
import os.path
import re
import glob
import textwrap
import StringIO

import shutil

import dummy_wintypes
import struct_parser
import func_parser
import def_parser
import com_parser

pjoin = os.path.join
pexists = os.path.exists
dedent = textwrap.dedent

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
print(SCRIPT_DIR)
from_here = lambda path: pjoin(SCRIPT_DIR, path)



class ParsedFile(object):
    def __init__(self, filename):
        self.filename = filename
        self.data = self.PARSER(open(filename).read()).parse()
        self.exports = set()
        self.imports = set()
        self.compute_imports_exports(self.data)

    def add_exports(self, *names):
        self.exports.update(names)

    def add_imports(self, *names):
        self.imports.update(names)

    def compute_imports_exports(self):
        raise NotImplementedError("compute_imports_exports")

    def __repr__(self):
        return '<{clsname} "{0}">'.format(self.filename, clsname=type(self).__name__)

class StructureParsedFile(ParsedFile):
    PARSER = struct_parser.WinStructParser

    def compute_imports_exports(self, data):
        structs, enums = data
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

class SimpleTypeParsedFile(ParsedFile):
    PARSER = struct_parser.SimpleTypesParser

    def compute_imports_exports(self, data):
        for simple_type in data:
            self.add_exports(simple_type.lvalue) # No dependancy check on rvalue for now


class DefinitionParsedFile(ParsedFile):
    PARSER = def_parser.WinDefParser

    def compute_imports_exports(self, data):
        for windef in data:
            self.add_exports(windef.name) # No dependancy check on rvalue for now

class NtStatusParsedFile(ParsedFile):
    PARSER = def_parser.NtStatusParser

    def compute_imports_exports(self, data):
        for ntstatus in data:
            self.add_exports(ntstatus[1])

class FunctionParsedFile(ParsedFile):
    PARSER = func_parser.WinFuncParser

    def compute_imports_exports(self, data):
        for func in data:
            if isinstance(func.return_type, tuple) and func.return_type[0] == "PTR":
                self.add_imports(func.return_type[1])
            else:
                self.add_imports(func.return_type)
            for param_type, _ in func.params:
                if param_type.startswith("POINTER(") and param_type.endswith(")"):
                    param_type = param_type[len("POINTER("): -1]
                self.add_imports(param_type)
            self.add_exports(func.name)


class COMParsedFile(ParsedFile):
    PARSER = com_parser.WinComParser

    def compute_imports_exports(self, cominterface):
        self.add_exports(cominterface.name)
        if cominterface.typedefptr:
            self.add_exports(cominterface.typedefptr)


class ParsedFileGraph(object):
    def __init__(self, nodes, depnodes): # depnodes: nodes that we dont have to handle but want can take export from
        self.nodes = nodes
        self.depnodes = depnodes
        self.exports_database = {}
        self.depandances_database = {node: set() for node in nodes}
        self.build_export_database(self.nodes)
        self.build_depandance_database()

    def build_dependancy_graph(self):
        todo = set(self.nodes)
        start = self.find_starting_node()
        print("Starting node is {0}".format(start))
        todo.remove(start)
        flatten = [start]
        depdone = set(flatten) | set(self.depnodes)
        while todo:
            for node in todo:
                if self.depandances_database[node].issubset(depdone):
                    break
            else:
                raise ValueError("POUET")

            flatten.append(node)
            depdone.add(node)
            todo.remove(node)
            print("Next is <{0}>".format(node))
        return flatten


    def build_depandance_database(self):
        for node in self.nodes:
            for import_ in node.imports:
                try:
                    self.depandances_database[node].add(self.exports_database[import_])
                except KeyError as e:
                    raise ValueError("Missing dependancy <{0}> of {1}".format(import_, node))


    def build_export_database(self, nodes):
        for node in self.nodes + self.depnodes:
            for export in node.exports:
                if export in self.exports_database:
                    raise ValueError("{0} IN {1} but  already exported by {2}".format(export, self.exports_database[export], node))
                self.exports_database[export] = node

    def find_starting_node(self):
        for node in self.nodes:
            if self.depandances_database[node].issubset(set(self.depnodes)):
                return node
        raise ValueError("Could not find a starting NODE without dependancy")


class BasicTypeNodes(object):
    @property
    def exports(self):
        # Let allow ourself to redefine the bugged BYTE define & MAX_PATH which is NOT A TYPE !
        return set(dummy_wintypes.names) - set(["BYTE", "MAX_PATH"])

class FakeExporter(object):
    def __init__(self, exports):
        self.exports = exports

class ParsedDirectory(object):
    def __init__(self, filetype, directory):
        self.nodes = [filetype(f) for f in glob.glob(directory)]


### Generation Class ###

class CtypesGenerator(object):
    def __init__(self, parsed_files, template):
        self.files = parsed_files # Already in generation order
        self.template = template # MAKE BETTER
        self.result = StringIO.StringIO()

    def emit(self, str):
        self.result.write(str)

    def emitline(self, str):
        self.emit(str)
        self.emit("\n")

    def before_emit_template(self):
        pass

    def after_emit_template(self):
        pass

    def copy_template(self):
        with open(self.template) as f:
            self.emit(f.read())

    def generate(self):
        self.before_emit_template()
        self.copy_template()
        self.after_emit_template()

        for file in self.files:
            self.generate_for_file(file)

    def generate_for_file(self, file):
        pass

NTSTATUS_MODULE = "ntstatus"

class DefineCtypesGenerator(CtypesGenerator):
    def after_emit_template(self):
        self.emitline("from {0} import *".format(NTSTATUS_MODULE))

    def generate_for_file(self, file):
        for define in file.data:
            self.emitline(define.generate_ctypes())

class NtStatusCtypesGenerator(CtypesGenerator):
    def generate_for_file(self, file):
        for value, name, descr in file.data:
            value = "{:#x}".format(value)
            line = '{1} = NtStatusException.register_ntstatus({0}, "{1}", "{2}")'.format(value, name, descr)
            self.emitline(line)

class COMCtypesGenerator(CtypesGenerator):
    IGNORED_INTERFACE = set(["ITypeInfo"])
    def __init__(self, *args, **kwargs):
        super(COMCtypesGenerator, self).__init__(*args, **kwargs)
        self.iids_def = {}
        self.generated_interfaces_names = set(self.IGNORED_INTERFACE)
        for file in self.files:
            self.generated_interfaces_names.update(file.exports)


    def parse_iid_file(self, filename):
        data = open(filename).read()
        for line in data.split("\n"):
            name, iid = line.split("|")
            self.iids_def[name] = self.parse_iid(iid), iid

    def before_emit_template(self):
        self.emitline("from POUET import *")
        self.emitline("")

    def generate_for_file(self, file):
        define = []
        cominterface = file.data
        return self.generate_com_interface(cominterface)

    def generate_com_interface(self, cominterface):
        name = cominterface.name
        if cominterface.iid is not None:
            iid_str = cominterface.iid
            iid_python = self.parse_iid(iid_str)
        else:
            print("Lookup of IID for <{0}>".format(cominterface.name))
            iid_python, iid_str = self.iids_def[cominterface.name]

        cls_format_param = {"name": name, "iid_python" : iid_python, "iid_str": iid_str}

        self.emitline("class {name} (COMInterface):".format(**cls_format_param))
        self.emitline('    IID = generate_IID({iid_python}, name="{name}", strid="{iid_str}")'.format(**cls_format_param))
        self.emitline('    _functions_ = {')
        self.emit_com_interface_functions(cominterface)
        self.emitline('    }')
        self.emitline('')


    def emit_com_interface_functions(self, cominterface):
        indent = " " * 8
        for method_nb, method in enumerate(cominterface.methods):
            args_to_define = method.args[1:] # ctypes doesnt not need the This
            name = method.name
            params = ", ".join([arg.name +":"+ ("*"* arg.byreflevel) +arg.type for arg in args_to_define])
            self.emitline(indent + "# {name} -> {params}".format(name=name, params=params))

            str_args = []
            for arg in args_to_define:
                if arg.type == "void" and arg.byreflevel > 0:
                    arg = type(arg)("PVOID", arg.byreflevel - 1, arg.name)
                atype = arg.type
                byreflevel = arg.byreflevel
                if atype in self.generated_interfaces_names:
                    byreflevel = arg.byreflevel - 1
                    atype = "PVOID"

                for i in range(byreflevel):
                    atype = "POINTER({0})".format(atype)
                str_args.append(atype)

            # methods_string.append(self.com_interface_method_template.format(method.name, ", ".join([method.ret_type] + str_args), method_nb))
            params = ", ".join([method.ret_type] + str_args)
            self.emitline(indent + '"{0}": ctypes.WINFUNCTYPE({1})({2}, "{0}"),'.format(name, params, method_nb))
        return


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

class FunctionCtypesGenerator(CtypesGenerator):
    def __init__(self, parsed_files):
        self.files = parsed_files # Already in generation order
        self.result = StringIO.StringIO()

    def copy_template(self):
        self.emitline("from ctypes import *")
        self.emitline("from POUET import *")
        # self.emitline("PPORT_MESSAGE = INT")

    def generate_for_file(self, file):
        for item in file.data:
            self.emitline(item.generate_ctypes())



EXTENDED_STRUCT_FILE = glob.glob(pjoin(SCRIPT_DIR, "extended_structs", "*.py"))
EXTENDED_STRUCT = [os.path.basename(filename)[:-len(".py")] for filename in EXTENDED_STRUCT_FILE]

class StructureCtypesGenerator(CtypesGenerator):
    def generate_for_simple_type_file(self, file):
        for simple_type in file.data:
            self.emitline(simple_type.generate_ctypes())

    def generate_for_file(self, file):
        if isinstance(file, SimpleTypeParsedFile):
            return self.generate_for_simple_type_file(file)
        structs, enums = file.data
        for definition in [d for l in (enums, structs) for d in l]:
            self.emitline(definition.generate_ctypes())
            if definition.name in EXTENDED_STRUCT:
                print("Including extended definition for <{0}>".format(definition.name))
                extended_struct_filename = from_here(os.path.join("extended_structs", "{0}.py".format(definition.name)))
                with open(extended_struct_filename) as f:
                    self.emitline(f.read())
                    # RE-generate the typedef to apply them to the extended definition
                    self.emitline(definition.generate_typedef_ctypes())



stfilename = r"C:\Users\hakril\Documents\projets\PythonForWindows\ctypes_generation\definitions\simple_types.txt"
struct_parser.SimpleTypesParser(open(stfilename).read()).parse()

ss = SimpleTypeParsedFile(stfilename)

ds = ParsedDirectory(DefinitionParsedFile, from_here(r"definitions\defines\*.txt"))
fds = ParsedDirectory(FunctionParsedFile, from_here(r"definitions\functions\*.txt"))

x = from_here("definitions\\structures\\*.txt")

ntp = NtStatusParsedFile(from_here(r"definitions\ntstatus.txt"))

sds = ParsedDirectory(StructureParsedFile, from_here(r"definitions\structures\*.txt"))

scom = ParsedDirectory(COMParsedFile, from_here(r"definitions\COM\*.txt"))

g = ParsedFileGraph(sds.nodes + [ss], depnodes=[BasicTypeNodes()] + ds.nodes)
snodes = g.build_dependancy_graph()


gg = ParsedFileGraph(fds.nodes, depnodes=[BasicTypeNodes()] + snodes)
fnodes = gg.build_dependancy_graph()

## EMIT TEST CODE



edef = DefineCtypesGenerator(ds.nodes, from_here(r"definitions\defines\template.py"))
edef.generate()


ents = NtStatusCtypesGenerator([ntp], from_here(r"definitions\ntstatus_template.py"))
ents.generate()

snts = StructureCtypesGenerator(snodes, from_here(r"definitions\structures\template.py"))
snts.generate()

fnts = FunctionCtypesGenerator(fnodes)
fnts.generate()

cnts = COMCtypesGenerator(scom.nodes, from_here(r"definitions\com\template.py"))
cnts.parse_iid_file(from_here("definitions\\interface_to_iid.txt"))
cnts.generate()

shutil.copy(from_here(r"definitions\flag.py"), "tmp\\")



with open(r"tmp\yolo.py", "w") as f:
    f.write(edef.result.getvalue())

with open(r"tmp\{0}.py".format(NTSTATUS_MODULE), "w") as f:
    f.write(ents.result.getvalue())

with open(r"tmp\POUET.py", "w") as f:
    f.write(snts.result.getvalue())

with open(r"tmp\FUNCS.py", "w") as f:
    f.write(fnts.result.getvalue())

with open(r"tmp\COM.py", "w") as f:
    f.write(cnts.result.getvalue())