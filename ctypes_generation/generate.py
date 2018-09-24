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

from simpleparser import ParsingError

pjoin = os.path.join
pexists = os.path.exists
dedent = textwrap.dedent

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
print(SCRIPT_DIR)
from_here = lambda path: pjoin(SCRIPT_DIR, path)

DEST_DIR = from_here(r"..\windows\generated_def")
to_dest = lambda path: pjoin(DEST_DIR, path)

class ParsedFile(object):
    def __init__(self, filename):
        self.filename = filename
        try:
            self.data = self.PARSER(open(filename).read()).parse()
        except ParsingError as e:
            print(" !! Error while parsing file <{0}> !!".format(filename))
            print(e)
            raise

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

    def __init__(self, *args, **kwargs):
        self.imports_by_struct = {}
        super(StructureParsedFile, self).__init__(*args, **kwargs)

    def compute_imports_exports(self, data):
        structs, enums = data
        for enum in enums:
            self.add_exports(enum.name)
            self.add_exports(*enum.typedef)
        for struct in structs:
            self.asser_struct_not_already_in_import(struct)
            if any(x in self.imports for x in [struct.name] + struct.typedef.keys()):
                print("Export <{0}> defined after first use".format(struct.name))
                raise ValueError("LOL")
            self.add_exports(struct.name)
            self.add_exports(*struct.typedef)
            for field_type, field_name, nb_rep in struct.fields:
                if field_type.name not in self.exports:
                    self.add_imports(field_type.name)
                    self.imports_by_struct[field_type.name] = struct.name
                try:
                    int(nb_rep)
                except:
                    self.add_imports(nb_rep)

    def asser_struct_not_already_in_import(self, struct):
        for sname in [struct.name] + struct.typedef.keys():
            try:
                already_used = self.imports_by_struct[sname]
                raise ValueError("Structure <{0}> is defined after being used in <{1}>".format(sname, already_used))
            except KeyError as e:
                pass

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
    IGNORED_INTERFACE = set(["ITypeInfo"])

    def compute_imports_exports(self, cominterface):
        self.add_exports(cominterface.name)
        if cominterface.typedefptr:
            self.add_exports(cominterface.typedefptr)

        for  method in cominterface.methods:
            self.compute_method_imports_exports(cominterface, method)


    def compute_method_imports_exports(self, interface, method):
        self.add_imports(method.ret_type)
        for arg in method.args[1:]: # First one is 'this'
            if arg.byreflevel > 0:
                if arg.type == "void":
                    continue # PVOID DEP: don't care
            if arg.type in self.IGNORED_INTERFACE:
                continue # Will be replaced by "PVOID" at generation: ignore dep
            if arg.type == interface.name:
                continue # Do not add dependence to our own COM interface

            self.add_imports(arg.type)



class ParsedFileGraph(object):
    def __init__(self, nodes, depnodes, missing_handler=None): # depnodes: nodes that we dont have to handle but want can take export from
        self.nodes = nodes
        self.depnodes = depnodes
        self.exports_database = {}
        self.depandances_database = {node: set() for node in nodes}
        self.build_export_database(self.nodes)
        self.missing_handler = missing_handler
        self.build_depandance_database()

    def build_dependancy_graph(self):
        todo = set(self.nodes)
        if not todo:
            return []
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
                import pdb;pdb.set_trace()
                raise ValueError("Could not find a next node for dep flattening")

            flatten.append(node)
            depdone.add(node)
            todo.remove(node)
            print("Next is <{0}>".format(node))
        return flatten


    def build_depandance_database(self):
        for node in self.nodes:
            for import_ in node.imports:
                try:
                    depnod = self.exports_database[import_]
                    if node is depnod:
                        raise ValueError("[ERROR] Node depend of itself {0}".format(node))
                    self.depandances_database[node].add(depnod)
                except KeyError as e:
                    self.on_missing_dependancy(import_, node)
                    # raise ValueError("Missing dependancy <{0}> of {1}".format(import_, node))

    def on_missing_dependancy(self, import_, node):
        if self.missing_handler is not None:
            return self.missing_handler(import_, node)
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
    def __init__(self, filetype, src, recurse=False):
        if not recurse:
            if os.path.isdir(src):
                srcglob = pjoin(src, "*.txt")
            else:
                srcglob = src
            files = glob.glob(srcglob)
        else:
            # Recurse search of .txt files
            files = [os.path.join(path, filename)
                        for (path, _, files) in os.walk(src)
                            for filename in files
                                if filename.endswith(".txt")]



        self.nodes = [filetype(f) for f in files]


### Generation Class ###

class CtypesGenerator(object):
    def __init__(self, parsed_files, template):
        self.files = parsed_files # Already in generation order
        self.template = template # MAKE BETTER
        self.result = StringIO.StringIO()
        self.imported_name = set([])

    def add_import_name(self, name):
        self.imported_name.add(name)

    def emit(self, str):
        self.result.write(str)

    def emitline(self, str):
        self.emit(str)
        self.emit("\n")

    def before_emit_template(self):
        pass

    def after_emit_template(self):
        pass

    def emit_import_dependancies(self):
        for name in self.imported_name:
            self.emitline("from {0} import *".format(name))

    def copy_template(self):
        with open(self.template) as f:
            self.emit(f.read())

    def generate(self):
        self.emit_import_dependancies()
        self.before_emit_template()
        self.copy_template()
        self.after_emit_template()
        self.generate_files(self.files)

    def generate_files(self, files):
        for file in files:
            self.generate_for_file(file)

    def generate_for_file(self, file):
        pass

    def generate_into(self, filename):
        self.generate()
        print("Writing generated code into {0}".format(filename))
        with open(filename, "w") as f:
            f.write(self.result.getvalue())

class NoTemplatedGenerator(CtypesGenerator):
   def __init__(self, parsed_files):
       self.files = parsed_files # Already in generation order
       self.result = StringIO.StringIO()
       self.imported_name = set([])

   def copy_template(self):
       pass

NTSTATUS_MODULE = "ntstatus"

class DefineCtypesGenerator(CtypesGenerator):
    def after_emit_template(self):
        self.emitline("from {0} import *".format(NTSTATUS_MODULE))

    def generate_for_file(self, file):
        for define in file.data:
            self.emitline(define.generate_ctypes())


# TEST Documentation generator
class DefineDocGenerator(NoTemplatedGenerator):
    def copy_template(self):
        self.emitline(".. currentmodule:: windows.generated_def")
        self.emitline("")
        self.emitline("Windef")
        self.emitline("------")

    def generate_for_file(self, file):
        for define in file.data:
            self.emitline(".. autodata:: {define.name}".format(define=define))


class NtStatusCtypesGenerator(CtypesGenerator):
    def generate_for_file(self, file):
        for value, name, descr in file.data:
            value = "{:#x}".format(value)
            line = '{1} = NtStatusException.register_ntstatus({0}, "{1}", "{2}")'.format(value, name, descr)
            self.emitline(line)


class NtStatusDocGenerator(NoTemplatedGenerator):
    def copy_template(self):
        self.emitline(".. currentmodule:: windows.generated_def")
        self.emitline("")
        self.emitline("Ntstatus")
        self.emitline("--------")

    def generate_for_file(self, file):
        for value, name, descr in file.data:
            self.emitline(".. autodata:: {name}".format(name=name))

class COMCtypesGenerator(CtypesGenerator):
    IGNORED_INTERFACE = set(COMParsedFile.IGNORED_INTERFACE)
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

    def generate_files(self, files):
        # We generate COM interface in 2 step
        # 1) The Class intself with the IDD
        # 2) The function list after all class we generated
        #    - This allow COM function to refer the interface in their def :)
        for file in files:
            self.generate_com_interface_class_iid(file.data)
        for file in files:
            self.generate_com_interface_functions(file.data)

    def generate_com_interface_class_iid(self, cominterface):
        name = cominterface.name
        if cominterface.iid is not None:
            iid_str = cominterface.iid
            iid_python = self.parse_iid(iid_str)
        else:
            print("Lookup of IID for <{0}>".format(cominterface.name))
            iid_python, iid_str = self.iids_def[cominterface.name]
        cls_format_param = {"name": name, "iid_python" : iid_python, "iid_str": iid_str}

        self.emitline("class {name}(COMInterface):".format(**cls_format_param))
        self.emitline('    IID = generate_IID({iid_python}, name="{name}", strid="{iid_str}")'.format(**cls_format_param))
        self.emitline('')

    def generate_com_interface_functions(self, cominterface):
        name = cominterface.name
        self.emitline("{name}._functions_ = {{".format(name=name))
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
                    # If the parameter is a COM interface, remove a *
                    # (as PFW ComInterface are PVOID)
                    byreflevel = arg.byreflevel - 1
                    if atype in self.IGNORED_INTERFACE:
                        # If the interface if ignored -> replace by a raw pointer
                        atype = "PVOID"

                for i in range(byreflevel):
                    atype = "POINTER({0})".format(atype)
                str_args.append(atype)

            params = ", ".join([method.ret_type] + str_args)
            ctypes_functype = 'WINFUNCTYPE' if method.functype == 'stdcall' else 'CFUNCTYPE'
            self.emitline(indent + '"{0}": ctypes.{functype}({1})({2}, "{0}"),'.format(name, params, method_nb, functype=ctypes_functype))
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

#TODO: subclass NOTEMPLATE
class FunctionCtypesGenerator(NoTemplatedGenerator):
    def generate_for_file(self, file):
        for item in file.data:
            self.emitline(item.generate_ctypes())



EXTENDED_STRUCT_FILE = glob.glob(pjoin(SCRIPT_DIR, "extended_structs", "*.py"))
EXTENDED_STRUCT = [os.path.basename(filename)[:-len(".py")] for filename in EXTENDED_STRUCT_FILE]

class StructureCtypesGenerator(CtypesGenerator):
    def generate_for_simple_type_file(self, file):
        for simple_type in file.data:
            self.emitline(simple_type.generate_ctypes())
            if simple_type.lvalue in EXTENDED_STRUCT:
                extended_struct_filename = from_here(os.path.join("extended_structs", "{0}.py".format(simple_type.lvalue)))
                print("Including extended definition for <{0}>".format(simple_type.lvalue))
                with open(extended_struct_filename) as f:
                    self.emitline(f.read())

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


class StructureDocGenerator(NoTemplatedGenerator):
    STRUCT_NAME_SEPARATOR = "'"

    def copy_template(self):
        self.emitline(".. module:: windows.generated_def.winstructs")
        self.emitline("")

    def generate(self):
        self.copy_template()

        self.emitline("Winstructs")
        self.emitline("----------")
        for file in self.files:
            self.generate_structures_for_file(file)

        self.emitline("WinEnums")
        self.emitline("--------")
        for file in self.files:
            self.generate_enums_for_file(file)

    def generate_doc_simple_type_file(self, file):
        # TODO !

        self.emitline("Simple types")
        self.emitline(self.STRUCT_NAME_SEPARATOR * len("Simple types"))


        for simpledef in file.data:
            if simpledef.rvalue.startswith("POINTER("):
                # import pdb;pdb.set_trace()
                rtype = simpledef.rvalue[len("POINTER("):-1]
                self.emitline(".. class:: {0}".format(simpledef.lvalue))
                self.emitline("")
                self.emitline("    Pointer to :class:`{0}`".format(rtype))
            else:
                self.emitline(".. autoclass:: {0}".format(simpledef.lvalue))
            self.emitline("")
        return

    def generate_structures_for_file(self, file):
        if isinstance(file, SimpleTypeParsedFile):
            return self.generate_doc_simple_type_file(file)

        structs, enums = file.data
        for struct in structs:
            self.emitline(struct.name)
            self.emitline(self.STRUCT_NAME_SEPARATOR * len(struct.name))
            # Emit typedef
            for name, type in  struct.typedef.items():
                self.emitline(".. class:: {0}".format(name))
                self.emitline("")
                if hasattr(type, "type"):
                    self.emitline("    Pointer to :class:`{0}`".format(type.type.name))
                else:
                    self.emitline("    Alias for :class:`{0}`".format(type.name))
                self.emitline("")
            # Emit struct Definition
            self.emitline(".. class:: {0}".format(struct.name))
            for ftype, fname, nb in struct.fields:
                array_str = " ``[{nb}]``".format(nb=nb) if nb > 1 else ""
                self.emitline("")
                self.emitline("    .. attribute:: {fname}".format(fname=fname))
                self.emitline("")
                self.emitline("        :class:`{ftype.name}`{array_str}".format(ftype=ftype, array_str=array_str))
                self.emitline("")

    def generate_enums_for_file(self, file):
        if isinstance(file, SimpleTypeParsedFile):
            return
        structs, enums = file.data
        for enum in enums:
            self.emitline(enum.name)
            self.emitline(self.STRUCT_NAME_SEPARATOR * len(enum.name))
             # Emit typedef
            for name, type in  enum.typedef.items():
                self.emitline(".. class:: {0}".format(name))
                self.emitline("")
                if hasattr(type, "type"):
                    self.emitline("    Pointer to :class:`{0}`\n\n".format(type.type.name))
                else:
                    self.emitline("    Alias for :class:`{0}`\n\n".format(type.name))
            # Emit enum Definition
            self.emitline(".. class:: {0}".format(enum.name))
            self.emitline("")
            for enum_value, enum_name in enum.fields:
                self.emitline("")
                self.emitline("    .. attribute:: {0}({1})".format(enum_name, enum_value))
                self.emitline("")

META_WALKER = """
def generate_walker(namelist, target_module):
    def my_walker():
        for name in namelist:
            yield name, getattr(target_module, name)
    return my_walker
"""

class MetaFileGenerator(NoTemplatedGenerator):
    def __init__(self):
       self.result = StringIO.StringIO()
       self.modules = []

    def add_exportlist(self, name, modname, exports):
        self.modules.append((name, modname, exports))

    def add_export_module(self, module):
        self.add_exportlist(module.name, module.name, module.modules_exports())

    def generate(self):

        for name, modname, exports in self.modules:
            self.emitline("{0} = {1}".format(name, exports))

        self.emitline(META_WALKER)

        for name, modname, exports in self.modules:
                self.emitline("import {0} as {0}_module".format(modname))
                self.emitline("{0}_walker = generate_walker({0}, {1}_module)".format(name, modname))

class ModuleGenerator(object):
    def __init__(self, name, filetype, ctypesgenerator, docgenerator, src):
        self.name = name
        self.filetype = filetype
        self.ctypesgenerator = ctypesgenerator
        self.docgenerator = docgenerator
        self.src = src
        self.parsed_dir = None
        self.nodes = []
        self.dependances_modules = set([])

    def add_module_dependancy(self, module):
        self.dependances_modules.add(module)


    def get_template_filename(self):
        return pjoin(self.src, "template.py")

    def parse_source_directory(self, recurse=False):
        self.nodes += ParsedDirectory(self.filetype, self.src, recurse=recurse).nodes

    def resolve_dependancies(self, depnodes=[]):
        g = ParsedFileGraph(self.nodes, depnodes=depnodes)
        return g.build_dependancy_graph()

    def check_dependancies_without_flattening(self, depnodes):
        self.missing_interfaces = []
        g = ParsedFileGraph(self.nodes, depnodes=depnodes, missing_handler=self.missing_com_interface) # init check for missing dependance
        if self.missing_interfaces:
            missing_names = [x[0] for x in self.missing_interfaces]
            if not args.autocopy:
                raise ValueError("Missing COM dependancy Names : {0}".format(missing_names))

            print("Missing COM interfaces are: {0}".format(missing_names))
            autocopied = []
            for name, node in self.missing_interfaces:
                filename = "{0}\\{1}.txt".format(args.autocopy, name)
                if os.path.exists(filename):
                    autocopied.append(name)
                    print("Auto-copy <{0}>".format(filename))
                    targetdir = os.path.dirname(node.filename)
                    print(filename, targetdir)
                    shutil.copy(filename, targetdir)
            if autocopied:
                raise ValueError("Auto-copyied Names : {0}".format(autocopied))
            raise ValueError("Missing COM dependancy Names : {0}".format(missing_names))
        return g.nodes

    def missing_com_interface(self, import_, node):
        print("Missing name <{0}> in file <{1}>".format(import_, node.filename))
        self.missing_interfaces.append((import_, node))

    def generate(self):
        self.parse_source_directory()
        # Flatten the graph
        flatten_nodes = self.resolve_dependancies()
        self.generate_from_nodelist(flatten_nodes)
        self.nodes = flatten_nodes

    def resolve_dep_and_generate(self, depnodes=[]):
        depnodes = list(depnodes)
        # Add module dependancies nodes to the finals depnodes
        for moddep in self.dependances_modules:
            depnodes += moddep.nodes
        flatten_nodes = self.resolve_dependancies(depnodes=depnodes)
        self.generate_from_nodelist(flatten_nodes)

    def after_ctypes_generator_init(self, ctypesgen):
        pass

    def generate_from_nodelist(self, nodelist):
        template = self.get_template_filename()
        if template is not None:
            ctypesgen = self.ctypesgenerator(nodelist, template)
        else:
            ctypesgen = self.ctypesgenerator(nodelist)
        for moddep in self.dependances_modules:
            ctypesgen.add_import_name(moddep.name)

        self.after_ctypes_generator_init(ctypesgen)
        finalfilename = "{0}.py".format(self.name)
        ctypesgen.generate_into(to_dest(finalfilename)) # Need to handle dest != PythonForWindows

    def generate_doc(self, filename):
        nodelist = self.nodes
        self.docgenerator(nodelist).generate_into(filename)


    def modules_exports(self):
        res = set([])
        for node in self.nodes:
            res = res | node.exports
        return res


import argparse

parser = argparse.ArgumentParser(prog=__file__)
parser.add_argument('--autocopy', help="[PRIVATE OPTION] A directory used to find missing COM interface")
args = parser.parse_args()



# Copy Flag code
shutil.copy(from_here(r"definitions\flag.py"), DEST_DIR)

print("== Generating defines ==")
# Generate defines
definemodulegenerator = ModuleGenerator("windef", DefinitionParsedFile, DefineCtypesGenerator, DefineDocGenerator, from_here(r"definitions\defines"))
definemodulegenerator.generate()
definemodulegenerator.generate_doc(from_here(r"..\docs\source\windef_generated.rst"))

print("== Generating NTSTATUS ==")
# Generate Ntstatus
ntstatus_module_generator = ModuleGenerator("ntstatus", NtStatusParsedFile, NtStatusCtypesGenerator, NtStatusDocGenerator, from_here(r"definitions\ntstatus.txt"))
# Hardcoded template file (no dir for ntstatus) -- Need one dir ?
ntstatus_module_generator.get_template_filename = lambda : from_here(r"definitions\ntstatus_template.py")
ntstatus_module_generator.generate()
ntstatus_module_generator.generate_doc(from_here(r"..\docs\source\ntstatus_generated.rst"))

print("== Generating structures ==")
# Parse the simple type file
stfilename = from_here(r"definitions\simple_types.txt")
struct_parser.SimpleTypesParser(open(stfilename).read()).parse()
ss = SimpleTypeParsedFile(stfilename)
# Generate struct + simple types
structure_module_generator = ModuleGenerator("winstructs", StructureParsedFile, StructureCtypesGenerator, StructureDocGenerator, from_here(r"definitions\structures"))
structure_module_generator.parse_source_directory()
# Add the simple type file to the know structures (for dep resolve + generation)
structure_module_generator.nodes.append(ss)
structure_module_generator.add_module_dependancy(definemodulegenerator)
structure_module_generator.resolve_dep_and_generate([BasicTypeNodes()])
structure_module_generator.generate_doc(from_here(r"..\docs\source\winstructs_generated.rst"))

print("== Generating COM interfaces ==")
# Generate COM interfaces
com_module_generator = ModuleGenerator("interfaces", COMParsedFile, COMCtypesGenerator, None, from_here(r"definitions\com"))
# Load the interface_to_iid file needed by the 'COMCtypesGenerator'
com_module_generator.after_ctypes_generator_init = lambda cgen: cgen.parse_iid_file(from_here("definitions\\interface_to_iid.txt"))
com_module_generator.parse_source_directory(recurse=True)
com_module_generator.add_module_dependancy(structure_module_generator)
com_module_generator.resolve_dependancies = com_module_generator.check_dependancies_without_flattening # No real flattening as we have circular dep in Interfaces VTBL
com_module_generator.resolve_dep_and_generate([BasicTypeNodes()])

print("== Generating functions ==")
# Generate function
functions_module_generator = ModuleGenerator("winfuncs", FunctionParsedFile, FunctionCtypesGenerator, None, from_here(r"definitions\functions"))
# no template file
functions_module_generator.get_template_filename = lambda : None
functions_module_generator.parse_source_directory()
functions_module_generator.add_module_dependancy(structure_module_generator)
functions_module_generator.add_module_dependancy(com_module_generator)
functions_module_generator.resolve_dep_and_generate([BasicTypeNodes()])


print("== Generating META file ==")
# Meta-file generator
enums_exports = set()
structs_exports = set()
# Extract enums export & structures exports
for node in structure_module_generator.nodes:
    if isinstance(node, SimpleTypeParsedFile):
        continue # Generate META for simple type ?
    structs, enums = node.data
    for struct in structs:
        structs_exports.add(struct.name)
        structs_exports.update(struct.typedef)
    for enum in enums:
        enums_exports.add(enum.name)
        enums_exports.update(enum.typedef)

meta = MetaFileGenerator()
meta.add_exportlist("windef", definemodulegenerator.name, definemodulegenerator.modules_exports() | ntstatus_module_generator.modules_exports())
# Add structs / enums as 2 differents lists
meta.add_exportlist("structs", structure_module_generator.name, structs_exports)
meta.add_exportlist("enums", structure_module_generator.name, enums_exports)
meta.add_exportlist("functions", functions_module_generator.name, functions_module_generator.modules_exports())
meta.add_exportlist("interfaces", com_module_generator.name, com_module_generator.modules_exports())
meta.generate_into(to_dest("meta.py"))

print("DONE !")