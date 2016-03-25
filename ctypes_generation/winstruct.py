import collections

#WinStructType = collections.namedtuple('WinStructType', ['name'])

#Ptr = collections.namedtuple('Ptr', [''])

class WinStructType(object):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "{0}({1})".format(type(self).__name__, self.name)

    def generate_ctypes(self):
        return self.name

class Ptr(object):

    def __init__(self, struct):
        self.type = struct
        self.name = struct.name

    def generate_ctypes(self):
        return "POINTER({0})".format(self.name)

    def __repr__(self):
        return "Ptr({0})".format(repr(self.type))


class WinStruct(object):
    ctypes_type = "Structure"
    def __init__(self, name):
        self.name = name
        self.fields = []
        self.typedef = {}

    def add_field(self, field):
        self.fields.append(field)

    def add_typedef(self, name):
        if name in self.typedef:
            raise ValueError("nop")
        self.typedef[name] = self

    def add_ptr_typedef(self, name):
        if name in self.typedef:
            raise ValueError("nop")
        self.typedef[name] = Ptr(self)

    def is_self_referencing(self):
        for type in [f[0] for f in self.fields]:
            if type.name == self.name:
                return True
        return False

    def generate_selfref_ctypes_class(self):
        res = "# Self referencing struct tricks\n"
        res += """class {0}(Structure): pass\n""".format(self.name)
        res += "{0}._fields_ = [\n".format(self.name)

        for (ftype, name, nb_rep) in self.fields:
            if  nb_rep == 1:
                res+= '    ("{0}", {1}),\n'.format(name, ftype.generate_ctypes())
            else:
                res+= '    ("{0}", {1} * {2}),\n'.format(name, ftype.generate_ctypes(), nb_rep)
        res += "]\n"
        return res

    def generate_ctypes_class(self):
        if self.is_self_referencing():
            return self.generate_selfref_ctypes_class()
        res = """class {0}({1}):
        _fields_ = [\n""".format(self.name, self.ctypes_type)

        for (ftype, name, nb_rep) in self.fields:
            if  nb_rep == 1:
                res+= '        ("{0}", {1}),\n'.format(name, ftype.generate_ctypes())
            else:
                res+= '        ("{0}", {1} * {2}),\n'.format(name, ftype.generate_ctypes(), nb_rep)
        res += "    ]\n"
        return res

    def generate_ctypes(self):
        ctypes_class = self.generate_ctypes_class()
        for typedef_name, value in self.typedef.items():
            str_value = self.name
            if type(value) == Ptr:
                str_value = "POINTER({0})".format(self.name)
            ctypes_class += "{0} = {1}\n".format(typedef_name, str_value)
        return ctypes_class

class WinUnion(WinStruct):
    ctypes_type = "Union"

class WinEnum(object):
    def __init__(self, name):
        self.name = name
        self.fields = []
        self.typedef = {}

    def add_enum_entry(self, number, name):
        self.fields.append((number, name))

    def add_typedef(self, name):
        if name in self.typedef:
            raise ValueError("nop")
        self.typedef[name] = self

    def add_ptr_typedef(self, name):
        if name in self.typedef:
            raise ValueError("nop")
        self.typedef[name] = Ptr(self)

    # Assert that enum are DWORD
    def generate_ctypes(self):
        #lines = ["{0} = DWORD".format(self.name)]
        lines = []
        for i, name in self.fields:
            lines.append('{0} = EnumValue("{2}", "{0}", {1})'.format(name, hex(i), self.name))

        lines += ["class {0}(EnumType):".format(self.name)]
        lines += ["    values = [{0}]".format(", ".join([name for i, name in self.fields]))]
        lines += ["    mapper = {{x:x for x in values}}".format(self.name)]

        for typedef_name, value in self.typedef.items():
            str_value = self.name
            if type(value) == Ptr:
                str_value = "POINTER({0})".format(self.name)
            lines += ["{0} = {1}".format(typedef_name, str_value)]
        #lines += ["{0} = {1}".format(t, self.name) for t in self.typedef]
        lines += [""]
        ctypes_class = "\n".join(lines)
        return ctypes_class + "\n"
