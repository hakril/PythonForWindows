import ctypes
import windows
import windows.hooks as hooks
import windows.utils as utils

from windows.generated_def.winstructs import *
import windows.remotectypes as rctypes

# This must go to windefs
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1

IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000


def RedefineCtypesStruct(struct, replacement):
    class NewStruct(ctypes.Structure):
        _fields_ = transform_ctypes_fields(struct, replacement_)
    NewStruct.__name__ = struct.__name__
    return NewStruct


# type replacement based on name
def transform_ctypes_fields(struct, replacement):
    return [(name, replacement.get(name, type)) for name, type in struct._fields_]


def PEFile(baseaddr, target=None):
    # TODO: 32 with target 32
    #       64 with target 64
    # For now you can do it by injecting a remote python..
    proc_bitness = windows.current_process.bitness
    if target is None:
        targetedbitness = proc_bitness
    else:
        targetedbitness = target.bitness

    if targetedbitness == 32 and proc_bitness == 64:
        raise NotImplementedError("Parse 32bits PE with 64bits current_process")
    elif targetedbitness == 64 and proc_bitness == 32:
        ctypes_structure_transformer = rctypes.transform_type_to_remote64bits

        def create_structure_at(structcls, addr):
                return rctypes.transform_type_to_remote64bits(structcls)(addr, target)
    elif targetedbitness == proc_bitness:  # Does not handle remote of same bitness..
        ctypes_structure_transformer = lambda x: x

        def create_structure_at(structcls, addr):
            return structcls.from_address(addr)
    else:
        raise NotImplementedError("Parsing {0} PE from {1} Process".format(targetedbitness, proc_bitness))

    if targetedbitness == 32:
        IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32
    else:
        IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64

    class RVA(DWORD):
        @property
        def addr(self):
            return baseaddr + self.value

        def __repr__(self):
            return "<DWORD {0} (RVA to '{1}')>".format(self.value, hex(self.addr))

    class StringRVa(RVA):
        if proc_bitness == 32 and targetedbitness == 64:
            @property
            def str(self):
                return rctypes.Remote_c_char_p64(self.addr, target=target).value
        else:
            @property
            def str(self):
                return ctypes.c_char_p(self.addr).value.decode()

        def __repr__(self):
            return "<DWORD {0} (String RVA to '{1}')>".format(self.value, self.str)

        def __int__(self):
            return self.value

    class IMPORT_BY_NAME(ctypes.Structure):
        _fields_ = [
            ("Hint", WORD),
            ("Name", BYTE)
        ]

    class THUNK_DATA(ctypes.Union):
        _fields_ = [
            ("Ordinal", PVOID),
            ("AddressOfData", PVOID)
        ]

    class IATEntry(ctypes.Structure):
        _fields_ = [
            ("value", PVOID)]

        @classmethod
        def create(cls, addr, ord, name):
            self = create_structure_at(cls, addr)
            self.addr = addr
            self.ord = ord
            self.name = name
            self.hook = None
            self.nonhookvalue = self.value
            return self

        def __repr__(self):
            return '<{0} "{1}" ordinal {2}>'.format(self.__class__.__name__, self.name, self.ord)

        def set_hook(self, callback, types=None):
            hook = hooks.IATHook(self, callback, types)
            self.hook = hook
            hook.enable()
            return hook

        def remove_hook(self):
            if self.hook is None:
                return False
            self.hook.disable()
            self.hook = None
            return True

    class PEFile(object):
        def __init__(self):
            self.baseaddr = baseaddr

        def get_DOS_HEADER(self):
            return create_structure_at(IMAGE_DOS_HEADER, baseaddr)

        def get_NT_HEADER(self):
            return self.get_DOS_HEADER().get_NT_HEADER()

        def get_OptionalHeader(self):
            return self.get_NT_HEADER().OptionalHeader

        def get_DataDirectory(self):
            return self.get_OptionalHeader().DataDirectory

        def get_IMPORT_DESCRIPTORS(self):
            import_datadir = self.get_DataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT]
            if import_datadir.VirtualAddress == 0:
                return []
            import_descriptor_addr = RVA(import_datadir.VirtualAddress).addr
            current_import_descriptor = create_structure_at(self.IMAGE_IMPORT_DESCRIPTOR, import_descriptor_addr)
            res = []
            while current_import_descriptor.FirstThunk:
                res.append(current_import_descriptor)
                import_descriptor_addr += ctypes.sizeof(self.IMAGE_IMPORT_DESCRIPTOR)
                current_import_descriptor = create_structure_at(self.IMAGE_IMPORT_DESCRIPTOR, import_descriptor_addr)
            return res

        def get_EXPORT_DIRECTORY(self):
            export_directory_rva = self.get_DataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
            if export_directory_rva == 0:
                return None
            export_directory_addr = baseaddr + export_directory_rva
            return create_structure_at(self._IMAGE_EXPORT_DIRECTORY, export_directory_addr)

        class PESection(ctypes_structure_transformer(IMAGE_SECTION_HEADER)):
            @utils.fixedpropety
            def name(self):
                return ctypes.c_char_p(ctypes.addressof(self.Name)).value

            def __repr__(self):
                return "<PESection \"{0}\">".format(self.name)

        @utils.fixedpropety
        def sections(self):
            nt_header = self.get_NT_HEADER()
            nb_section = nt_header.FileHeader.NumberOfSections
            base_section = ctypes.addressof(nt_header) + ctypes.sizeof(nt_header)
            sections_array = create_structure_at(self.PESection * nb_section, base_section)
            return list(sections_array)

        @utils.fixedpropety
        def exports(self):
            res = {}
            exp_dir = self.get_EXPORT_DIRECTORY()
            if exp_dir is None:
                return res
            raw_exports = exp_dir.get_exports()
            for id, rva_addr, rva_name in raw_exports:
                res[id] = rva_addr.addr
                if rva_name is not None:
                    res[rva_name.str] = rva_addr.addr
            return res

        # TODO: get imports by parsing other modules exports if no INT
        @utils.fixedpropety
        def imports(self):
            res = {}
            for import_descriptor in self.get_IMPORT_DESCRIPTORS():
                INT = import_descriptor.get_INT()
                IAT = import_descriptor.get_IAT()
                if INT is not None:
                    for iat_entry, (ord, name) in zip(IAT, INT):
                        # str(name.decode()) -> python2 and python3 compatible for str result
                        iat_entry.ord = ord
                        iat_entry.name = str(name.decode()) if name else ""
                res.setdefault(import_descriptor.Name.str.lower(), []).extend(IAT)
            return res

        # Will be usable as `self.IMAGE_IMPORT_DESCRIPTOR`
        class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
            _fields_ = transform_ctypes_fields(IMAGE_IMPORT_DESCRIPTOR, {"Name": StringRVa, "OriginalFirstThunk": RVA, "FirstThunk": RVA})

            def get_INT(self):
                if not self.OriginalFirstThunk.value:
                    return None
                int_addr = self.OriginalFirstThunk.addr
                int_entry = create_structure_at(THUNK_DATA, int_addr)
                res = []
                while int_entry.Ordinal:
                    if int_entry.Ordinal & IMAGE_ORDINAL_FLAG:
                        res += [(int_entry.Ordinal & 0x7fffffff, None)]
                    else:
                        import_by_name = create_structure_at(IMPORT_BY_NAME, baseaddr + int_entry.AddressOfData)
                        name_address = baseaddr + int_entry.AddressOfData + type(import_by_name).Name.offset
                        if proc_bitness == 32 and targetedbitness == 64:
                            name = rctypes.Remote_c_char_p64(name_address, target=target).value
                        else:
                            name = ctypes.c_char_p(name_address).value
                        res.append((import_by_name.Hint, name))
                    int_addr += ctypes.sizeof(type(int_entry))
                    int_entry = create_structure_at(THUNK_DATA, int_addr)
                return res

            def get_IAT(self):
                iat_addr = self.FirstThunk.addr
                iat_entry = create_structure_at(THUNK_DATA, iat_addr)
                res = []
                while iat_entry.Ordinal:
                    res.append(IATEntry.create(iat_addr, -1, "??"))
                    iat_addr += ctypes.sizeof(type(iat_entry))
                    iat_entry = create_structure_at(THUNK_DATA, iat_addr)
                return res

        # Will be usable as `self._IMAGE_EXPORT_DIRECTORY`
        class _IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
            _fields_ = transform_ctypes_fields(IMAGE_EXPORT_DIRECTORY, {"Name": StringRVa, "AddressOfFunctions": RVA, "AddressOfNames": RVA, "AddressOfNameOrdinals": RVA})

            def get_exports(self):
                NameOrdinals = create_structure_at((WORD * self.NumberOfNames), self.AddressOfNameOrdinals.addr)
                NameOrdinals = list(NameOrdinals)
                Functions = create_structure_at((RVA * self.NumberOfFunctions), self.AddressOfFunctions.addr)
                Names = create_structure_at((StringRVa * self.NumberOfNames), self.AddressOfNames.addr)
                res = []
                for nb, func in enumerate(Functions):
                    if nb in NameOrdinals:
                        name = Names[NameOrdinals.index(nb)]
                    else:
                        name = None
                    res.append((nb, func, name))
                return res

    current_pe = PEFile()

    class IMAGE_DOS_HEADER(ctypes.Structure):
        _fields_ = [
            ("e_magic", CHAR * 2),
            ("e_cblp", WORD),
            ("e_cp", WORD),
            ("e_crlc", WORD),
            ("e_cparhdr", WORD),
            ("e_minalloc", WORD),
            ("e_maxalloc", WORD),
            ("e_ss", WORD),
            ("e_sp", WORD),
            ("e_csum", WORD),
            ("e_ip", WORD),
            ("e_cs", WORD),
            ("e_lfarlc", WORD),
            ("e_ovno", WORD),
            ("e_res", WORD * 4),
            ("e_oemid", WORD),
            ("e_oeminfo", WORD),
            ("e_res2", WORD * 10),
            ("e_lfanew", DWORD),
        ]

        def get_NT_HEADER(self):
            if targetedbitness == 32:
                return create_structure_at(IMAGE_NT_HEADERS32, baseaddr + self.e_lfanew)
            return create_structure_at(IMAGE_NT_HEADERS64, baseaddr + self.e_lfanew)

    return current_pe

tst = PEFile.__code__.co_consts[13]
