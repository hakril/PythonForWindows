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


def get_structure_transformer_for_target(target, targetbitness=None):
    current_bitness = windows.current_process.bitness
    if target is None:
        ctypes_structure_transformer = lambda x:x
        create_structure_at = lambda structcls, addr: structcls.from_address(addr)
        return ctypes_structure_transformer, create_structure_at

    if targetbitness is None:
        targetbitness = target.bitness

    if targetbitness == 32 and current_bitness == 64:
        ctypes_structure_transformer = rctypes.transform_type_to_remote32bits
    elif targetbitness == 64 and current_bitness == 32:
        ctypes_structure_transformer = rctypes.transform_type_to_remote64bits
    elif targetbitness == current_bitness:
        ctypes_structure_transformer = rctypes.transform_type_to_remote
    else:
        raise NotImplementedError("Parsing {0} PE from {1} Process".format(targetedbitness, proc_bitness))

    def create_structure_at(structcls, addr):
        return ctypes_structure_transformer(structcls)(addr, target)
    return ctypes_structure_transformer, create_structure_at

def get_pe_bitness(baseaddr, target):
    # We can force bitness as the filed we access are bitness-independant
    pe = GetPEFile(baseaddr, target, force_bitness=32)
    machine = pe.get_NT_HEADER().FileHeader.Machine
    if machine == 0x14c:
        return 32
    elif machine == 0x8664:
        return 64
    else:
        raise ValueError("Unknow PE target machine <0x{0:x}>".format(machine))


def GetPEFile(baseaddr, target=None, force_bitness=None):
    """Returns a :class:`PEFile` to explore a PE loaded at `baseaddr` in process `target`.

    :rtype: :class:`PEFile`

    .. note::

        If target is ``None`` it refers to the curent process
    """
    proc_bitness = windows.current_process.bitness

    if force_bitness is None:
        targetedbitness = get_pe_bitness(baseaddr, target)
    else:
        targetedbitness = force_bitness

    transformers = get_structure_transformer_for_target(target, targetedbitness)
    ctypes_structure_transformer, create_structure_at = transformers

    if targetedbitness == 32:
        IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32
    else:
        IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64

    def get_string(addr):
        if target is None:
            return ctypes.c_char_p(addr).value
        return target.read_string(addr)

    class RVA(DWORD):
        @property
        def addr(self):
            return baseaddr + self.value

        def __repr__(self):
            return "<DWORD {0} (RVA to '{1}')>".format(self.value, hex(self.addr))

    class StringRVa(RVA):
        if target is None:
            @property
            def str(self):
                return get_string(self.addr).decode()
        else:
            @property
            def str(self):
                return get_string(self.addr).decode()

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
        """Represent an entry in the IAT of a module
        Can be used to get resolved value and setup hook
        """
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
            """Setup a hook on the entry and return it.

            :param callback: the hook

                .. note::

                    see :ref:`hook_protocol`

            :rtype: :class:`windows.hooks.IATHook`

            .. warning::

                This works only for PEFile with the current process as target.
            """
            if target is not None:
                raise NotImplementedError("Setting hook in remote process (use python code injection)")

            hook = hooks.IATHook(self, callback, types)
            self.hook = hook
            hook.enable()
            return hook

        def remove_hook(self):
            """Remove the hook on the entry"""
            if self.hook is None:
                return False
            self.hook.disable()
            self.hook = None
            return True

    class PEFile(object):
        """Represent a PE loaded in a process (current or remote)"""
        def __init__(self):
            self.baseaddr = baseaddr
            self.bitness = targetedbitness

        def get_DOS_HEADER(self):
            return create_structure_at(IMAGE_DOS_HEADER, baseaddr)

        def get_NT_HEADER(self):
            return self.get_DOS_HEADER().get_NT_HEADER()

        def get_OptionalHeader(self):
            return self.get_NT_HEADER().OptionalHeader

        def get_DataDirectory(self):
            # This won't work if we load a PE32 in a 64bit process
            # PE32 .NET...
            #return self.get_OptionalHeader().DataDirectory
            DataDirectory_type = IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES
            SizeOfOptionalHeader = self.get_NT_HEADER().FileHeader.SizeOfOptionalHeader
            if target is None:
                opt_header_addr = ctypes.addressof(self.get_NT_HEADER().OptionalHeader)
            else:
                opt_header_addr = self.get_NT_HEADER().OptionalHeader._base_addr
            DataDirectory_addr = opt_header_addr + SizeOfOptionalHeader - ctypes.sizeof(DataDirectory_type)
            return create_structure_at(DataDirectory_type, DataDirectory_addr)


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

        class PESection((IMAGE_SECTION_HEADER)):
            if target is None:
                @property
                def name(self):
                    return get_string(ctypes.addressof(self.Name))[:8]
            else:
                @property
                def name(self):
                    return get_string(self._base_addr)[:8]

            @property
            def start(self):
                return baseaddr + self.VirtualAddress

            @property
            def size(self):
                return self.VirtualSize

            def __repr__(self):
                return "<PESection \"{0}\">".format(self.name)

        @utils.fixedpropety
        def sections(self):
            nt_header = self.get_NT_HEADER()
            nb_section = nt_header.FileHeader.NumberOfSections
            SizeOfOptionalHeader = self.get_NT_HEADER().FileHeader.SizeOfOptionalHeader
            if target is None:
                opt_header_addr = ctypes.addressof(self.get_NT_HEADER().OptionalHeader)
            else:
                opt_header_addr = self.get_NT_HEADER().OptionalHeader._base_addr
            base_section = opt_header_addr + SizeOfOptionalHeader
            sections_array = create_structure_at((self.PESection * nb_section), base_section)
            return list(sections_array)

        @utils.fixedpropety
        def exports(self):
            """The exports of the PE in a dict. Keys are ordinal (:class:`int`) and name (:class:`str`).
             The values are the addresses of the exports.

                :type: {(:class:`int` or :class:`str`) : :class:`int`}"""
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

        @utils.fixedpropety
        def export_name(self):
            """The Name attribute of the ``EXPORT_DIRECTORY``"""
            return self.get_EXPORT_DIRECTORY().Name.str

        # TODO: get imports by parsing other modules exports if no INT
        @utils.fixedpropety
        def imports(self):
            """The imports of the PE in a dict.
            Keys are the names of DLL to import from and values are :class:`list`
            of :class:`IATEntry`

                :type: {:class:`str` : [:class:`IATEntry`]}"""
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
                        if target is None:
                            name = get_string(name_address)
                        else:
                            name = get_string(name_address).decode()
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