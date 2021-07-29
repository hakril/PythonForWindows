import ctypes
import windows
import windows.hooks as hooks
import windows.utils as utils

from windows.generated_def.winstructs import *
from windows.utils import transform_ctypes_fields
import windows.remotectypes as rctypes

IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000


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

    def create_structure_at(structcls, addr):  # Il reste une closure sur 'target' ici !!
        return ctypes_structure_transformer(structcls)(addr, target)
    return ctypes_structure_transformer, create_structure_at

def get_pe_bitness(baseaddr, target):
    # We can force bitness as the field we access are bitness-independant
    pe = GetPEFile(baseaddr, target, force_bitness=32)
    machine = pe.get_NT_HEADER().FileHeader.Machine
    if machine == 0x14c:
        return 32
    elif machine == 0x8664:
        return 64
    else:
        raise ValueError("Unknow PE target machine <0x{0:x}>".format(machine))


## == PEPARSE V2 ==


import collections
CtypesStructureTransformers = collections.namedtuple("CtypesStructureTransformers", ["ctypes_structure_transformer", "create_structure_at"])

def GetPEFile(baseaddr, target=None, force_bitness=None):
    """Returns a :class:`PEFile` to explore a PE loaded at `baseaddr` in process `target`.

    :rtype: :class:`PEFile`

    .. note::

        If target is ``None`` it refers to the current process
    """
    proc_bitness = windows.current_process.bitness

    if force_bitness is None:
        targetedbitness = get_pe_bitness(baseaddr, target)
    else:
        targetedbitness = force_bitness

    transformers = get_structure_transformer_for_target(target, targetedbitness)
    #ctypes_structure_transformer, create_structure_at = transformers
    transfor_funcs = CtypesStructureTransformers(*transformers)  # TODO: rename
    return PEFile(target, baseaddr, targetedbitness, transfor_funcs)


class THUNK_DATA(ctypes.Union):
    _fields_ = [
        ("Ordinal", PVOID),
        ("AddressOfData", PVOID)
    ]

# Special case for .NET PE32 rewrite as 64b
# We may have a PE in a 64b process with a 32b IAT
class THUNK_DATA_32(ctypes.Union):
    _fields_ = [
        ("Ordinal", DWORD),
        ("AddressOfData", DWORD)
    ]

class IMPORT_BY_NAME(ctypes.Structure):
    _fields_ = [
        ("Hint", WORD),
        ("Name", BYTE)
    ]


def get_string(target, addr):
    if target is None:
        return ctypes.c_char_p(addr).value.decode("latin1")
    return target.read_string(addr)


class PESection(IMAGE_SECTION_HEADER):

    @property
    def name(self):
        if self.target is None:
            name = get_string(self.target, ctypes.addressof(self.Name))[:8]
        else:
            name = get_string(self.target, self._base_addr)[:8]
        # Decode as UTF-8 as the MS doc say ?
        return name

    @property
    def start(self):
        return self.baseaddr + self.VirtualAddress

    @property
    def size(self):
        return self.VirtualSize

    def __repr__(self):
        return "<PESection \"{0}\">".format(self.name)


    @classmethod
    def create(cls, pefile, addr):
        self = pefile.transformers.create_structure_at(cls, addr)
        self.baseaddr = pefile.baseaddr
        self.target = pefile.target
        return self


class IATPtr(PVOID):
    @classmethod
    def from_iatentry(cls, iat_entry):
        self = cls.from_address(iat_entry.addr)
        self.addr = iat_entry.addr
        self.nonhookvalue = iat_entry.nonhookvalue
        return self

class IATEntry(ctypes.Structure):
    """Represent an entry in the IAT of a module
    Can be used to get resolved value and setup hook
    """
    _fields_ = [
        ("value", PVOID)]

    @classmethod
    def create(cls, addr, ord, name, target, transformers):
        self = transformers.create_structure_at(cls, addr)
        self.addr = addr
        self.ord = ord
        self.name = name
        self.hook = None
        self.nonhookvalue = self.value
        self.target = target
        return self

    def __repr__(self):
        return '<{0} "{1}" ordinal {2}>'.format(self.__class__.__name__, self.name, self.ord)

    def set_hook(self, callback, types=None):
        """Setup a hook on the entry and return it.
        You MUST keep a reference to the hook while the hook is enabled.

        :param callback: the hook

            .. note::

                see :ref:`hook_protocol`

        :rtype: :class:`windows.hooks.IATHook`

        .. warning::

            This works only for PEFile with the current process as target.
        """
        if self.target is not None:
            raise NotImplementedError("Setting hook in remote process (use python code injection)")

        hook = hooks.IATHook(self, callback, types)
        import weakref
        self.whook = weakref.ref(hook, self.on_destroy)
        self.hook = hook
        hook.enable()
        return hook

    def on_destroy(self, *args):
        # We cannot know if the hook was enabled here..
        print("DESTROY: {0} -> ".format(args, self.enabled))
        # print(args[0]())

    def remove_hook(self):
        """Remove the hook on the entry"""
        if self.hook is None:
            return False
        self.hook.disable()
        self.hook = None
        return True

    # def __del__(self):
        # print(self.hook)
        # if self.hook:
            # print("LOL BYE {0}".format(self.hook))


class IMAGE_IMPORT_DESCRIPTOR(IMAGE_IMPORT_DESCRIPTOR): # TODO: use explicite name winstructs.IMAGE_IMPORT_DESCRIPTOR
    def get_INT(self, pe):
        THUNK_DATA_TYPE = THUNK_DATA
        if not self.OriginalFirstThunk:
            return None
        # We may have 32bits PE mapped in 32bits process (thanks to .NET PE)
        if self.target is None and pe.bitness != windows.current_process.bitness:
            assert windows.current_process.bitness == 64 and pe.bitness == 32, "Mapped 64b PE in current process 32b not handled"
            THUNK_DATA_TYPE = THUNK_DATA_32
        int_addr = self.OriginalFirstThunk + self.baseaddr
        int_entry = self.transformers.create_structure_at(THUNK_DATA_TYPE, int_addr)
        res = []
        while int_entry.Ordinal:
            if int_entry.Ordinal & self.IMAGE_ORDINAL_FLAG:
                res += [(int_entry.Ordinal & 0x7fffffff, None)]
            else:
                import_by_name = self.transformers.create_structure_at(IMPORT_BY_NAME, self.baseaddr + int_entry.AddressOfData)
                name_address = self.baseaddr + int_entry.AddressOfData + type(import_by_name).Name.offset
                name = get_string(self.target, name_address)
                res.append((import_by_name.Hint, name))
            int_addr += ctypes.sizeof(type(int_entry))
            int_entry = self.transformers.create_structure_at(THUNK_DATA_TYPE, int_addr)
        return res

    def get_IAT(self, pe):
        THUNK_DATA_TYPE = THUNK_DATA
        if self.target is None and pe.bitness != windows.current_process.bitness:
            assert windows.current_process.bitness == 64 and pe.bitness == 32, "Mapped 64b PE in current process 32b not handled"
            THUNK_DATA_TYPE = THUNK_DATA_32
        iat_addr = self.FirstThunk + self.baseaddr
        iat_entry = self.transformers.create_structure_at(THUNK_DATA_TYPE, iat_addr)
        res = []
        while iat_entry.Ordinal:
            res.append(IATEntry.create(iat_addr, -1, "??", self.target, self.transformers))
            iat_addr += ctypes.sizeof(type(iat_entry))
            iat_entry = self.transformers.create_structure_at(THUNK_DATA_TYPE, iat_addr)
        return res

    @classmethod
    def create(cls, pefile, addr):
        self = pefile.transformers.create_structure_at(cls, addr)
        self.baseaddr = pefile.baseaddr
        self.transformers = pefile.transformers
        self.IMAGE_ORDINAL_FLAG = pefile.IMAGE_ORDINAL_FLAG
        self.target = pefile.target
        return self

class IMAGE_EXPORT_DIRECTORY(IMAGE_EXPORT_DIRECTORY): # TODO: use explicite name winstructs._IMAGE_EXPORT_DIRECTORY
    def get_exports(self):
        NameOrdinals = self.transformers.create_structure_at((WORD * self.NumberOfNames), self.AddressOfNameOrdinals + self.baseaddr)
        NameOrdinals = list(NameOrdinals)
        Functions = self.transformers.create_structure_at((DWORD * self.NumberOfFunctions), self.AddressOfFunctions + self.baseaddr)
        Names = self.transformers.create_structure_at((DWORD * self.NumberOfNames), self.AddressOfNames + self.baseaddr)
        res = []
        for nb, func in enumerate(Functions):
            func += self.baseaddr
            if nb in NameOrdinals:
                name = get_string(self.target, Names[NameOrdinals.index(nb)] + self.baseaddr)
                # Export name should be ascii
                # Decode from ascii or return bytes ?
                # https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table
            else:
                name = None
            res.append((nb, func, name))
        return res

    @classmethod
    def create(cls, pefile, addr):
        self = pefile.transformers.create_structure_at(cls, addr)
        self.transformers = pefile.transformers
        self.target = pefile.target
        self.baseaddr = pefile.baseaddr
        return self


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

class PEFile(object):
    """Represent a PE loaded in a process (current or remote)"""

    def __init__(self, target, baseaddr, targetedbitness, transformers):
        self.target = target
        self.baseaddr = baseaddr
        self.bitness = targetedbitness
        self.transformers = transformers

        if targetedbitness == 32:
            self.IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32
        else:
            self.IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64

    def get_DOS_HEADER(self):
        return self.transformers.create_structure_at(IMAGE_DOS_HEADER, self.baseaddr)

    def get_NT_HEADER(self):
        offset = self.get_DOS_HEADER().e_lfanew
        if self.bitness == 32:
            return self.transformers.create_structure_at(IMAGE_NT_HEADERS32, self.baseaddr + offset)
        return self.transformers.create_structure_at(IMAGE_NT_HEADERS64, self.baseaddr + offset)


    STANDARD_OPTIONAL_HEADER_TYPE_PER_MAGIC = {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC: IMAGE_OPTIONAL_HEADER32,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC: IMAGE_OPTIONAL_HEADER64,
    }

    STANDARD_OPTIONAL_HEADER_SIZE_PER_MAGIC = (
        (IMAGE_NT_OPTIONAL_HDR32_MAGIC, ctypes.sizeof(IMAGE_OPTIONAL_HEADER32)),
        (IMAGE_NT_OPTIONAL_HDR64_MAGIC, ctypes.sizeof(IMAGE_OPTIONAL_HEADER64)),
    )

    def get_OptionalHeader(self):
        # We can have a 32bits PE with a 64 bits OptionalHeader
        # Ex  : PE32 .NET that allow to be loaded in 64b process
        # See: https://github.com/dotnet/runtime/blob/8bbe33819464216becffb7cf8b7ea8dd3bab5836/src/coreclr/src/vm/peimagelayout.cpp#L599
        # In this case the OptionalHeader is transformed in 64bits & OptionalHeader.Magic is changed accordingly
        # So we cannot just rely on get_NT_HEADER() to give us the correct OptionalHeader type. some re-check are required
        default_opth = self.get_NT_HEADER().OptionalHeader
        # Cannot juste compare types with type(default_opth) as it may be a remoteType
        current_opth_infos = (default_opth.Magic, ctypes.sizeof(default_opth))
        if current_opth_infos in self.STANDARD_OPTIONAL_HEADER_SIZE_PER_MAGIC:
            # The default OptionalHeader structure match what we expect based on the magic (most of the cases)
            return default_opth
        # Mismatch -> PE32 remapped as 64b (with OptionalHeader rewrite)
        # Remap the correct OptionalHeader
        opt_header_real_type = self.STANDARD_OPTIONAL_HEADER_TYPE_PER_MAGIC[default_opth.Magic]
        opt_header_addr = default_opth._base_addr if self.target else ctypes.addressof(default_opth)
        return self.transformers.create_structure_at(opt_header_real_type, opt_header_addr)

    def get_DataDirectory(self):
        return self.get_OptionalHeader().DataDirectory


    def get_IMPORT_DESCRIPTORS(self):
        import_datadir = self.get_DataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT]
        if import_datadir.VirtualAddress == 0:
            return []
        import_descriptor_addr = self.baseaddr + import_datadir.VirtualAddress
        current_import_descriptor =  IMAGE_IMPORT_DESCRIPTOR.create(self, import_descriptor_addr)
        res = []
        while current_import_descriptor.FirstThunk:
            res.append(current_import_descriptor)
            import_descriptor_addr += ctypes.sizeof(IMAGE_IMPORT_DESCRIPTOR)
            current_import_descriptor =  IMAGE_IMPORT_DESCRIPTOR.create(self, import_descriptor_addr)
        return res

    def get_EXPORT_DIRECTORY(self):
        export_directory_rva = self.get_DataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        if export_directory_rva == 0:
            return None
        export_directory_addr = self.baseaddr + export_directory_rva
        exp_dir = IMAGE_EXPORT_DIRECTORY.create(self, export_directory_addr)
        return exp_dir

    @utils.fixedpropety
    def sections(self):
        nt_header = self.get_NT_HEADER()
        nb_section = nt_header.FileHeader.NumberOfSections
        SizeOfOptionalHeader = self.get_NT_HEADER().FileHeader.SizeOfOptionalHeader
        if self.target is None:
            opt_header_addr = ctypes.addressof(self.get_NT_HEADER().OptionalHeader)
        else:
            opt_header_addr = self.get_NT_HEADER().OptionalHeader._base_addr
        base_section = opt_header_addr + SizeOfOptionalHeader
        #pe_section_type = IMAGE_SECTION_HEADER
        return [PESection.create(self, base_section + (sizeof(IMAGE_SECTION_HEADER) * i)) for i in range(nb_section)]
        #sections_array = self.transformers.create_structure_at((self.PESection * nb_section), base_section)
        #return list(sections_array)

    @utils.fixedpropety
    def exports(self):
        """The exports of the PE in a dict. Keys are ordinal (:class:`int`) and name (:class:`str`).
         The values are the addresses of the exports.

            :type: {(:class:`int` or :class:`str`) : :class:`int`}"""
        res = {}
        exp_dir = self.get_EXPORT_DIRECTORY()
        export_datadir = self.get_DataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT]
        export_start = self.baseaddr + export_datadir.VirtualAddress
        export_end = export_start + export_datadir.Size
        if exp_dir is None:
            return res
        raw_exports = exp_dir.get_exports()
        for id, rva_addr, rva_name in raw_exports:
            if export_start <= rva_addr < export_end:
                # Export proxy...
                # Contains the string to another Dll.Function
                rva_addr = get_string(self.target, rva_addr) # Put the string proxy instead

            res[id] = rva_addr
            if rva_name is not None:
                res[rva_name] = rva_addr
        return res

    @utils.fixedpropety
    def export_name(self):
        """The Name attribute of the ``EXPORT_DIRECTORY``"""
        exp_dir = self.get_EXPORT_DIRECTORY()
        if exp_dir is None:
            return None
        if not exp_dir.Name:
            return None
        return get_string(self.target, self.baseaddr + exp_dir.Name)

    # TODO: get imports by parsing other modules exports if no INT
    @utils.fixedpropety
    def imports(self):
        """The imports of the PE in a dict.
        Keys are the names of DLL to import from and values are :class:`list`
        of :class:`IATEntry`

            :type: {:class:`str` : [:class:`IATEntry`]}"""
        res = {}
        for import_descriptor in self.get_IMPORT_DESCRIPTORS():
            INT = import_descriptor.get_INT(self)
            IAT = import_descriptor.get_IAT(self)
            if INT is not None:
                for iat_entry, (ord, name) in zip(IAT, INT):
                    # str(name.decode()) -> python2 and python3 compatible for str result
                    iat_entry.ord = ord
                    iat_entry.name = str(name) if name else ""
            name = get_string(self.target, self.baseaddr + import_descriptor.Name)
            res.setdefault(name.lower(), []).extend(IAT)
        return res