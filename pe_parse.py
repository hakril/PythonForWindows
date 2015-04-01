import ctypes
import windows

from generated_def.winstructs import *

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

def PEFile(baseaddr):
    if windows.current_process.bitness == 32:
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
        @property
        def str(self):
            return ctypes.c_char_p(self.addr).value

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
            self = cls.from_address(addr)
            self.addr = addr
            self.ord = ord
            self.name = name
            self.hook = None
            self.nonhookvalue = self.value
            return self

        def __repr__(self):
            return '<{0} "{1}" ordinal {2}>'.format(self.__class__.__name__, self.name, self.ord)

        def set_hook(self, callback, types=None):
            import hooks # TODO: set import at the beginning
            hook = hooks.IATHook(self, callback, types)
            self.hook = hook
            hook.enable()
            return hook

        def remove_hook(self):
            if self.hook is None:
                return None
            self.hook.disable()
            self.hook = None
            return True

    class PEFile(object):
        def __init__(self):
            self.baseaddr = baseaddr

        def get_DOS_HEADER(self):
            return IMAGE_DOS_HEADER.from_address(baseaddr)

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
            current_import_descriptor = self.IMAGE_IMPORT_DESCRIPTOR.from_address(import_descriptor_addr)
            res = []
            while current_import_descriptor.FirstThunk:
                 res.append(current_import_descriptor)
                 import_descriptor_addr += ctypes.sizeof(self.IMAGE_IMPORT_DESCRIPTOR)
                 current_import_descriptor = self.IMAGE_IMPORT_DESCRIPTOR.from_address(import_descriptor_addr)
            return res


        #def get_EXPORT_DIRECTORY(self):
        #    return self.get_OptionalHeader().get_EXPORT_DIRECTORY()

        #@property
        #def exports(self):
        #    return self.get_EXPORT_DIRECTORY().get_exports()

        # TODO: get imports by parsing other modules exports if no INT
        @property
        def imports(self):
            res = {}
            for import_descriptor in self.get_IMPORT_DESCRIPTORS():
                INT = import_descriptor.get_INT()
                IAT = import_descriptor.get_IAT()
                if INT is not None:
                    for iat_entry, (ord, name) in zip(IAT, INT):
                        iat_entry.name = name
                        iat_entry.ord = ord
                res.setdefault(import_descriptor.Name.str.lower(),[]).extend(IAT)
            return res

        # Will be usable as `self.IMPORT_DESCRIPTOR`
        class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
            _fields_ = transform_ctypes_fields(IMAGE_IMPORT_DESCRIPTOR, {"Name" : StringRVa, "OriginalFirstThunk" : RVA, "FirstThunk" : RVA})

            def get_INT(self):
                if not self.OriginalFirstThunk.value:
                    return None
                int_addr = self.OriginalFirstThunk.addr
                int_entry = THUNK_DATA.from_address(int_addr)
                res = []
                while int_entry.Ordinal:
                    if int_entry.Ordinal & IMAGE_ORDINAL_FLAG:
                        res += [(int_entry.Ordinal & 0x7fffffff, None)]
                    else:
                        import_by_name = IMPORT_BY_NAME.from_address(baseaddr + int_entry.AddressOfData)
                        name = ctypes.c_char_p(ctypes.addressof(import_by_name) + IMPORT_BY_NAME.Name.offset).value
                        res.append((import_by_name.Hint, name))
                    int_addr += ctypes.sizeof(THUNK_DATA)
                    int_entry = THUNK_DATA.from_address(int_addr)
                return res

            def get_IAT(self):
                iat_addr = self.FirstThunk.addr
                iat_entry = THUNK_DATA.from_address(iat_addr)
                res = []
                while iat_entry.Ordinal:
                    res.append(IATEntry.create(iat_addr, -1, "??"))
                    iat_addr += ctypes.sizeof(THUNK_DATA)
                    iat_entry = THUNK_DATA.from_address(iat_addr)
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
            if windows.current_process.bitness == 32:
                return IMAGE_NT_HEADERS32.from_address(baseaddr + self.e_lfanew)
            return IMAGE_NT_HEADERS64.from_address(baseaddr + self.e_lfanew)

    #
    #    def get_EXPORT_DIRECTORY(self):
    #        export_directory_rva = self.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    #        if export_directory_rva == 0:
    #            return None
    #        export_directory_addr = baseaddr + export_directory_rva
    #        return IMAGE_EXPORT_DIRECTORY.from_address(export_directory_addr)
    #


    #class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
    #    _fields_ = [
    #        ("Characteristics", DWORD),
    #        ("TimeDateStamp", DWORD),
    #        ("MajorVersion", WORD),
    #        ("MinorVersion", WORD),
    #        ("Name", StringRVa),
    #        ("Base", DWORD),
    #        ("NumberOfFunctions", DWORD),
    #        ("NumberOfNames", DWORD),
    #        ("AddressOfFunctions", RVA),
    #        ("AddressOfNames", RVA),
    #        ("AddressOfNameOrdinals", RVA),
    #    ]
    #
    #    def get_exports(self):
    #        NameOrdinals = (WORD * self.NumberOfNames).from_address(self.AddressOfNameOrdinals.addr)
    #        NameOrdinals = list(NameOrdinals)
    #        Functions = (RVA * self.NumberOfFunctions).from_address(self.AddressOfFunctions.addr)
    #        Names = (StringRVa * self.NumberOfNames).from_address(self.AddressOfNames.addr)
    #        res = []
    #        for nb,func in enumerate(Functions):
    #            if nb in NameOrdinals:
    #                name = Names[NameOrdinals.index(nb)]
    #            else:
    #                name = None
    #            res.append((nb, func, name))
    #        return res
    #
    return current_pe