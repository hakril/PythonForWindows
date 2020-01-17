import os.path
import ctypes
import copy
import itertools
from collections import namedtuple

import windows
import windows.generated_def as gdef
from windows import winproxy

DEFAULT_DBG_OPTION = gdef.SYMOPT_DEFERRED_LOADS + gdef.SYMOPT_UNDNAME

def set_dbghelp_path(path):
    loaded_modules =  [m.name.lower() for m in windows.current_process.peb.modules]
    if os.path.isdir(path):
        path = os.path.join(path, str(windows.current_process.bitness), "dbghelp.dll")
    if "dbghelp.dll" in loaded_modules:
        raise ValueError("setup_dbghelp_path should be called before any dbghelp function")
    # Change the DLL used by DbgHelpProxy
    winproxy.DbgHelpProxy.APIDLL = path
    return


class SymbolInfoBase(object):
    # Init on ctypes struct is not always called
    # resolver & displacement should be set manually
    CHAR_TYPE = None

    def __init__(self, *args, **kwargs):
        self.resolver = kwargs.get("resolver", None)
        self.displacement = kwargs.get("displacement", 0)

    def as_type(self):
        # assert self.Address == 0 ?
        return SymbolType(self.Index, self.ModBase, self.resolver)

    @property
    def name(self):
        if not self.NameLen:
            return None
        size = self.NameLen
        addr = ctypes.addressof(self) + type(self).Name.offset
        return (self.CHAR_TYPE * size).from_address(addr)[:]

    @property
    def fullname(self):
        return str(self)

    @property
    def addr(self):
        return self.Address

    @property # Fixed ?
    def module(self):
        return self.resolver.get_module(self.ModBase)

    def __int__(self):
        return self.addr + self.displacement

    def __str__(self):
        if self.displacement:
            return "{self.module.name}!{self.name}+{self.displacement:#x}".format(self=self)
        return "{self.module.name}!{self.name}".format(self=self)

    def __repr__(self):
        if self.displacement:
            return '<{0} name="{1}" addr={2:#x} displacement={3:#x} tag={4}>'.format(type(self).__name__, self.name, self.addr, self.displacement, self.tag)
        return '<{0} name="{1}" addr={2:#x} tag={3}>'.format(type(self).__name__, self.name, self.addr, self.tag)


class SymbolInfoA(gdef.SYMBOL_INFO, SymbolInfoBase):
    CHAR_TYPE = gdef.CHAR

class SymbolInfoW(gdef.SYMBOL_INFOW, SymbolInfoBase):
    CHAR_TYPE = gdef.WCHAR

# We use the A Api in our code (for now)
SymbolInfo = SymbolInfoA

class SymbolType(object):
    def __init__(self, typeid, modbase, resolver):
        # Inheritance ?
        self.resolver = resolver
        self._typeid = typeid # Kind of a handle. Different of typeid property.
        self.modbase = modbase

    def _get_type_info(self, typeinfo, ires=None):
        res = ires
        if res is None:
            res = TST_TYPE_RES_TYPE.get(typeinfo, gdef.DWORD)()
        windows.winproxy.SymGetTypeInfo(self.resolver.handle, self.modbase, self._typeid, typeinfo, ctypes.byref(res))
        if ires is not None:
            return ires
        newres = res.value
        if isinstance(res, gdef.LPWSTR):
            windows.winproxy.LocalFree(res)
        return newres

    @property
    def name(self):
        return self._get_type_info(gdef.TI_GET_SYMNAME)

    @property
    def size(self):
        return self._get_type_info(gdef.TI_GET_LENGTH)

    @property
    def tag(self):
        return self._get_type_info(gdef.TI_GET_SYMTAG)

    # Diff type/typeid ?
    @property
    def type(self):
        return self.new_typeid(self._get_type_info(gdef.TI_GET_TYPE))

    @property
    def typeid(self):
        return self.new_typeid(self._get_type_info(gdef.TI_GET_TYPEID))

    @property
    def basetype(self):
        return gdef.BasicType.mapper[self._get_type_info(gdef.TI_GET_BASETYPE)]

    @property
    def datakind(self):
        return gdef.DataKind.mapper[self._get_type_info(gdef.TI_GET_DATAKIND)]

    @property
    def udtkind(self):
        return gdef.UdtKind.mapper[self._get_type_info(gdef.TI_GET_UDTKIND)]

    @property
    def offset(self):
        return self._get_type_info(gdef.TI_GET_OFFSET)

    @property
    def nb_children(self):
        return self._get_type_info(gdef.TI_GET_CHILDRENCOUNT)

    @property
    def children(self):
        count = self.nb_children
        class res_struct(ctypes.Structure):
            _fields_ = [("Count", gdef.ULONG), ("Start", gdef.ULONG), ("Types", (gdef.ULONG * count))]
        x = res_struct()
        x.Count = count
        x.Start = 0
        self._get_type_info(gdef.TI_FINDCHILDREN, x)
        return [self.new_typeid(ch) for ch in x.Types]

    # Constructor
    @classmethod
    def from_symbol_info(cls, syminfo, resolver):
        return cls(syminfo.TypeIndex, syminfo.ModBase, resolver)

    # Constructor
    def new_typeid(self, newtypeid):
        return type(self)(newtypeid, self.modbase, self.resolver)

    def __repr__(self):
        if self.tag == gdef.SymTagBaseType:
            return '<{0} <basetype> {1}>'.format(type(self).__name__, self.basetype)
        return '<{0} name="{1}" tag={2}>'.format(type(self).__name__, self.name, self.tag)


class SymbolModule(gdef.IMAGEHLP_MODULE64):
    # Init on ctypes struct is not always called
    # resolver should be set manually
    def __init__(self, resolver):
        self.resolver = resolver

    @property
    def addr(self):
        return self.BaseOfImage

    @property
    def name(self):
        return self.ModuleName

    @property
    def path(self):
        return self.LoadedImageName

    @property
    def type(self):
        return self.SymType

    @property
    def pdb(self):
        LoadedPdbName = self.LoadedPdbName
        if not LoadedPdbName:
            return None
        return LoadedPdbName

    def __repr__(self):
        pdb_basename = self.LoadedPdbName.split("\\")[-1]
        return '<{0} name="{1}" type={2} pdb="{3}" addr={4:#x}>'.format(type(self).__name__, self.name, self.type.value.name, pdb_basename, self.addr)


# https://docs.microsoft.com/en-us/windows/win32/debug/symbol-handler-initialization
class SymbolHandler(object):
    """Base class of symbol handler"""
    INIT_SYMBOL_OPTION = False

    def __init__(self, handle, search_path=None, invade_process=False):
        # https://docs.microsoft.com/en-us/windows/desktop/api/dbghelp/nf-dbghelp-syminitialize
        # This value should be unique and nonzero, but need not be a process handle.
        # be sure to use the correct handle.
        self.handle = handle
        if not SymbolHandler.INIT_SYMBOL_OPTION:
            # Normally the first real call to DbgHelp -> setup our options
            # Should check if  SymSetOptions was not called by someone else
            # windows.winproxy.SymSetOptions(DEFAULT_DBG_OPTION)
            SymbolHandler.INIT_SYMBOL_OPTION = True
        winproxy.SymInitialize(handle, search_path, invade_process)


    # Config

    # def get_search_path(): ?


    # Loading

    def load_module(self, file_handle=None, path=None, name=None, addr=0, size=0, data=None, flags=0):
        # Is that a bug in SymLoadModuleEx ?
        # To get a custom name for a module it use "path"
        # So we need to use file_handle and set a custom path
        # ! BUT it means we cannot get a custom name for a module where the path is not explicit and need to be searched
        if name is not None and file_handle is None and os.path.exists(path):
            try:
                f = open(path)
                file_handle = windows.utils.get_handle_from_file(f)
                path = name
            except Exception as e:
                pass
        try:
            load_addr = winproxy.SymLoadModuleEx(self.handle, file_handle, path, name, addr, size, data, flags)
        except WindowsError as e:
            # if e.winerror == 0:
                # Already loaded ?
                # What if someone try to load another PE at the same BaseOfDll ?
                # return BaseOfDll
            raise
        return self.get_module(load_addr)

    def load_file(self, path, name=None, addr=0, size=0, data=None, flags=0):
        return self.load_module(path=path, name=name, addr=addr, size=size, data=data, flags=flags)

    def unload(self, addr):
        return winproxy.SymUnloadModule64(self.handle, addr)


    @staticmethod
    @ctypes.WINFUNCTYPE(gdef.BOOL, gdef.PCSTR, gdef.DWORD64, ctypes.py_object)
    def modules_aggregator(modname, modaddr, ctx):
        ctx.append(modaddr)
        return True

    @property
    def modules(self):
        res = []
        windows.winproxy.SymEnumerateModules64(self.handle, self.modules_aggregator, res)
        return [self.get_module(addr) for addr in res]


    def get_module(self, base):
        modinfo = SymbolModule(self)
        modinfo.SizeOfStruct = ctypes.sizeof(modinfo)
        winproxy.SymGetModuleInfo64(self.handle, base, modinfo)
        return modinfo

    def symbol_and_displacement_from_address(self, addr):
        displacement = gdef.DWORD64()
        max_len_size = 0x1000
        full_size = ctypes.sizeof(SymbolInfo) + (max_len_size - 1)
        buff = windows.utils.BUFFER(SymbolInfo)(size=full_size)
        sym = buff[0]
        sym.SizeOfStruct = ctypes.sizeof(SymbolInfo)
        sym.MaxNameLen  = max_len_size
        winproxy.SymFromAddr(self.handle, addr, displacement, buff) # SymFromAddrW	 ?
        sym.resolver = self
        sym.displacement = displacement.value
        return sym

    # Keep it ?
    # def get_symbol(self, addr):
        # return self.symbol_and_displacement_from_address(addr)

    def symbol_from_name(self, name):
        max_len_size = 0x1000
        full_size = ctypes.sizeof(SymbolInfo) + (max_len_size - 1)
        buff = windows.utils.BUFFER(SymbolInfo)(size=full_size)
        sym = buff[0]
        sym.SizeOfStruct = ctypes.sizeof(SymbolInfo)
        sym.MaxNameLen  = max_len_size
        windows.winproxy.SymFromName(self.handle, name, buff)
        sym.resolver = self
        sym.displacement = 0
        return sym

    def resolve(self, name_or_addr):
        # Only returns None if symbol is not Found ?
        if isinstance(name_or_addr, basestring):
            return self.symbol_from_name(name_or_addr)
        try:
            return self.symbol_and_displacement_from_address(name_or_addr)
        except WindowsError as e:
            if e.winerror != gdef.ERROR_MOD_NOT_FOUND:
                raise
            # We could not resolve and address -> return None
            return None

    __getitem__ = resolve

    @staticmethod
    @ctypes.WINFUNCTYPE(gdef.BOOL, ctypes.POINTER(SymbolInfo), gdef.ULONG , ctypes.py_object)
    def simple_aggregator(info, size, ctx):
        sym = info[0]
        fullsize = sym.SizeOfStruct + sym.NameLen
        cpy = windows.utils.BUFFER(SymbolInfo)(size=fullsize)
        ctypes.memmove(cpy, info, fullsize)
        ctx.append(cpy[0])
        return True

    def search(self, mask, mod=0, tag=0, options=gdef.SYMSEARCH_ALLITEMS, callback=None):
        res = []
        if callback is None:
            callback = self.simple_aggregator
        else:
            callback = ctypes.WINFUNCTYPE(gdef.BOOL, ctypes.POINTER(SymbolInfo), gdef.ULONG , ctypes.py_object)(callback)
        windows.winproxy.SymSearch(self.handle, gdef.DWORD64(mod), 0, tag, mask, 0, callback, res, options)
        for sym in res:
            sym.resolver = self
            sym.displacement = 0
        return res

    def get_symbols(self, addr, callback=None):
        res = []
        if callback is None:
            callback = self.simple_aggregator
        else:
            callback = ctypes.WINFUNCTYPE(gdef.BOOL, ctypes.POINTER(SymbolInfo), gdef.ULONG , ctypes.py_object)(callback)
        try:
            windows.winproxy.SymEnumSymbolsForAddr(self.handle, addr, callback, res)
        except WindowsError as e:
            if e.winerror == gdef.ERROR_MOD_NOT_FOUND:
                return []
            raise

        for sym in res:
            sym.resolver = self
            sym.displacement = 0
        return res


    # Type stuff
    def get_type(self, name, mod=0):
        max_len_size = 0x1000
        full_size = ctypes.sizeof(SymbolInfo) + (max_len_size - 1)
        buff = windows.utils.BUFFER(SymbolInfo)(size=full_size)
        buff[0].SizeOfStruct = ctypes.sizeof(SymbolInfo)
        buff[0].MaxNameLen  = max_len_size
        windows.winproxy.SymGetTypeFromName(self.handle, mod, name, buff)
        return SymbolType.from_symbol_info(buff[0], resolver=self)

    # SymbolInfo info ?
    # def type_info(self, mod, typeid, typeinfo, ires=None):
        # res = ires
        # if res is None:
            # res = TST_TYPE_RES_TYPE.get(typeinfo, gdef.DWORD)()
        # windows.winproxy.SymGetTypeInfo(self.handle, mod, typeid, typeinfo, ctypes.byref(res))
        # if ires is not None:
            # return ires
        # newres = res.value
        # if isinstance(res, gdef.LPWSTR):
            # windows.winproxy.LocalFree(res)
        # return newres

class StackWalker(object):
    def __init__(self, resolver, process=None, thread=None, context=None):
        self.resolver = resolver
        if process is None and thread is None:
            raise ValueError("At least a process or thread must be provided")
        if process is None:
            process = thread.owner
        self.process = process
        self.thread = thread
        self.context = context
        if windows.current_process.bitness == 32 and process.bitness == 64:
            raise NotImplementedError("StackWalking 64b does not seems to works from 32b process")

    def _stack_frame_generator(self):
        ctx, machine = self._get_effective_context_and_machine()
        frame = self._setup_initial_frame_from_context(ctx, machine)
        thread_handle = self.thread.handle if self.thread else None
        while True:
            try:
                windows.winproxy.StackWalkEx(machine,
                                    # dbg.current_process.handle,
                                    self.resolver.handle,
                                    thread_handle,
                                    # 0,
                                    frame,
                                    ctypes.byref(ctx),
                                    None,
                                    winproxy.resolve(winproxy.SymFunctionTableAccess64),
                                    winproxy.resolve(winproxy.SymGetModuleBase64),
                                    None,
                                    0)
            except WindowsError as e:
                if not e.winerror:
                    return # No_ERROR -> end of stack walking
                raise
            yield type(frame).from_buffer_copy(frame) # Make a copy ?

    def __iter__(self):
        return self._stack_frame_generator()

    # Autorise to force the retrieving of 32b stack when code is currently on 64b code ?
    def _get_effective_context_and_machine(self):
        ctx = self.context or self.thread.context
        if self.process.bitness == 32:
            # Process is 32b, so the context is inevitably x86
            return (ctx, gdef.IMAGE_FILE_MACHINE_I386)
        if windows.current_process.bitness == 32:
            # If we are 32b, we will only be able to handle x86 stack
            # ctx is obligatory a 32b one, as the case us32/target64 is handled
            # in __init__ with a NotImplementedError
            return (ctx, gdef.IMAGE_FILE_MACHINE_I386)
        if self.process.bitness == 64:
            # Process is 64b, so the context is inevitably x64
            return (ctx, gdef.IMAGE_FILE_MACHINE_AMD64)
        # Thing get a little more complicated here :)
        # We are a 64b process and target is 32b.
        # So we must find-out if we are in 32 or 64b world at the moment.
        # The context_syswow.SegCS give us the information
        # The context32.SegCs would be always 32
        ctxsyswow = dbg.current_thread.context_syswow
        if ctxsyswow.SegCs == gdef.CS_USER_32B:
            return (ctx, gdef.IMAGE_FILE_MACHINE_I386)
        return (ctxsyswow, gdef.IMAGE_FILE_MACHINE_AMD64)

    def _setup_initial_frame_from_context(self, ctx, machine):
        frame = gdef.STACKFRAME_EX()
        frame.AddrPC.Mode = gdef.AddrModeFlat
        frame.AddrFrame.Mode = gdef.AddrModeFlat
        frame.AddrStack.Mode = gdef.AddrModeFlat
        frame.AddrPC.Offset = ctx.pc
        frame.AddrStack.Offset = ctx.sp
        if machine == gdef.IMAGE_FILE_MACHINE_I386:
            frame.AddrFrame.Offset = ctx.Ebp
        # Need RBP on 64b ?
        return frame






class VirtualSymbolHandler(SymbolHandler):
    """A SymbolHandler where its handle is not a valid process handle
    Allow to create/resolve symbol in a 'virtual' process
    But all API needing a real process handle will fail
    """
    VIRTUAL_HANDLER_COUNTER = itertools.count(0x11223344)
    def __init__(self, search_path=None):
        handle = next(self.VIRTUAL_HANDLER_COUNTER)
        super(VirtualSymbolHandler, self).__init__(handle, search_path, False)

    # The VirtualSymbolHandler is not based on an existing process
    # So load() in its simplest for should just take the path of the file to load
    load = SymbolHandler.load_file

    def refresh(self):
        # Do nothing on a VirtualSymbolHandler
        return False


class ProcessSymbolHandler(SymbolHandler):
    def __init__(self, process, search_path=None, invade_process=False):
        super(ProcessSymbolHandler, self).__init__(process.handle, search_path, invade_process)
        self.target = process

    # The ProcessSymbolHandler is based on an existing process
    # So load() in its simplest form should be able to load the symbol for an existing
    # module that is already loaded
    # Question: should be able to load other module at other address ?
    def load(self, name):
        mods = [x for x in self.target.peb.modules if x.name == name]
        if not mods:
            raise ValueError("Could not find module <{0}>".format(name))
        assert len(mods) == 1 # Load all if multiple match ?
        mod = mods[0]
        return self.load_module(addr=mod.baseaddr, path=mod.fullname)

    def refresh(self):
        return windows.winproxy.SymRefreshModuleList(self.handle)


    def stackwalk(self, ctx):
        pass


class SymbolEngine(object):
    def set_options(self, options):
        return windows.winproxy.SymSetOptions(options)

    def get_options(self):
        return windows.winproxy.SymGetOptions()

    options = property(get_options, set_options)

engine = SymbolEngine()

TST_TYPE_RES_TYPE = {
    gdef.TI_GET_SYMNAME: gdef.LPWSTR,
    gdef.TI_GET_LENGTH: gdef.ULONG64,
    gdef.TI_GET_ADDRESS: gdef.ULONG64,
    gdef.TI_GTIEX_REQS_VALID: gdef.ULONG64,
    gdef.TI_GET_SYMTAG: gdef.SymTagEnum,
}


# class ProcessSymbolResolver(SymbolResolver):

    # def load_all(self):
        # result = []
        # for mod in self.target.peb.modules:
            # try:
                # result.append(self.load_module(BaseOfDll=mod.baseaddr, ImageName=mod.fullname))
            # except WindowsError as e:
                # # Already loaded: ignore the error
                # if e.winerror == gdef.ERROR_SUCCESS:
                    # continue
        # return result


