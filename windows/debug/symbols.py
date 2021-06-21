import os.path
import ctypes
import copy
import itertools
from collections import namedtuple

import windows
import windows.generated_def as gdef
from windows import winproxy
from windows.pycompat import basestring

DEFAULT_DBG_OPTION = gdef.SYMOPT_DEFERRED_LOADS + gdef.SYMOPT_UNDNAME


def set_dbghelp_path(path):
    """Set the path of the ``dbghelp.dll`` file to use. It allow to configure a different version of the DLL handling PDB downloading.

    If ``path`` is a directory, the final ``dbghelp.dll`` will be computed as
    ``path\<current_process_bitness>\dbghelp.dll``.

    This allow to use the same script transparently in both 32b & 64b python interpreters.
    """
    loaded_modules =  [m.name.lower() for m in windows.current_process.peb.modules]
    if os.path.isdir(path):
        path = os.path.join(path, str(windows.current_process.bitness), "dbghelp.dll")
    if "dbghelp.dll" in loaded_modules:
        raise ValueError("setup_dbghelp_path should be called before any dbghelp function")
    # Change the DLL used by DbgHelpProxy
    winproxy.DbgHelpProxy.APIDLL = path
    return

# Load symbol config from ENV if present
try:
    env_dbghelp_path = os.environ["PFW_DBGHELP_PATH"]
    # Setup the dbghelp path used by PFW
    set_dbghelp_path(env_dbghelp_path)
except KeyError as e:
    pass



class SymbolInfoBase(object):
    """Represent a Symbol.
    This class in based on the class `SYMBOL_INFO <https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-symbol_info>`_
    with the handling on displacement embeded into it.
    """
    # Init on ctypes struct is not always called
    # resolver & displacement should be set manually
    CHAR_TYPE = None

    def __init__(self, *args, **kwargs):
        self.resolver = kwargs.get("resolver", None)
        #: POUET POUET
        self.displacement = kwargs.get("displacement", 0) #: POUET POUET


    def as_type(self):
        # assert self.Address == 0 ?
        return SymbolType(self.Index, self.ModBase, self.resolver)

    @property
    def name(self):
        """The name of the symbol"""
        if not self.NameLen:
            return None
        size = self.NameLen
        addr = ctypes.addressof(self) + type(self).Name.offset
        return (self.CHAR_TYPE * size).from_address(addr)[:]

    @property
    def fullname(self):
        """The fullname of the symbol in the windbg format ``mod!sym+displacement``"""
        return str(self)

    @property
    def addr(self):
        """The address of the symbol"""
        return self.Address + self.displacement

    @property
    def start(self):
        """The address of the start of the symbol
        If the symbol include a displacement, it is not taken into account
        """
        return self.Address

    @property # Fixed ?
    def module(self):
        """The module containing the symbol

        :type: :class:`SymbolModule`
        """
        return self.resolver.get_module(self.ModBase)

    @property
    def tag(self):
        """The Tag of the module

        :type: :class:`~windows.generated_def.winstructs.SymTagEnum`
        """
        return gdef.SymTagEnum.mapper[self.Tag]

    def __int__(self):
        """An alias for ``addr``"""
        return self.addr

    def __str__(self):
        """The fullname of the symbol in the windbg format ``mod!sym+displacement``"""
        if self.displacement:
            return "{self.module.name}!{self.name}+{self.displacement:#x}".format(self=self)
        return "{self.module.name}!{self.name}".format(self=self)

    def __repr__(self):
        if self.displacement:
            return '<{0} name="{1}" start={2:#x} displacement={3:#x} tag={4}>'.format(type(self).__name__, self.name, self.start, self.displacement, self.tag.name)
        return '<{0} name="{1}" start={2:#x} tag={3}>'.format(type(self).__name__, self.name, self.start, self.tag.name)


class SymbolInfoA(gdef.SYMBOL_INFO, SymbolInfoBase):
    """Represent a Symbol.
    This class in based on the class `SYMBOL_INFO <https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-symbol_info>`_
    with the handling on displacement embeded into it.s

    Exemple:

        >>> sh = windows.debug.symbols.VirtualSymbolHandler()
        >>> mod = sh.load_file(r"c:\windows\system32\kernelbase.dll")
        >>> sym1 = sh["kernelbase!CreateFileW"]
        >>> sym2 = sh[int(sym1) + 3]
        >>> sym2
        <SymbolInfoA name="CreateFileW" start=0x100f20b0 displacement=0x3 tag=SymTagPublicSymbol>
        >>> hex(sym2.start)
        '0x100f20b0L'
        >>> hex(sym2.addr)
        '0x100f20b3L'
        >>> hex(sym2.displacement)
        '0x3L'
        >>> str(sym2)
        'kernelbase!CreateFileW+0x3'
    """
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
    def parent(self):
        return self.new_typeid(self._get_type_info(gdef.TI_GET_CLASSPARENTID))

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
    def value(self):
        return self._get_type_info(gdef.TI_GET_VALUE)

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
            return '<{0} <basetype> {1!r}>'.format(type(self).__name__, self.basetype)
        elif self.tag == gdef.SymTagPointerType:
            target_type = self.type.name
            return '<{0} PTR TO "{1}" tag={2}>'.format(type(self).__name__, target_type, self.tag)
        return '<{0} name="{1}" tag={2}>'.format(type(self).__name__, self.name, self.tag)


class SymbolModule(gdef.IMAGEHLP_MODULE64):
    """Represent a loaded symbol module
    (see `MSDN IMAGEHLP_MODULE64 <https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-imagehlp_module64>`_)

    .. note::

        This represent a module in the ``symbol space`` for symbol resolution.
        This can be completly virtual (particularly in the case of :class:`VirtualSymbolHandler`
    """
    # Init on ctypes struct is not always called
    # resolver should be set manually
    def __init__(self, resolver):
        self.resolver = resolver

    @property
    def addr(self):
        """The load address of the module"""
        return self.BaseOfImage

    @property
    def name(self):
        """The name of the module"""
        return self.ModuleName

    @property
    def path(self):
        """The full path and file name of the file from which symbols were loaded."""
        return self.LoadedImageName

    @property
    def type(self):
        """The type of module (:class:`~windows.generated_def.winstructs.SYM_TYPE`),
        which can be one of:

            =========== =========================
            SymCoff     COFF symbols.
            SymCv       CodeView symbols.
            SymDeferred Symbol loading deferred.
            SymDia      DIA symbols.
            SymExport   Symbols generated from a DLL export table.
            SymNone     No symbols are loaded.
            SymPdb      PDB symbols.
            SymSym      .sym file.
            SymVirtual  The virtual module created by SymLoadModuleEx with SLMFLAG_VIRTUAL.
            =========== =========================
        """
        return self.SymType

    @property
    def pdb(self):
        """The local path of the loaded PDB if present

        Exemple:
            >>> sh = windows.debug.symbols.VirtualSymbolHandler()
            >>> mod = sh.load_file(r"c:\windows\system32\kernelbase.dll")
            >>> mod.pdb
            'd:\\symbols\\wkernelbase.pdb\\017FA9C5278235B7E6BFBA74A9A5AAD91\\wkernelbase.pdb'
        """
        LoadedPdbName = self.LoadedPdbName
        if not LoadedPdbName:
            return None
        return LoadedPdbName

    def __repr__(self):
        pdb_basename = self.LoadedPdbName.split(b"\\")[-1]
        return '<{0} name="{1}" type={2} pdb="{3}" addr={4:#x}>'.format(type(self).__name__, self.name, self.type.value.name, pdb_basename, self.addr)


# https://docs.microsoft.com/en-us/windows/win32/debug/symbol-handler-initialization
class SymbolHandler(object):
    """Base class of symbol handler"""

    def __init__(self, handle, search_path=None, invade_process=False):
        # https://docs.microsoft.com/en-us/windows/desktop/api/dbghelp/nf-dbghelp-syminitialize
        # This value should be unique and nonzero, but need not be a process handle.
        # be sure to use the correct handle.
        self.handle = handle #: The handle of the symbol handler
        if not engine.options_already_setup:
            engine.set_options(DEFAULT_DBG_OPTION)
        winproxy.SymInitialize(handle, search_path, invade_process)


    def load_module(self, file_handle=None, path=None, name=None, addr=0, size=0, data=None, flags=0):
        """Load a module at a given ``addr``. The module to load can be pass via a ``file_handle``
        or the direct ``path`` of the file to load.

        :return: :class:`SymbolModule` -- The loaded module

        .. note::

            The logic of ``SymLoadModuleEx`` seems somewhat strange about the naming of the loaded module.
            A custom module ``name`` is only taken into account if the file is passed via a File handle.
            To make it more intuitive, if this function is call with a ``path`` and ``name`` and no ``file_handle``,
            it will open the path and directly call ``SymLoadModuleEx`` with a file handle and a name.
        """

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
        # Expect a-string
        path = windows.pycompat.raw_encode(path)
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
        """Load the module ``path`` at ``addr``

        :return: :class:`SymbolModule` -- The loaded module
        """
        return self.load_module(path=path, name=name, addr=addr, size=size, data=data, flags=flags)

    def unload(self, addr):
        """Unload the module at ``addr``"""
        return winproxy.SymUnloadModule64(self.handle, addr)


    @staticmethod
    @ctypes.WINFUNCTYPE(gdef.BOOL, gdef.PCSTR, gdef.DWORD64, ctypes.py_object)
    def modules_aggregator(modname, modaddr, ctx):
        ctx.append(modaddr)
        return True

    @property
    def modules(self):
        """The list of loaded modules

        :return: [:class:`SymbolModule`] -- A list of modules
        """
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


    def symbol_from_name(self, name):
        max_len_size = 0x1000
        full_size = ctypes.sizeof(SymbolInfo) + (max_len_size - 1)
        buff = windows.utils.BUFFER(SymbolInfo)(size=full_size)
        sym = buff[0]
        sym.SizeOfStruct = ctypes.sizeof(SymbolInfo)
        sym.MaxNameLen  = max_len_size
        # Expect a-string
        name = windows.pycompat.raw_encode(name)
        windows.winproxy.SymFromName(self.handle, name, buff)
        sym.resolver = self
        sym.displacement = 0
        return sym

    def resolve(self, name_or_addr):
        """Resolve ``name_or_addr``.

        If its an int -> Return the :class:`SymbolInfo` at the address.
        If its a string -> Return the :class:`SymbolInfo` corresponding to the symbol name

        :return: :class:`SymbolInfo`

        .. note::

            ``__getitem__`` is an alias for ``resolve()``

        Exemple:

            >>> sh = windows.debug.symbols.VirtualSymbolHandler()
            >>> mod = sh.load_file(r"c:\windows\system32\kernelbase.dll")
            >>> mod
            <SymbolModule name="kernelbase" type=SymPdb pdb="wkernelbase.pdb" addr=0x10000000>
            >>> sh.resolve("kernelbase!CreateFileInternal")
            <SymbolInfoA name="CreateFileInternal" addr=0x100f2120 tag=SymTagFunction>
            >>> sh[0x100f2042]
            <SymbolInfoA name="ReadFile" addr=0x100f1ee0 displacement=0x162 tag=SymTagFunction>
            >>> str(sh[0x100f2042])
            'kernelbase!ReadFile+0x162'
        """
        # Only returns None if symbol is not Found ?
        if isinstance(name_or_addr, windows.pycompat.anybuff):
            return self.symbol_from_name(name_or_addr)
        try:
            return self.symbol_and_displacement_from_address(name_or_addr)
        except WindowsError as e:
            if e.winerror != gdef.ERROR_MOD_NOT_FOUND:
                raise
            # We could not resolve and address -> return None
            return None

    __getitem__ = resolve
    """Alias to resolve for simpler use"""

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
        """Search the symbols matching ``mask`` (``Windbg`` like).

        :return: [:class:`SymbolInfo`] -- A list of :class:`SymbolInfo`

        >>> sh = windows.debug.symbols.VirtualSymbolHandler()
        >>> mod = sh.load_file(r"c:\windows\system32\kernelbase.dll")
        >>> sh.search("kernelbase!CreateFile*")
        [<SymbolInfoA name="CreateFileInternal" addr=0x100f2120 tag=SymTagFunction>,
            <SymbolInfoA name="CreateFileMoniker" addr=0x10117d80 tag=SymTagFunction>,
            <SymbolInfoA name="CreateFile2" addr=0x1011e690 tag=SymTagFunction>,
            ...]
        """
        res = []
        if callback is None:
            callback = self.simple_aggregator
        else:
            callback = ctypes.WINFUNCTYPE(gdef.BOOL, ctypes.POINTER(SymbolInfo), gdef.ULONG , ctypes.py_object)(callback)

        addr = getattr(mod, "addr", mod) # Retrieve mod.addr, else us the value directly
        # Expect A-string
        mask = windows.pycompat.raw_encode(mask)
        windows.winproxy.SymSearch(self.handle, gdef.DWORD64(addr), 0, tag, mask, 0, callback, res, options)
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


# TODO: mets de l'huile pour w4kfu
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
    """An alias for :func:`VirtualSymbolHandler.load_file`"""

    def refresh(self):
        """Do nothing for a :class:`VirtualSymbolHandler`"""
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
        """Load the :class:`SymbolModule` associated with the loaded module ``name`` (as found in the PEB)

        :return: :class:`SymbolModule`

        Exemple:

            >>> sh = windows.debug.symbols.ProcessSymbolHandler(windows.test.pop_proc_64())
            <windows.debug.symbols.ProcessSymbolHandler object at 0x033A2C30>
            >>> sh
            <windows.debug.symbols.ProcessSymbolHandler object at 0x033A2C30>
            >>> sh.load("kernelbase.dll")
            <SymbolModule name="kernelbase" type=SymDeferred pdb="" addr=0x7ffb5b090000>
            >>> sh["kernelbase!CreateProcessA"]
            <SymbolInfoA name="CreateProcessA" start=0x7ffb5b2371f0 tag=SymTagPublicSymbol>
        """
        mods = [x for x in self.target.peb.modules if x.name == name]
        if not mods:
            raise ValueError("Could not find module <{0}>".format(name))
        assert len(mods) == 1 # Load all if multiple match ?
        mod = mods[0]
        return self.load_module(addr=mod.baseaddr, path=mod.fullname)

    def refresh(self):
        """Update the list of loaded modules to match the modules present in the target process

        .. note::
            This function only call `SymRefreshModuleList <https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symrefreshmodulelist>`_ for now.
            It seems that this function do not handle refreshing a 64b target from a 32b python

            Also, on a 32b target from a 64b python it seems to only load symbols for the 64b modules (ntdll + syswow dll)

        Exemple:

            >>> sh = windows.debug.symbols.ProcessSymbolHandler(windows.test.pop_proc_64())
            >>> sh.modules
            []
            >>> sh.refresh()
            44
            >>> sh.modules
            [<SymbolModule name="notepad" type=SymDeferred pdb="" addr=0x7ff772b80000>,
                <SymbolModule name="ntdll" type=SymDeferred pdb="" addr=0x7ffb5d860000>,
                <SymbolModule name="KERNEL32" type=SymDeferred pdb="" addr=0x7ffb5bb90000>,
                <SymbolModule name="KERNELBASE" type=SymDeferred pdb="" addr=0x7ffb5b090000>,
                ...]
        """
        return windows.winproxy.SymRefreshModuleList(self.handle)


    def stackwalk(self, ctx):
        pass


class SymbolEngine(object):
    """Represent the global symbol engine. Just a proxy to get/set global engine options

    Its instance can be accessed using ``windows.debug.symbols.engine``

    Exemple:

        >>> windows.debug.symbols.engine.options
        6L
        >>> windows.debug.symbols.engine.options = gdef.SYMOPT_UNDNAME
        >>> windows.debug.symbols.engine.options
        2L

    """
    def __init__(self):
        # use to now if we need to call the setup of options
        # At the first DbgHelp call
        self.options_already_setup = False

    def set_options(self, options):
        self.options_already_setup = True
        return windows.winproxy.SymSetOptions(options)

    def get_options(self):
        return windows.winproxy.SymGetOptions()

    options = property(get_options, set_options)
    """The options of the Symbol engine
    (`see options <https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symsetoptions#parameters>`_)

    .. note::

        Default options are: ``gdef.SYMOPT_DEFERRED_LOADS + gdef.SYMOPT_UNDNAME``
    """

engine = SymbolEngine()
"""The instance of the :class:`SymbolEngine`"""


TST_TYPE_RES_TYPE = {
    gdef.TI_GET_SYMNAME: gdef.LPWSTR,
    gdef.TI_GET_LENGTH: gdef.ULONG64,
    gdef.TI_GET_ADDRESS: gdef.ULONG64,
    gdef.TI_GTIEX_REQS_VALID: gdef.ULONG64,
    gdef.TI_GET_SYMTAG: gdef.SymTagEnum,
    gdef.TI_GET_VALUE: windows.com.Variant,
}
