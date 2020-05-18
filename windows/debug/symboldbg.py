import windows
import windows.generated_def as gdef
from windows.pycompat import int_types

from . import Debugger
from . import symbols

class SymbolDebugger(Debugger):
    """A debugger using the symbol API (hence PDB) for name resolution.
    To use PDB, a correct version of dbghelp should be configured as well as ``_NT_SYMBOL_PATH``.
    (See :ref:`debug_symbols_module`)

    This debugger add a ``current_resolver`` variable (A :class:`~windows.debug.symbols.ProcessSymbolHandler`) for the ``current_process``.
    """
    def __init__(self, *args, **kwargs):
        super(SymbolDebugger, self).__init__(*args, **kwargs)
        self._resolvers = {}

    def _internal_on_load_dll(self, load_dll):
        path = self._get_loaded_dll(load_dll)
        # Path is used instead of name for naming the module (and can be set to whatever if using file handle)
        x = self.current_resolver.load_module(load_dll.hFile, path=path, addr=load_dll.lpBaseOfDll)

    def _internal_on_create_process(self, create_process):
        # Create and setup a symbol resolver for the new process
        resolver = symbols.ProcessSymbolHandler(self.current_process)
        self._resolvers[self.current_process.pid] = resolver
        self.current_resolver = resolver

    def _update_debugger_state(self, debug_event):
        super(SymbolDebugger, self)._update_debugger_state(debug_event)
        self.current_resolver = self._resolvers[debug_event.dwProcessId]

    def _resolve(self, addr, target):
        if isinstance(addr, int_types):
            return addr
        if "+" in addr:
            symbol, deplacement = addr.split("+", 1)
            deplacement = int(deplacement, 0)
        else:
            symbol = addr
            deplacement = 0
        try:
            return self.current_resolver[symbol].addr + deplacement
        except WindowsError as e:
            if not e.winerror in (gdef.ERROR_NOT_FOUND, gdef.ERROR_MOD_NOT_FOUND):
                raise
            return None