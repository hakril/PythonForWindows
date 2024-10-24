import pytest

import windows.generated_def as gdef
import windows.debug.symbols as symbols
from .pfwtest import *


@pytest.fixture()
def symctx():
    yield symbols.VirtualSymbolHandler()

# Disable defered loading
# symbols.engine.options = gdef.SYMOPT_UNDNAME

def test_symbols_loadfile(symctx):
    mod = symctx.load_file(path=u"c:\\windows\\system32\\ntdll.dll", addr=0x42000)
    assert mod.addr == 0x42000
    # Resolve by name
    createfile = symctx[u"ntdll!NtCreateFile"]
    # Resolve by addr
    assert symctx[createfile.addr].name in (u"NtCreateFile", u"ZwCreateFile")


def test_symbols_module_info(symctx):
    mod = symctx.load_file(path=u"c:\\windows\\system32\\ntdll.dll", addr=0x42000)
    assert mod.name == u"ntdll" # SymGetModuleInfo64
    assert symctx.modules[0].name == u"ntdll" # SymEnumerateModules64

def test_symbols_search(symctx):
    mod = symctx.load_file(path=u"c:\\windows\\system32\\ntdll.dll", addr=0x42000)
    res = symctx.search(u"ntdll!*CreateFile")
    assert set(s.name for s in res) >= {"NtCreateFile", "ZwCreateFile"} # May have other names


def test_symbols(symctx):
    mod = symctx.load_file(path=u"c:\\windows\\system32\\ntdll.dll", addr=0x42000)
    createfile = symctx[u"ntdll!NtCreateFile"]
    res = symctx.get_symbols(int(createfile))
    assert set(s.name for s in res) == {"NtCreateFile", "ZwCreateFile"}
    print("LOL")

# TO test:

# SymbolInfoBase / SymbolType / get_type