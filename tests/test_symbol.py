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
    mod = symctx.load_file(path=r"c:\windows\system32\ntdll.dll", addr=0x42000)
    assert mod.addr == 0x42000
    # Resolve by name
    createfile = symctx[b"ntdll!NtCreateFile"]
    # Resolve by addr
    assert symctx[createfile.addr].name in (b"NtCreateFile", b"ZwCreateFile")