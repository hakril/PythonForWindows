import pytest
import windows
import time
import weakref

from .conftest import pop_proc_32, pop_proc_64

@pytest.fixture(params=[None, pop_proc_32, pop_proc_64], ids=["local-pe", "remote-pe32", "remote-pe64"])
def pe(request):
    # Pe will be kernelbase.dll
    if request.param is None:
        yield windows.current_process.peb.modules[2].pe
        return

    pop_proc = request.param
    proc = pop_proc()
    time.sleep(0.01)
    yield proc.peb.modules[2].pe
    proc.exit(0)



def test_pe_imports(pe):
    imports = pe.imports
    assert imports
    assert "ntdll.dll" in imports
    assert "NtCreateFile" in [x.name for x in imports["ntdll.dll"]]

def test_pe_exports(pe):
    exports = pe.exports
    assert "CreateFileA" in pe.exports

def test_pe_exports_name(pe):
    assert "kernel" in pe.export_name.lower()

def test_pe_sections(pe):
    sections_names = [s.name for s in pe.sections]
    assert ".text" in sections_names


