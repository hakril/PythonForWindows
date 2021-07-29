import pytest
import time
import zlib
import ctypes
import windows

from .conftest import pop_proc_32, pop_proc_64
from .pfwtest import *

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


# This is a PE build with LIEF & containing a somewhat strange OptionalHeader which is
# not sizeof(IMAGE_OPTIONAL_HEADER32) nor sizeof(IMAGE_OPTIONAL_HEADER64)
# Its sizeof(IMAGE_OPTIONAL_HEADER32)+8 (0xd8) indicating  a "hole" between data directory & the sections header
# The building script is build_pe_strange_optionalheader_size.py

strange_optional_header_size_pe = b"""eJzzjZrAwMzAwMACxP//MzDsYIAABwbC4AMRagYbCHBlYPBhZEYRu8HAxMjNyMnAwMQAwSAgAMUK
II4DhA2UY4VKw2hwQLFAmBBTFSBqQYQAwig4MECyg4ogAGiuMRZxvZLUihIQg5EB7gcGNlQ1CgwM
CXopiSWJQLY2VACsjgNVnQMDwwG9HEMIByQP8wsXhnkPyPTGKBgFo4COoPNp4xtQ2ZDx9T8QiNoY
ODD01qhwZIDkwjNApUEGg4IDQ8B/UQegVOebwxOGFxjg4B9w4JGak5OvUJ5flJOikFaUn6uQqBBQ
WZKRn+eWXxSemZeSX16sUJJaXKIAqjhHwbADGgYIdhOQbWOAXR2ofZEAxDlAXGGAW4yBwT21JLgk
xSMxLyUnFcQPL8osSXXLBHOCUhNToEwGYOpyrUhNZshOLcpLzTE20kvJyaGRJ0cBTgAAMrq98g=="""


def test_pe_parsing_strange_optional_header_size(tmp_path, proc32):
    pe_path = (tmp_path / "pe_strange_optionalheader_size.exe")
    pe_data = zlib.decompress(b64decode(strange_optional_header_size_pe))

    with pe_path.open("wb") as f:
        f.write(pe_data)

    mod = proc32.load_library(str(pe_path))
    # Check imports (This data directory retrieval) works
    assert mod.pe.imports
    assert set(imp.name for imp in mod.pe.imports["kernel32.dll"]) == {'WriteFile', 'WinExec', 'GetStdHandle', 'ReadFile'}
    # Also check that section retrieval works (as its position is based on OptionalHeader Size)
    assert set(s.name for s in mod.pe.sections) == {".text", ".data", ".l1"}

#  Make a test from current_process parsing ?
def test_pe_parsing_dotnet_32_process_64(proc64):
    # .NET pe32 loadable in 64bit process -> rewrite of the OptionalHeader
    mod = proc64.load_library(r"C:\Windows\System32\stordiag.exe")
    # It was a PE32
    assert mod.pe.get_NT_HEADER().FileHeader.Machine == gdef.IMAGE_FILE_MACHINE_I386
    # Now Optional Header should be 64b
    opt_hdr = mod.pe.get_OptionalHeader()
    assert mod.pe.get_NT_HEADER().FileHeader.SizeOfOptionalHeader == ctypes.sizeof(gdef.IMAGE_OPTIONAL_HEADER64)
    assert mod.pe.get_OptionalHeader().Magic == gdef.IMAGE_NT_OPTIONAL_HDR64_MAGIC
    # Check imports (This data directory retrieval) works
    assert mod.pe.imports
    assert mod.pe.imports["mscoree.dll"][0].name == "_CorExeMain"
    # Also check that section retrieval works (as its position is based on OptionalHeader Size)
    assert mod.pe.sections
    assert ".text" in  set(s.name for s in mod.pe.sections)

def test_pe_parsing_dotnet_32_current_process_64(proc64):
    # .NET pe32 loadable in 64bit process -> rewrite of the OptionalHeader
    # So we injecte python code in a the remote proc64 to test the parsing from itself

    PIPE_NAME = "PFW_TEST_Pipe"
    rcode = r"""import sys; import windows; import windows.pipe; windows.pipe.send_object("{pipe}", )"""

    mod = proc64.load_library(r"C:\Windows\System32\stordiag.exe")
    assert proc64.peb.modules[-1].name == "stordiag.exe"
    proc64.execute_python("import sys; import windows; import windows.pipe")
    with windows.pipe.create(PIPE_NAME) as np:
        proc64.execute_python("""pemod = [x for x in windows.current_process.peb.modules if x.name == 'stordiag.exe'][0].pe""")
        rcode = """windows.pipe.send_object("{pipe}", (list(pemod.imports), [sec.name for sec in pemod.sections]))"""
        proc64.execute_python(rcode.format(pipe=PIPE_NAME))
        imported_dlls, sections_names = np.recv()
        assert imported_dlls == ['mscoree.dll']
        assert ".text" in  sections_names
