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

    for i in range(10):
        try:
            time.sleep(0.1)
            yield proc.peb.modules[2].pe
            break
        except ValueError:
            if i == 9:
                # Last change failed
                raise
            continue # PEB.Ldr not ready yet
    proc.exit(0)

PE_DOTNET32_DLL_NAME = "test_pe_dotnet32.dll"

@pytest.fixture(scope="session")
def pe_dotnet32(tmpdir_factory):
    tmpdir = tmpdir_factory.mktemp("pe_dotnet32_test_dir")
    pe_dotnet32_data = zlib.decompress(b64decode(PE_DOTNET32_DLL_BASE64))
    fullpath = str(tmpdir.join(PE_DOTNET32_DLL_NAME))
    with open(fullpath, "wb") as f:
        f.write(pe_dotnet32_data)

    try:
        yield fullpath
    finally:
        try:
            os.unlink(fullpath)
        except WindowsError as e:
            pass # Ignore delete fail, may happend if injected process is cleaned after the dll..

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

@dll_injection
def test_pe_parsing_dotnet32_process_64(proc64, pe_dotnet32):
    # .NET pe32 loadable in 64bit process -> rewrite of the OptionalHeader
    mod = proc64.load_library(pe_dotnet32)
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

@dll_injection
def test_pe_parsing_dotnet32_current_process_64(proc64, pe_dotnet32):
    # .NET pe32 loadable in 64bit process -> rewrite of the OptionalHeader
    # So we injecte python code in a the remote proc64 to test the parsing from itself
    PIPE_NAME = "PFW_TEST_Pipe"
    mod = proc64.load_library(pe_dotnet32)
    assert proc64.peb.modules[-1].name == PE_DOTNET32_DLL_NAME
    proc64.execute_python("import sys; import windows; import windows.pipe")
    proc64.execute_python("""pemod = [x for x in windows.current_process.peb.modules if x.name == '{0}'][0].pe""".format(PE_DOTNET32_DLL_NAME))
    with windows.pipe.create(PIPE_NAME) as np:
        rcode = """windows.pipe.send_object("{pipe}", (list(pemod.imports), [sec.name for sec in pemod.sections]))"""
        proc64.execute_python(rcode.format(pipe=PIPE_NAME))
        imported_dlls, sections_names = np.recv()
        assert imported_dlls == ['mscoree.dll']
        assert ".text" in  sections_names

# PE header of Syschpe32\ntdll.dll with a 8 chars sections .hexpthk that broke the parseur
# This PE as 8 bytes sections name + VirtualSize non aligned on 0x100 so there is a non-null non-ascii byte after the name
PE_SECTION_8CHARS = b"""
eJzzjZrAwMzAwMACxP//MzDsYIAABwbC4AMRagYbCHBlYPBhZEYRu8HAxMjNyMnAwMQAwSAgAMUK
II4DhA2UY4VKw2hwQLFAmBBTFSBqQYQAwig4MECyg4ogAGiuMRZxvQgIuMDIAPcDAxuqGgUGhgS9
SAjQhgqA1XGgqnNgYDigFwUBYHmYX7gwzHtAmW9GwSgYBfQAnU8b3zAAy4aMr/+BQNTGwIGht0aF
IwMkF54BKg0yGBQcGAL+izoApTrfHJ4wvMAAB/+AA4/UnJx8hfL8opwUhbSi/FyFRIWAypKM/Dy3
/KLwzLyU/PJihZLU4hIFUMU5CoYd0DBAsJuAbBsD7OpA7YsEIM4B4goD3GIMDO6pJcElKR6JeSk5
qSB+eFFmSapbJpgTlJqYAmUyAFOXa0VqMkN2alFeao6xkV5KTg6NPDkKcAIAM7/CEw=="""

def test_pe_parsing_section_8_chars(proc32, tmp_path):
    pe_path = (tmp_path / "pe_parsing_8chars_section.exe")
    pe_data = pe_data = zlib.decompress(b64decode(PE_SECTION_8CHARS))

    with pe_path.open("wb") as f:
        f.write(pe_data)

    mod = proc32.load_library(str(pe_path))
    # check that section retrieval works
    assert set(s.name for s in mod.pe.sections) == {u".XXXXXXX", u".YYYYYYY", u".ZZZZZZZ"}

# A "Portable Executable 32 .NET Assembly" DLL
# Result of compiling a simple hello-world
# Can be loaded into a 64b process to witness 32 -> 64b PE conversion at load time
PE_DOTNET32_DLL_BASE64 = b"""
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
"""