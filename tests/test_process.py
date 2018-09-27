import pytest

import os
import sys
import time
import struct
import textwrap
import shutil

import windows
import windows.generated_def as gdef
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

from pfwtest import *

@check_for_gc_garbage
class TestCurrentProcessWithCheckGarbage(object):
    def test_current_process_ppid(self):
        myself = [p for p in windows.system.processes if p.pid == windows.current_process.pid][0]
        assert myself.ppid == windows.current_process.ppid

    def test_get_current_process_peb(self):
        return windows.current_process.peb

    def test_get_current_process_modules(self):
        # Use sys.executable because executable can be a PyInstaller exe
        assert os.path.basename(sys.executable) in windows.current_process.peb.modules[0].name

    def test_get_current_process_exe(self):
        exe = windows.current_process.peb.exe
        exe_by_module = windows.current_process.peb.modules[0].pe
        exe.baseaddr == exe_by_module.baseaddr
        exe.bitness ==  exe_by_module.bitness

    def test_current_process_pe_imports(self):
        python_module = windows.current_process.peb.modules[0]
        imp = python_module.pe.imports
        assert "kernel32.dll" in imp.keys(), 'Kernel32.dll not in python imports'
        current_proc_id_iat = [f for f in imp["kernel32.dll"] if f.name == "GetCurrentProcessId"][0]
        k32_base = windows.winproxy.LoadLibraryA("kernel32.dll")
        assert windows.winproxy.GetProcAddress(k32_base, "GetCurrentProcessId") == current_proc_id_iat.value

    def test_current_process_pe_exports(self):
        mods = [m for m in windows.current_process.peb.modules if m.name == "kernel32.dll"]
        assert mods, 'Could not find "kernel32.dll" in current process modules'
        k32 = mods[0]
        get_current_proc_id = k32.pe.exports['GetCurrentProcessId']
        k32_base = windows.winproxy.LoadLibraryA("kernel32.dll")
        assert windows.winproxy.GetProcAddress(k32_base, "GetCurrentProcessId") ==  get_current_proc_id

    def test_local_process_pe_sections(self):
        mods = [m for m in windows.current_process.peb.modules if m.name == "kernel32.dll"]
        assert mods, 'Could not find "kernel32.dll" in current process modules'
        k32 = mods[0]
        sections = k32.pe.sections
        all_sections_name = [s.name for s in sections]
        assert ".text" in  all_sections_name
        sections[0].start
        sections[0].size

    def test_token_info(self):
        token = windows.current_process.token
        assert isinstance(token.computername, basestring)
        assert isinstance(token.username, basestring)
        assert isinstance(token.integrity, (int, long))
        assert isinstance(token.is_elevated, (bool))

    def test_local_ProcessParameters_LSA_UNICODE_STRING(self):
        image_path_from_process_params = windows.current_process.peb.ProcessParameters.contents.ImagePathName.str.lower()
        image_path_from_module = windows.current_process.peb.modules[0].fullname.lower()
        assert image_path_from_process_params == image_path_from_module





@check_for_gc_garbage
class TestProcessWithCheckGarbage(object):
    def test_pop_proc_32(self, proc32):
        assert proc32.bitness == 32

    @windows_64bit_only
    def test_pop_proc_64(self, proc64):
         assert proc64.bitness == 64

    def test_process_ppid(self, proc32_64):
        assert proc32_64.ppid ==  windows.current_process.pid

    # Test process read/write

    def test_read_memory(self, proc32_64):
        k32 = [m for m in proc32_64.peb.modules if m.name == "kernel32.dll"][0]
        assert proc32_64.read_memory(k32.baseaddr, 2), "MZ"

    def test_write_memory(self, proc32_64):
        k32 = [m for m in proc32_64.peb.modules if m.name == "kernel32.dll"][0]
        with proc32_64.virtual_protected(k32.baseaddr, 2, gdef.PAGE_EXECUTE_READWRITE):
            proc32_64.write_memory(k32.baseaddr, "XD")
        assert proc32_64.read_memory(k32.baseaddr, 2) ==  "XD"

    def test_read_string(self, proc32_64):
        test_string = "TEST_STRING"
        string_to_write = test_string + "\x00"
        with proc32_64.allocated_memory(0x1000) as addr:
            proc32_64.write_memory(addr, string_to_write)
            assert proc32_64.read_string(addr) ==  test_string

    def test_read_string_end_page(self, proc32_64):
        test_string = "TEST_STRING"
        string_to_write = test_string + "\x00"
        with proc32_64.allocated_memory(0x1000) as addr:
            waddr = addr + 0x1000 - len(string_to_write)
            proc32_64.write_memory(addr, string_to_write)
            assert proc32_64.read_string(addr) ==  test_string


    def test_wread_string(self, proc32_64):
        test_string = "TEST_STRING"
        string_to_write = test_string + "\x00"
        with proc32_64.allocated_memory(0x1000) as addr:
            proc32_64.write_memory(addr, "\x00".join(string_to_write))
            assert proc32_64.read_wstring(addr) ==  test_string

    def test_read_wstring_end_page(self, proc32_64):
        test_string = "TEST_STRING"
        string_to_write = test_string + "\x00"
        with proc32_64.allocated_memory(0x1000) as addr:
            waddr = addr + 0x1000 - len(string_to_write)
            proc32_64.write_memory(addr, "\x00".join(string_to_write))
            assert proc32_64.read_wstring(addr) ==  test_string

    # Test native execution
    def test_execute_to_proc32(self, proc32):
            with proc32.allocated_memory(0x1000) as addr:
                shellcode = x86.MultipleInstr()
                shellcode += x86.Mov('EAX', 0x42424242)
                shellcode += x86.Mov(x86.create_displacement(disp=addr), 'EAX')
                shellcode += x86.Ret()
                proc32.execute(shellcode.get_code())
                time.sleep(0.1)
                dword = proc32.read_dword(addr)
                assert dword == 0x42424242

    @windows_64bit_only
    def test_execute_to_64(self, proc64):
        with proc64.allocated_memory(0x1000) as addr:
            shellcode = x64.MultipleInstr()
            shellcode += x64.Mov('RAX', 0x4242424243434343)
            shellcode += x64.Mov(x64.create_displacement(disp=addr), 'RAX')
            shellcode += x64.Ret()
            proc64.execute(shellcode.get_code())
            time.sleep(0.1)
            qword = proc64.read_qword(addr)
            assert qword == 0x4242424243434343


    @python_injection
    def test_execute_python(self, proc32_64):
        with proc32_64.allocated_memory(0x1000) as addr:
            proc32_64.execute_python('import ctypes; ctypes.c_uint.from_address({0}).value = 0x42424242'.format(addr))
            dword = proc32_64.read_dword(addr)
            assert dword == 0x42424242

    @python_injection
    def test_execute_python_suspended(self, proc32_64_suspended):
        proc = proc32_64_suspended
        with proc.allocated_memory(0x1000) as addr:
            proc.execute_python('import ctypes; ctypes.c_uint.from_address({0}).value = 0x42424242'.format(addr))
            dword = proc.read_dword(addr)
            assert dword ==  0x42424242
            # Check calc32 is still suspended:
                # 1 thread | except windows 10 that pop threads
                # main thread suspend count == 1
            assert proc.threads[0].suspend() ==  1
            if not is_windows_10:
                assert len(proc.threads) ==  1


    # Remote structure parsing

    def test_parse_remote_peb(self, proc32_64):
        # Wait for PEB initialization
        # Yeah a don't know but on 32bits system the parsing might begin before
        # InMemoryOrderModuleList is setup..
        import time; time.sleep(0.1)
        assert proc32_64.peb.modules[0].name == test_binary_name

    @python_injection
    def test_parse_remote_pe(self, proc32_64):
        # Wait for PEB initialization
        # Yeah a don't know but on 32bits system the parsing might begin before
        # InMemoryOrderModuleList is setup..
        import time; time.sleep(0.1)
        mods = [m for m in proc32_64.peb.modules if m.name == "kernel32.dll"]
        assert mods, 'Could not find "kernel32.dll" in calc32'
        k32 = mods[0]
        mods[0].pe.sections[0].name # Just see if it's parse
        assert mods[0].pe.export_name.lower() == "kernel32.dll"
        get_current_proc_id = k32.pe.exports['GetCurrentProcessId']
        # TODO: check get_current_proc_id value (but we cannot do 64->32 injection for now)
        #if is_process_64_bits:
        #    raise NotImplementedError("Python execution 64->32")
        with proc32_64.allocated_memory(0x1000) as addr:
            remote_python_code = """
                                import ctypes
                                import windows
                                # windows.utils.create_console() # remove comment for debug
                                k32 = [m for m in windows.current_process.peb.modules if m.name == "kernel32.dll"][0]
                                GetCurrentProcessId = k32.pe.exports['GetCurrentProcessId']
                                ctypes.c_void_p.from_address({1}).value = GetCurrentProcessId
                                """.format(os.getcwd(), addr)
            x = proc32_64.execute_python(textwrap.dedent(remote_python_code))
            dword = proc32_64.read_ptr(addr)
        assert dword == get_current_proc_id


    def test_remote_peb_exe(self, proc32_64):
        exe = proc32_64.peb.exe
        exe_by_module = proc32_64.peb.modules[0].pe
        assert exe.baseaddr == exe_by_module.baseaddr
        assert exe.bitness == exe_by_module.bitness

    @python_injection
    def test_execute_python_raises(self, proc32_64):
        res = proc32_64.execute_python("import time;time.sleep(0.1); 2")
        assert res == True
        with pytest.raises(windows.injection.RemotePythonError) as ar:
            t = proc32_64.execute_python("import time;time.sleep(0.1); raise ValueError('BYE')")

    def test_thread_start_address(self, proc32_64):
        t = proc32_64.threads[0]
        t.start_address  # No better idea right now that checking for crash/exception


    def test_get_context_address_32(self, proc32):
        code = x86.MultipleInstr()
        code += x86.Mov("EAX", 0x42424242)
        code += x86.Label(":LOOP")
        code += x86.Jmp(":LOOP")
        t = proc32.execute(code.get_code())
        time.sleep(0.5)
        cont = t.context
        assert cont.Eax == 0x42424242

    @windows_64bit_only
    def test_get_context_address_64(self, proc64):
        code = x64.MultipleInstr()
        code += x64.Mov("RAX", 0x4242424243434343)
        code += x64.Label(":LOOP")
        code += x64.Jmp(":LOOP")
        t = proc64.execute(code.get_code())
        time.sleep(0.5)
        cont = t.context
        assert cont.Rax == 0x4242424243434343


    def test_process_is_exit(self, proc32_64):
        assert proc32_64.is_exit == False
        proc32_64.exit(42)
        assert proc32_64.exit_code == 42
        assert proc32_64.is_exit == True


    def test_set_thread_context_32(self, proc32):
        code =  x86.MultipleInstr()
        code += x86.Label(":LOOP")
        code += x86.Jmp(":LOOP")
        data_len = len(code.get_code())
        code += x86.Ret()

        t = proc32.execute(code.get_code())
        time.sleep(0.1)
        assert proc32.is_exit == False
        t.suspend()
        ctx = t.context
        ctx.Eip += data_len
        ctx.Eax = 0x11223344
        t.set_context(ctx)
        t.resume()
        time.sleep(0.1)
        assert t.exit_code == 0x11223344


    @windows_64bit_only
    def test_set_thread_context_64(self, proc64):
        code =  x64.MultipleInstr()
        code += x64.Label(":LOOP")
        code += x64.Jmp(":LOOP")
        data_len = len(code.get_code())
        code += x64.Ret()
        t = proc64.execute(code.get_code())
        time.sleep(0.1)
        assert proc64.is_exit ==  False
        t.suspend()
        ctx = t.context
        ctx.Rip += data_len
        ctx.Rax = 0x11223344
        t.set_context(ctx)
        t.resume()
        time.sleep(0.1)
        assert t.exit_code == 0x11223344


    def test_load_library(self, proc32_64):
        DLL = "wintrust.dll"
        proc32_64.load_library(DLL)
        assert DLL in [m.name for m in proc32_64.peb.modules]

    def test_load_library_unicode_name(self, proc32_64, tmpdir):
        mybitness = windows.current_process.bitness
        UNICODE_FILENAME = u'\u4e2d\u56fd\u94f6\u884c\u7f51\u94f6\u52a9\u624b.dll'

        if proc32_64.bitness == mybitness:
            DLLPATH = r"c:\windows\system32\wintrust.dll"
        elif mybitness == 64: # target is 32
            DLLPATH = r"c:\windows\syswow64\wintrust.dll"
        elif mybitness == 32: # target is 64
            DLLPATH = r"c:\windows\sysnative\wintrust.dll"
        else:
            raise Value("WTF ARE THE BITNESS ?")
        targetname = os.path.join(str(tmpdir), UNICODE_FILENAME)
        shutil.copy(DLLPATH, targetname)
        proc32_64.load_library(targetname)
        dlls = [m for m in proc32_64.peb.modules if m.name == UNICODE_FILENAME]
        assert len(dlls) == 1
        injecteddll = dlls[0]
        # Check that the DLL is the one we asked to load
        assert injecteddll.fullname == targetname

# UNICODE_PATH_NAME = u'\u4e2d\u56fd\u94f6\u884c\u7f51\u94f6\u52a9\u624b'

# def test_unicode_path_module(tmpdir, proc32_64):
    # assert windows.current_process.bitness == 32
    # if proc32_64.bitness == 64:
        # wintrust_native_path = r'c:\windows\sysnative\wintrust.dll'
    # else:
        # wintrust_native_path = r'c:\windows\system32\wintrust.dll'

    # full_dirpath = os.path.join(tmpdir, UNICODE_PATH_NAME)
    # full_dllpath = os.path.join(full_dirpath, "wintrust.dll")
    # os.mkdir(full_dirpath)
    # shutil.copy(wintrust_native_path, full_dllpath)
    # wintrust_sha256 = hashlib.sha256(open(wintrust_native_path, "rb").read()).hexdigest()


    def test_get_working_set(self, proc32_64):
        k32 = [m for m in proc32_64.peb.modules if m.name == "kernel32.dll"][0]
        api_addr = k32.pe.exports["CreateFileA"]
        data = proc32_64.read_memory(api_addr, 5)
        page_target = api_addr >> 12
        for page_info in proc32_64.query_working_set():
            if page_info.virtualpage == page_target:
                assert page_info.shared == True
                break
        else:
            raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))
        with proc32_64.virtual_protected(api_addr, 5, gdef.PAGE_EXECUTE_READWRITE):
            data = proc32_64.write_memory(api_addr, data)
        for page_info in proc32_64.query_working_set():
            if page_info.virtualpage == page_target:
                assert page_info.shared == False
                break
        else:
            raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))


    def test_get_working_setex(self, proc32_64):
        k32 = [m for m in proc32_64.peb.modules if m.name == "kernel32.dll"][0]

        text = [s for s in k32.pe.sections if s.name == ".text"][0]
        pages = [text.start + off for off in range(0, text.size, 0x1000)]

        api_addr = k32.pe.exports["CreateFileA"]
        data = proc32_64.read_memory(api_addr, 5)
        page_target = (api_addr >> 12) << 12

        for page_info in proc32_64.query_working_setex(pages):
            assert page_info.VirtualAddress in pages
            if page_info.VirtualAddress == page_target:
                assert page_info.VirtualAttributes.shared == True
                break
        else:
            raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))
        with proc32_64.virtual_protected(api_addr, 5, gdef.PAGE_EXECUTE_READWRITE):
            data = proc32_64.write_memory(api_addr, data)
        for page_info in proc32_64.query_working_setex(pages):
            assert page_info.VirtualAddress in pages
            if page_info.VirtualAddress == page_target:
                assert page_info.VirtualAttributes.shared == False
                break
        else:
            raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))


    def test_mapped_filename(self, proc32_64):
        k32 = [m for m in proc32_64.peb.modules if m.name == "kernel32.dll"][0]
        mapped_filname = proc32_64.get_mapped_filename(k32.baseaddr)
        assert mapped_filname.endswith("kernel32.dll")
        # Test on non-commit & non file-mapped addresses
        assert proc32_64.get_mapped_filename(0) == None
        assert proc32_64.get_mapped_filename(id(object())) == None


    def test_thread_teb_base(self, proc32_64):
        t = proc32_64.threads[0]
        assert t.teb_base != 0


    def test_thread_owner_from_tid(self, proc32_64):
        thread = proc32_64.threads[0]
        tst_thread = windows.winobject.process.WinThread(tid=thread.tid)
        assert thread.owner_pid == tst_thread.owner_pid
        assert thread.owner.name == tst_thread.owner.name

    def test_ProcessParameters_LSA_UNICODE_STRING(self, proc32_64):
        image_path_from_process_params = proc32_64.peb.ProcessParameters.contents.ImagePathName.str.lower()
        image_path_from_module = proc32_64.peb.modules[0].fullname.lower()
        assert image_path_from_process_params == image_path_from_module

    def test_lower_integrity(self, proc32):
        # Lowering the integrity in remote process
        # Because we don't want to mess with the token of our testing process

        proc32.execute_python("import windows")
        # We stock the handle becase lowering the integrity
        # will mess with token retrieval
        proc32.execute_python("token = windows.current_process.token")
        proc32.execute_python("token.integrity = 123")
        # execute_python will raise this in our own process :)
        proc32.execute_python("assert token.integrity == 123")

    def test_remote_assertion_error(self, proc32):
        proc32.execute_python("assert 1 == 1")
        with pytest.raises(windows.injection.RemotePythonError):
            proc32.execute_python("assert 1 == 2")
