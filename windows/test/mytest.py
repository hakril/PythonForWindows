import sys
import struct
import time
import os
import textwrap
import random
import pickle

from test_utils import *
from windows.generated_def.winstructs import *


class SystemTestCase(unittest.TestCase):
    @check_for_gc_garbage
    def test_version(self):
        return windows.system.version

    @check_for_gc_garbage
    def test_version_name(self):
        return windows.system.version_name

    @check_for_gc_garbage
    def test_computer_name(self):
        return windows.system.computer_name

    @check_for_gc_garbage
    def test_services(self):
        return windows.system.services

    @check_for_gc_garbage
    def test_logicaldrives(self):
        return windows.system.logicaldrives

    @check_for_gc_garbage
    @check_for_handle_leak
    def test_threads(self):
        return windows.system.threads

    @check_for_gc_garbage
    def test_wmi(self):
        return windows.system.wmi.select("Win32_Process", "*")

    @check_for_gc_garbage
    @check_for_handle_leak
    def test_processes(self):
        procs = windows.system.processes
        self.assertIn(windows.current_process.pid, [p.pid for p in procs])


class WindowsTestCase(unittest.TestCase):
    # def setUp(self):
    #     pass

    @check_for_gc_garbage
    def test_limited_handle_query(self):
        #if len(smss_list) != 1:
        #    raise ValueError("Not just one smss.exe: {0}".format(smss_list))

        class CustomTestRaise(ValueError):
            pass

        def custom_get_handle():
            raise CustomTestRaise("_get_handle() should not be called during this test")

        with Calc32() as calc:
            save_handle =  calc._handle
            del calc._handle
            calc._get_handle = custom_get_handle
            # Check that trying to get a handle raise 'CustomTestRaise'
            with self.assertRaises(CustomTestRaise):
                calc.handle
            # List of attributes that only require PROCESS_QUERY_INFOR
            calc.bitness
            calc.time_info
            # Re-set the handle to be able to kill it
            calc._handle = save_handle


    @check_for_gc_garbage
    def test_pop_calc_32(self):
        with Calc32() as calc:
            self.assertEqual(calc.bitness, 32)

    @windows_64bit_only
    def test_pop_calc_64(self):
        with Calc64() as calc:
            self.assertEqual(calc.bitness, 64)

    @check_for_gc_garbage
    def test_current_process_ppid(self):
        myself = [p for p in windows.system.processes if p.pid == windows.current_process.pid][0]
        self.assertEqual(myself.ppid, windows.current_process.ppid)

    @check_for_gc_garbage
    def test_process_ppid_32(self):
        with Calc32() as calc:
            self.assertEqual(calc.ppid, windows.current_process.pid)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_process_ppid_64(self):
        with Calc64() as calc:
            self.assertEqual(calc.ppid, windows.current_process.pid)

    @check_for_gc_garbage
    def test_get_current_process_peb(self):
        return windows.current_process.peb

    @check_for_gc_garbage
    def test_get_current_process_modules(self):
        self.assertIn("python", windows.current_process.peb.modules[0].name)

    @check_for_gc_garbage
    def test_get_current_process_exe(self):
        exe = windows.current_process.peb.exe
        exe_by_module = windows.current_process.peb.modules[0].pe
        self.assertEqual(exe.baseaddr, exe_by_module.baseaddr)
        self.assertEqual(exe.bitness, exe_by_module.bitness)


    @check_for_gc_garbage
    def test_local_process_pe_imports(self):
        python_module = windows.current_process.peb.modules[0]
        imp = python_module.pe.imports
        self.assertIn("kernel32.dll", imp.keys(), 'Kernel32.dll not in python imports')
        current_proc_id_iat = [f for f in imp["kernel32.dll"] if f.name == "GetCurrentProcessId"][0]
        k32_base = windows.winproxy.LoadLibraryA("kernel32.dll")
        self.assertEqual(windows.winproxy.GetProcAddress(k32_base, "GetCurrentProcessId"), current_proc_id_iat.value)

    @check_for_gc_garbage
    def test_local_process_pe_exports(self):
        mods = [m for m in windows.current_process.peb.modules if m.name == "kernel32.dll"]
        self.assertTrue(mods, 'Could not find "kernel32.dll" in current process modules')
        k32 = mods[0]
        get_current_proc_id = k32.pe.exports['GetCurrentProcessId']
        k32_base = windows.winproxy.LoadLibraryA("kernel32.dll")
        self.assertEqual(windows.winproxy.GetProcAddress(k32_base, "GetCurrentProcessId"), get_current_proc_id)

    @check_for_gc_garbage
    def test_local_process_pe_sections(self):
        mods = [m for m in windows.current_process.peb.modules if m.name == "kernel32.dll"]
        self.assertTrue(mods, 'Could not find "kernel32.dll" in current process modules')
        k32 = mods[0]
        sections = k32.pe.sections
        all_sections_name = [s.name for s in sections]
        self.assertIn(".text", all_sections_name)
        sections[0].start
        sections[0].size

    # Read / write
    @check_for_gc_garbage
    def test_read_memory_32(self):
        with Calc32() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            self.assertEqual(calc.read_memory(k32.baseaddr, 2), "MZ")

    @windows_64bit_only
    @check_for_gc_garbage
    def test_read_memory_64(self):
        with Calc64() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            self.assertEqual(calc.read_memory(k32.baseaddr, 2), "MZ")

    @check_for_gc_garbage
    def test_write_memory_32(self):
        with Calc32() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            with calc.virtual_protected(k32.baseaddr, 2, PAGE_EXECUTE_READWRITE):
                calc.write_memory(k32.baseaddr, "XD")
            self.assertEqual(calc.read_memory(k32.baseaddr, 2), "XD")

    @windows_64bit_only
    @check_for_gc_garbage
    def test_write_memory_64(self):
        with Calc64() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            with calc.virtual_protected(k32.baseaddr, 2, PAGE_EXECUTE_READWRITE):
                calc.write_memory(k32.baseaddr, "XD")
            self.assertEqual(calc.read_memory(k32.baseaddr, 2), "XD")

    @check_for_gc_garbage
    def test_read_string(self):
        test_string = "TEST_STRING"
        string_to_write = test_string + "\x00"
        with Calc32() as calc:
            addr = calc.virtual_alloc(0x1000)
            calc.write_memory(addr, string_to_write)
            self.assertEqual(calc.read_string(addr), test_string)

    @check_for_gc_garbage
    def test_read_string_end_page(self):
        test_string = "TEST_STRING"
        string_to_write = test_string + "\x00"
        with Calc32() as calc:
            addr = calc.virtual_alloc(0x1000) + 0x1000 - len(string_to_write)
            calc.write_memory(addr, string_to_write)
            self.assertEqual(calc.read_string(addr), test_string)

    @check_for_gc_garbage
    def test_read_wstring(self):
        test_string = "TEST_STRING"
        string_to_write = test_string + "\x00"
        with Calc32() as calc:
            addr = calc.virtual_alloc(0x1000)
            calc.write_memory(addr, "\x00".join(string_to_write))
            self.assertEqual(calc.read_wstring(addr), test_string)

    @check_for_gc_garbage
    def test_read_wstring_end_page(self):
        test_string = "TEST_STRING"
        string_to_write = test_string + "\x00"
        with Calc32() as calc:
            # Setup string addr at end of page
            addr = calc.virtual_alloc(0x1000) + 0x1000 - 26
            calc.write_memory(addr, "\x00".join(string_to_write))
            self.assertEqual(calc.read_wstring(addr), test_string)

    # Native execution
    @check_for_gc_garbage
    def test_execute_to_32(self):
        with Calc32() as calc:
            data = calc.virtual_alloc(0x1000)
            shellcode = x86.MultipleInstr()
            shellcode += x86.Mov('EAX', 0x42424242)
            shellcode += x86.Mov(x86.create_displacement(disp=data), 'EAX')
            shellcode += x86.Ret()
            calc.execute(shellcode.get_code())
            time.sleep(0.1)
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, 0x42424242)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_execute_to_64(self):
        with Calc64() as calc:
            data = calc.virtual_alloc(0x1000)
            shellcode = x64.MultipleInstr()
            shellcode += x64.Mov('RAX', 0x4242424243434343)
            shellcode += x64.Mov(x64.create_displacement(disp=data), 'RAX')
            shellcode += x64.Ret()
            calc.execute(shellcode.get_code())
            time.sleep(0.1)
            dword = struct.unpack("<Q", calc.read_memory(data, 8))[0]
            self.assertEqual(dword, 0x4242424243434343)

    # Python execution
    @windows_64bit_only
    @check_for_gc_garbage
    def test_execute_python_to_64(self):
        with Calc64() as calc:
            data = calc.virtual_alloc(0x1000)
            calc.execute_python('import ctypes; ctypes.c_uint.from_address({0}).value = 0x42424242'.format(data))
            #time.sleep(0.1)
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, 0x42424242)

    @check_for_gc_garbage
    def test_execute_python_to_32(self):
        with Calc32() as calc:
            data = calc.virtual_alloc(0x1000)
            calc.execute_python('import ctypes; ctypes.c_uint.from_address({0}).value = 0x42424242'.format(data))
            #time.sleep(0.1)
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, 0x42424242)

    @check_for_gc_garbage
    def test_execute_python_to_32_suspended(self):
        with Calc32(dwCreationFlags=CREATE_SUSPENDED) as calc:
            data = calc.virtual_alloc(0x1000)
            calc.execute_python('import ctypes; ctypes.c_uint.from_address({0}).value = 0x42424242'.format(data))
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, 0x42424242)
            # Check calc32 is still suspended:
                # 1 thread | except windows 10 that pop threads
                # main thread suspend count == 1
            self.assertEqual(calc.threads[0].suspend(), 1)
            if not is_windows_10:
                self.assertEqual(len(calc.threads), 1)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_execute_python_to_64_suspended(self):
        with Calc64(dwCreationFlags=CREATE_SUSPENDED) as calc:
            data = calc.virtual_alloc(0x1000)
            calc.execute_python('import ctypes; ctypes.c_uint.from_address({0}).value = 0x42424242'.format(data))
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, 0x42424242)
            # Check calc32 is still suspended:
                # 1 thread | except windows 10 that pop threads
                # main thread suspend count == 1
            self.assertEqual(calc.threads[0].suspend(), 1)
            if not is_windows_10:
                self.assertEqual(len(calc.threads), 1)

    @check_for_gc_garbage
    def test_parse_remote_32_peb(self):
        with Calc32() as calc:
            # Wait for PEB initialization
            # Yeah a don't know but on 32bits system the parsing might begin before
            # InMemoryOrderModuleList is setup..
            import time; time.sleep(0.1)
            self.assertEqual(calc.peb.modules[0].name, test_binary_name)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_parse_remote_64_peb(self):
        with Calc64() as calc:
            self.assertEqual(calc.peb.modules[0].name, test_binary_name)

    @check_for_gc_garbage
    def test_parse_remote_32_pe(self):
        with Calc32() as calc:
            # Wait for PEB initialization
            # Yeah a don't know but on 32bits system the parsing might begin before
            # InMemoryOrderModuleList is setup..
            import time; time.sleep(0.1)
            mods = [m for m in calc.peb.modules if m.name == "kernel32.dll"]
            self.assertTrue(mods, 'Could not find "kernel32.dll" in calc32')
            k32 = mods[0]
            mods[0].pe.sections[0].name # Just see if it's parse
            self.assertEqual(mods[0].pe.export_name.lower(), "kernel32.dll")
            get_current_proc_id = k32.pe.exports['GetCurrentProcessId']
            # TODO: check get_current_proc_id value (but we cannot do 64->32 injection for now)
            #if is_process_64_bits:
            #    raise NotImplementedError("Python execution 64->32")
            data = calc.virtual_alloc(0x1000)
            remote_python_code = """
                                import ctypes
                                import windows
                                # windows.utils.create_console() # remove comment for debug
                                k32 = [m for m in windows.current_process.peb.modules if m.name == "kernel32.dll"][0]
                                GetCurrentProcessId = k32.pe.exports['GetCurrentProcessId']
                                ctypes.c_uint.from_address({1}).value = GetCurrentProcessId
                                """.format(os.getcwd(), data)
            calc.execute_python(textwrap.dedent(remote_python_code))
            #time.sleep(0.5)
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, get_current_proc_id)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_parse_remote_64_pe(self):
        with Calc64() as calc:
            mods = [m for m in calc.peb.modules if m.name == "kernel32.dll"]
            self.assertTrue(mods, 'Could not find "kernel32.dll" in calc32')
            k32 = mods[0]
            mods[0].pe.sections[0].name
            self.assertEqual(mods[0].pe.export_name.lower(), "kernel32.dll")
            get_current_proc_id = k32.pe.exports['GetCurrentProcessId']
            data = calc.virtual_alloc(0x1000)
            remote_python_code = """
                                import ctypes
                                import windows
                                # windows.utils.create_console() # remove comment for debug
                                k32 = [m for m in windows.current_process.peb.modules if m.name == "kernel32.dll"][0]
                                GetCurrentProcessId = k32.pe.exports['GetCurrentProcessId']
                                ctypes.c_ulonglong.from_address({1}).value = GetCurrentProcessId
                                """.format(os.getcwd(), data)
            calc.execute_python(textwrap.dedent(remote_python_code))
            #time.sleep(0.5)
            dword = struct.unpack("<Q", calc.read_memory(data, 8))[0]
            self.assertEqual(dword, get_current_proc_id)

    @check_for_gc_garbage
    def test_remote_peb_exe_32(self):
        with Calc32() as calc:
            exe = calc.peb.exe
            exe_by_module = calc.peb.modules[0].pe
            self.assertEqual(exe.baseaddr, exe_by_module.baseaddr)
            self.assertEqual(exe.bitness, exe_by_module.bitness)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_remote_peb_exe_64(self):
        with Calc64() as calc:
            exe = calc.peb.exe
            exe_by_module = calc.peb.modules[0].pe
            self.assertEqual(exe.baseaddr, exe_by_module.baseaddr)
            self.assertEqual(exe.bitness, exe_by_module.bitness)

    @check_for_gc_garbage
    def test_thread_exit_value_32(self):
        with Calc32() as calc:
            res = calc.execute_python("import time;time.sleep(0.1); 2")
            self.assertEqual(res, True)
            with self.assertRaises(windows.injection.RemotePythonError) as ar:
                t = calc.execute_python("import time;time.sleep(0.1); raise ValueError('BYE')")

    @windows_64bit_only
    @check_for_gc_garbage
    def test_thread_exit_value_64(self):
        with Calc64() as calc:
            res = calc.execute_python("import time;time.sleep(0.1); 2")
            self.assertEqual(res, True)
            with self.assertRaises(windows.injection.RemotePythonError) as ar:
                t = calc.execute_python("import time;time.sleep(0.1); raise ValueError('BYE')")

    @check_for_gc_garbage
    def test_thread_start_address_32(self):
        with Calc32() as calc:
            t = calc.threads[0]
            t.start_address  # No better idea right now that checking for crash/exception

    @windows_64bit_only
    @check_for_gc_garbage
    def test_thread_start_address_64(self):
        with Calc64() as calc:
            t = calc.threads[0]
            t.start_address  # No better idea right now that checking for crash/exception

    @check_for_gc_garbage
    def test_get_context_address_32(self):
        with Calc32() as calc:
            code = x86.MultipleInstr()
            code += x86.Mov("EAX", 0x42424242)
            code += x86.Label(":LOOP")
            code += x86.Jmp(":LOOP")
            t = calc.execute(code.get_code())
            time.sleep(0.5)
            cont = t.context
            self.assertEqual(cont.Eax, 0x42424242)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_get_context_address_64(self):
        with Calc64() as calc:
            code = x64.MultipleInstr()
            code += x64.Mov("RAX", 0x4242424243434343)
            code += x64.Label(":LOOP")
            code += x64.Jmp(":LOOP")
            t = calc.execute(code.get_code())
            time.sleep(0.5)
            cont = t.context
            self.assertEqual(cont.Rax, 0x4242424243434343)

    @check_for_gc_garbage
    def test_process_is_exit(self):
        with Calc32(exit_code=42) as calc:
            self.assertEqual(calc.is_exit, False)
        # out of context manager: process is exit
        self.assertEqual(calc.exit_code, 42)
        self.assertEqual(calc.is_exit, True)

    @check_for_gc_garbage
    def test_set_thread_context_32(self):
        code =  x86.MultipleInstr()
        code += x86.Label(":LOOP")
        code += x86.Jmp(":LOOP")
        data_len = len(code.get_code())
        code += x86.Ret()

        with Calc32() as calc:
            t = calc.execute(code.get_code())
            time.sleep(0.1)
            self.assertEqual(calc.is_exit, False)
            t.suspend()
            ctx = t.context
            ctx.Eip += data_len
            ctx.Eax = 0x11223344
            t.set_context(ctx)
            t.resume()
            time.sleep(0.1)
        self.assertEqual(t.exit_code, 0x11223344)


    @windows_64bit_only
    @check_for_gc_garbage
    def test_set_thread_context_64(self):
        code =  x64.MultipleInstr()
        code += x64.Label(":LOOP")
        code += x64.Jmp(":LOOP")
        data_len = len(code.get_code())
        code += x64.Ret()

        with Calc64() as calc:
            t = calc.execute(code.get_code())
            time.sleep(0.1)
            self.assertEqual(calc.is_exit, False)
            t.suspend()
            ctx = t.context
            ctx.Rip += data_len
            ctx.Rax = 0x11223344
            t.set_context(ctx)
            t.resume()
            time.sleep(0.1)
        self.assertEqual(t.exit_code, 0x11223344)

    @check_for_gc_garbage
    def test_load_library_32(self):
        DLL = "wintrust.dll"
        with Calc32() as calc:
            calc.load_library(DLL)
            self.assertIn(DLL, [m.name for m in calc.peb.modules])

    @windows_64bit_only
    @check_for_gc_garbage
    def test_load_library_64(self):
        DLL = "wintrust.dll"
        with Calc64() as calc:
            calc.load_library(DLL)
            self.assertIn(DLL, [m.name for m in calc.peb.modules])

    @check_for_gc_garbage
    def test_token_info(self):
        token = windows.current_process.token
        self.assertIsInstance(token.computername, basestring)
        self.assertIsInstance(token.username, basestring)
        self.assertIsInstance(token.integrity, (int, long))
        self.assertIsInstance(token.is_elevated, (bool))

    @check_for_gc_garbage
    def test_get_working_set_32(self):
        with Calc32() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            api_addr = k32.pe.exports["CreateFileA"]
            data = calc.read_memory(api_addr, 5)
            page_target = api_addr >> 12
            for page_info in calc.query_working_set():
                if page_info.virtualpage == page_target:
                    self.assertEqual(page_info.shared, True)
                    break
            else:
                raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))
            data = calc.write_memory(api_addr, data)
            for page_info in calc.query_working_set():
                if page_info.virtualpage == page_target:
                    self.assertEqual(page_info.shared, False)
                    break
            else:
                raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))

    @windows_64bit_only
    @check_for_gc_garbage
    def test_get_working_set_64(self):
        with Calc64() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            api_addr = k32.pe.exports["CreateFileA"]
            data = calc.read_memory(api_addr, 5)
            page_target = api_addr >> 12
            for page_info in calc.query_working_set():
                if page_info.virtualpage == page_target:
                    self.assertEqual(page_info.shared, True)
                    break
            else:
                raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))
            with calc.virtual_protected(api_addr, 5, PAGE_EXECUTE_READWRITE):
                data = calc.write_memory(api_addr, data)
            for page_info in calc.query_working_set():
                if page_info.virtualpage == page_target:
                    self.assertEqual(page_info.shared, False)
                    break
            else:
                raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))

    @check_for_gc_garbage
    def test_get_working_setex_32(self):
        with Calc32() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]

            text = [s for s in k32.pe.sections if s.name == ".text"][0]
            pages = [text.start + off for off in range(0, text.size, 0x1000)]

            api_addr = k32.pe.exports["CreateFileA"]
            data = calc.read_memory(api_addr, 5)
            page_target = (api_addr >> 12) << 12

            for page_info in calc.query_working_setex(pages):
                self.assertIn(page_info.VirtualAddress, pages)
                if page_info.VirtualAddress == page_target:
                    self.assertEqual(page_info.VirtualAttributes.shared, True)
                    break
            else:
                raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))
            with calc.virtual_protected(api_addr, 5, PAGE_EXECUTE_READWRITE):
                data = calc.write_memory(api_addr, data)
            for page_info in calc.query_working_setex(pages):
                self.assertIn(page_info.VirtualAddress, pages)
                if page_info.VirtualAddress == page_target:
                    self.assertEqual(page_info.VirtualAttributes.shared, False)
                    break
            else:
                raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))

    @windows_64bit_only
    @check_for_gc_garbage
    def test_get_working_setex_64(self):
        with Calc64() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]

            text = [s for s in k32.pe.sections if s.name == ".text"][0]
            pages = [text.start + off for off in range(0, text.size, 0x1000)]

            api_addr = k32.pe.exports["CreateFileA"]

            data = calc.read_memory(api_addr, 5)
            page_target = (api_addr >> 12) << 12

            for page_info in calc.query_working_setex(pages):
                self.assertIn(page_info.VirtualAddress, pages)
                if page_info.VirtualAddress == page_target:
                    self.assertEqual(page_info.VirtualAttributes.shared, True)
                    break
            else:
                raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))

            with calc.virtual_protected(api_addr, 5, PAGE_EXECUTE_READWRITE):
                data = calc.write_memory(api_addr, data)
            for page_info in calc.query_working_setex(pages):
                self.assertIn(page_info.VirtualAddress, pages)
                if page_info.VirtualAddress == page_target:
                    self.assertEqual(page_info.VirtualAttributes.shared, False)
                    break
            else:
                raise ValueError("query_working_set page info for <0x{0:x}> not found".format(page_target))

    @check_for_gc_garbage
    def test_mapped_filename_32(self):
        with Calc32() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            mapped_filname = calc.get_mapped_filename(k32.baseaddr)
            self.assertTrue(mapped_filname.endswith("kernel32.dll"))

    @windows_64bit_only
    @check_for_gc_garbage
    def test_mapped_filename_64(self):
        with Calc64() as calc:
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            mapped_filname = calc.get_mapped_filename(k32.baseaddr)
            self.assertTrue(mapped_filname.endswith("kernel32.dll"))

    @check_for_gc_garbage
    def test_thread_teb_base_32(self):
        with Calc32() as calc:
            t = calc.threads[0]
            self.assertNotEqual(t.teb_base, 0)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_thread_teb_base_64(self):
        with Calc64() as calc:
            t = calc.threads[0]
            self.assertNotEqual(t.teb_base, 0)

    @check_for_gc_garbage
    def test_thread_owner_from_tid_32(self):
        with Calc32() as calc:
            thread = calc.threads[0]
            tst_thread = windows.winobject.process.WinThread(tid=thread.tid)
            self.assertEqual(thread.owner_pid, tst_thread.owner_pid)
            self.assertEqual(thread.owner.name, tst_thread.owner.name)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_thread_owner_from_tid_64(self):
        with Calc64() as calc:
            thread = calc.threads[0]
            tst_thread = windows.winobject.process.WinThread(tid=thread.tid)
            self.assertEqual(thread.owner_pid, tst_thread.owner_pid)
            self.assertEqual(thread.owner.name, tst_thread.owner.name)


class WindowsAPITestCase(unittest.TestCase):
    def test_createfileA_fail(self):
        with self.assertRaises(WindowsError) as ar:
            windows.winproxy.CreateFileA("NONEXISTFILE.FILE")

class GeneratedCodeTestCase(unittest.TestCase):
    def test_str_flags_value(self):
        self.assertEqual(windows.generated_def.MS_ENHANCED_PROV, windows.generated_def.MS_ENHANCED_PROV_A)

    def _test_pickle_unpickle(self, obj, protocol=0):
        pickled = pickle.dumps(obj, protocol)
        unpickled = pickle.loads(pickled)
        self.assertEqual(unpickled, obj)

    def test_long_flag_picke_v0(self):
        self._test_pickle_unpickle(windows.generated_def.PAGE_EXECUTE_READWRITE, 0)

    def test_long_flag_picke_v1(self):
        self._test_pickle_unpickle(windows.generated_def.PAGE_EXECUTE_READWRITE, 1)

    def test_long_flag_picke_v2(self):
        self._test_pickle_unpickle(windows.generated_def.PAGE_EXECUTE_READWRITE, 2)

    def test_str_flag_picke_v0(self):
        self._test_pickle_unpickle(windows.generated_def.szOID_RSA, 0)

    def test_str_flag_picke_v1(self):
        self._test_pickle_unpickle(windows.generated_def.szOID_RSA, 1)

    def test_str_flag_picke_v2(self):
        self._test_pickle_unpickle(windows.generated_def.szOID_RSA, 2)

class NativeUtilsTestCase(unittest.TestCase):
    @process_64bit_only
    def test_strlenw64(self):
        strlenw64 = windows.native_exec.create_function(nativeutils.StrlenW64.get_code(), [UINT, LPCWSTR])
        self.assertEqual(strlenw64("YOLO"), 4)
        self.assertEqual(strlenw64(""), 0)

    @process_64bit_only
    def test_strlena64(self):
        strlena64 = windows.native_exec.create_function(nativeutils.StrlenA64.get_code(), [UINT, LPCSTR])
        self.assertEqual(strlena64("YOLO"), 4)
        self.assertEqual(strlena64(""), 0)

    @process_64bit_only
    def test_getprocaddr64(self):
        getprocaddr64 = windows.native_exec.create_function(nativeutils.GetProcAddress64.get_code(), [ULONG64, LPCWSTR, LPCSTR])
        k32 = [mod for mod in windows.current_process.peb.modules if mod.name == "kernel32.dll"][0]
        exports = [(x,y) for x,y in k32.pe.exports.items() if isinstance(x, basestring)]

        for name, addr in exports:
            name = name.encode()
            compute_addr = getprocaddr64("KERNEL32.DLL", name)
            # Put name in test to know which function caused the assert fails
            self.assertEqual((name, hex(addr)), (name, hex(compute_addr)))

        self.assertEqual(getprocaddr64("YOLO.DLL", "whatever"), 0xfffffffffffffffe)
        self.assertEqual(getprocaddr64("KERNEL32.DLL", "YOLOAPI"), 0xffffffffffffffff)

    @process_32bit_only
    def test_strlenw32(self):
        strlenw32 = windows.native_exec.create_function(nativeutils.StrlenW32.get_code(), [UINT, LPCWSTR])
        self.assertEqual(strlenw32("YOLO"), 4)
        self.assertEqual(strlenw32(""), 0)

    @process_32bit_only
    def test_strlena32(self):
        strlena32 = windows.native_exec.create_function(nativeutils.StrlenA32.get_code(), [UINT, LPCSTR])
        self.assertEqual(strlena32("YOLO"), 4)
        self.assertEqual(strlena32(""), 0)

    @process_32bit_only
    def test_getprocaddr32(self):
        getprocaddr32 = windows.native_exec.create_function(nativeutils.GetProcAddress32.get_code(), [UINT, LPCWSTR, LPCSTR])
        k32 = [mod for mod in windows.current_process.peb.modules if mod.name == "kernel32.dll"][0]
        exports = [(x,y) for x,y in k32.pe.exports.items() if isinstance(x, basestring)]

        for name, addr in exports:
            name = name.encode()
            compute_addr = getprocaddr32("KERNEL32.DLL", name)
            # Put name in test to know which function caused the assert fails
            self.assertEqual((name, hex(addr)), (name, hex(compute_addr)))

        self.assertEqual(getprocaddr32("YOLO.DLL", "whatever"), 0xfffffffe)
        self.assertEqual(getprocaddr32("KERNEL32.DLL", "YOLOAPI"), 0xffffffff)


if __name__ == '__main__':
    alltests = unittest.TestSuite()
    alltests.addTest(unittest.makeSuite(SystemTestCase))
    alltests.addTest(unittest.makeSuite(WindowsTestCase))
    alltests.addTest(unittest.makeSuite(WindowsAPITestCase))
    alltests.addTest(unittest.makeSuite(NativeUtilsTestCase))
    alltests.addTest(unittest.makeSuite(GeneratedCodeTestCase))
    alltests.debug()
    tester = unittest.TextTestRunner(verbosity=2)
    tester.run(alltests)
