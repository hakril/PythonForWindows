import sys
import struct
import time
import os
import textwrap
import random
from contextlib import contextmanager

sys.path.append(".")
import unittest
import windows
import windows.debug
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64
import windows.native_exec.nativeutils as nativeutils

from windows.generated_def.winstructs import *



is_process_32_bits = windows.current_process.bitness == 32
is_process_64_bits = windows.current_process.bitness == 64

is_windows_32_bits = windows.system.bitness == 32
is_windows_64_bits = windows.system.bitness == 64

windows_32bit_only = unittest.skipIf(not is_windows_32_bits, "Test for 32bits Kernel only")
windows_64bit_only = unittest.skipIf(not is_windows_64_bits, "Test for 64bits Kernel only")

process_32bit_only = unittest.skipIf(not is_process_32_bits, "Test for 32bits process only")
process_64bit_only = unittest.skipIf(not is_process_64_bits, "Test for 64bits process only")


if is_windows_32_bits:
    def pop_calc_32(dwCreationFlags=0):
        return windows.utils.create_process(r"C:\Windows\system32\calc.exe", dwCreationFlags=dwCreationFlags, show_windows=True)

    def pop_calc_64(dwCreationFlags=0):
        raise WindowsError("Cannot create calc64 in 32bits system")
else:
    def pop_calc_32(dwCreationFlags=0):
        return windows.utils.create_process(r"C:\Windows\syswow64\calc.exe", dwCreationFlags=dwCreationFlags, show_windows=True)

    if is_process_32_bits:
        def pop_calc_64(dwCreationFlags=0):
            with windows.utils.DisableWow64FsRedirection():
                return windows.utils.create_process(r"C:\Windows\system32\calc.exe", dwCreationFlags=dwCreationFlags, show_windows=True)
    else:
        def pop_calc_64(dwCreationFlags=0):
            return windows.utils.create_process(r"C:\Windows\system32\calc.exe", dwCreationFlags=dwCreationFlags, show_windows=True)


@contextmanager
def Calc64(exit_code=0):
    try:
        calc = pop_calc_64()
        yield calc
    finally:
        calc.exit(exit_code)

@contextmanager
def Calc32(exit_code=0):
    try:
        calc = pop_calc_32()
        yield calc
    finally:
        calc.exit(exit_code)


class WindowsTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_pop_calc_32(self):
        with Calc32() as calc:
            self.assertEqual(calc.bitness, 32)

    @windows_64bit_only
    def test_pop_calc_64(self):
        with Calc64() as calc:
            self.assertEqual(calc.bitness, 64)

    def test_get_current_process_peb(self):
        return windows.current_process.peb

    def test_get_current_process_modules(self):
        self.assertIn("python", windows.current_process.peb.modules[0].name)

    def test_local_process_pe_imports(self):
        python_module = windows.current_process.peb.modules[0]
        imp = python_module.pe.imports
        self.assertIn("kernel32.dll", imp.keys(), 'Kernel32.dll not in python imports')
        current_proc_id_iat = [f for f in imp["kernel32.dll"] if f.name == "GetCurrentProcessId"][0]
        k32_base = windows.winproxy.LoadLibraryA("kernel32.dll")
        self.assertEqual(windows.winproxy.GetProcAddress(k32_base, "GetCurrentProcessId"), current_proc_id_iat.value)

    def test_local_process_pe_exports(self):
        mods = [m for m in windows.current_process.peb.modules if m.name == "kernel32.dll"]
        self.assertTrue(mods, 'Could not find "kernel32.dll" in current process modules')
        k32 = mods[0]
        get_current_proc_id = k32.pe.exports['GetCurrentProcessId']
        k32_base = windows.winproxy.LoadLibraryA("kernel32.dll")
        self.assertEqual(windows.winproxy.GetProcAddress(k32_base, "GetCurrentProcessId"), get_current_proc_id)

    # Native execution
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
    def test_execute_python_to_64(self):
        with Calc64() as calc:
            data = calc.virtual_alloc(0x1000)
            calc.execute_python('import ctypes; ctypes.c_uint.from_address({0}).value = 0x42424242'.format(data))
            #time.sleep(0.1)
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, 0x42424242)

    def test_execute_python_to_32(self):
        with Calc32() as calc:
            data = calc.virtual_alloc(0x1000)
            calc.execute_python('import ctypes; ctypes.c_uint.from_address({0}).value = 0x42424242'.format(data))
            #time.sleep(0.1)
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, 0x42424242)

    def test_parse_remote_32_peb(self):
        with Calc32() as calc:
            # Wait for PEB initialization
            # Yeah a don't know but on 32bits system the parsing might begin before
            # InMemoryOrderModuleList is setup..
            import time; time.sleep(0.1)
            self.assertEqual(calc.peb.modules[0].name, "calc.exe")

    @windows_64bit_only
    def test_parse_remote_64_peb(self):
        with Calc64() as calc:
            self.assertEqual(calc.peb.modules[0].name, "calc.exe")

    def test_parse_remote_32_pe(self):
        with Calc32() as calc:
            # Wait for PEB initialization
            # Yeah a don't know but on 32bits system the parsing might begin before
            # InMemoryOrderModuleList is setup..
            import time; time.sleep(0.1)
            mods = [m for m in calc.peb.modules if m.name == "kernel32.dll"]
            self.assertTrue(mods, 'Could not find "kernel32.dll" in calc32')
            k32 = mods[0]
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
    def test_parse_remote_64_pe(self):
        with Calc64() as calc:
            mods = [m for m in calc.peb.modules if m.name == "kernel32.dll"]
            self.assertTrue(mods, 'Could not find "kernel32.dll" in calc32')
            k32 = mods[0]
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

    def test_self_iat_hook_sucess(self):
        pythondll_mod = [m for m in windows.current_process.peb.modules if m.name.startswith("python") and m.name.endswith(".dll")][0]
        RegOpenKeyExA = [n for n in pythondll_mod.pe.imports['advapi32.dll'] if n.name == "RegOpenKeyExA"][0]

        hook_value = []

        @windows.hooks.RegOpenKeyExACallback
        def open_reg_hook(hKey, lpSubKey, ulOptions, samDesired, phkResult, real_function):
            hook_value.append((hKey, lpSubKey.value))
            phkResult[0] = 12345678
            return 0

        RegOpenKeyExA.set_hook(open_reg_hook)
        import _winreg
        open_args = (0x12345678, "MY_KEY_VALUE")
        k = _winreg.OpenKey(*open_args)
        self.assertEqual(k.handle, 12345678)
        self.assertEqual(hook_value[0], open_args)

    def test_self_iat_hook_fail_return(self):
        pythondll_mod = [m for m in windows.current_process.peb.modules if m.name.startswith("python") and m.name.endswith(".dll")][0]
        RegOpenKeyExA = [n for n in pythondll_mod.pe.imports['advapi32.dll'] if n.name == "RegOpenKeyExA"][0]

        @windows.hooks.RegOpenKeyExACallback
        def open_reg_hook_fail(hKey, lpSubKey, ulOptions, samDesired, phkResult, real_function):
            return 0x11223344

        RegOpenKeyExA.set_hook(open_reg_hook_fail)
        import _winreg
        open_args = (0x12345678, "MY_KEY_VALUE")
        with self.assertRaises(WindowsError) as ar:
            _winreg.OpenKey(*open_args)
        self.assertEqual(ar.exception.winerror, 0x11223344)

    def test_thread_exit_value_32(self):
        with Calc32() as calc:
            res = calc.execute_python("import time;time.sleep(0.1); 2")
            self.assertEqual(res, True)
            with self.assertRaises(windows.injection.RemotePythonError) as ar:
                t = calc.execute_python("import time;time.sleep(0.1); raise ValueError('BYE')")

    @windows_64bit_only
    def test_thread_exit_value_64(self):
        with Calc64() as calc:
            res = calc.execute_python("import time;time.sleep(0.1); 2")
            self.assertEqual(res, True)
            with self.assertRaises(windows.injection.RemotePythonError) as ar:
                t = calc.execute_python("import time;time.sleep(0.1); raise ValueError('BYE')")

    def test_thread_start_address_32(self):
        with Calc32() as calc:
            t = calc.threads[0]
            t.start_address  # No better idea right now that checking for crash/exception

    @windows_64bit_only
    def test_thread_start_address_64(self):
        with Calc64() as calc:
            t = calc.threads[0]
            t.start_address  # No better idea right now that checking for crash/exception

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

    def test_process_is_exit(self):
        with Calc32(exit_code=42) as calc:
            self.assertEqual(calc.is_exit, False)
        # out of context manager: process is exit
        self.assertEqual(calc.exit_code, 42)
        self.assertEqual(calc.is_exit, True)

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

class WindowsAPITestCase(unittest.TestCase):
    def test_createfileA_fail(self):
        with self.assertRaises(WindowsError) as ar:
            windows.winproxy.CreateFileA("NONEXISTFILE.FILE")

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


class DebuggerTestCase(unittest.TestCase):

    def debuggable_calc_32(self):
        return windows.utils.create_process(r"C:\python27\python.exe", dwCreationFlags=DEBUG_PROCESS | CREATE_NEW_CONSOLE, show_windows=True)

    def test_init_breakpoint_callback(self):
        TEST_CASE = self
        class MyDbg(windows.debug.Debugger):
            def on_exception(self, exception):
                TEST_CASE.assertEqual(exception.ExceptionRecord.ExceptionCode, EXCEPTION_BREAKPOINT)
                self.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = MyDbg(calc)
        d.loop()

    def test_simple_standard_breakpoint(self):
        TEST_CASE = self

        class TSTBP(windows.debug.Breakpoint):
            def trigger(self, dbg, exc):
                TEST_CASE.assertEqual(dbg.current_process.pid, calc.pid)
                TEST_CASE.assertEqual(dbg.current_process.read_memory(self.addr, 1), "\xcc")
                TEST_CASE.assertEqual(dbg.current_thread.context.pc - 1, self.addr)
                d.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)

        if windows.current_process.bitness == 32:
            LdrLoadDll32 = windows.current_process.peb.modules[1].pe.exports["LdrLoadDll"]
        else:
            calcref = pop_calc_32()
            LdrLoadDll32 = calcref.peb.modules[1].pe.exports["LdrLoadDll"]
            calcref.exit()

        d = windows.debug.Debugger(calc)
        d.add_bp(TSTBP(LdrLoadDll32))
        d.loop()

    def test_simple_hwx_breakpoint(self):
        TEST_CASE = self

        class TSTBP(windows.debug.HXBreakpoint):
            def trigger(self, dbg, exc):
                TEST_CASE.assertEqual(dbg.current_process.pid, calc.pid)
                TEST_CASE.assertEqual(dbg.current_thread.context.pc, self.addr)
                TEST_CASE.assertNotEqual(dbg.current_thread.context.Dr7, 0)
                d.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)

        if windows.current_process.bitness == 32:
            LdrLoadDll32 = windows.current_process.peb.modules[1].pe.exports["LdrLoadDll"]
        else:
            calcref = pop_calc_32()
            LdrLoadDll32 = calcref.peb.modules[1].pe.exports["LdrLoadDll"]
            calcref.exit()

        d = windows.debug.Debugger(calc)
        d.add_bp(TSTBP(LdrLoadDll32))
        d.loop()

    def test_multiple_hwx_breakpoint(self):
        TEST_CASE = self
        data = [0]
        class TSTBP(windows.debug.HXBreakpoint):
            def __init__(self, addr, expec_before):
                self.addr = addr
                self.expec_before = expec_before

            def trigger(self, dbg, exc):
                TEST_CASE.assertEqual(dbg.current_process.pid, calc.pid)
                TEST_CASE.assertEqual(dbg.current_thread.context.pc, self.addr)
                TEST_CASE.assertNotEqual(dbg.current_thread.context.Dr7, 0)
                TEST_CASE.assertEqual(data[0], self.expec_before)
                TEST_CASE.assertNotEqual(dbg.current_process.read_memory(self.addr, 1), "\xcc")
                data[0] += 1
                if data[0] == 4:
                    d.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = windows.debug.Debugger(calc)
        addr = calc.virtual_alloc(0x1000)
        calc.write_memory(addr, "\x90" * 8)
        d.add_bp(TSTBP(addr, 0))
        d.add_bp(TSTBP(addr + 1, 1))
        d.add_bp(TSTBP(addr + 2, 2))
        d.add_bp(TSTBP(addr + 3, 3))

        calc.create_thread(addr, 0)
        d.loop()
        # Used to verif we actually called the Breakpoints
        TEST_CASE.assertEqual(data[0], 4)

    def test_four_hwx_breakpoint_fail(self):
        TEST_CASE = self
        data = [0]

        class TSTBP(windows.debug.HXBreakpoint):
            def __init__(self, addr, expec_before):
                self.addr = addr
                self.expec_before = expec_before

            def trigger(self, dbg, exc):
                raise NotImplementedError("Should fail before")

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = windows.debug.Debugger(calc)
        addr = calc.virtual_alloc(0x1000)
        calc.write_memory(addr, "\x90" * 8 + "\xc3")
        d.add_bp(TSTBP(addr, 0))
        d.add_bp(TSTBP(addr + 1, 1))
        d.add_bp(TSTBP(addr + 2, 2))
        d.add_bp(TSTBP(addr + 3, 3))
        d.add_bp(TSTBP(addr + 4, 4))

        calc.create_thread(addr, 0)
        with self.assertRaises(ValueError) as e:
            d.loop()
        self.assertIn("DRx", e.exception.message)
        # Used to verif we actually NOT called the Breakpoints
        TEST_CASE.assertEqual(data[0], 0)

    def test_hwx_breakpoint_are_on_all_thread(self):
        TEST_CASE = self
        data = [0]

        class MyDbg(windows.debug.Debugger):
            def on_create_thread(self, exception):
                # Check that later created thread have their HWX breakpoint :)
                TEST_CASE.assertNotEqual(self.current_thread.context.Dr7, 0)

        class TSTBP(windows.debug.HXBreakpoint):
            def __init__(self, addr, expec_before):
                self.addr = addr
                self.expec_before = expec_before

            def trigger(self, dbg, exc):
                TEST_CASE.assertNotEqual(len(dbg.current_process.threads), 1)
                for t in dbg.current_process.threads:
                    TEST_CASE.assertNotEqual(t.context.Dr7, 0)
                if data[0] == 0: #First time we got it ! create new thread
                    data[0] = 1
                    calc.create_thread(addr, 0)
                else:
                    d.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = MyDbg(calc)
        addr = calc.virtual_alloc(0x1000)
        calc.write_memory(addr, "\x90" * 2 + "\xc3")
        d.add_bp(TSTBP(addr, 0))
        calc.create_thread(addr, 0)
        d.loop()
        # Used to verif we actually called the Breakpoints
        TEST_CASE.assertEqual(data[0], 1)


if __name__ == '__main__':
    alltests = unittest.TestSuite()
    alltests.addTest(unittest.makeSuite(WindowsTestCase))
    alltests.addTest(unittest.makeSuite(WindowsAPITestCase))
    alltests.addTest(unittest.makeSuite(DebuggerTestCase))
    alltests.addTest(unittest.makeSuite(NativeUtilsTestCase))
    alltests.debug()
    tester = unittest.TextTestRunner(verbosity=2)
    tester.run(alltests)
