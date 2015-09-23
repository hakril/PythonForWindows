import sys
import struct
import time
import os
import textwrap
from contextlib import contextmanager

sys.path.append(".")
import unittest
import windows
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

is_process_32_bits = windows.current_process.bitness == 32
is_process_64_bits = windows.current_process.bitness == 64

is_windows_32_bits = windows.system.bitness == 32
is_windows_64_bits = windows.system.bitness == 64

windows_32bit_only = unittest.skipIf(not is_windows_32_bits, "Test for 32bits Kernel only")
windows_64bit_only = unittest.skipIf(not is_windows_64_bits, "Test for 64bits Kernel only")

process_32bit_only = unittest.skipIf(not is_process_32_bits, "Test for 32bits process only")
process_64bit_only = unittest.skipIf(not is_process_64_bits, "Test for 64bits process only")


if is_windows_32_bits:
    def pop_calc_32():
        return windows.utils.create_process(r"C:\Windows\system32\calc.exe", True)

    def pop_calc_64():
        raise WindowsError("Cannot create calc64 in 32bits system")
else:
    def pop_calc_32():
        return windows.utils.create_process(r"C:\Windows\syswow64\calc.exe", True)

    if is_process_32_bits:
        def pop_calc_64():
            with windows.utils.DisableWow64FsRedirection():
                return windows.utils.create_process(r"C:\Windows\system32\calc.exe", True)
    else:
        def pop_calc_64():
            return windows.utils.create_process(r"C:\Windows\system32\calc.exe", True)


@contextmanager
def Calc64():
    try:
        calc = pop_calc_64()
        yield calc
    finally:
        calc.exit()


@contextmanager
def Calc32():
    try:
        calc = pop_calc_32()
        yield calc
    finally:
        calc.exit()


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
            time.sleep(0.1)
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, 0x42424242)

    def test_execute_python_to_32(self):
        with Calc32() as calc:
            data = calc.virtual_alloc(0x1000)
            calc.execute_python('import ctypes; ctypes.c_uint.from_address({0}).value = 0x42424242'.format(data))
            time.sleep(0.1)
            dword = struct.unpack("<I", calc.read_memory(data, 4))[0]
            self.assertEqual(dword, 0x42424242)

    def test_parse_remote_32_peb(self):
        with Calc32() as calc:
            self.assertEqual(calc.peb.modules[0].name, "calc.exe")

    @windows_64bit_only
    def test_parse_remote_64_peb(self):
        with Calc64() as calc:
            self.assertEqual(calc.peb.modules[0].name, "calc.exe")

    def test_parse_remote_32_pe(self):
        with Calc32() as calc:
            mods = [m for m in calc.peb.modules if m.name == "kernel32.dll"]
            self.assertTrue(mods, 'Could not find "kernel32.dll" in calc32')
            k32 = mods[0]
            get_current_proc_id = k32.pe.exports['GetCurrentProcessId']
            # TODO: check get_current_proc_id value (but we cannot do 64->32 injection for now)
            if is_process_64_bits:
                raise NotImplementedError("Python execution 64->32")
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
            time.sleep(0.5)
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
            time.sleep(0.5)
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


if __name__ == '__main__':
    alltests = unittest.TestSuite()
    alltests.addTest(unittest.makeSuite(WindowsTestCase))
    unittest.TextTestRunner(verbosity=2).run(alltests)
