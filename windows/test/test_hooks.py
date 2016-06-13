import ctypes
import textwrap

from test_utils import *
from windows.generated_def.winstructs import *


class HookTestCase(unittest.TestCase):

    def test_self_iat_hook_success(self):
        """Test hook success in single(self) thread"""
        pythondll_mod = [m for m in windows.current_process.peb.modules if m.name.startswith("python") and m.name.endswith(".dll")][0]
        RegOpenKeyExA = [n for n in pythondll_mod.pe.imports['advapi32.dll'] if n.name == "RegOpenKeyExA"][0]

        hook_value = []

        @windows.hooks.RegOpenKeyExACallback
        def open_reg_hook(hKey, lpSubKey, ulOptions, samDesired, phkResult, real_function):
            hook_value.append((hKey, lpSubKey.value))
            phkResult[0] = 12345678
            return 0

        x = RegOpenKeyExA.set_hook(open_reg_hook)
        import _winreg
        open_args = (0x12345678, "MY_KEY_VALUE")
        k = _winreg.OpenKey(*open_args)
        self.assertEqual(k.handle, 12345678)
        self.assertEqual(hook_value[0], open_args)
        # Remove the hook
        x.disable()

    def test_self_iat_hook_fail_return(self):
        """Test hook fail in single(self) thread"""
        pythondll_mod = [m for m in windows.current_process.peb.modules if m.name.startswith("python") and m.name.endswith(".dll")][0]
        RegOpenKeyExA = [n for n in pythondll_mod.pe.imports['advapi32.dll'] if n.name == "RegOpenKeyExA"][0]

        @windows.hooks.RegOpenKeyExACallback
        def open_reg_hook_fail(hKey, lpSubKey, ulOptions, samDesired, phkResult, real_function):
            return 0x11223344

        x = RegOpenKeyExA.set_hook(open_reg_hook_fail)
        import _winreg
        open_args = (0x12345678, "MY_KEY_VALUE")
        with self.assertRaises(WindowsError) as ar:
            _winreg.OpenKey(*open_args)
        self.assertEqual(ar.exception.winerror, 0x11223344)
        x.disable()

    def test_self_iat_hook_multithread(self):
        """Test IAT hook in current process with multi thread trigger"""
        cp = windows.current_process
        # Might change this to XP compat ?
        kernelbase_mod = [m for m in cp.peb.modules if m.name == "kernelbase.dll"][0]
        LdrLoadDll = [n for n in kernelbase_mod.pe.imports['ntdll.dll'] if n.name == "LdrLoadDll"][0]

        calling_thread = set([])
        @windows.hooks.LdrLoadDllCallback
        def MyHook(*args, **kwargs):
            calling_thread.add(windows.current_thread.tid)
            return kwargs["real_function"]()

        x = LdrLoadDll.set_hook(MyHook)
        # Trigger from local thread
        ctypes.WinDLL("kernel32.dll")
        self.assertEqual(calling_thread, set([windows.current_thread.tid]))
        # Trigger from another thread
        k32 = [m for m in cp.peb.modules if m.name == "kernel32.dll"][0]
        load_libraryA = k32.pe.exports["LoadLibraryA"]
        with cp.allocated_memory(0x1000) as addr:
            cp.write_memory(addr, "DLLNOTFOUND.NOT_A_REAL_DLL" + "\x00")
            t = cp.create_thread(load_libraryA, addr)
            t.wait()
        self.assertEqual(len(calling_thread), 2)
        x.disable()

    def test_remote_iat_hook_32(self):
        with Calc32() as calc:
            calc.execute_python("import windows")
            calc.execute_python("windows.utils.create_console()")

            code = """
            import windows.generated_def as gdef

            cp = windows.current_process
            kernelbase_mod = [m for m in cp.peb.modules if m.name == "kernelbase.dll"][0]
            LdrLoadDll = [n for n in kernelbase_mod.pe.imports['ntdll.dll'] if n.name == "LdrLoadDll"][0]

            calling_thread = set([])
            hooking_thread = windows.current_thread.tid
            @windows.hooks.LdrLoadDllCallback
            def MyHook(*args, **kwargs):
                calling_thread.add(windows.current_thread.tid)
                print(windows.current_thread.tid)
                return kwargs["real_function"]()

            x = LdrLoadDll.set_hook(MyHook)
            print("Hooker = " + str(windows.current_thread.tid))
            import ctypes
            try:
                ctypes.WinDLL("NOT_A_REAL_DLL")
            except WindowsError as e:
                pass
            """
            calc.execute_python_unsafe(textwrap.dedent(code))
            # Tricky part: we use an injected thread exit_value to ask stuff about the remote python
            def remote_ask(request):
                t = calc.execute_python_unsafe(request)
                t.wait()
                return t.exit_code

            self.assertEqual(remote_ask("windows.current_thread.exit(len(calling_thread))"), 1)
            self.assertEqual(remote_ask("windows.current_thread.exit(calling_thread == set([hooking_thread]))"), 1)

            # Trigger hook from another Python thread
            calc.execute_python_unsafe("ctypes.WinDLL('ANOTHER_FAKE_DLL')").wait()
            self.assertEqual(remote_ask("windows.current_thread.exit(len(calling_thread))"), 2)

            # Trigger hook from a NONPython thread
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            load_libraryA = k32.pe.exports["LoadLibraryA"]
            with calc.allocated_memory(0x1000) as addr:
                calc.write_memory(addr, "DLLNOTFOUND.NOT_A_REAL_DLL" + "\x00")
                t = calc.create_thread(load_libraryA, addr)
                t.wait()
            self.assertEqual(remote_ask("windows.current_thread.exit(len(calling_thread))"), 3)

    def test_remote_iat_hook_64(self):
        with Calc64() as calc:
            calc.execute_python("import windows")
            calc.execute_python("windows.utils.create_console()")

            code = """
            import windows.generated_def as gdef

            cp = windows.current_process
            kernelbase_mod = [m for m in cp.peb.modules if m.name == "kernelbase.dll"][0]
            LdrLoadDll = [n for n in kernelbase_mod.pe.imports['ntdll.dll'] if n.name == "LdrLoadDll"][0]

            calling_thread = set([])
            hooking_thread = windows.current_thread.tid
            @windows.hooks.Callback(*[gdef.PVOID] * 5)
            def MyHook(*args, **kwargs):
                calling_thread.add(windows.current_thread.tid)
                print(windows.current_thread.tid)
                return kwargs["real_function"]()

            x = LdrLoadDll.set_hook(MyHook)
            print("Hooker = " + str(windows.current_thread.tid))
            import ctypes
            try:
                ctypes.WinDLL("NOT_A_REAL_DLL")
            except WindowsError as e:
                pass
            """
            calc.execute_python_unsafe(textwrap.dedent(code))
            # Tricky part: we use an injected thread exit_value to ask stuff about the remote python
            def remote_ask(request):
                t = calc.execute_python_unsafe(request)
                t.wait()
                return t.exit_code

            self.assertEqual(remote_ask("windows.current_thread.exit(len(calling_thread))"), 1)
            self.assertEqual(remote_ask("windows.current_thread.exit(calling_thread == set([hooking_thread]))"), 1)

            # Trigger hook from another Python thread
            calc.execute_python_unsafe("ctypes.WinDLL('ANOTHER_FAKE_DLL')").wait()
            self.assertEqual(remote_ask("windows.current_thread.exit(len(calling_thread))"), 2)

            # Trigger hook from a NONPython thread
            k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
            load_libraryA = k32.pe.exports["LoadLibraryA"]
            with calc.allocated_memory(0x1000) as addr:
                calc.write_memory(addr, "DLLNOTFOUND.NOT_A_REAL_DLL" + "\x00")
                t = calc.create_thread(load_libraryA, addr)
                t.wait()
            self.assertEqual(remote_ask("windows.current_thread.exit(len(calling_thread))"), 3)
