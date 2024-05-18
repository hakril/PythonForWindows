import pytest
import textwrap
import ctypes
import time

import windows
import windows.generated_def as gdef
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

try:
    import _winreg as winreg
except ImportError as e:
    import winreg


from .pfwtest import *

pytestmark = pytest.mark.usefixtures('check_for_gc_garbage')

if windows.pycompat.is_py3:
    function_to_hook = "RegOpenKeyExW"
    callback_type = windows.hooks.RegOpenKeyExWCallback
else:
    function_to_hook = "RegOpenKeyExA"
    callback_type = windows.hooks.RegOpenKeyExACallback


def test_self_iat_hook_success():
    """Test hook success in single(self) thread"""
    pythondll_mod = [m for m in windows.current_process.peb.modules if m.name.startswith("python") and m.name.endswith(".dll")][0]
    RegOpenKeyEx = [n for n in pythondll_mod.pe.imports['advapi32.dll'] if n.name == function_to_hook][0]

    hook_value = []

    @callback_type
    def open_reg_hook(hKey, lpSubKey, ulOptions, samDesired, phkResult, real_function):
        hook_value.append((hKey, lpSubKey.value))
        phkResult[0] = 12345678
        return 0

    x = RegOpenKeyEx.set_hook(open_reg_hook)

    open_args = (0x12345678, "MY_KEY_VALUE")
    k = winreg.OpenKey(*open_args)
    assert k.handle == 12345678
    assert hook_value[0] == open_args
    # Remove the hook
    x.disable()

def test_self_iat_hook_fail_return():
    """Test hook fail in single(self) thread"""
    pythondll_mod = [m for m in windows.current_process.peb.modules if m.name.startswith("python") and m.name.endswith(".dll")][0]
    RegOpenKeyEx = [n for n in pythondll_mod.pe.imports['advapi32.dll'] if n.name == function_to_hook][0]

    @callback_type
    def open_reg_hook_fail(hKey, lpSubKey, ulOptions, samDesired, phkResult, real_function):
        return 0x11223344

    x = RegOpenKeyEx.set_hook(open_reg_hook_fail)
    open_args = (0x12345678, "MY_KEY_VALUE")
    with pytest.raises(WindowsError) as ar:
        winreg.OpenKey(*open_args)
    assert ar.value.winerror == 0x11223344
    x.disable()


def test_self_iat_hook_multithread():
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
    assert calling_thread == set([windows.current_thread.tid])
    # Trigger from another thread
    k32 = [m for m in cp.peb.modules if m.name == "kernel32.dll"][0]
    load_libraryA = k32.pe.exports["LoadLibraryA"]

    with cp.allocated_memory(0x1000) as addr:
        cp.write_memory(addr, "DLLNOTFOUND.NOT_A_REAL_DLL" + "\x00")
        t = cp.create_thread(load_libraryA, addr)
        t.wait()
    assert len(calling_thread) == 2
    x.disable()

@python_injection
@check_for_gc_garbage
def test_remote_iat_hook(proc32_64):
    proc32_64.execute_python("import windows")
    proc32_64.execute_python("windows.utils.create_console()")
    time.sleep(0.5) # Let all initialisation finish (runtime windows + remote python)

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
    proc32_64.execute_python(textwrap.dedent(code))
    # Tricky part: we use an injected thread exit_value to ask stuff about the remote python
    def remote_ask(request):
        t = proc32_64.execute_python_unsafe(request)
        t.wait()
        result = t.exit_code
        if result > 100:
            import pdb;pdb.set_trace()
        return result

    assert remote_ask("windows.current_thread.exit(len(calling_thread))") ==  1
    assert remote_ask("windows.current_thread.exit(calling_thread == set([hooking_thread]))") == 1

    # Trigger hook from another Python thread
    proc32_64.execute_python_unsafe("ctypes.WinDLL('ANOTHER_FAKE_DLL')").wait()
    assert remote_ask("windows.current_thread.exit(len(calling_thread))") == 2

    # Trigger hook from a NONPython thread
    k32 = [m for m in proc32_64.peb.modules if m.name == "kernel32.dll"][0]
    load_libraryA = k32.pe.exports["LoadLibraryA"]
    with proc32_64.allocated_memory(0x1000) as addr:
        proc32_64.write_memory(addr, "DLLNOTFOUND.NOT_A_REAL_DLL" + "\x00")
        t = proc32_64.create_thread(load_libraryA, addr)
        t.wait()
    assert remote_ask("windows.current_thread.exit(len(calling_thread))") == 3

#@check_for_gc_garbage
#def test_remote_iat_hook_64(self):
#    with Calc64() as calc:
#        calc.execute_python("import windows")
#        calc.execute_python("windows.utils.create_console()")
#
#        code = """
#        import windows.generated_def as gdef
#
#        cp = windows.current_process
#        kernelbase_mod = [m for m in cp.peb.modules if m.name == "kernelbase.dll"][0]
#        LdrLoadDll = [n for n in kernelbase_mod.pe.imports['ntdll.dll'] if n.name == "LdrLoadDll"][0]
#
#        calling_thread = set([])
#        hooking_thread = windows.current_thread.tid
#        @windows.hooks.Callback(*[gdef.PVOID] * 5)
#        def MyHook(*args, **kwargs):
#            calling_thread.add(windows.current_thread.tid)
#            print(windows.current_thread.tid)
#            return kwargs["real_function"]()
#
#        x = LdrLoadDll.set_hook(MyHook)
#        print("Hooker = " + str(windows.current_thread.tid))
#        import ctypes
#        try:
#            ctypes.WinDLL("NOT_A_REAL_DLL")
#        except WindowsError as e:
#            pass
#        """
#        calc.execute_python(textwrap.dedent(code))
#        # Tricky part: we use an injected thread exit_value to ask stuff about the remote python
#        def remote_ask(request):
#            t = calc.execute_python_unsafe(request)
#            t.wait()
#            return t.exit_code
#
#        self.assertEqual(remote_ask("windows.current_thread.exit(len(calling_thread))"), 1)
#        self.assertEqual(remote_ask("windows.current_thread.exit(calling_thread == set([hooking_thread]))"), 1)
#
#        # Trigger hook from another Python thread
#        calc.execute_python_unsafe("ctypes.WinDLL('ANOTHER_FAKE_DLL')").wait()
#        self.assertEqual(remote_ask("windows.current_thread.exit(len(calling_thread))"), 2)
#
#        # Trigger hook from a NONPython thread
#        k32 = [m for m in calc.peb.modules if m.name == "kernel32.dll"][0]
#        load_libraryA = k32.pe.exports["LoadLibraryA"]
#        with calc.allocated_memory(0x1000) as addr:
#            calc.write_memory(addr, "DLLNOTFOUND.NOT_A_REAL_DLL" + "\x00")
#            t = calc.create_thread(load_libraryA, addr)
#            t.wait()
#        self.assertEqual(remote_ask("windows.current_thread.exit(len(calling_thread))"), 3)


# TODO: test new hook API
