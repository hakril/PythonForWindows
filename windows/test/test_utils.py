from contextlib import contextmanager

import unittest
import windows
import windows.debug
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64
import windows.native_exec.nativeutils as nativeutils
from windows.generated_def import CREATE_NEW_CONSOLE

import gc


is_process_32_bits = windows.current_process.bitness == 32
is_process_64_bits = windows.current_process.bitness == 64

is_windows_32_bits = windows.system.bitness == 32
is_windows_64_bits = windows.system.bitness == 64

is_windows_10 = (windows.system.version[0] == 10)

windows_32bit_only = unittest.skipIf(not is_windows_32_bits, "Test for 32bits Kernel only")
windows_64bit_only = unittest.skipIf(not is_windows_64_bits, "Test for 64bits Kernel only")

process_32bit_only = unittest.skipIf(not is_process_32_bits, "Test for 32bits process only")
process_64bit_only = unittest.skipIf(not is_process_64_bits, "Test for 64bits process only")

if windows.system.version[0] < 10:
    test_binary_name = "calc.exe"
else:
    test_binary_name = "cmd.exe"
    test_binary_name = "notepad.exe"

DEFAULT_CREATION_FLAGS = CREATE_NEW_CONSOLE

if is_windows_32_bits:
    def pop_calc_32(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        return windows.utils.create_process(r"C:\Windows\system32\{0}".format(test_binary_name), dwCreationFlags=dwCreationFlags, show_windows=True)

    def pop_calc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        raise WindowsError("Cannot create calc64 in 32bits system")
else:
    def pop_calc_32(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        return windows.utils.create_process(r"C:\Windows\syswow64\{0}".format(test_binary_name), dwCreationFlags=dwCreationFlags, show_windows=True)

    if is_process_32_bits:
        def pop_calc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
            with windows.utils.DisableWow64FsRedirection():
                return windows.utils.create_process(r"C:\Windows\system32\{0}".format(test_binary_name), dwCreationFlags=dwCreationFlags, show_windows=True)
    else:
        def pop_calc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
            return windows.utils.create_process(r"C:\Windows\system32\{0}".format(test_binary_name), dwCreationFlags=dwCreationFlags, show_windows=True)


@contextmanager
def Calc64(dwCreationFlags=DEFAULT_CREATION_FLAGS, exit_code=0):
    try:
        calc = pop_calc_64(dwCreationFlags)
        yield calc
    except Exception as e:
        print(e)
        raise
    finally:
        if "calc" in locals():
            calc.exit(exit_code)

@contextmanager
def Calc32(dwCreationFlags=DEFAULT_CREATION_FLAGS, exit_code=0):
    try:
        calc = pop_calc_32(dwCreationFlags)
        yield calc
    except Exception as e:
        print(e)
        raise
    finally:
        if "calc" in locals():
            calc.exit(exit_code)


def check_for_gc_garbage(f):
    def wrapper(testcase, *args, **kwargs):
        garbage_before = set(gc.garbage)
        res = f(testcase, *args, **kwargs)
        gc.collect()
        new_garbage = set(gc.garbage) - garbage_before
        testcase.assertFalse(new_garbage, "Test generated uncollectable object ({0})".format(new_garbage))
        return res
    return wrapper




def print_call(f):
    def wrapper(*args, **kwargs):
        res = f(*args, **kwargs)
        print("Call to <{0}>({1}) returned <{2}>".format(f.func_name, (args, kwargs), res))
        return res
    return wrapper