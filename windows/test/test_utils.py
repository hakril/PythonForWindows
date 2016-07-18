from contextlib import contextmanager

import unittest
import windows
import windows.debug
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64
import windows.native_exec.nativeutils as nativeutils


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
def Calc64(dwCreationFlags=0, exit_code=0):
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
def Calc32(dwCreationFlags=0, exit_code=0):
    try:
        calc = pop_calc_32(dwCreationFlags)
        yield calc
    except Exception as e:
        print(e)
        raise
    finally:
        if "calc" in locals():
            calc.exit(exit_code)


def print_call(f):
    def wrapper(*args, **kwargs):
        res = f(*args, **kwargs)
        print("Call to <{0}>({1}) returned <{2}>".format(f.func_name, (args, kwargs), res))
        return res
    return wrapper