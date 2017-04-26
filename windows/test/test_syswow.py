import windows
import time
import textwrap
from test_utils import *
from windows.generated_def.winstructs import *


class SyswowTestCase(unittest.TestCase):
    @windows_64bit_only
    @process_32bit_only
    @check_for_gc_garbage
    def test_exec_syswow(self):
        x64_code = x64.assemble("mov rax, 0x4040404040404040; mov r11, 0x0202020202020202; add rax, r11; ret")
        res = windows.syswow64.execute_64bits_code_from_syswow(x64_code)
        self.assertEqual(res, 0x4242424242424242)

    @windows_64bit_only
    @process_32bit_only
    @check_for_gc_garbage
    def test_self_pebsyswow(self):
        peb64 = windows.current_process.peb_syswow
        modules_names = [m.name for m in peb64.modules]
        self.assertIn("wow64.dll", modules_names)
        # Parsing
        wow64 = [m for m in peb64.modules if m.name == "wow64.dll"][0]
        self.assertIn("Wow64LdrpInitialize", wow64.pe.exports)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_remote_pebsyswow(self):
        with Calc32() as calc:
            peb64 = calc.peb_syswow
            modules_names = [m.name for m in peb64.modules]
            self.assertIn("wow64.dll", modules_names)
            # Parsing
            wow64 = [m for m in peb64.modules if m.name == "wow64.dll"][0]
            self.assertIn("Wow64LdrpInitialize", wow64.pe.exports)

    @windows_64bit_only
    @check_for_gc_garbage
    def test_getset_syswow_context(self):
        with Calc32() as calc:
            addr = calc.virtual_alloc(0x1000)

            remote_python_code = """
            import windows
            import windows.native_exec.simple_x64 as x64
            windows.utils.create_console()
            x64_code = x64.assemble("mov r11, 0x1122334455667788; mov rax, 0x8877665544332211; mov [{0}], rax ;label :loop; jmp :loop; nop; nop; ret")
            res = windows.syswow64.execute_64bits_code_from_syswow(x64_code)
            print("res = {{0}}".format(hex(res)))
            windows.current_process.write_qword({0},  res)
            """.format(addr)

            t = calc.execute_python_unsafe(textwrap.dedent(remote_python_code))
            # Wait for python execution
            while calc.read_qword(addr) != 0x8877665544332211:
                pass
            ctx = t.context_syswow
            # Check the get context
            self.assertEqual(ctx.R11, 0x1122334455667788)
            self.assertEqual(calc.read_memory(ctx.Rip, 2), x64.assemble("label :loop; jmp :loop"))
            t.suspend()
            calc.write_memory(ctx.Rip, "\x90\x90")
            # Check the set context
            RETURN_VALUE = 0x4041424344454647
            ctx.Rax = RETURN_VALUE
            ctx.Rip += 2
            t.set_syswow_context(ctx)
            t.resume()
            t.wait()
            self.assertEqual(RETURN_VALUE, calc.read_qword(addr))


