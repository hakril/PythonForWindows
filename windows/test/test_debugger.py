from test_utils import *
from windows.generated_def.winstructs import *

class DebuggerTestCase(unittest.TestCase):
    def debuggable_calc_32(self):
        return windows.utils.create_process(r"C:\python27\python.exe", dwCreationFlags=DEBUG_PROCESS | CREATE_NEW_CONSOLE, show_windows=True)

    def test_init_breakpoint_callback(self):
        """Checking that the initial breakpoint call `on_exception`"""
        TEST_CASE = self
        class MyDbg(windows.debug.Debugger):
            def on_exception(self, exception):
                TEST_CASE.assertEqual(exception.ExceptionRecord.ExceptionCode, EXCEPTION_BREAKPOINT)
                self.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = MyDbg(calc)
        d.loop()

    def test_simple_standard_breakpoint(self):
        """Check that a standard Breakpoint method `trigger` is called with the correct informations"""
        TEST_CASE = self

        class TSTBP(windows.debug.Breakpoint):
            def trigger(self, dbg, exc):
                TEST_CASE.assertEqual(dbg.current_process.pid, calc.pid)
                TEST_CASE.assertEqual(dbg.current_process.read_memory(self.addr, 1), "\xcc")
                TEST_CASE.assertEqual(dbg.current_thread.context.pc, self.addr)
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

    #def test_standard_breakpoint_multiple_threads(self):
    #    """Check standard BP trigger by multiples threads"""
    #    TEST_CASE = self
    #    data = [0]
    #
    #    class TSTBP(windows.debug.Breakpoint):
    #        def trigger(self, dbg, exc):
    #            TEST_CASE.assertEqual(dbg.current_process.pid, calc.pid)
    #            TEST_CASE.assertEqual(dbg.current_process.read_memory(self.addr, 1), "\xcc")
    #            TEST_CASE.assertEqual(dbg.current_thread.context.pc, self.addr)
    #            data[0] += 1
    #            print("POUET <{0}>".format(dbg.current_thread.tid))
    #            d.current_process.exit()
    #
    #    calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
    #
    #    if windows.current_process.bitness == 32:
    #        LdrLoadDll32 = windows.current_process.peb.modules[1].pe.exports["LdrLoadDll"]
    #    else:
    #        calcref = pop_calc_32()
    #        LdrLoadDll32 = calcref.peb.modules[1].pe.exports["LdrLoadDll"]
    #        calcref.exit()
    #
    #    d = windows.debug.Debugger(calc)
    #    calc.execute("\xc3")
    #    calc.execute("\xc3")
    #    calc.execute("\xc3")
    #    d.add_bp(TSTBP(LdrLoadDll32))
    #    d.loop()

    def test_simple_hwx_breakpoint(self):
        """Test that simple HXBP are trigger"""
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
        """Checking that multiple succesives HXBP are properly triggered"""
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
        """Check that setting 4HXBP in the same thread fails"""
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
        """Checking that HXBP without target are set on all threads"""
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
                #for t in dbg.current_process.threads:
                #    TEST_CASE.assertNotEqual(t.context.Dr7, 0)
                if data[0] == 0: #First time we got it ! create new thread
                    data[0] = 1
                    calc.create_thread(addr, 0)
                else:
                    data[0] += 1
                    d.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = MyDbg(calc)
        addr = calc.virtual_alloc(0x1000)
        calc.write_memory(addr, "\x90" * 2 + "\xc3")
        d.add_bp(TSTBP(addr, 0))
        calc.create_thread(addr, 0)
        d.loop()
        # Used to verif we actually called the Breakpoints
        TEST_CASE.assertEqual(data[0], 2)

    def test_simple_breakpoint_name_addr(self):
        """Check breakpoint address resolution for format dll!api"""
        TEST_CASE = self
        data = [0]
        class TSTBP(windows.debug.Breakpoint):
            def trigger(self, dbg, exc):
                addr = exc.ExceptionRecord.ExceptionAddress
                LdrLoadDlladdr = dbg.current_process.peb.modules[1].pe.exports["LdrLoadDll"]

                TEST_CASE.assertEqual(dbg.current_process.pid, calc.pid)
                TEST_CASE.assertEqual(dbg.current_process.read_memory(addr, 1), "\xcc")
                TEST_CASE.assertEqual(dbg.current_thread.context.pc, addr)
                TEST_CASE.assertEqual(LdrLoadDlladdr, addr)
                data[0] += 1
                d.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)

        d = windows.debug.Debugger(calc)
        d.add_bp(TSTBP("ntdll.dll!LdrLoadDll"))
        d.loop()
        TEST_CASE.assertEqual(data[0], 1)

    def test_simple_hardware_breakpoint_name_addr(self):
        """Check HXBP address resolution for format dll!api"""
        TEST_CASE = self
        data = [0]
        class TSTBP(windows.debug.HXBreakpoint):
            def trigger(self, dbg, exc):
                addr = exc.ExceptionRecord.ExceptionAddress
                LdrLoadDlladdr = dbg.current_process.peb.modules[1].pe.exports["LdrLoadDll"]

                TEST_CASE.assertEqual(dbg.current_process.pid, calc.pid)
                TEST_CASE.assertEqual(dbg.current_thread.context.pc, addr)
                TEST_CASE.assertEqual(LdrLoadDlladdr, addr)
                TEST_CASE.assertNotEqual(dbg.current_thread.context.Dr7, 0)
                TEST_CASE.assertNotEqual(dbg.current_process.read_memory(addr, 1), "\xcc")
                data[0] += 1
                d.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = windows.debug.Debugger(calc)
        d.add_bp(TSTBP("ntdll.dll!LdrLoadDll"))
        d.loop()
        TEST_CASE.assertEqual(data[0], 1)

    def perform_manual_getproc_loadlib_32(self, target, dll_name):
        dll = "KERNEL32.DLL\x00".encode("utf-16-le")
        api = "LoadLibraryA\x00"
        dll_to_load = dll_name + "\x00"

        RemoteManualLoadLibray = x86.MultipleInstr()
        code = RemoteManualLoadLibray
        code += x86.Mov("ECX", x86.mem("[ESP + 4]"))
        code += x86.Push(x86.mem("[ECX + 4]"))
        code += x86.Push(x86.mem("[ECX]"))
        code += x86.Call(":FUNC_GETPROCADDRESS32")
        code += x86.Push(x86.mem("[ECX + 8]"))
        code += x86.Call("EAX") # LoadLibrary
        code += x86.Pop("ECX")
        code += x86.Pop("ECX")
        code += x86.Ret()
        RemoteManualLoadLibray += nativeutils.GetProcAddress32

        addr = target.virtual_alloc(0x1000)
        addr2 = addr + len(dll)
        addr3 = addr2 + len(api)
        addr4 = addr3 + len(dll_to_load)
        target.write_memory(addr, dll)
        target.write_memory(addr2, api)
        target.write_memory(addr3, dll_to_load)
        target.write_qword(addr4, addr)
        target.write_qword(addr4 + 4, addr2)
        target.write_qword(addr4 + 0x8, addr3)
        t = target.execute(RemoteManualLoadLibray.get_code(), addr4)
        return t


    def test_hardware_breakpoint_name_addr(self):
        """Check that name addr in HXBP are trigger in all threads"""
        TEST_CASE = self
        data = [0]
        class TSTBP(windows.debug.HXBreakpoint):
            def trigger(self, dbg, exc):
                addr = exc.ExceptionRecord.ExceptionAddress
                TEST_CASE.assertEqual(dbg.current_process.pid, calc.pid)
                TEST_CASE.assertEqual(dbg.current_thread.context.pc, dbg._resolve(self.addr, dbg.current_process))
                TEST_CASE.assertNotEqual(dbg.current_thread.context.Dr7, 0)
                TEST_CASE.assertNotEqual(dbg.current_process.read_memory(addr, 1), "\xcc")
                data[0] += 1
                if data[0] == 1:
                    # Perform a loaddll in a new thread :)
                    # See if it's trigger a bp
                    t = TEST_CASE.perform_manual_getproc_loadlib_32(dbg.current_process, "wintrust.dll")
                    self.new_thread = t
                if hasattr(self, "new_thread") and dbg.current_thread.tid == self.new_thread.tid:
                    for t in dbg.current_process.threads:
                        TEST_CASE.assertNotEqual(t.context.Dr7, 0)
                    d.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = windows.debug.Debugger(calc)
        d.add_bp(TSTBP("ntdll.dll!LdrLoadDll"))
        # Code that will load wintrust !
        d.loop()
        #TEST_CASE.assertEqual(data[0], 1)

    def test_single_step(self):
        """Check that BP/dbg can trigger single step and that instruction follows"""
        TEST_CASE = self
        NB_SINGLE_STEP = 3
        data = []

        class MyDbg(windows.debug.Debugger):
            def on_single_step(self, exception):
                # Check that later created thread have their HWX breakpoint :)
                addr = exception.ExceptionRecord.ExceptionAddress
                TEST_CASE.assertEqual(self.current_thread.context.pc, addr)
                if len(data) < NB_SINGLE_STEP:
                    data.append(addr)
                    return self.single_step()
                self.current_process.exit()
                return

        class TSTBP(windows.debug.Breakpoint):
            """Check that BP/dbg can trigger single step and that instruction follows"""
            def trigger(self, dbg, exc):
                return dbg.single_step()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = MyDbg(calc)
        addr = calc.virtual_alloc(0x1000)
        calc.write_memory(addr, "\x90" * 3 + "\xc3")
        d.add_bp(TSTBP(addr))
        calc.create_thread(addr, 0)
        d.loop()
        # Used to verif we actually called the Breakpoints
        TEST_CASE.assertEqual(len(data), NB_SINGLE_STEP)
        for i in range(NB_SINGLE_STEP):
            TEST_CASE.assertEqual(data[i], addr + 1 + i)


    def test_single_step_hxbp(self):
        """Check that HXBPBP/dbg can trigger single step"""
        TEST_CASE = self
        NB_SINGLE_STEP = 3
        data = []

        class MyDbg(windows.debug.Debugger):
            def on_single_step(self, exception):
                # Check that later created thread have their HWX breakpoint :)
                addr = exception.ExceptionRecord.ExceptionAddress
                TEST_CASE.assertEqual(self.current_thread.context.pc, addr)
                if len(data) < NB_SINGLE_STEP:
                    data.append(addr)
                    return self.single_step()
                self.current_process.exit()
                return

        class TSTBP(windows.debug.HXBreakpoint):
            """Check that BP/dbg can trigger single step and that instruction follows"""
            def trigger(self, dbg, exc):
                return dbg.single_step()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = MyDbg(calc)
        addr = calc.virtual_alloc(0x1000)
        calc.write_memory(addr, "\x90" * 3 + "\xc3")
        d.add_bp(TSTBP(addr))
        calc.create_thread(addr, 0)
        d.loop()
        # Used to verif we actually called the Breakpoints
        TEST_CASE.assertEqual(len(data), NB_SINGLE_STEP)
        for i in range(NB_SINGLE_STEP):
            TEST_CASE.assertEqual(data[i], addr + 1 + i)


    def test_memory_breakpoint_write(self):
        """Check MemoryBP WRITE"""

        TEST_CASE = self
        store_data = [0]
        class TSTBP(windows.debug.MemoryBreakpoint):
            DEFAULT_PROTECT = PAGE_READONLY
            """Check that BP/dbg can trigger single step and that instruction follows"""
            def trigger(self, dbg, exc):
                fault_addr = exc.ExceptionRecord.ExceptionInformation[1]
                eax = dbg.current_thread.context.Eax
                TEST_CASE.assertEqual(fault_addr, data + eax)
                store_data[0] += 1
                if store_data[0] == 2:
                    dbg.current_process.exit()
                return

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = windows.debug.Debugger(calc)
        addr = calc.virtual_alloc(0x1000)
        data = calc.virtual_alloc(0x1000)

        injected = x86.MultipleInstr()
        injected += x86.Mov("EAX", 0)
        injected += x86.Mov(x86.deref(data), "EAX")
        injected += x86.Add("EAX", 4)
        injected += x86.Mov(x86.deref(data + 4), "EAX")
        injected += x86.Ret()

        calc.write_memory(addr, injected.get_code())
        d.add_bp(TSTBP(data, size=0x1000))
        calc.create_thread(addr, 0)
        d.loop()
        # Used to verif we actually called the Breakpoints
        TEST_CASE.assertEqual(store_data[0], 2)

    def test_memory_breakpoint_exec(self):
        """Check that HXBPBP/dbg can trigger single step"""
        TEST_CASE = self
        NB_NOP_IN_PAGE = 3
        data = []

        class TSTBP(windows.debug.MemoryBreakpoint):
            """Check that BP/dbg can trigger single step and that instruction follows"""
            DEFAULT_PROTECT = PAGE_NOACCESS
            def trigger(self, dbg, exc):
                fault_addr = exc.ExceptionRecord.ExceptionInformation[1]
                data.append(fault_addr)
                if len(data) == NB_NOP_IN_PAGE + 1:
                    dbg.current_process.exit()

        calc = pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
        d = windows.debug.Debugger(calc)
        addr = calc.virtual_alloc(0x1000)
        calc.write_memory(addr, "\x90" * NB_NOP_IN_PAGE + "\xc3")
        d.add_bp(TSTBP(addr, size=0x1000))
        calc.create_thread(addr, 0)
        d.loop()
        # Used to verif we actually called the Breakpoints
        TEST_CASE.assertEqual(len(data), NB_NOP_IN_PAGE + 1)
        for i in range(NB_NOP_IN_PAGE + 1):
            TEST_CASE.assertEqual(data[i], addr + i)

if __name__ == '__main__':
    alltests = unittest.TestSuite()
    alltests.addTest(unittest.makeSuite(DebuggerTestCase))
    alltests.debug()
    tester = unittest.TextTestRunner(verbosity=2)
    tester.run(alltests)