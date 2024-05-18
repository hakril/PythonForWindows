import pytest
import textwrap
import ctypes
import os
import time

import windows
import windows.debug
import windows.generated_def as gdef
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

from .conftest import generate_pop_and_exit_fixtures, pop_proc_32, pop_proc_64
from .pfwtest import *

proc32_debug = generate_pop_and_exit_fixtures([pop_proc_32], ids=["proc32dbg"], dwCreationFlags=gdef.DEBUG_PROCESS)
proc64_debug = generate_pop_and_exit_fixtures([pop_proc_64], ids=["proc64dbg"], dwCreationFlags=gdef.DEBUG_PROCESS)

if is_process_64_bits:
    proc32_64_debug =  generate_pop_and_exit_fixtures([pop_proc_32, pop_proc_64], ids=["proc32dbg", "proc64dbg"],
                                                               dwCreationFlags=gdef.DEBUG_PROCESS)
else:
    # proc32_64_debug = proc32_debug
    no_dbg_64_from_32 = lambda *x, **kwargs: pytest.skip("Cannot debug a proc64 from a 32b process")
    proc32_64_debug = generate_pop_and_exit_fixtures([pop_proc_32, no_dbg_64_from_32], ids=["proc32dbg", "proc64dbg"], dwCreationFlags=gdef.DEBUG_PROCESS)

yolo = generate_pop_and_exit_fixtures([pop_proc_32, pop_proc_64], ids=["proc32dbg", "proc64dbg"], dwCreationFlags=gdef.CREATE_SUSPENDED)

DEFAULT_DEBUGGER_TIMEOUT = 10

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_init_breakpoint_callback(proc32_64_debug):
    """Checking that the initial breakpoint call `on_exception`"""
    class MyDbg(windows.debug.Debugger):
        def on_exception(self, exception):
            assert exception.ExceptionRecord.ExceptionCode == gdef.EXCEPTION_BREAKPOINT
            self.current_process.exit()

    d = MyDbg(proc32_64_debug)
    d.loop()


def get_debug_process_ndll(proc):
    proc_pc = proc.threads[0].context.pc
    ntdll_addr = proc.query_memory(proc_pc).AllocationBase
    return windows.pe_parse.GetPEFile(ntdll_addr, target=proc)


@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_simple_standard_breakpoint(proc32_64_debug):
    """Check that a standard Breakpoint method `trigger` is called with the correct informations"""
    class TSTBP(windows.debug.Breakpoint):
        def trigger(self, dbg, exc):
            assert dbg.current_process.pid == proc32_64_debug.pid
            assert dbg.current_process.read_memory(self.addr, 1) ==  b"\xcc"
            assert dbg.current_thread.context.pc ==  self.addr
            d.current_process.exit()

    LdrLoadDll = get_debug_process_ndll(proc32_64_debug).exports["LdrLoadDll"]
    d = windows.debug.Debugger(proc32_64_debug)
    d.add_bp(TSTBP(LdrLoadDll))
    d.loop()

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_simple_hwx_breakpoint(proc32_64_debug):
    """Test that simple HXBP are trigger"""

    class TSTBP(windows.debug.HXBreakpoint):
        def trigger(self, dbg, exc):
            assert dbg.current_process.pid ==  proc32_64_debug.pid
            assert dbg.current_thread.context.pc ==  self.addr
            assert dbg.current_thread.context.Dr7 != 0
            d.current_process.exit()

    LdrLoadDll = get_debug_process_ndll(proc32_64_debug).exports["LdrLoadDll"]
    d = windows.debug.Debugger(proc32_64_debug)
    d.add_bp(TSTBP(LdrLoadDll))
    d.loop()


@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_multiple_hwx_breakpoint(proc32_64_debug):
    """Checking that multiple succesives HXBP are properly triggered"""
    class TSTBP(windows.debug.HXBreakpoint):
        COUNTER = 0
        def __init__(self, addr, expec_before):
            self.addr = addr
            self.expec_before = expec_before

        def trigger(self, dbg, exc):
            assert dbg.current_process.pid == proc32_64_debug.pid
            assert dbg.current_thread.context.pc == self.addr
            assert dbg.current_thread.context.Dr7 != 0
            assert TSTBP.COUNTER == self.expec_before
            assert dbg.current_process.read_memory(self.addr, 1) != b"\xcc"
            TSTBP.COUNTER += 1
            if TSTBP.COUNTER == 4:
                d.current_process.exit()

    d = windows.debug.Debugger(proc32_64_debug)
    addr = proc32_64_debug.virtual_alloc(0x1000)
    proc32_64_debug.write_memory(addr, "\x90" * 8)
    d.add_bp(TSTBP(addr, 0))
    d.add_bp(TSTBP(addr + 1, 1))
    d.add_bp(TSTBP(addr + 2, 2))
    d.add_bp(TSTBP(addr + 3, 3))
    proc32_64_debug.create_thread(addr, 0)
    d.loop()
    # Used to verif we actually called the Breakpoints
    assert TSTBP.COUNTER == 4


@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_four_hwx_breakpoint_fail(proc32_64_debug):
    """Check that setting 4HXBP in the same thread fails"""
    # print("test_four_hwx_breakpoint_fail {0}".format(proc32_64_debug))
    class TSTBP(windows.debug.HXBreakpoint):
        def __init__(self, addr, expec_before):
            self.addr = addr
            self.expec_before = expec_before

        def trigger(self, dbg, exc):
            raise NotImplementedError("Should fail before")

    d = windows.debug.Debugger(proc32_64_debug)
    addr = proc32_64_debug.virtual_alloc(0x1000)
    proc32_64_debug.write_memory(addr, "\x90" * 8 + "\xc3")
    d.add_bp(TSTBP(addr, 0))
    d.add_bp(TSTBP(addr + 1, 1))
    d.add_bp(TSTBP(addr + 2, 2))
    d.add_bp(TSTBP(addr + 3, 3))
    d.add_bp(TSTBP(addr + 4, 4))

    proc32_64_debug.create_thread(addr, 0)
    with pytest.raises(ValueError) as e:
        d.loop()
    d.detach()
    proc32_64_debug.exit()
    assert "DRx" in e.value.args[0]


@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_hwx_breakpoint_are_on_all_thread(proc32_64_debug):
    """Checking that HXBP without target are set on all threads"""
    class MyDbg(windows.debug.Debugger):
        def on_create_thread(self, exception):
            # Check that later created thread have their HWX breakpoint :)
            assert self.current_thread.context.Dr7 != 0

    class TSTBP(windows.debug.HXBreakpoint):
        COUNTER = 0
        def __init__(self, addr, expec_before):
            self.addr = addr
            self.expec_before = expec_before

        def trigger(self, dbg, exc):
            assert len(dbg.current_process.threads) != 1
            #for t in dbg.current_process.threads:
            #    TEST_CASE.assertNotEqual(t.context.Dr7, 0)
            if TSTBP.COUNTER == 0: #First time we got it ! create new thread
                TSTBP.COUNTER = 1
                dbg.current_process.create_thread(addr, 0)
            else:
                TSTBP.COUNTER += 1
                d.current_process.exit()

    d = MyDbg(proc32_64_debug)
    addr = proc32_64_debug.virtual_alloc(0x1000)
    proc32_64_debug.write_memory(addr, "\x90" * 2 + "\xc3")
    d.add_bp(TSTBP(addr, 0))
    proc32_64_debug.create_thread(addr, 0)
    d.loop()
    # Used to verif we actually called the Breakpoints
    assert TSTBP.COUNTER == 2


@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
@pytest.mark.parametrize("bptype", [windows.debug.Breakpoint, windows.debug.HXBreakpoint])
def test_simple_breakpoint_name_addr(proc32_64_debug, bptype):
    """Check breakpoint address resolution for format dll!api"""
    class TSTBP(bptype):
        COUNTER = 0
        def trigger(self, dbg, exc):
            addr = exc.ExceptionRecord.ExceptionAddress
            LdrLoadDlladdr = dbg.current_process.peb.modules[1].pe.exports["LdrLoadDll"]
            assert dbg.current_process.pid == proc32_64_debug.pid
            assert dbg.current_thread.context.pc == addr
            assert LdrLoadDlladdr == addr
            TSTBP.COUNTER += 1
            d.current_process.exit()

    # import pdb; pdb.set_trace()
    d = windows.debug.Debugger(proc32_64_debug)
    # Broken in Win11 for now: https://twitter.com/hakril/status/1555473886321549312
    d.add_bp(TSTBP("ntdll!LdrLoadDll"))
    d.loop()
    assert TSTBP.COUNTER == 1

from . import dbg_injection

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_hardware_breakpoint_name_addr(proc32_64_debug):
    """Check that name addr in HXBP are trigger in all threads"""
    class TSTBP(windows.debug.HXBreakpoint):
        COUNTER = 0
        def trigger(self, dbg, exc):
            addr = exc.ExceptionRecord.ExceptionAddress
            assert dbg.current_process.pid == proc32_64_debug.pid
            assert dbg.current_thread.context.pc == dbg._resolve(self.addr, dbg.current_process)
            TSTBP.COUNTER += 1
            if TSTBP.COUNTER == 1:
                # Perform a loaddll in a new thread :)
                # See if it triggers a bp
                t = dbg_injection.perform_manual_getproc_loadlib_for_dbg(dbg.current_process, "wintrust.dll")
                self.new_thread = t
            if hasattr(self, "new_thread") and dbg.current_thread.tid == self.new_thread.tid:
                for t in dbg.current_process.threads:
                    assert t.context.Dr7 != 0
                d.current_process.exit()

    d = windows.debug.Debugger(proc32_64_debug)
    d.add_bp(TSTBP("ntdll!LdrLoadDll"))
    # Code that will load wintrust !
    d.loop()

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_single_step(proc32_64_debug):
    """Check that BP/dbg can trigger single step and that instruction follows"""
    NB_SINGLE_STEP = 3
    class MyDbg(windows.debug.Debugger):
        DATA = []
        def on_single_step(self, exception):
            # Check that later created thread have their HWX breakpoint :)
            addr = exception.ExceptionRecord.ExceptionAddress
            assert self.current_thread.context.pc == addr
            if len(MyDbg.DATA) < NB_SINGLE_STEP:
                MyDbg.DATA.append(addr)
                return self.single_step()
            self.current_process.exit()
            return

    class TSTBP(windows.debug.Breakpoint):
        """Check that BP/dbg can trigger single step and that instruction follows"""
        def trigger(self, dbg, exc):
            return dbg.single_step()

    d = MyDbg(proc32_64_debug)
    addr = proc32_64_debug.virtual_alloc(0x1000)
    proc32_64_debug.write_memory(addr, "\x90" * 3 + "\xc3")
    d.add_bp(TSTBP(addr))
    proc32_64_debug.create_thread(addr, 0)
    d.loop()
    # Used to verif we actually called the Breakpoints
    assert len(MyDbg.DATA) == NB_SINGLE_STEP
    for i in range(NB_SINGLE_STEP):
        assert MyDbg.DATA[i] == addr + 1 + i

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
@pytest.mark.parametrize("bptype", [windows.debug.Breakpoint, windows.debug.HXBreakpoint])
def test_single_step_from_bp(proc32_64_debug, bptype):
    """Check that HXBPBP/dbg can trigger single step"""
    NB_SINGLE_STEP = 3
    class MyDbg(windows.debug.Debugger):
        DATA = []
        def on_single_step(self, exception):
            # Check that later created thread have their HWX breakpoint :)
            addr = exception.ExceptionRecord.ExceptionAddress
            assert self.current_thread.context.pc == addr
            if len(MyDbg.DATA) < NB_SINGLE_STEP:
                MyDbg.DATA.append(addr)
                return self.single_step()
            self.current_process.exit()
            return

    # class TSTBP(windows.debug.HXBreakpoint):
    class TSTBP(bptype):
        """Check that BP/dbg can trigger single step and that instruction follows"""
        def trigger(self, dbg, exc):
            return dbg.single_step()

    d = MyDbg(proc32_64_debug)
    addr = proc32_64_debug.virtual_alloc(0x1000)
    proc32_64_debug.write_memory(addr, "\x90" * 3 + "\xc3")
    d.add_bp(TSTBP(addr))
    proc32_64_debug.create_thread(addr, 0)
    d.loop()
    # Used to verif we actually called the Breakpoints
    assert len(MyDbg.DATA) == NB_SINGLE_STEP
    for i in range(NB_SINGLE_STEP):
        assert MyDbg.DATA[i] == addr + 1 + i


# MEMBP

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_memory_breakpoint_write(proc32_64_debug):
    """Check MemoryBP WRITE"""
    class TSTBP(windows.debug.MemoryBreakpoint):
        #DEFAULT_PROTECT = PAGE_READONLY
        #DEFAULT_PROTECT = PAGE_READONLY
        DEFAULT_EVENTS = "W"
        COUNTER = 0
        """Check that BP/dbg can trigger single step and that instruction follows"""
        def trigger(self, dbg, exc):
            fault_addr = exc.ExceptionRecord.ExceptionInformation[1]
            eax = dbg.current_thread.context.func_result # Rax | Eax
            if eax == 42:
                dbg.current_process.exit()
                return
            assert fault_addr == data + eax
            TSTBP.COUNTER += 1
            return

    if proc32_64_debug.bitness == 32:
        asm, reg = (x86, "EAX")
    else:
        asm, reg = (x64, "RAX")

    d = windows.debug.Debugger(proc32_64_debug)
    addr = proc32_64_debug.virtual_alloc(0x1000)
    data = proc32_64_debug.virtual_alloc(0x1000)

    injected = asm.MultipleInstr()
    injected += asm.Mov(reg, 0)
    injected += asm.Mov(asm.deref(data), reg)
    injected += asm.Add(reg, 4)
    injected += asm.Mov(asm.deref(data + 4), reg)
    injected += asm.Add(reg, 4)
    # This one should NOT trigger the MemBP of size 8
    injected += asm.Mov(asm.deref(data + 8), reg)
    injected += asm.Mov(reg, 42)
    injected += asm.Mov(asm.deref(data), reg)
    injected += asm.Ret()

    proc32_64_debug.write_memory(addr, injected.get_code())
    d.add_bp(TSTBP(data, size=0x8))
    proc32_64_debug.create_thread(addr, 0)
    d.loop()
    # Used to verif we actually called the Breakpoints for the good addresses
    assert TSTBP.COUNTER == 2

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_memory_breakpoint_exec(proc32_64_debug):
    """Check MemoryBP EXEC"""
    NB_NOP_IN_PAGE = 3

    class TSTBP(windows.debug.MemoryBreakpoint):
        """Check that BP/dbg can trigger single step and that instruction follows"""
        #DEFAULT_PROTECT = PAGE_NOACCESS
        DEFAULT_EVENTS = "X"
        DATA = []
        def trigger(self, dbg, exc):
            fault_addr = exc.ExceptionRecord.ExceptionInformation[1]
            TSTBP.DATA.append(fault_addr)
            if len(TSTBP.DATA) == NB_NOP_IN_PAGE + 1:
                dbg.current_process.exit()

    d = windows.debug.Debugger(proc32_64_debug)
    addr = proc32_64_debug.virtual_alloc(0x1000)
    proc32_64_debug.write_memory(addr, "\x90" * NB_NOP_IN_PAGE + "\xc3")
    d.add_bp(TSTBP(addr, size=0x1000))
    proc32_64_debug.create_thread(addr, 0)
    d.loop()
    # Used to verif we actually called the Breakpoints
    assert len(TSTBP.DATA) == NB_NOP_IN_PAGE + 1
    for i in range(NB_NOP_IN_PAGE + 1):
        assert TSTBP.DATA[i] == addr + i


# breakpoint remove
import threading

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
@python_injection
@pytest.mark.parametrize("bptype", [windows.debug.FunctionParamDumpHXBP, windows.debug.FunctionParamDumpBP])
def test_standard_breakpoint_self_remove(proc32_64_debug, bptype):
    data = set()

    def do_check():
        print("[==================] OPEN SELF_FILENAME1")
        proc32_64_debug.execute_python_unsafe("open(u'SELF_FILENAME1')").wait()
        time.sleep(0.1)
        print("[==================] OPEN SELF_FILENAME2")
        proc32_64_debug.execute_python_unsafe("open(u'SELF_FILENAME2')").wait()
        time.sleep(0.1)
        print("[==================] OPEN SELF_FILENAME3")
        proc32_64_debug.execute_python_unsafe("open(u'SELF_FILENAME3')").wait()
        time.sleep(0.1)
        proc32_64_debug.exit()

    class TSTBP(bptype):
        TARGET = windows.winproxy.CreateFileW
        def trigger(self, dbg, exc):
            addr = exc.ExceptionRecord.ExceptionAddress
            ctx = dbg.current_thread.context
            filename = self.extract_arguments(dbg.current_process, dbg.current_thread)["lpFileName"]
            data.add(filename)
            print("[+++++++++++++++++] Filename: {0}".format(filename))
            if filename == u"SELF_FILENAME2":
            print("[+++++++++++++++++] del_bp")
                dbg.del_bp(self)

    d = windows.debug.Debugger(proc32_64_debug)
    d.add_bp(TSTBP("kernelbase!CreateFileW"))
    threading.Thread(target=do_check).start()
    d.loop()
    assert data >= set([u"SELF_FILENAME1", u"SELF_FILENAME2"])
    assert u"SELF_FILENAME3" not in data

class MyMetaDbgDebuger(windows.debug.Debugger):
    def on_exception(self, exc):
        print(exc)
        import pdb;pdb.set_trace()
        print(exc)
        x = 2
        if x == 3:
            return gdef.DBG_EXCEPTION_NOT_HANDLED
        return gdef.DBG_CONTINUE

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
@python_injection
@pytest.mark.parametrize("bptype", [windows.debug.FunctionParamDumpHXBP, windows.debug.FunctionParamDumpBP])
def test_standard_breakpoint_remove(proc32_64_debug, bptype):
    data = set()

    def do_check():
        print("[==================] OPEN FILENAME1")
        proc32_64_debug.execute_python_unsafe("open(u'FILENAME1')").wait()
        time.sleep(0.1)
        print("[==================] OPEN FILENAME2")
        proc32_64_debug.execute_python_unsafe("open(u'FILENAME2')").wait()
        time.sleep(0.1)
        print("[==================] RM BP")
        d.del_bp(the_bp)
        print("[==================] OPEN FILENAME3")
        proc32_64_debug.execute_python_unsafe("open(u'FILENAME3')").wait()
        time.sleep(0.1)
        proc32_64_debug.exit()

    class TSTBP(bptype):
        TARGET = windows.winproxy.CreateFileW
        def trigger(self, dbg, exc):
            addr = exc.ExceptionRecord.ExceptionAddress
            ctx = dbg.current_thread.context
            filename = self.extract_arguments(dbg.current_process, dbg.current_thread)["lpFileName"]
            print("[+++++++++++++++++] Filename: {0}".format(filename))
            data.add(filename)

    d = windows.debug.Debugger(proc32_64_debug)
    # d = MyMetaDbgDebuger(proc32_64_debug)
    the_bp = TSTBP("kernelbase!CreateFileW")
    # import pdb;pdb.set_trace()
    d.add_bp(the_bp)
    time.sleep(0.1)
    threading.Thread(target=do_check).start()
    d.loop()
    assert data >= set([u"FILENAME1", u"FILENAME2"])
    assert u"FILENAME3" not in data



def get_generate_read_at_for_proc(target):
    if target.bitness == 32:
        def generate_read_at(addr):
            res = x86.MultipleInstr()
            res += x86.Mov("EAX", x86.deref(addr))
            res += x86.Ret()
            return res.get_code()
    else:
        def generate_read_at(addr):
            res = x64.MultipleInstr()
            res += x64.Mov("RAX", x64.deref(addr))
            res += x64.Ret()
            return res.get_code()
    return generate_read_at

def get_generate_write_at_for_proc(target):
    if target.bitness == 32:
        def generate_write_at(addr):
            res = x86.MultipleInstr()
            res += x86.Mov(x86.deref(addr), "EAX")
            res += x86.Ret()
            return res.get_code()
    else:
        def generate_write_at(addr):
            res = x64.MultipleInstr()
            res += x64.Mov(x64.deref(addr), "RAX")
            res += x64.Ret()
            return res.get_code()
    return generate_write_at

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_mem_breakpoint_remove(proc32_64_debug):
    data = []
    generate_read_at = get_generate_read_at_for_proc(proc32_64_debug)

    def do_check():
        proc32_64_debug.execute(generate_read_at(data_addr)).wait()
        proc32_64_debug.execute(generate_read_at(data_addr + 4)).wait()
        d.del_bp(the_bp)
        proc32_64_debug.execute(generate_read_at(data_addr + 8)).wait()
        proc32_64_debug.exit()

    class TSTBP(windows.debug.MemoryBreakpoint):
        #DEFAULT_PROTECT = PAGE_NOACCESS
        DEFAULT_EVENTS = "RWX"
        def trigger(self, dbg, exc):
            addr = exc.ExceptionRecord.ExceptionAddress
            fault_addr = exc.ExceptionRecord.ExceptionInformation[1]
            data.append(fault_addr)

    d = windows.debug.Debugger(proc32_64_debug)
    data_addr = proc32_64_debug.virtual_alloc(0x1000)
    the_bp = TSTBP(data_addr, size=0x1000)
    d.add_bp(the_bp)
    threading.Thread(target=do_check).start()
    d.loop()
    assert data == [data_addr, data_addr + 4]

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_mem_breakpoint_self_remove(proc32_64_debug):
    data = []
    generate_read_at = get_generate_read_at_for_proc(proc32_64_debug)

    def do_check():
        proc32_64_debug.execute(generate_read_at(data_addr)).wait()
        proc32_64_debug.execute(generate_read_at(data_addr + 4)).wait()
        proc32_64_debug.execute(generate_read_at(data_addr + 8)).wait()
        proc32_64_debug.exit()

    class TSTBP(windows.debug.MemoryBreakpoint):
        #DEFAULT_PROTECT = PAGE_NOACCESS
        DEFAULT_EVENTS = "RWX"
        def trigger(self, dbg, exc):
            addr = exc.ExceptionRecord.ExceptionAddress
            fault_addr = exc.ExceptionRecord.ExceptionInformation[1]
            data.append(fault_addr)
            if fault_addr == data_addr + 4:
                dbg.del_bp(self)

    d = windows.debug.Debugger(proc32_64_debug)
    data_addr = proc32_64_debug.virtual_alloc(0x1000)
    the_bp = TSTBP(data_addr, size=0x1000)
    d.add_bp(the_bp)
    threading.Thread(target=do_check).start()
    d.loop()
    assert data == [data_addr, data_addr + 4]


@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_read_write_bp_same_page(proc32_64_debug):
    data = []
    generate_read_at = get_generate_read_at_for_proc(proc32_64_debug)
    generate_write_at = get_generate_write_at_for_proc(proc32_64_debug)

    def do_check():
        proc32_64_debug.execute(generate_read_at(data_addr)).wait()
        proc32_64_debug.execute(generate_write_at(data_addr + 4)).wait()
        proc32_64_debug.execute(generate_read_at(data_addr + 0x500)).wait()
        proc32_64_debug.execute(generate_write_at(data_addr + 0x504)).wait()
        proc32_64_debug.exit()

    class MemBP(windows.debug.MemoryBreakpoint):
        #DEFAULT_PROTECT = PAGE_NOACCESS
        DEFAULT_EVENTS = "RWX"
        def trigger(self, dbg, exc):
            addr = exc.ExceptionRecord.ExceptionAddress
            fault_addr = exc.ExceptionRecord.ExceptionInformation[1]
            #print("Got <{0:#x}> <{1}>".format(fault_addr, exc.ExceptionRecord.ExceptionInformation[0]))
            data.append((self, fault_addr))

    d = windows.debug.Debugger(proc32_64_debug)
    data_addr = proc32_64_debug.virtual_alloc(0x1000)
    the_write_bp = MemBP(data_addr + 0x500, size=0x500, events="W")
    the_read_bp = MemBP(data_addr, size=0x500, events="RW")
    d.add_bp(the_write_bp)
    d.add_bp(the_read_bp)
    threading.Thread(target=do_check).start()
    d.loop()

    # generate_read_at (data_addr + 0x500)) (write_bp (PAGE_READONLY)) should not be triggered
    expected_result = [(the_read_bp, data_addr), (the_read_bp, data_addr + 4),
                       (the_write_bp, data_addr + 0x504)]

    assert data == expected_result

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_exe_in_module_list(proc32_64_debug):
    class MyDbg(windows.debug.Debugger):
        def on_exception(self, exception):
            exename = os.path.basename(proc32_64_debug.peb.imagepath.str)
            assert exename.endswith(".exe")
            exename = exename[:-len(".exe")] # Remove the .exe from the module name
            this_process_modules = self._module_by_process[self.current_process.pid]
            assert exename and exename in this_process_modules.keys()
            self.current_process.exit()

    d = MyDbg(proc32_64_debug)
    d.loop()

@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_bp_exe_by_name(proc32_64_debug):
    class TSTBP(windows.debug.Breakpoint):
        COUNTER = 0
        def trigger(self, dbg, exc):
            TSTBP.COUNTER += 1
            assert TSTBP.COUNTER == 1
            # Kill the target in 0.5s
            # It's not too long
            # It's long enought to get trigger being recalled if implem is broken
            threading.Timer(0.5, proc32_64_debug.exit).start()

    exepe = proc32_64_debug.peb.exe
    entrypoint = exepe.get_OptionalHeader().AddressOfEntryPoint
    exename = os.path.basename(proc32_64_debug.peb.imagepath.str)
    assert exename.endswith(".exe")
    exename = exename[:-len(".exe")] # Remove the .exe from the module name
    d = windows.debug.Debugger(proc32_64_debug)
    # The goal is to test bp of format 'exename!offset' so we craft a string based on the entrypoint
    d.add_bp(TSTBP("{name}!{offset}".format(name=exename, offset=entrypoint)))
    d.loop()
    assert TSTBP.COUNTER == 1


@pytest.mark.timeout(DEFAULT_DEBUGGER_TIMEOUT)
def test_keyboardinterrupt_when_bp_event(proc32_64_debug, monkeypatch):
    class ShouldNotTrigger(windows.debug.Breakpoint):
        COUNTER = 0
        def trigger(self, dbg, exc):
            raise ValueError("This BP should not trigger in this test !")

    real_WaitForDebugEvent = windows.winproxy.WaitForDebugEvent

    def WaitForDebugEvent_KeyboardInterrupt(debug_event):
        real_WaitForDebugEvent(debug_event)
        if not debug_event.dwDebugEventCode == gdef.EXCEPTION_DEBUG_EVENT:
            return
        if not debug_event.u.Exception.ExceptionRecord.ExceptionCode in [gdef.EXCEPTION_BREAKPOINT, gdef.STATUS_WX86_BREAKPOINT]:
            return # Not a BP
        if debug_event.u.Exception.ExceptionRecord.ExceptionAddress == addr:
            # Our own breakpoint
            # Trigger the fake Ctrl+c
            raise KeyboardInterrupt("TEST BP")

    xx = monkeypatch.setattr(windows.winproxy, "WaitForDebugEvent", WaitForDebugEvent_KeyboardInterrupt)

    # This should emultate a ctrl+c on when waiting for the event
    # Our goal is to set the target back to a good state :)
    TEST_CODE = b"\xeb\xfe\xff\xff\xff\xff\xff" # Loop + invalid instr
    addr = proc32_64_debug.virtual_alloc(0x1000)
    proc32_64_debug.write_memory(addr, TEST_CODE)
    d = windows.debug.Debugger(proc32_64_debug)
    bad_thread = proc32_64_debug.create_thread(addr, 0)
    d.add_bp(ShouldNotTrigger(addr))
    d.kill_on_exit(False)
    try:
        d.loop()
    except KeyboardInterrupt as e:
        for t in proc32_64_debug.threads:
            t.suspend()
        d.detach()
        # So we have detached when a BP was triggered
        # We should have the original memory under the BP
        # We should have EIP/RIP decremented by one (should be at <addr> not <addr+1>
        assert proc32_64_debug.read_memory(addr, len(TEST_CODE)) == TEST_CODE
        assert bad_thread.context.pc == addr
    else:
        raise ValueError("Should have raised")