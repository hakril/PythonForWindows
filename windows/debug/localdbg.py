from collections import defaultdict
from contextlib import contextmanager

import windows
import windows.winobject.exception as winexception

from windows import winproxy
from windows.generated_def import windef
from windows.generated_def.winstructs import *
from .breakpoints import *

class FakeDebuggerCurrentThread(object):
    """A pseudo thread representing the current thread at exception time"""
    def __init__(self, dbg):
        self.dbg = dbg

    @property
    def tid(self):
        return windows.current_thread.tid

    @property
    def context(self):
        """!!! This context in-place modification will be effective without set_context"""
        return self.dbg.get_exception_context()

    def set_context(self, context):
        # The context returned by 'self.context' already modify the return context in place..
        pass

class LocalDebugger(object):
    """A debugger interface around :func:`AddVectoredExceptionHandler`.

    Handle:

        * Standard BP (int3)
        * Hardware-Exec BP (DrX)
    """

    def __init__(self):
        self.breakpoints = {}
        self._memory_save = {}
        self._reput_breakpoint = {}
        self._hxbp_breakpoint = defaultdict(dict)

        self.callback_vectored = winexception.VectoredException(self.callback)
        winproxy.AddVectoredExceptionHandler(0, self.callback_vectored)
        self.setup_hxbp_callback_vectored =  winexception.VectoredException(self.setup_hxbp_callback)
        self.hxbp_info = None
        self.code = windows.native_exec.create_function(b"\xcc\xc3", [PVOID])
        self.veh_depth = 0
        self.current_exception = None
        self.exceptions_stack = [None]
        self.current_process =  windows.current_process
        self.current_thread = FakeDebuggerCurrentThread(self)

    @contextmanager
    def NewCurrentException(self, exc):
        try:
            self.exceptions_stack.append(exc)
            self.current_exception = exc
            self.veh_depth += 1
            yield exc
        finally:
            self.exceptions_stack.pop()
            self.current_exception = self.exceptions_stack[-1]
            self.veh_depth -= 1

    def get_exception_code(self):
        """Return ExceptionCode of current exception"""
        return self.current_exception[0].ExceptionRecord[0].ExceptionCode

    def get_exception_context(self):
        """Return context of current exception"""
        return self.current_exception[0].ContextRecord[0]

    def single_step(self):
        """Make the current thread to single step"""
        self.get_exception_context().EEFlags.TF = 1
        return windef.EXCEPTION_CONTINUE_EXECUTION

    def _pass_breakpoint(self, addr, single_step):
        with windows.utils.VirtualProtected(addr, 1, PAGE_EXECUTE_READWRITE):
            windows.current_process.write_memory(addr, self._memory_save[addr])
        self._reput_breakpoint[windows.current_thread.tid] = self.breakpoints[addr], single_step
        return self.single_step()

    def _local_resolve(self, addr):
        if not isinstance(addr, basestring):
            return addr
        dll, api = addr.split("!")
        dll = dll.lower()
        modules = {m.name[:-len(".dll")] if m.name.endswith(".dll") else m.name : m for m in windows.current_process.peb.modules}
        mod = None
        if dll in modules:
            mod = [modules[dll]]
        if not mod:
            return None
        # TODO: optim exports are the same for whole system (32 vs 64 bits)
        # I don't have to reparse the exports each time..
        # Try to interpret api as an int
        try:
            api_int = int(api, 0)
            return mod[0].baseaddr + api_int
        except ValueError:
            pass
        exports = mod[0].pe.exports
        if api not in exports:
            dbgprint("Error resolving <{0}> in local process".format(addr, target), "DBG")
            raise ValueError("Unknown API <{0}> in DLL {1}".format(api, dll))
        return exports[api]

    def callback(self, exc):
        with self.NewCurrentException(exc):
            return self.handle_exception(exc)

    def handle_exception(self, exc):
        exp_code = self.get_exception_code()
        context = self.get_exception_context()
        exp_addr = context.pc
        if exp_code == EXCEPTION_BREAKPOINT and exp_addr in self.breakpoints:
            res = self.breakpoints[exp_addr].trigger(self, exc)
            single_step = self.get_exception_context().EEFlags.TF # single step activated by breakpoint
            if exp_addr in self.breakpoints: # Breakpoint deleted itself ?
                return self._pass_breakpoint(exp_addr, single_step)
            return EXCEPTION_CONTINUE_EXECUTION

        if exp_code == EXCEPTION_SINGLE_STEP and windows.current_thread.tid in self._reput_breakpoint:
            bp, single_step = self._reput_breakpoint[windows.current_thread.tid]
            self._memory_save[bp._addr] = windows.current_process.read_memory(bp._addr, 1)
            with windows.utils.VirtualProtected(bp._addr, 1, PAGE_EXECUTE_READWRITE):
                windows.current_process.write_memory(bp._addr, b"\xcc")
            del self._reput_breakpoint[windows.current_thread.tid]
            if single_step:
                return self.on_exception(exc)
            return windef.EXCEPTION_CONTINUE_EXECUTION
        elif exp_code == EXCEPTION_SINGLE_STEP and exp_addr in self._hxbp_breakpoint[windows.current_thread.tid]:
            res = self._hxbp_breakpoint[windows.current_thread.tid][exp_addr].trigger(self, exc)
            context.EEFlags.RF = 1
            return EXCEPTION_CONTINUE_EXECUTION
        return self.on_exception(exc)

    def on_exception(self, exc):
        """Called on exception"""
        if not self.get_exception_code() in winexception.exception_name_by_value:
            return windef.EXCEPTION_CONTINUE_SEARCH
        return windef.EXCEPTION_CONTINUE_EXECUTION

    def del_bp(self, bp, targets=None):
        """Delete a breakpoint"""
        # TODO: check targets..
        if bp.type == STANDARD_BP:
            with windows.utils.VirtualProtected(bp.addr, 1, PAGE_EXECUTE_READWRITE):
                windows.current_process.write_memory(bp.addr, self._memory_save[bp.addr])
            del self._memory_save[bp.addr]
            del self.breakpoints[bp.addr]
            return
        if bp.type == HARDWARE_EXEC_BP:
            threads_by_tid = {t.tid: t for t in windows.current_process.threads}
            for tid in self._hxbp_breakpoint:
                if bp.addr in self._hxbp_breakpoint[tid] and self._hxbp_breakpoint[tid][bp.addr] == bp:
                    if tid == windows.current_thread.tid:
                        self.remove_hxbp_self_thread(bp.addr)
                    else:
                        self.remove_hxbp_other_thread(bp.addr, threads_by_tid[tid])
                    del self._hxbp_breakpoint[tid][bp.addr]
            return
        raise NotImplementedError("Unknow BP type {0}".format(bp.type))

    def add_bp(self, bp, target=None):
        """Add a breakpoint, bp is a "class:`Breakpoint`

            If the ``bp`` type is ``STANDARD_BP``, target must be None.

            If the ``bp`` type is ``HARDWARE_EXEC_BP``, target can be None (all threads), or some threads of the process
        """
        if bp.type == HARDWARE_EXEC_BP:
            return self.add_bp_hxbp(bp, target)
        if bp.type != STANDARD_BP:
            raise NotImplementedError("Unknow BP type {0}".format(bp.type))
        if target not in [None, windows.current_process]:
            raise ValueError("LocalDebugger: STANDARD_BP doest not support targets {0}".format(targets))
        addr = self._local_resolve(bp.addr)
        bp._addr = addr
        self.breakpoints[addr] = bp
        self._memory_save[addr] = windows.current_process.read_memory(addr, 1)
        with windows.utils.VirtualProtected(addr, 1, PAGE_EXECUTE_READWRITE):
            windows.current_process.write_memory(addr, b"\xcc")
        return

    def add_bp_hxbp(self, bp, targets=None):
        if bp.type != HARDWARE_EXEC_BP:
            raise NotImplementedError("Add non standard-BP in LocalDebugger")
        if targets is None:
            targets = windows.current_process.threads
        for thread in targets:
            if thread.owner.pid != windows.current_process.pid:
                raise ValueError("Cannot add HXBP to target in remote process {0}".format(thread))
            if thread.tid == windows.current_thread.tid:
                self.setup_hxbp_self_thread(bp.addr)
            else:
                self.setup_hxbp_other_thread(bp.addr, thread)
            self._hxbp_breakpoint[thread.tid][bp.addr] = bp

    def setup_hxbp_callback(self, exc):
        with self.NewCurrentException(exc):
            exp_code = self.get_exception_code()
            if exp_code != windef.EXCEPTION_BREAKPOINT:
                 return windef.EXCEPTION_CONTINUE_SEARCH
            context = self.get_exception_context()
            exp_addr = context.pc
            hxbp_used = self.setup_hxbp_in_context(context, self.data)
            windows.current_process.write_memory(exp_addr, b"\x90")
            # Raising in the VEH is a bad idea..
            # So better give the information to triggerer..
            if hxbp_used is not None:
                self.get_exception_context().func_result = exp_addr
            else:
                self.get_exception_context().func_result = 0
            return windef.EXCEPTION_CONTINUE_EXECUTION

    def remove_hxbp_callback(self, exc):
        with self.NewCurrentException(exc):
            exp_code = self.get_exception_code()
            context = self.get_exception_context()
            exp_addr = context.pc
            hxbp_used = self.remove_hxbp_in_context(context, self.data)
            windows.current_process.write_memory(exp_addr, b"\x90")
            # Raising in the VEH is a bad idea..
            # So better give the information to triggerer..
            if hxbp_used is not None:
                self.get_exception_context().Eax = exp_addr
            else:
                self.get_exception_context().Eax = 0
            return windef.EXCEPTION_CONTINUE_EXECUTION

    def setup_hxbp_in_context(self, context, addr):
        for i in range(4):
            is_used = getattr(context.EDr7, "L" + str(i))
            empty_drx = str(i)
            if not is_used:
                context.EDr7.GE = 1
                context.EDr7.LE = 1
                setattr(context.EDr7, "L" + empty_drx, 1)
                setattr(context, "Dr" + empty_drx, addr)
                return i
        return None

    def remove_hxbp_in_context(self, context, addr):
        for i in range(4):
            target_drx = str(i)
            is_used = getattr(context.EDr7, "L" + str(i))
            draddr = getattr(context, "Dr" + target_drx)

            if is_used and draddr == addr:
                setattr(context.EDr7, "L" + target_drx, 0)
                setattr(context, "Dr" + target_drx, 0)
                return i
        return None

    def setup_hxbp_self_thread(self, addr):
        if self.current_exception is not None:
            x = self.setup_hxbp_in_context(self.get_exception_context(), addr)
            if x is None:
                raise ValueError("Could not setup HXBP")
            return

        self.data = addr
        with winexception.VectoredExceptionHandler(1, self.setup_hxbp_callback):
            x = self.code()
            if x is None:
                raise ValueError("Could not setup HXBP")
            windows.current_process.write_memory(x, b"\xcc")
        return

    def setup_hxbp_other_thread(self, addr, thread):
        thread.suspend()
        ctx = thread.context
        x = self.setup_hxbp_in_context(ctx, addr)
        if x is None:
            raise ValueError("Could not setup HXBP in {0}".format(thread))
        thread.set_context(ctx)
        thread.resume()

    def remove_hxbp_self_thread(self, addr):
        if self.current_exception is not None:
            x = self.remove_hxbp_in_context(self.get_exception_context(), addr)
            if x is None:
                raise ValueError("Could not setup HXBP")
            return
        self.data = addr
        with winexception.VectoredExceptionHandler(1, self.remove_hxbp_callback):
            x = self.code()
            if x is None:
                raise ValueError("Could not remove HXBP")
            windows.current_process.write_memory(x, b"\xcc")
        return

    def remove_hxbp_other_thread(self, addr, thread):
        thread.suspend()
        ctx = thread.context
        x = self.remove_hxbp_in_context(ctx, addr)
        if x is None:
            raise ValueError("Could not setup HXBP in {0}".format(thread))
        thread.set_context(ctx)
        thread.resume()