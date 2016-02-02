import windows
import windows.winproxy as winproxy

from windows.winobject import WinProcess, WinThread
from windows.dbgprint import dbgprint

import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

from windows.generated_def.winstructs import *
from .generated_def import windef

from collections import defaultdict

STANDARD_BP = "BP"
HARDWARE_EXEC_BP = "HXBP"

class DEBUG_EVENT(DEBUG_EVENT):
    KNOWN_EVENT_CODE = dict((x,x) for x in [EXCEPTION_DEBUG_EVENT,
        CREATE_THREAD_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT,
        EXIT_THREAD_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
        UNLOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT])

    @property
    def code(self):
        return self.KNOWN_EVENT_CODE.get(self.dwDebugEventCode, self.dwDebugEventCode)

class Debugger(object):

    def __init__(self, target):
    # Todo: accept PID / String / WinProcess
        self._init_dispatch_handlers()
        self.target = target
        self.is_target_launched = False
        #winproxy.DebugActiveProcess(target.pid)
        self.processes = {}
        self.threads = {}
        self.current_process = None
        self.current_thread = None
        # List of breakpoints
        self.breakpoints = {}
        self._pending_breakpoints = {} #Breakpoints to put in new process / threads
        # Values rewritten by "\xcc"
        self._memory_save = defaultdict(dict)
        # Dict of {tid : {drx taken : BP}}
        self._hardware_breakpoint = defaultdict(dict)
        # Breakpoints to reput..
        self._breakpoint_to_reput = {}


    def _init_dispatch_handlers(self):
        dbg_evt_dispatch = {}
        dbg_evt_dispatch[EXCEPTION_DEBUG_EVENT] = self._handle_exception
        dbg_evt_dispatch[CREATE_THREAD_DEBUG_EVENT] = self._handle_create_thread
        dbg_evt_dispatch[CREATE_PROCESS_DEBUG_EVENT] = self._handle_create_process
        dbg_evt_dispatch[EXIT_PROCESS_DEBUG_EVENT] = self._handle_exit_process
        dbg_evt_dispatch[EXIT_THREAD_DEBUG_EVENT] = self._handle_exit_thread
        dbg_evt_dispatch[LOAD_DLL_DEBUG_EVENT] = self._handle_load_dll
        dbg_evt_dispatch[UNLOAD_DLL_DEBUG_EVENT] = self._handle_unload_dll
        dbg_evt_dispatch[RIP_EVENT] = self._handle_rip
        dbg_evt_dispatch[OUTPUT_DEBUG_STRING_EVENT] = self._handle_output_debug_string
        self._DebugEventCode_dispatch = dbg_evt_dispatch
        # TODO: breakpoint type dispatch

    def _debug_event_generator(self):
        while True:
            debug_event = DEBUG_EVENT()
            winproxy.WaitForDebugEvent(debug_event)
            yield debug_event

    def _finish_debug_event(self, event, action):
        if action not in [windef.DBG_CONTINUE, windef.DBG_EXCEPTION_NOT_HANDLED]:
            raise ValueError('Unknow action : <0>'.format(action))
        winproxy.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, action)

    def _update_debugger_state(self, debug_event):
        self.current_process = self.processes[debug_event.dwProcessId]
        self.current_thread = self.threads[debug_event.dwThreadId]

    def _dispatch_debug_event(self, debug_event):
        handler = self._DebugEventCode_dispatch.get(debug_event.dwDebugEventCode, self._handle_unknown_debug_event)
        return handler(debug_event)

    def _dispatch_breakpoint(self, exception, addr):
        bp = self.breakpoints[addr]
        x = bp.trigger(self, exception)
        return x

    def _setup_breakpoint_BP(self, bp, targets):
        for target in targets:
            if not isinstance(target, WinProcess):
                raise ValueError("Cannot put standard breakpoint on target {0} (not a process)".format(target))
            self._memory_save[target.pid][bp.addr] = target.read_memory(bp.addr, 1)
            #print("Write BP: {0} at {1}".format(process, addr))
            target.write_memory(bp.addr, "\xcc")

    def _setup_breakpoint_HXBP(self, bp, targets):
        all_threads = []
        for target in targets:
            if isinstance(target, WinProcess):
                for t in target.threads:
                    all_threads.append(t)
            elif isinstance(target, WinThread):
                all_threads.append(target)
            else:
                raise ValueError("Unknow HXBP target type for <{0}>".format(target))
        for target_thread in all_threads:
            x = self._hardware_breakpoint[target_thread.tid]
            if all(pos in x for pos in range(4)):
                raise ValueError("Cannot put {0} in {1} (DRx full)".format(bp, target_thread))
            empty_drx = str([pos for pos in range(4) if pos not in x][0])
            ctx = target_thread.context
            ctx.EDr7.GE = 1
            ctx.EDr7.LE = 1

            setattr(ctx.EDr7, "L" + empty_drx, 1)
            setattr(ctx, "Dr" + empty_drx, bp.addr)
            x[int(empty_drx)] = bp
            target_thread.set_context(ctx)


    def _setup_pending_breakpoints(self, target):
        # TODO: good format of data ? (dict and we just use values)
        # TODO: need to handle threads ?
        # TODO: handle target/expected_target is a thread :)
        # Can it happen ?
        pending_todo = list(self._pending_breakpoints.values())
        for bp, expected_target in pending_todo:
            # Valid addr ? (in non-loaded module: raise / pass ?)
            if expected_target is None or expected_target.pid == target.pid:
                if isinstance(target, WinThread):
                    x = self._hardware_breakpoint[target.tid]
                    # Ignore BP on thread_create that have already been
                    # put by the process_create event
                    if bp in x.values():
                        continue
                _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
                _setup_method(bp, [target])
                # TODO REMOVE PENDING HERE if target is not None..


    def _pass_breakpoint(self, addr):
        process = self.current_process
        thread = self.current_thread
        process.write_memory(addr, self._memory_save[process.pid][addr])
        regs = thread.context
        regs.EFlags |= (1 << 8)
        regs.Eip -= 1
        thread.set_context(regs)
        self._breakpoint_to_reput[thread.tid] = addr #Register pending breakpoint for next single step

    # debug event handlers
    def _handle_unknown_debug_event(self, debug_event):
        raise NotImplementedError("dwDebugEventCode = {0}".format(debug_event.dwDebugEventCode))

    def _handle_exception(self, debug_event):
        """Handle EXCEPTION_DEBUG_EVENT"""
        exception = debug_event.u.Exception
        self._update_debugger_state(debug_event)

        if windows.current_process.bitness == 32:
            exception.__class__ = windows.vectored_exception.EEXCEPTION_DEBUG_INFO32
        else:
            exception.__class__ = windows.vectored_exception.EEXCEPTION_DEBUG_INFO64

        excp_code = exception.ExceptionRecord.ExceptionCode
        excp_addr = exception.ExceptionRecord.ExceptionAddress

        if excp_code in [EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT] and excp_addr in self.breakpoints:
            continue_flag = self._dispatch_breakpoint(exception, excp_addr)
            self._pass_breakpoint(excp_addr)
            return continue_flag
        elif excp_code in [EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP]:
            if self.current_thread.tid in self._breakpoint_to_reput:
                addr = self._breakpoint_to_reput[self.current_thread.tid]
                del self._breakpoint_to_reput[self.current_thread.tid]
                # Re-put the breakpoint
                self.current_process.write_memory(addr, "\xcc")
                return DBG_CONTINUE
            elif excp_addr in self.breakpoints:
                # Verif that's not a standard BP ?
                bp = self.breakpoints[excp_addr]
                bp.trigger(self, exception)
                ctx = self.current_thread.context
                ctx.EEFlags.RF = 1
                self.current_thread.set_context(ctx)
                return DBG_CONTINUE
            else:
                return self.on_exception(exception)
        else: # Do not trigger self.on_exception if breakpoint was registered
            return self.on_exception(exception)


    def _handle_create_process(self, debug_event):
        """Handle CREATE_PROCESS_DEBUG_EVENT"""
        create_process = debug_event.u.CreateProcessInfo

        self.current_process = WinProcess._from_handle(create_process.hProcess)
        self.current_thread = WinThread._from_handle(create_process.hThread)
        self.threads[self.current_thread.tid] = self.current_thread
        self.processes[self.current_process.pid] = self.current_process
        self._update_debugger_state(debug_event)
        self._setup_pending_breakpoints(self.current_process)
        return self.on_create_process(create_process)
        # TODO: clode hFile

    def _handle_exit_process(self, debug_event):
        """Handle EXIT_PROCESS_DEBUG_EVENT"""
        self._update_debugger_state(debug_event)
        exit_process = debug_event.u.ExitProcess
        retvalue = self.on_exit_process(exit_process)
        del self.threads[self.current_thread.tid]
        del self.processes[self.current_process.pid]
        # Hack IT, ContinueDebugEvent will close the HANDLE for us
        # Should we make another handle instead ?
        dbgprint("Removing handle {0} for {1} (will be closed by continueDebugEvent".format(hex(self.current_process._handle), self.current_process), "HANDLE")
        del self.current_process._handle
        del self.current_thread._handle
        return retvalue

    def _handle_create_thread(self, debug_event):
        """Handle CREATE_THREAD_DEBUG_EVENT"""
        create_thread = debug_event.u.CreateThread
        self.current_thread = WinThread._from_handle(create_thread.hThread)
        self.threads[self.current_thread.tid] = self.current_thread
        self._setup_pending_breakpoints(self.current_thread)
        return self.on_create_thread(create_thread)


    def _handle_exit_thread(self, debug_event):
        """Handle EXIT_THREAD_DEBUG_EVENT"""
        self._update_debugger_state(debug_event)
        exit_thread = debug_event.u.ExitThread
        retvalue = self.on_exit_thread(exit_thread)
        del self.threads[self.current_thread.tid]
        # Hack IT, ContinueDebugEvent will close the HANDLE for us
        # Should we make another handle instead ?
        dbgprint("Removing handle {0} for {1} (will be closed by continueDebugEvent".format(hex(self.current_thread._handle), self.current_thread), "HANDLE")
        del self.current_thread._handle
        return retvalue

    def _handle_load_dll(self, debug_event):
        """Handle LOAD_DLL_DEBUG_EVENT"""
        self._update_debugger_state(debug_event)
        load_dll = debug_event.u.LoadDll
        return self.on_load_dll(load_dll)

    def _handle_unload_dll(self, debug_event):
        """Handle UNLOAD_DLL_DEBUG_EVENT"""
        self._update_debugger_state(debug_event)
        unload_dll = debug_event.u.UnloadDll
        return self.on_unload_dll(unload_dll)

    def _handle_output_debug_string(self, debug_event):
        """Handle OUTPUT_DEBUG_STRING_EVENT"""
        self._update_debugger_state(debug_event)
        debug_string = debug_event.u.DebugString
        return self.on_output_debug_string(debug_string)

    def _handle_rip(self, debug_event):
        """Handle RIP_EVENT"""
        self._update_debugger_state(debug_event)
        rip_info = debug_event.u.RipInfo
        return self.on_rip(rip_info)

    # Public API
    def loop(self):
        for debug_event in self._debug_event_generator():
            dbg_continue_flag = self._dispatch_debug_event(debug_event)
            if dbg_continue_flag is None:
                dbg_continue_flag = DBG_CONTINUE
            self._finish_debug_event(debug_event, dbg_continue_flag)
            if not self.processes:
                break

    def add_bp(self, bp, addr=None, type=None, target=None):
        """TODO: use type for hardware breakpoints"""
        if getattr(bp, "addr", None) is None:
            if addr is None or type is None:
                raise ValueError("SUCK YOUR NONE")
            bp = ProxyBreakpoint(bp, addr, type)
        else:
            if addr is not None or type is not None:
                raise ValueError("Given <addr|type> by parameters but BP object have them")
        del addr
        del type
        if target is None:
            # Raise on multiple pending at same addr ?
            # We will add the pending breakpoint to other new processes
            if bp.addr in self._pending_breakpoints:
                raise ValueError("Pending breakpoint already at {0}".format(hex(bp.addr)))
            self._pending_breakpoints[bp.addr] = (bp, target)
            targets = self.processes.values()
            if targets is None:
                return
        else:
            targets = [target]
        if bp.addr in self.breakpoints:
            raise ValueError("Breakpoint already at {0}".format(hex(bp.addr)))
        self.breakpoints[bp.addr] = bp
        _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
        _setup_method(bp, targets)
        return True

    # Public callback
    def on_exception(self, exception):
        pass

    def on_create_process(self, create_process):
        pass

    def on_exit_process(self, exit_process):
        pass

    def on_create_thread(self, create_thread):
        pass

    def on_exit_thread(self, exit_thread):
        pass

    def on_load_dll(self, load_dll):
        pass

    def on_unload_dll(self, unload_dll):
        pass

    def on_output_debug_string(self, debug_string):
        pass

    def on_rip(self, rip_info):
        pass


class Breakpoint(object):
    type = "BP" # REAL BP
    def __init__(self, addr):
        self.addr = addr

    def trigger(self, dbg, exception):
        pass

class ProxyBreakpoint(Breakpoint):
    def __init__(self, target, addr, type):
        self.target = target
        self.addr = addr
        self.type = type

    def trigger(self, dbg, exception):
        return self.target(dbg, exception)

class HXBreakpoint(Breakpoint):
    type = HARDWARE_EXEC_BP



