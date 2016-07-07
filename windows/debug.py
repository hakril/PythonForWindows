import os.path
from collections import defaultdict
from contextlib import contextmanager

import windows
import windows.winobject.exception as winexception
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

from windows.winobject.process import WinProcess, WinThread
from windows.dbgprint import dbgprint
from windows import winproxy
from windows.generated_def.winstructs import *
from .generated_def import windef


from windows.winobject.exception import VectoredException



STANDARD_BP = "BP"
HARDWARE_EXEC_BP = "HXBP"
MEMORY_BREAKPOINT = "MEMBP"

class DEBUG_EVENT(DEBUG_EVENT):
    KNOWN_EVENT_CODE = dict((x,x) for x in [EXCEPTION_DEBUG_EVENT,
        CREATE_THREAD_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT,
        EXIT_THREAD_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
        UNLOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT])

    @property
    def code(self):
        return self.KNOWN_EVENT_CODE.get(self.dwDebugEventCode, self.dwDebugEventCode)

class Debugger(object):
    """A debugger based on standard Win32 API. Handle standard (int3) and Hardware-Exec Breakpoints"""
    def __init__(self, target):
        """``target`` must be a WinProcess.

        ``already_debuggable`` must be set to ``True`` if process is already expecting a debugger (created with ``DEBUG_PROCESS``)"""
        self._init_dispatch_handlers()
        self.target = target
        self.is_target_launched = False
        #if not already_debuggable:
        #    winproxy.DebugActiveProcess(target.pid)
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

        self._module_by_process = {}

        self._pending_breakpoints_new = defaultdict(list)

        self._explicit_single_step = {}

        self._watched_memory = []


    @classmethod
    def attach(cls, target):
        winproxy.DebugActiveProcess(target.pid)
        return cls(target)

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
        #print("DISPATCH {0}".format(DEBUG_EVENT.KNOWN_EVENT_CODE.get(debug_event.dwDebugEventCode)))
        handler = self._DebugEventCode_dispatch.get(debug_event.dwDebugEventCode, self._handle_unknown_debug_event)
        return handler(debug_event)

    def _dispatch_breakpoint(self, exception, addr):
        bp = self.breakpoints[self.current_process.pid][addr]
        x = bp.trigger(self, exception)
        return x

    def _resolve(self, addr, target):
        if not isinstance(addr, basestring):
            return addr
        dll, api = addr.split("!")
        dll = dll.lower()
        modules = self._module_by_process[target.pid]
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
        exports = mod[0].exports
        if api not in exports:
            raise ValueError("Unknown API <{0}> in DLL {1}".format(api, dll))
        return exports[api]


    def add_pending_breakpoint(self, bp, target):
        self._pending_breakpoints_new[target].append(bp)

    def _setup_breakpoint(self, bp, target):
        _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
        if target is None:
            if bp.type in [STANDARD_BP, MEMORY_BREAKPOINT]: #TODO: better..
                targets = self.processes.values()
            else:
                targets = self.threads.values()
        else:
            targets = [target]
        for target in targets:
            return _setup_method(bp, target)


    def _setup_breakpoint_BP(self, bp, target):
        if not isinstance(target, WinProcess):
            raise ValueError("SETUP STANDARD_BP on {0}".format(target))

        addr = self._resolve(bp.addr, target)
        if addr is None:
            return False
        self._memory_save[target.pid][addr] = target.read_memory(addr, 1)
        self.breakpoints[target.pid][addr] = bp
        target.write_memory(addr, "\xcc")
        return True

    def _setup_breakpoint_HXBP(self, bp, target):
        if not isinstance(target, WinThread):
            raise ValueError("SETUP HXBP_BP on {0}".format(target))
        # Todo: opti, not reparse exports for all thread of the same process..
        addr = self._resolve(bp.addr, target.owner)
        if addr is None:
            return False
        x = self._hardware_breakpoint[target.tid]
        if all(pos in x for pos in range(4)):
            raise ValueError("Cannot put {0} in {1} (DRx full)".format(bp, target))
        empty_drx = str([pos for pos in range(4) if pos not in x][0])
        ctx = target.context
        ctx.EDr7.GE = 1
        ctx.EDr7.LE = 1
        setattr(ctx.EDr7, "L" + empty_drx, 1)
        setattr(ctx, "Dr" + empty_drx, addr)
        x[int(empty_drx)] = bp
        target.set_context(ctx)
        self.breakpoints[target.owner.pid][addr] = bp
        return True

    def _setup_breakpoint_MEMBP(self, bp, target):
        addr = self._resolve(bp.addr, target)
        if addr is None:
            return False
        old_prot = DWORD()
        target.virtual_protect(addr, bp.size, bp.protect, old_prot)
        self._watched_memory.append((bp, addr, addr + bp.size, old_prot.value))
        # TODO: watch for overlap with other MEM breakpoints
        return True

    def _setup_pending_breakpoints_new_process(self, new_process):
        for bp in self._pending_breakpoints_new[None]:
            if bp.apply_to_target(new_process): #BP for thread or process ?
                _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
                _setup_method(bp, new_process)

        for bp in list(self._pending_breakpoints_new[new_process.pid]):
            if  bp.apply_to_target(new_process):
                _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
                if _setup_method(bp, new_process):
                    self._pending_breakpoints_new[new_process.pid].remove(bp)

    def _setup_pending_breakpoints_new_thread(self, new_thread):
        for bp in self._pending_breakpoints_new[None]:
            if bp.apply_to_target(new_thread): #BP for thread or process ?
                _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
                _setup_method(bp, new_thread)

        for bp in self._pending_breakpoints_new[new_thread.owner.pid]:
            if bp.apply_to_target(new_thread):
                _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
                _setup_method(bp, new_thread)

        for bp in list(self._pending_breakpoints_new[new_thread.tid]):
            _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
            if _setup_method(bp, new_thread):
                self._pending_breakpoints_new[new_thread.tid].remove(bp)


    def _setup_pending_breakpoints_load_dll(self, dll_name):
        for bp in self._pending_breakpoints_new[None]:
            if isinstance(bp.addr, basestring):
                target_dll = bp.addr.split("!")[0]
                if target_dll == dll_name:
                    _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
                    if bp.apply_to_target(self.current_process):
                        _setup_method(bp, self.current_process)
                    else:
                        for t in self.current_process.threads:
                            _setup_method(bp, t)

        for bp in self._pending_breakpoints_new[self.current_process.pid]:
            if isinstance(bp.addr, basestring):
                target_dll = bp.addr.split("!")[0]
                if target_dll == dll_name:
                    _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
                    _setup_method(bp, self.current_process)

        for thread in self.current_process.threads:
            for bp in self._pending_breakpoints_new[thread.tid]:
                if isinstance(bp.addr, basestring):
                    target_dll = bp.addr.split("!")[0]
                    if target_dll == dll_name:
                        _setup_method = getattr(self, "_setup_breakpoint_" + bp.type)
                        _setup_method(bp, self.thread)

    def _pass_breakpoint(self, addr):
        process = self.current_process
        thread = self.current_thread
        process.write_memory(addr, self._memory_save[process.pid][addr])
        regs = thread.context
        regs.EFlags |= (1 << 8)
        #regs.pc -= 1 # Done in _handle_exception_breakpoint before dispatch
        thread.set_context(regs)
        bp = self.breakpoints[self.current_process.pid][addr]
        self._breakpoint_to_reput[thread.tid].append(bp) #Register pending breakpoint for next single step

    def _pass_memory_breakpoint(self, bp, begin, end, original_prot):
        cp = self.current_process
        cp.virtual_protect(begin, bp.size, original_prot, None)
        thread = self.current_thread
        ctx = thread.context
        ctx.EEFlags.TF = 1
        thread.set_context(ctx)
        self._breakpoint_to_reput[thread.tid].append(bp)

    # debug event handlers
    def _handle_unknown_debug_event(self, debug_event):
        raise NotImplementedError("dwDebugEventCode = {0}".format(debug_event.dwDebugEventCode))


    def _handle_exception_breakpoint(self, exception, excp_addr):
        if excp_addr in self.breakpoints[self.current_process.pid]:
            thread = self.current_thread
            ctx = thread.context
            ctx.pc -= 1
            thread.set_context(ctx)
            continue_flag = self._dispatch_breakpoint(exception, excp_addr)
            self._explicit_single_step[self.current_thread.tid] = self.current_thread.context.EEFlags.TF
            self._pass_breakpoint(excp_addr)
            return continue_flag
        return self.on_exception(exception)

    # TODO: mov me
    def _restore_breakpoints(self):
        for bp in self._breakpoint_to_reput[self.current_thread.tid]:
            #print("TODO: restore {0}".format(bp))
            if bp.type == HARDWARE_EXEC_BP:
                raise NotImplementedError("Why is this here ? we use RF flags to pass HXBP")
            #print("[RST] Restoring <{0}>".format(bp))
            self._setup_breakpoint(bp, self.current_process)
        del self._breakpoint_to_reput[self.current_thread.tid][:]
        return


    def _handle_exception_singlestep(self, exception, excp_addr):
        if self.current_thread.tid in self._breakpoint_to_reput and self._breakpoint_to_reput[self.current_thread.tid]:
            self._restore_breakpoints()
            if self._explicit_single_step[self.current_thread.tid]:
                self.on_single_step(exception) # TODO: default implem / dispatcher ?
            self._explicit_single_step[self.current_thread.tid] = self.current_thread.context.EEFlags.TF
            return DBG_CONTINUE
        elif excp_addr in self.breakpoints[self.current_process.pid]:
            # Verif that's not a standard BP ?
            bp = self.breakpoints[self.current_process.pid][excp_addr]
            bp.trigger(self, exception)
            ctx = self.current_thread.context
            self._explicit_single_step[self.current_thread.tid] = ctx.EEFlags.TF
            ctx.EEFlags.RF = 1
            self.current_thread.set_context(ctx)
            return DBG_CONTINUE
        elif self._explicit_single_step[self.current_thread.tid]:
            continue_flag = self.on_single_step(exception)
            return continue_flag # TODO: default implem / dispatcher ?
        else:
            continue_flag = self.on_exception(exception)
            self._explicit_single_step[self.current_thread.tid] = self.current_thread.context.EEFlags.TF
            return continue_flag

    def _handle_exception_access_violation(self, exception, excp_addr):
        READ = 0
        WRITE = 1
        EXEC = 2

        fault_type = exception.ExceptionRecord.ExceptionInformation[0]
        fault_addr = exception.ExceptionRecord.ExceptionInformation[1]
        pc_addr = self.current_thread.context.pc
        if fault_addr == pc_addr:
            fault_type = EXEC

        #print("FAULT AT {0:#x} ({1})".format(fault_addr, fault_type))
        for bp, begin, end, original_prot in self._watched_memory:
            if begin <= fault_addr < end:
                ## Reject bad EXCEPTION ?
                #if fault_type == EXEC and bp.PROTECT not in [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE]:
                #    break
                #if fault_type == READ and bp.PROTECT not in [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE]:
                #    break
                #if fault_type == EXEC and bp.PROTECT not in [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE]:
                #    break



                #print("BP MEM TRIGGER {0}".format(bp))
                continue_flag = bp.trigger(self, exception)
                self._explicit_single_step[self.current_thread.tid] = self.current_thread.context.EEFlags.TF
                self._pass_memory_breakpoint(bp, begin, end, original_prot)
                return continue_flag
        else:
            self.on_exception(exception)


    # TODO: self._explicit_single_step setup by single_step() ? check at the end ? finally ?
    def _handle_exception(self, debug_event):
        """Handle EXCEPTION_DEBUG_EVENT"""
        exception = debug_event.u.Exception
        self._update_debugger_state(debug_event)

        if windows.current_process.bitness == 32:
            exception.__class__ = winexception.EEXCEPTION_DEBUG_INFO32
        else:
            exception.__class__ = winexception.EEXCEPTION_DEBUG_INFO64

        excp_code = exception.ExceptionRecord.ExceptionCode
        excp_addr = exception.ExceptionRecord.ExceptionAddress

        #print("[DBG] Got a <{0}> in <{1}>".format(excp_code, self.current_thread.tid))

        if excp_code in [EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT] and excp_addr in self.breakpoints[self.current_process.pid]:
            return self._handle_exception_breakpoint(exception, excp_addr)
        elif excp_code in [EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP]:
            return self._handle_exception_singlestep(exception, excp_addr)
        elif excp_code in [EXCEPTION_ACCESS_VIOLATION]:
            return self._handle_exception_access_violation(exception, excp_addr)
        else:
            continue_flag = self.on_exception(exception)
            self._explicit_single_step[self.current_thread.tid] = self.current_thread.context.EEFlags.TF
            return continue_flag


    def _get_loaded_dll(self, load_dll):
        name_sufix = ""
        pe = windows.pe_parse.GetPEFile(load_dll.lpBaseOfDll, self.current_process)
        if self.current_process.bitness == 32 and pe.bitness == 64:
            name_sufix = "64"

        if not load_dll.lpImageName:
            return pe.export_name + name_sufix
        try:
            addr = self.current_process.read_ptr(load_dll.lpImageName)
        except:
            addr = None

        if not addr:
            pe = windows.pe_parse.GetPEFile(load_dll.lpBaseOfDll, self.current_process)
            return pe.export_name + name_sufix

        if load_dll.fUnicode:
            return self.current_process.read_wstring(addr) + name_sufix
        return self.current_process.read_string(addr) + name_sufix

    def _handle_create_process(self, debug_event):
        """Handle CREATE_PROCESS_DEBUG_EVENT"""
        create_process = debug_event.u.CreateProcessInfo

        self.current_process = WinProcess._from_handle(create_process.hProcess)
        self.current_thread = WinThread._from_handle(create_process.hThread)
        self.threads[self.current_thread.tid] = self.current_thread
        self._explicit_single_step[self.current_thread.tid] = False
        self._breakpoint_to_reput[self.current_thread.tid] = []
        self.processes[self.current_process.pid] = self.current_process
        self.breakpoints[self.current_process.pid] = {}
        self._module_by_process[self.current_process.pid] = {}
        self._update_debugger_state(debug_event)
        self._setup_pending_breakpoints_new_process(self.current_process)
        self._setup_pending_breakpoints_new_thread(self.current_thread)
        return self.on_create_process(create_process)
        # TODO: clode hFile

    def _handle_exit_process(self, debug_event):
        """Handle EXIT_PROCESS_DEBUG_EVENT"""
        self._update_debugger_state(debug_event)
        exit_process = debug_event.u.ExitProcess
        retvalue = self.on_exit_process(exit_process)
        del self.threads[self.current_thread.tid]
        del self._explicit_single_step[self.current_thread.tid]
        del self._breakpoint_to_reput[self.current_thread.tid]
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
        self._explicit_single_step[self.current_thread.tid] = False
        self._breakpoint_to_reput[self.current_thread.tid] = []
        self._setup_pending_breakpoints_new_thread(self.current_thread)
        return self.on_create_thread(create_thread)


    def _handle_exit_thread(self, debug_event):
        """Handle EXIT_THREAD_DEBUG_EVENT"""
        self._update_debugger_state(debug_event)
        exit_thread = debug_event.u.ExitThread
        retvalue = self.on_exit_thread(exit_thread)
        del self.threads[self.current_thread.tid]
        del self._explicit_single_step[self.current_thread.tid]
        del self._breakpoint_to_reput[self.current_thread.tid]
        # Hack IT, ContinueDebugEvent will close the HANDLE for us
        # Should we make another handle instead ?
        dbgprint("Removing handle {0} for {1} (will be closed by continueDebugEvent".format(hex(self.current_thread._handle), self.current_thread), "HANDLE")
        del self.current_thread._handle
        return retvalue

    def _handle_load_dll(self, debug_event):
        """Handle LOAD_DLL_DEBUG_EVENT"""
        self._update_debugger_state(debug_event)
        load_dll = debug_event.u.LoadDll
        dll = self._get_loaded_dll(load_dll)
        dll_name = os.path.basename(dll).lower()
        self._module_by_process[self.current_process.pid][dll_name] = windows.pe_parse.GetPEFile(load_dll.lpBaseOfDll, self.current_process)
        self._setup_pending_breakpoints_load_dll(dll_name)
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
        """Debugging loop: handle event / dispatch to breakpoint. Returns when all targets are dead"""
        for debug_event in self._debug_event_generator():
            dbg_continue_flag = self._dispatch_debug_event(debug_event)
            if dbg_continue_flag is None:
                dbg_continue_flag = DBG_CONTINUE
            self._finish_debug_event(debug_event, dbg_continue_flag)
            if not self.processes:
                break

    def add_bp(self, bp, addr=None, type=None, target=None):
        """Add a breakpoint, bp can be:

            * a :class:`Breakpoint` (addr and type must be None)
            * any callable (addr and type must NOT be None) (NON-TESTED)

            If the ``bp`` type is ``STANDARD_BP``, target can be None (all targets) or a process.

            If the ``bp`` type is ``HARDWARE_EXEC_BP``, target can be None (all targets), a process or a thread.
        """
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
            # Need to add it to all other breakpoint
            self.add_pending_breakpoint(bp, None)
        elif target is not None:
            # Check that targets are accepted
            if target not in self.processes.values() + self.threads.values():
                if target == self.target: # Original target (that have not been lauched yet)
                    return self.add_pending_breakpoint(bp, target)
                else:
                    raise ValueError("Unknown target {0}".format(target))
        return self._setup_breakpoint(bp, target)

    def single_step(self):
        t = self.current_thread
        ctx = t.context
        ctx.EEFlags.TF = 1
        t.set_context(ctx)

    # Public callback
    def on_exception(self, exception):
        """Called on exception event other that known breakpoint. ``exception`` is one of the following type:

                * :class:`windows.winobject.exception.EEXCEPTION_DEBUG_INFO32`
                * :class:`windows.winobject.exception.EEXCEPTION_DEBUG_INFO64`

           The default behaviour is to return ``DBG_CONTINUE`` for the known exception code
           and ``DBG_EXCEPTION_NOT_HANDLED`` else
        """
        if not exception.ExceptionRecord.ExceptionCode in winexception.exception_name_by_value:
            return DBG_EXCEPTION_NOT_HANDLED
        return DBG_CONTINUE

    def on_single_step(self, exception):
        raise NotImplementedError("Debugger that explicitly single step should implement <on_single_step>")

    def on_create_process(self, create_process):
        """Called on create_process event (for param type see https://msdn.microsoft.com/en-us/library/windows/desktop/ms679286(v=vs.85).aspx)"""
        pass

    def on_exit_process(self, exit_process):
        """Called on exit_process event (for param type see https://msdn.microsoft.com/en-us/library/windows/desktop/ms679334(v=vs.85).aspx)"""
        pass

    def on_create_thread(self, create_thread):
        """Called on create_thread event (for param type see https://msdn.microsoft.com/en-us/library/windows/desktop/ms679287(v=vs.85).aspx)"""
        pass

    def on_exit_thread(self, exit_thread):
        """Called on exit_thread event (for param type see https://msdn.microsoft.com/en-us/library/windows/desktop/ms679335(v=vs.85).aspx)"""
        pass

    def on_load_dll(self, load_dll):
        """Called on load_dll event (for param type see https://msdn.microsoft.com/en-us/library/windows/desktop/ms680351(v=vs.85).aspx)"""
        pass

    def on_unload_dll(self, unload_dll):
        """Called on unload_dll event (for param type see https://msdn.microsoft.com/en-us/library/windows/desktop/ms681403(v=vs.85).aspx)"""
        pass

    def on_output_debug_string(self, debug_string):
        """Called on debug_string event (for param type see https://msdn.microsoft.com/en-us/library/windows/desktop/ms680545(v=vs.85).aspx)"""
        pass

    def on_rip(self, rip_info):
        """Called on rip_info event (for param type see https://msdn.microsoft.com/en-us/library/windows/desktop/ms680587(v=vs.85).aspx)"""
        pass

def debug(path, args=None, dwCreationFlags=0, show_windows=False):
    dwCreationFlags |= DEBUG_PROCESS
    c = windows.utils.create_process(path, args=args, dwCreationFlags=dwCreationFlags, show_windows=show_windows)
    return Debugger(c)


class Breakpoint(object):
    """An standard (Int3) breakpoint (type == ``STANDARD_BP``)"""
    type = STANDARD_BP # REAL BP
    def __init__(self, addr):
        self.addr = addr

    def apply_to_target(self, target):
        return isinstance(target, WinProcess)

    def trigger(self, dbg, exception):
        """Called when breakpoint is hit"""
        pass


class ProxyBreakpoint(Breakpoint):
    def __init__(self, target, addr, type):
        self.target = target
        self.addr = addr
        self.type = type

    def trigger(self, dbg, exception):
        return self.target(dbg, exception)


class HXBreakpoint(Breakpoint):
    """An hardware-execution breakpoint (type == ``HARDWARE_EXEC_BP``)"""
    type = HARDWARE_EXEC_BP

    def apply_to_target(self, target):
        return isinstance(target, WinThread)

class MemoryBreakpoint(Breakpoint):
    type = MEMORY_BREAKPOINT

    DEFAULT_PROTECT = PAGE_READONLY
    DEFAULT_SIZE = 0x1000
    def __init__(self, addr, size=None, prot=None):
        super(MemoryBreakpoint, self).__init__(addr)
        self.size = size if size is not None else self.DEFAULT_SIZE
        self.protect = size if prot is not None else self.DEFAULT_PROTECT


    def trigger(self, dbg, exception):
        """Called when breakpoint is hit"""
        pass


class LocalDebugger(object):
    """A debugger interface around :func:`AddVectoredExceptionHandler`"""
    def __init__(self):
        self.breakpoints = {}
        self._memory_save = {}
        self._reput_breakpoint = {}
        self._hxbp_breakpoint = defaultdict(dict)

        self.callback_vectored = winexception.VectoredException(self.callback)
        winproxy.AddVectoredExceptionHandler(0, self.callback_vectored)
        self.setup_hxbp_callback_vectored =  winexception.VectoredException(self.setup_hxbp_callback)
        self.hxbp_info = None
        self.code = windows.native_exec.create_function("\xcc\xc3", [PVOID])
        self.veh_depth = 0
        self.current_exception = None
        self.exceptions_stack = [None]

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
            self._memory_save[bp.addr] = windows.current_process.read_memory(bp.addr, 1)
            with windows.utils.VirtualProtected(bp.addr, 1, PAGE_EXECUTE_READWRITE):
                windows.current_process.write_memory(bp.addr, "\xcc")
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

    def del_bp(self, bp):
        if bp.type == STANDARD_BP:
            with windows.utils.VirtualProtected(bp.addr, 1, PAGE_EXECUTE_READWRITE):
                windows.current_process.write_memory(bp.addr, self._memory_save[bp.addr])
            del self._memory_save[bp.addr]
            del self.breakpoints[bp.addr]
            return
        if bp.type == HARDWARE_EXEC_BP:
            for tid in self._hxbp_breakpoint:
                if bp.addr in self._hxbp_breakpoint[tid] and self._hxbp_breakpoint[tid][bp.addr] == bp:
                    if tid == windows.current_thread.tid:
                        self.remove_hxbp_self_thread(bp.addr)
                    else:
                        self.remove_hxbp_other_thread(bp.addr)
                    del self._hxbp_breakpoint[tid][bp.addr]
                    #print("Need to remove {0} in {1}".format(self._hxbp_breakpoint[tid][bp.addr], tid))
            return
        raise NotImplementedError("Unknow BP type {0}".format(bp.type))

    def add_bp(self, bp, targets=None):
        """Add a breakpoint, bp is a "class:`Breakpoint`

            If the ``bp`` type is ``STANDARD_BP``, target must be None.

            If the ``bp`` type is ``HARDWARE_EXEC_BP``, target can be None (all threads), or some threads of the process
        """
        if bp.type == HARDWARE_EXEC_BP:
            return self.add_bp_hxbp(bp, targets)
        if bp.type != STANDARD_BP:
            raise NotImplementedError("Unknow BP type {0}".format(bp.type))
        if targets is not None:
            raise ValueError("LocalDebugger: STANDARD_BP doest not support targets {0}".format(targets))
        self.breakpoints[bp.addr] = bp
        self._memory_save[bp.addr] = windows.current_process.read_memory(bp.addr, 1)
        with windows.utils.VirtualProtected(bp.addr, 1, PAGE_EXECUTE_READWRITE):
            windows.current_process.write_memory(bp.addr, "\xcc")
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
            context = self.get_exception_context()
            exp_addr = context.pc
            hxbp_used = self.setup_hxbp_in_context(context, self.data)
            windows.current_process.write_memory(exp_addr, "\x90")
            # Raising in the VEH is a bad idea..
            # So better give the information to triggerer..
            if hxbp_used is not None:
                self.get_exception_context().Eax = exp_addr
            else:
                self.get_exception_context().Eax = 0
            return windef.EXCEPTION_CONTINUE_EXECUTION

    def remove_hxbp_callback(self, exc):
        with self.NewCurrentException(exc):
            exp_code = self.get_exception_code()
            context = self.get_exception_context()
            exp_addr = context.pc
            hxbp_used = self.remove_hxbp_in_context(context, self.data)
            windows.current_process.write_memory(exp_addr, "\x90")
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
            windows.current_process.write_memory(x, "\xcc")
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
            windows.current_process.write_memory(x, "\xcc")
        return

    def remove_hxbp_other_thread(self, addr, thread):
        thread.suspend()
        ctx = thread.context
        x = self.remove_hxbp_in_context(ctx, addr)
        if x is None:
            raise ValueError("Could not setup HXBP in {0}".format(thread))
        thread.set_context(ctx)
        thread.resume()