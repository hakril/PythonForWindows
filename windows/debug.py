import windows
import windows.winproxy as winproxy

from windows.winobject import WinProcess, WinThread

import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

from windows.generated_def.winstructs import *
from .generated_def import windef


class DEBUG_EVENT(DEBUG_EVENT):
    KNOWN_EVENT_CODE = dict((x,x) for x in [EXCEPTION_DEBUG_EVENT,
        CREATE_THREAD_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT,
        EXIT_THREAD_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
        UNLOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT])

    @property
    def code(self):
        return self.KNOWN_EVENT_CODE.get(self.dwDebugEventCode, self.dwDebugEventCode)

class Debugger(object):

    dwDebugEventCode_handlers = {}

    def handle_dwDebugEventCode(code_number, d=dwDebugEventCode_handlers):
        def wrapper(f):
            d[code_number] = (f)
            return f
        return wrapper

    def __init__(self, target):
    # Todo: accept PID / String / WinProcess
        self.target = target
        #winproxy.DebugActiveProcess(target.pid)
        self.processes = {}
        self.threads = {}
        self.current_process = None
        self.current_thread = None

        self.breakpoints = {}
        self._break_metadata = {}

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
        handler = self.dwDebugEventCode_handlers.get(debug_event.dwDebugEventCode, self._handle_unknown_debug_event)
        return handler(self, debug_event)

    def _dispatch_breakpoint(self, exception, addr):
        bp = self.breakpoints[addr]
        return bp(exception)

    def _setup_breakpoint(self, addr, type, target):
        if type != 0:
            raise NotImplementedError("BP TYPE != 0 (TODO)")
        if target is None:
            targets = self.processes.items()
        else:
            targets = [(target.pid, target)]
        for pid, process in targets:
            self._break_metadata[pid] = process.read_memory(addr, 1)
            print("Write BP: {0} at {1}".format(process, addr))
            process.write_memory(addr, "\xcc")
        return

    @staticmethod
    def _handle_unknown_debug_event(self, debug_event):
        raise NotImplementedError("dwDebugEventCode = {0}".format(debug_event.dwDebugEventCode))

    @handle_dwDebugEventCode(EXCEPTION_DEBUG_EVENT)
    def _handle_exception(self, debug_event):
        exception = debug_event.u.Exception
        self._update_debugger_state(debug_event)
        if self.current_process.bitness == 32:
            exception.__class__ = windows.vectored_exception.EEXCEPTION_DEBUG_INFO32
        else:
            exception.__class__ = windows.vectored_exception.EEXCEPTION_DEBUG_INFO64

        excp_code = exception.ExceptionRecord.ExceptionCode
        excp_addr = exception.ExceptionRecord.ExceptionAddress

        if excp_code == EXCEPTION_BREAKPOINT and excp_addr in self.breakpoints:
            self._dispatch_breakpoint(exception, excp_addr)
        else: # Do not trigger self.on_exception if breakpoint was registered
            self.on_exception(exception)



    @handle_dwDebugEventCode(CREATE_THREAD_DEBUG_EVENT)
    def _handle_create_thread(self, debug_event):
        create_thread = debug_event.u.CreateThread
        self.current_thread = WinThread._from_handle(create_thread.hThread)
        self.threads[self.current_thread.tid] = self.current_thread
        self.on_create_thread(create_thread)

    @handle_dwDebugEventCode(CREATE_PROCESS_DEBUG_EVENT)
    def _handle_create_process(self, debug_event):
        create_process = debug_event.u.CreateProcessInfo

        self.current_process = WinProcess._from_handle(create_process.hProcess)
        self.current_thread = WinThread._from_handle(create_process.hThread)
        self.threads[self.current_thread.tid] = self.current_thread
        self.processes[self.current_process.pid] = self.current_process
        self._update_debugger_state(debug_event)
        self.on_create_process(create_process)
        # TODO: clode hFile

    @handle_dwDebugEventCode(EXIT_PROCESS_DEBUG_EVENT)
    def _handle_exit_process(self, debug_event):
        self._update_debugger_state(debug_event)
        exit_process = debug_event.u.ExitProcess
        self.on_exit_process(exit_process)
        del self.processes[self.current_process.pid]
        # Hack IT, ContinueDebugEvent will close the HANDLE for us
        # Should we make another handle instead ?
        del self.current_process._handle


    @handle_dwDebugEventCode(EXIT_THREAD_DEBUG_EVENT)
    def _handle_exit_thread(self, debug_event):
        self._update_debugger_state(debug_event)
        exit_thread = debug_event.u.ExitThread
        self.on_exit_thread(exit_thread)
        del self.threads[self.current_thread.tid]
        # Hack IT, ContinueDebugEvent will close the HANDLE for us
        # Should we make another handle instead ?
        del self.current_thread._handle

    @handle_dwDebugEventCode(LOAD_DLL_DEBUG_EVENT)
    def _handle_load_dll(self, debug_event):
        self._update_debugger_state(debug_event)
        load_dll = debug_event.u.LoadDll
        self.on_load_dll(load_dll)

    @handle_dwDebugEventCode(UNLOAD_DLL_DEBUG_EVENT)
    def _handle_unload_dll(self, debug_event):
        self._update_debugger_state(debug_event)
        unload_dll = debug_event.u.UnloadDll
        self.on_unload_dll(unload_dll)

    @handle_dwDebugEventCode(OUTPUT_DEBUG_STRING_EVENT)
    def _handle_output_debug_string(self, debug_event):
        self._update_debugger_state(debug_event)
        debug_string = debug_event.u.DebugString
        self.on_output_debug_string(debug_string)

    @handle_dwDebugEventCode(RIP_EVENT)
    def _handle_rip(self, debug_event):
        self._update_debugger_state(debug_event)
        rip_info = debug_event.u.RipInfo
        self.on_rip(rip_info)

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

    # Public API

    def loop(self):
        for x, debug_event in enumerate(self._debug_event_generator()):
            self._dispatch_debug_event(debug_event)
            self._finish_debug_event(debug_event, windef.DBG_CONTINUE)
            if not self.processes:
                # No More process to debug
                break

    def add_bp(self, bp, addr=None, target=None):
        """TODO: use type for hardware breakpoints"""
        if getattr(bp, "addr", None) is not None:
            self.breakpoints[bp.addr] = bp.trigger
            self._setup_breakpoint(addr, bp.type, target)
            return

        # Non object breakpoint
        if addr is None:
            raise ValueError("No address: need a valid <bp.addr> or <addr> parameter")
        self.breakpoints[addr] = bp
        self._setup_breakpoint(addr, bp.type, target)
        return True


class Breakpoint(object):
    type = 0 # REAL BP
    def __init__(self, addr):
        self.addr = addr

    def trigger(self, exception):
        pass

