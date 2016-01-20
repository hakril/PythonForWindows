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
        winproxy.DebugActiveProcess(target.pid)

        self.processes = {}
        self.threads = {}
        self.current_process = None
        self.current_thread = None

    def _debug_event_generator(self):
        while True:
            debug_event = DEBUG_EVENT()
            winproxy.WaitForDebugEvent(debug_event)
            yield debug_event

    def _finish_debug_event(self, event, action):
        if action not in [windef.DBG_CONTINUE, windef.DBG_EXCEPTION_NOT_HANDLED]:
            raise ValueError('Unknow action : <0>'.format(action))
        winproxy.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, action)

    def loop(self):
        for x, debug_event in enumerate(self._debug_event_generator()):
            #print(debug_event, debug_event.code)
            self._dispatch_debug_event(debug_event)
            self._finish_debug_event(debug_event, windef.DBG_CONTINUE)
            # TODO: exit on process exit

    def _update_debugger_state(self, debug_event):
        self.current_process = self.processes[debug_event.dwProcessId]
        self.current_thread = self.threads[debug_event.dwThreadId]

    def _dispatch_debug_event(self, debug_event):
        handler = self.dwDebugEventCode_handlers.get(debug_event.dwDebugEventCode, self._handle_unknown_debug_event)
        return handler(self, debug_event)

    @staticmethod
    def _handle_unknown_debug_event(self, debug_event):
        raise NotImplementedError("dwDebugEventCode = {0}".format(debug_event.dwDebugEventCode))

    @handle_dwDebugEventCode(EXCEPTION_DEBUG_EVENT)
    def _handle_exception(self, debug_event):
        print("_handle_exception")
        self._update_debugger_state(debug_event)

    @handle_dwDebugEventCode(CREATE_THREAD_DEBUG_EVENT)
    def _handle_create_thread(self, debug_event):
        print("_handle_create_thread")
        create_thread = debug_event.u.CreateThread
        self.current_thread = WinThread._from_handle(create_thread.hThread)
        self.threads[self.current_thread.tid] = self.current_thread

    @handle_dwDebugEventCode(CREATE_PROCESS_DEBUG_EVENT)
    def _handle_create_process(self, debug_event):
        print("_handle_create_process")
        create_process = debug_event.u.CreateProcessInfo

        self.current_process = WinProcess._from_handle(create_process.hProcess)
        self.current_thread = WinThread._from_handle(create_process.hThread)
        # TODO: verif debug_event.dwProcessId for REAL process creation :)
        # Voir ce qu'on fout en current ? le parent ? (!le fils ?)
        self.threads[self.current_thread.tid] = self.current_thread
        self.processes[self.current_process.pid] = self.current_process
        self._update_debugger_state(debug_event)


    @handle_dwDebugEventCode(EXIT_PROCESS_DEBUG_EVENT)
    def _handle_exit_process(self, debug_event):
        self._update_debugger_state(debug_event)
        del self.processes[self.current_process.pid]
        print("Remove PID {0}".format(self.current_process.pid))
        print("Bye")
        exit()

    @handle_dwDebugEventCode(EXIT_THREAD_DEBUG_EVENT)
    def _handle_exit_thread(self, debug_event):
        self._update_debugger_state(debug_event)
        del self.threads[self.current_thread.tid]
        print("Remove TID {0}".format(self.current_thread.tid))

    @handle_dwDebugEventCode(LOAD_DLL_DEBUG_EVENT)
    def _handle_load_dll(self, debug_event):
        self._update_debugger_state(debug_event)
        load_dll = debug_event.u.LoadDll
        print("_handle_load_dll")

    @handle_dwDebugEventCode(UNLOAD_DLL_DEBUG_EVENT)
    def _handle_unload_dll(self, debug_event):
        self._update_debugger_state(debug_event)
        pass
        print("_handle_unload_dll")

    @handle_dwDebugEventCode(OUTPUT_DEBUG_STRING_EVENT)
    def _handle_output_debug_string(self, debug_event):
        self._update_debugger_state(debug_event)
        pass
        print("_handle_output_debug_string")

    @handle_dwDebugEventCode(RIP_EVENT)
    def _handle_rip(self, debug_event):
        self._update_debugger_state(debug_event)
        pass
        print("_handle_rip")
