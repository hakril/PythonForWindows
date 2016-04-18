import ctypes
import windows
import windows.debug
from windows.generated_def.winstructs import *

ct = windows.current_thread
t = [t for t in windows.current_process.threads if t.tid == ct.tid][0]



class YoloDebugger(windows.debug.LocalDebugger):
    def __init__(self, single_step_count):
        super(YoloDebugger, self).__init__()
        self.single_step_count = single_step_count

    def on_exception(self, exc):
        code = self.get_exception_code()
        context = self.get_exception_context()
        print("EXCEPTION !!!! Got a {0} at 0x{1:x}".format(code, context.pc))
        if self.single_step_count:
            self.single_step_count -= 1
            return self.single_step()
        return EXCEPTION_CONTINUE_EXECUTION


class YoloHXBP(windows.debug.HXBreakpoint):
    def trigger(self, dbg, exc):
        context = dbg.get_exception_context()
        print("GOT AN HXBP <3 at 0x{0:x}".format(context.pc))
        windows.current_process.write_memory(self.addr, "\x90\x90")
        return dbg.single_step()

print("Your main thread is {0}".format(windows.current_thread.tid))


d = YoloDebugger(5)
# Infinite loop + nop + ret

addr = windows.native_exec.native_function.allocator.write_code("\xeb\xfe\x90\x90\x90\x90\xc3")
func_type = ctypes.CFUNCTYPE(PVOID)
func = func_type(addr)

print("Code addr = 0x{0:x}".format(addr))

t = windows.current_process.create_thread(addr, 0)

d.add_bp(YoloHXBP(addr))

t.wait()


