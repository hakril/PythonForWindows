import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.debug
from windows.generated_def.winstructs import *
import windows.native_exec.simple_x86 as x86

class SingleSteppingDebugger(windows.debug.LocalDebugger):
    SINGLE_STEP_COUNT = 4
    def on_exception(self, exc):
        code = self.get_exception_code()
        context = self.get_exception_context()
        print("EXCEPTION !!!! Got a {0!r} at 0x{1:x}".format(code, context.pc))
        self.SINGLE_STEP_COUNT -= 1
        if self.SINGLE_STEP_COUNT:
            return self.single_step()
        return EXCEPTION_CONTINUE_EXECUTION

class RewriteBreakpoint(windows.debug.HXBreakpoint):
    def trigger(self, dbg, exc):
        context = dbg.get_exception_context()
        print("GOT AN HXBP at 0x{0:x}".format(context.pc))
        # Rewrite the infinite loop with 2 nop
        windows.current_process.write_memory(self.addr, b"\x90\x90")
        # Ask for a single stepping
        return dbg.single_step()


d = SingleSteppingDebugger()
# Infinite loop + nop + ret
code = x86.assemble("label :begin; jmp :begin; nop; ret")
func = windows.native_exec.create_function(code, [PVOID])
print("Code addr = 0x{0:x}".format(func.code_addr))
# Create a thread that will infinite loop
t = windows.current_process.create_thread(func.code_addr, 0)
# Add a breakpoint on the infitine loop
d.add_bp(RewriteBreakpoint(func.code_addr))
t.wait()
print("Done!")


