import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.test
import windows.debug

import windows.native_exec.simple_x86 as x86
from windows.generated_def.winstructs import *


class MyDebugger(windows.debug.Debugger):
    def __init__(self, *args, **kwargs):
        super(MyDebugger, self).__init__(*args, **kwargs)
        self.single_step_counter = 0

    def on_exception(self, exception):
        code = exception.ExceptionRecord.ExceptionCode
        addr = exception.ExceptionRecord.ExceptionAddress
        print("Got exception {0} at 0x{1:x}".format(code, addr))

    def on_single_step(self, exception):
        code = exception.ExceptionRecord.ExceptionCode
        addr = exception.ExceptionRecord.ExceptionAddress
        print("Got single_step {0} at 0x{1:x}".format(code, addr))
        self.single_step_counter -= 1
        if self.single_step_counter > 0:
            return self.single_step()
        else:
            print("No more single step: exiting")
            self.current_process.exit()


class SingleStepOnWrite(windows.debug.MemoryBreakpoint):
    """Check that BP/dbg can trigger single step and that instruction follows"""
    def trigger(self, dbg, exc):
        fault_addr = exc.ExceptionRecord.ExceptionInformation[1]
        eip = dbg.current_thread.context.pc
        print("Instruction at <{0:#x}> wrote at <{1:#x}>".format(eip, fault_addr))
        dbg.single_step_counter = 4
        return dbg.single_step()


calc = windows.test.pop_proc_32(dwCreationFlags=DEBUG_PROCESS)
d = MyDebugger(calc)

code = calc.virtual_alloc(0x1000)
data = calc.virtual_alloc(0x1000)

injected = x86.MultipleInstr()
injected += x86.Mov("EAX", 0)
injected += x86.Mov(x86.deref(data), "EAX")
injected += x86.Add("EAX", 4)
injected += x86.Mov(x86.deref(data + 4), "EAX")
injected += x86.Add("EAX", 8)
injected += x86.Mov(x86.deref(data + 8), "EAX")
injected += x86.Nop()
injected += x86.Nop()
injected += x86.Ret()

calc.write_memory(code, injected.get_code())
d.add_bp(SingleStepOnWrite(data, size=8, events="W"))
calc.create_thread(code, 0)
d.loop()

