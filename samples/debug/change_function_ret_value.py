import sys
import os.path
import pprint
import threading
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.test
import windows.debug
import windows.generated_def as gdef

# The debugge python will just print the result of
# 3 call to IsDebuggerPresent
TARGET_PYTHON_CODE = '"\
import ctypes;\
import time;\
IsDebuggerPresent = ctypes.windll.kernel32.IsDebuggerPresent;\
print(\'[DEBUGGE] IsDebuggerPresent={0}\'.format(IsDebuggerPresent()));\
time.sleep(1);\
print(\'[DEBUGGE] IsDebuggerPresent={0}\'.format(IsDebuggerPresent()));\
time.sleep(1);\
print(\'[DEBUGGE] IsDebuggerPresent={0}\'.format(IsDebuggerPresent()));\
"'

# This breakpoint now nothing about its target argument
# It only now how to break at the return of the function
# This allow us to change the return value of any function
class IncrementReturnValue(windows.debug.FunctionCallBP):
    def __init__(self, addr, initialvalue):
        super(IncrementReturnValue, self).__init__(addr)
        self.initialvalue = initialvalue

    def trigger(self, dbg, exc):
        # Ask to break a the return of the function
        # callback is ret_trigger
        self.break_on_ret(dbg, exc)

    def ret_trigger(self, dbg, exc):
        ctx = dbg.current_thread.context
        # Func result is an alias to EAX/RAX
        ctx.func_result = self.initialvalue
        # Set the new context for the target thread
        dbg.current_thread.set_context(ctx)
        self.initialvalue += 1

d = windows.debug.Debugger.debug(sys.executable, [sys.executable, "-c", TARGET_PYTHON_CODE])
# We could also give the direct address of the function
# But it would require to wait for the module to be loaded
d.add_bp(IncrementReturnValue("kernelbase!IsDebuggerPresent", 42))
d.loop()

