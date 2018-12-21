import windows.debug

class MySetupDebugger(windows.debug.Debugger):
    def on_setup(self):
        super(MySetupDebugger, self).on_setup()
        print("Setup called: {0}".format(self.current_process))

    def on_exception(self, exc):
        print("Exception: {0}".format(exc.ExceptionRecord.ExceptionCode))

    def on_exit_process(self, evt):
        print("Process exit: {0}".format(self.current_process))

class SimpleDebugger(windows.debug.Debugger):
    def on_exception(self, exc):
        print("Exception: {0}".format(exc.ExceptionRecord.ExceptionCode))

    def on_exit_process(self, evt):
        print("Process exit: {0}".format(self.current_process))



print("== With on_setup ==")
dbg = MySetupDebugger.debug(r"c:\windows\system32\whoami.exe")
dbg.loop()

print("\n== Without on_setup ==")
dbg = SimpleDebugger.debug(r"c:\windows\system32\whoami.exe")
dbg.loop()