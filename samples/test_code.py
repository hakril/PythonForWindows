import sys

import windows
import windows.test
import windows.debug as dbg
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64
from windows.generated_def import *

def hexdump(string, start_addr=0):
    result = ""
    if len(string) == 0:
        return
    ascii = list("."*256)
    for i in range(1,0x7f):
        ascii[i] = chr(i)
    ascii[0x0] = "."
    ascii[0x7] = "."
    ascii[0x8] = "."
    ascii[0x9] = "."
    ascii[0xa] = "."
    ascii[0x1b] = "."
    ascii[0xd] = "."
    ascii[0xff] = "\x13"
    ascii = "".join(ascii)
    offset = 0
    while (offset+0x10) <= len(string):
        line = string[offset:(offset+0x10)]
        linebuf = " %08X " % (offset + start_addr)
        for i in range(0,16):
            if i == 8:
                linebuf += " "
            linebuf += "%02X " % ord(line[i])
        linebuf += " "
        for i in range(0,16):
            linebuf += ascii[ord(line[i])]
        result += linebuf+"\n"
        offset += 0x10
    if (len(string) % 0x10) > 0:
        linebuf = " %08X " % (offset + start_addr)
        for i in range((len(string)-(len(string) % 0x10)),(len(string))):
            if i == 8:
                linebuf += " "
            linebuf += "%02X " % ord(string[i])
        linebuf += "   "*(0x10-(len(string) % 0x10))
        linebuf += " "
        for i in range((len(string)-(len(string) % 0x10)),(len(string))):
            linebuf += ascii[ord(string[i])]
        result += linebuf+"\n"
    return result


class CodeTesteur(dbg.Debugger):
    def __init__(self, process, code, register_start={}):
        super(CodeTesteur, self).__init__(process, already_debuggable=True)

        self.initial_code = code
        code += "\xcc"

        code_addr = self.write_code_in_target(process, code)
        register_start["pc"] = code_addr
        self.thread_exec = process.threads[0]
        self.context_exec = self.thread_exec.context
        self.setup_target_context(self.context_exec, register_start)
        print("Startup context is:")
        self.context_exec.dump()
        print(self.context_exec.EEFlags)
        self.thread_exec.suspend()
        self.thread_exec.set_context(self.context_exec)
        self.thread_exec.resume()
        self.init_breakpoint = False

    def write_code_in_target(self, process, code):
        addr = process.virtual_alloc(len(code))
        process.write_memory(addr, code)
        return addr

    def setup_target_context(self, ctx, register_start):
        for name, value in register_start.items():
            if not hasattr(ctx, name):
                raise ValueError("Unknown register to setup <{0}>".format(name))
            setattr(ctx, name, value)

    def on_exception(self, x):
        exc_code = x.ExceptionRecord.ExceptionCode
        exc_addr = x.ExceptionRecord.ExceptionAddress
        if not self.init_breakpoint and exc_code == EXCEPTION_BREAKPOINT:
            self.init_breakpoint = True
            return
        ctx = self.current_thread.context
        print("==Post-exec context==")
        ctx.dump()
        print(ctx.EEFlags)
        if exc_code == EXCEPTION_BREAKPOINT and exc_addr == self.context_exec.pc + len(self.initial_code):
            print("<Normal terminaison>")
        else:
            print("<{0}> at <{1:#x}>".format(exc_code, exc_addr))
        self.report_ctx_diff(self.context_exec, ctx)
        self.current_process.exit()
        return

    def report_ctx_diff(self, start, now):
        print("==DIFF==")
        for name, start_value in start.regs():
            now_value = getattr(now, name)
            if start_value != now_value:
                diff = now_value - start_value
                print("{0}: {1:#x} -> {2:#x} ({3:+#x})".format(name, start_value, now_value, diff))
        if start.sp > now.sp:
            print("Negative Stack: dumping:")
            data = self.current_process.read_memory(now.sp, start.sp - now.sp)
            print(hexdump(data, start.sp))


def test_code_x86():
    print("Testing x86 code")
    process = windows.test.pop_calc_32(dwCreationFlags=DEBUG_PROCESS)
    code = x86.assemble(sys.argv[1])

    start_register = {}
    if len(sys.argv) > 2:
        for name_value in sys.argv[2].split(";"):
            name, value = name_value.split("=")
            name = name.strip().capitalize()
            if name == "Eflags":
                name = "EFlags"
            value = int(value.strip(), 0)
            start_register[name] = value


    x = CodeTesteur(process, code, start_register)
    x.loop()

def test_code_x64():
    print("Testing x64 code")
    if windows.current_process.bitness == 32:
        raise ValueError("Cannot debug a 64b process from 32b python")
    process = windows.test.pop_calc_64(dwCreationFlags=DEBUG_PROCESS)
    code = x64.assemble(sys.argv[1])

    start_register = {}
    if len(sys.argv) > 2:
        for name_value in sys.argv[2].split(";"):
            name, value = name_value.split("=")
            name = name.strip().capitalize()
            if name == "Eflags":
                name = "EFlags"
            value = int(value.strip(), 0)
            start_register[name] = value


    x = CodeTesteur(process, code, start_register)
    x.loop()

import sys
if len(sys.argv) < 2:
    print("Need x86 code to exec as first argument")
    exit(1)

if sys.argv[1] == "-x64":
    sys.argv.remove("-x64")
    test_code_x64()
elif sys.argv[1] == "--raw":
    sys.argv.remove("--raw")
    pass
else:
    test_code_x86()







#test_code(c, "\xcc")