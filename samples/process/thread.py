import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

print("Creating a notepad") ## Replaced calc.exe by notepad.exe cause of windows 10.
notepad = windows.utils.create_process(r"C:\windows\system32\notepad.exe")
# You don't need to do that in our case, but it's useful to now

print("Priting threads")
for th in notepad.threads:
    print("    * {0}".format(th))

print("Writing some code in memory")


if notepad.bitness == 32:
    code = "mov eax, 0x42424242; label :start ; jmp :start; nop; nop; ret"
    rawcode = x86.assemble(code)
else:
    code = "mov rax, 0x4242424242424242; label :start ; jmp :start; nop; nop; ret"
    rawcode = x64.assemble(code)

print("Allocating memory")
with notepad.allocated_memory(0x1000) as addr:
    print("Writing code at <{0:#x}>".format(addr))
    notepad.write_memory(addr, rawcode)

    print("Creating thread on injected code")
    t = notepad.create_thread(addr, 0x11223344)
    print("New thread is {0}".format(t))

    print("Suspending thread")
    t.suspend()

    ctx = t.context
    print("Thread context is {0}".format(ctx))
    print("Dumping thread context:")
    ctx.dump()
    print("Changing context")
    ctx.pc += 2  # EIP / RIP
    ctx.func_result = 0x12345678 # EAX / RAX
    print("Setting new thread context")
    t.set_context(ctx)
    print("Resuming thread")
    t.resume()
    print("Waiting thread")
    t.wait()
    print("Thread has exit: {0}".format(t.is_exit))
    print("Thread exit value = {0:#x}".format(t.exit_code))



