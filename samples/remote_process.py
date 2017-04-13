import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

print("Creating a notepad") ## Replaced calc.exe by notepad.exe cause of windows 10.
notepad = windows.utils.create_process(r"C:\windows\system32\notepad.exe")
# You don't need to do that in our case, but it's useful to now
print("Looking for notepads in the processes")
all_notepads = [proc for proc in windows.system.processes if proc.name == "notepad.exe"]
print("They are currently <{0}> notepads running on the system".format(len(all_notepads)))

print("Let's play with our notepad: <{notepad}>".format(notepad=notepad))
print("Our notepad pid is {notepad.pid}".format(notepad=notepad))
print("Our notepad is a <{notepad.bitness}> bits process".format(notepad=notepad))
print("Our notepad is a SysWow64 process ? <{notepad.is_wow_64}>".format(notepad=notepad))
print("Our notepad have threads ! <{notepad.threads}>".format(notepad=notepad))

# PEB STUFF
peb = notepad.peb
print("Exploring our notepad PEB ! {peb}".format(peb=peb))
print("Command line is {peb.commandline}".format(peb=peb))
modules = peb.modules
print("Here are 3 loaded modules: {0}".format(modules[:3]))
# See iat_hook.py for module exploration


# Remote alloc / read / write

print("Allocating memory in our notepad")
addr = notepad.virtual_alloc(0x1000)
print("Allocated memory is at <{0}>".format(hex(addr)))
print("Writing 'SOME STUFF' in allocated memory")
notepad.write_memory(addr, "SOME STUFF")
print("Reading allocated memory : <{0}>".format(repr(notepad.read_memory(addr, 20))))


# Remote Execution

print("Execution some native code in our notepad (write 0x424242 at allocated address + return 0x1337)")

if notepad.bitness == 32:
    # Let's generate some native code
    code =  x86.MultipleInstr()
    code += x86.Mov(x86.deref(addr), 0x42424242)
    code += x86.Mov("EAX", 0x1337)
    code += x86.Ret()
else:
    code =  x64.MultipleInstr()
    code += x64.Mov('RAX', addr)
    code += x64.Mov(x64.mem("[RAX]"), 0x42424242)
    code += x64.Mov("RAX", 0x1337)
    code += x64.Ret()

print("Executing native code !")
t = notepad.execute(code.get_code())
t.wait()
print("Return code = {0}".format(hex(t.exit_code)))
print("Reading allocated memory : <{0}>".format(repr(notepad.read_memory(addr, 20))))

print("Executing python code !")
# Make 'windows' importable in remote python
notepad.execute_python("import sys; sys.path.append(r'{0}')".format(sys.path[-1]))

notepad.execute_python("import windows")
# Let's write in the notepad 'current_process' memory :)
notepad.execute_python("addr = {addr}; windows.current_process.write_memory(addr, 'HELLO FROM notepad')".format(addr=addr))
print("Reading allocated memory : <{0}>".format(repr(notepad.read_memory(addr, 20))))

# python_execute is 'safe':
# - it waits for the thread completion
# - it raise an error if remote code raised some

try:
    print("Trying to import in remote module 'FAKE_MODULE'")
    notepad.execute_python("def func():\n   import FAKE_MODULE\nfunc()")
except windows.injection.RemotePythonError as e:
    print("Remote ERROR !")
    print(e)

print("That's all ! killing the notepad")
notepad.exit()







