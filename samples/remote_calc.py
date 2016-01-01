import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

print("Creating a calc")
calc = windows.utils.create_process(r"C:\windows\system32\calc.exe")
# You don't need to do that in our case, but it's useful to now
print("Looking for calcs in the processes")
all_calcs = [proc for proc in windows.system.processes if proc.name == "calc.exe"]
print("They are currently <{0}> calcs running on the system".format(len(all_calcs)))

print("Let's play with our calc: <{calc}>".format(calc=calc))
print("Our calc pid is {calc.pid}".format(calc=calc))
print("Our calc is a <{calc.bitness}> bits process".format(calc=calc))
print("Our calc is a SysWow64 process ? <{calc.is_wow_64}>".format(calc=calc))
print("Our calc have threads ! <{calc.threads}>".format(calc=calc))

# PEB STUFF
peb = calc.peb
print("Exploring our calc PEB ! {peb}".format(peb=peb))
print("Command line is {peb.commandline}".format(peb=peb))
modules = peb.modules
print("Here are 3 loaded modules: {0}".format(modules[:3]))
# See iat_hook.py for module exploration


# Remote alloc / read / write

print("Allocating memory in our calc")
addr = calc.virtual_alloc(0x1000)
print("Allocated memory is at <{0}>".format(hex(addr)))
print("Writing 'SOME STUFF' in allocated memory")
calc.write_memory(addr, "SOME STUFF")
print("Reading allocated memory : <{0}>".format(repr(calc.read_memory(addr, 20))))


# Remote Execution

print("Execution some native code in our calc (write 0x424242 at allocated address + return 0x1337")

if calc.bitness == 32:
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
t = calc.execute(code.get_code())
t.wait()
print("Return code = {0}".format(hex(t.exit_code)))
print("Reading allocated memory : <{0}>".format(repr(calc.read_memory(addr, 20))))

print("Executing python code !")
# Make 'windows' importable in remote python
calc.execute_python("import sys; sys.path.append(r'{0}')".format(sys.path[-1]))

calc.execute_python("import windows")
# Let's write in the calc 'current_process' memory :)
calc.execute_python("addr = {addr}; windows.current_process.write_memory(addr, 'HELLO FROM CALC')".format(addr=addr))
print("Reading allocated memory : <{0}>".format(repr(calc.read_memory(addr, 20))))

# python_execute is 'safe':
# - it waits for the thread completion
# - it raise an error if remote code raised some

try:
    print("Trying to import in remote module 'FAKE_MODULE'")
    calc.execute_python("def func():\n   import FAKE_MODULE\nfunc()")
except windows.injection.RemotePythonError as e:
    print("Remote ERROR !")
    print(e)
    
print("That's all ! killing the calc")
calc.exit()
    






