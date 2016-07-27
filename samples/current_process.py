import sys
import os.path
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64
# Here is our current process
cp = windows.current_process

print("current process is {cp}".format(cp=windows.current_process))
print("current process is a <{cp.bitness}> bits process".format(cp=cp))
print("current process is a SysWow64 process ? <{cp.is_wow_64}>".format(cp=cp))
print("current process pid <{cp.pid}>  and ppid <{cp.ppid}>".format(cp=cp))
print("Here are the current process threads: <{cp.threads}>".format(cp=cp))

print("Let's execute some native code ! (0x41 + 1)")

if windows.current_process.bitness == 32:
    # Let's generate some native code
    code =  x86.MultipleInstr()
    code += x86.Mov("Eax", 0x41)
    code += x86.Inc("EAX")
    code += x86.Ret()
else:
    code =  x64.MultipleInstr()
    code += x64.Mov("RAX", 0x41)
    code += x64.Inc("RAX")
    code += x64.Ret()

native_code = code.get_code()

v = windows.current_process.execute(native_code)
print("Native code returned <{0}>".format(hex(v)))

print("Allocating memory in current process")
addr = cp.virtual_alloc(0x1000) # Default alloc is RWX (so secure !)
print("Allocated memory is at <{0}>".format(hex(addr)))

print("Writing 'SOME STUFF' in allocation memory")
cp.write_memory(addr, "SOME STUFF")
print("Reading memory : <{0}>".format(repr(cp.read_memory(addr, 20))))


