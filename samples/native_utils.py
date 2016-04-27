import sys
import os.path
import pprint
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows
import windows.test

import windows.native_exec.simple_x64 as x64
import windows.native_exec.nativeutils
from windows.generated_def.winstructs import *

GetProcAddress64 = windows.native_exec.nativeutils.GetProcAddress64

dll = "KERNEL32.DLL\x00".encode("utf-16-le")
api = "LoadLibraryA\x00"
dll_to_load = "SUCE"


RemoteManualLoadLibray = x64.MultipleInstr()
c = RemoteManualLoadLibray
c += x64.Mov("R15", "RCX")
c += x64.Mov("RCX", x64.mem("[R15 + 0]"))
c += x64.Mov("RDX", x64.mem("[R15 + 8]"))
c += x64.Call(":FUNC_GETPROCADDRESS64")
c += x64.Mov("RCX", x64.mem("[R15 + 0x10]"))
c += x64.Push("RCX")
c += x64.Push("RCX")
c += x64.Push("RCX")
c += x64.Call("RAX")
c += x64.Pop("RCX")
c += x64.Pop("RCX")
c += x64.Pop("RCX")
c += x64.Ret()

RemoteManualLoadLibray += GetProcAddress64


calc= windows.test.pop_calc_64(dwCreationFlags=CREATE_SUSPENDED)

addr = calc.virtual_alloc(0x1000)
addr2 = addr + len(dll)
addr3 = addr2 + len(api)
addr4 = addr3 + len(dll_to_load)

calc.write_memory(addr, dll)
calc.write_memory(addr2, api)
calc.write_memory(addr3, dll_to_load)
calc.write_qword(addr4, addr)
calc.write_qword(addr4 + 8, addr2)
calc.write_qword(addr4 + 0x10, addr3)

calc.execute(RemoteManualLoadLibray.get_code(), addr4)

