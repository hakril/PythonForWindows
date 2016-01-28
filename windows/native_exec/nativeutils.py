import windows

import windows.native_exec.simple_x64 as x64
from windows.generated_def.winstructs import *


StrlenW64  = x64.MultipleInstr()
StrlenW64 += x64.Label(":FUNC_STRLENW64")
StrlenW64 += x64.Push("RCX")
StrlenW64 += x64.Push("RDI")
StrlenW64 += x64.Mov("RDI", "RCX")
StrlenW64 += x64.Xor("RAX", "RAX")
StrlenW64 += x64.Xor("RCX", "RCX")
StrlenW64 += x64.Dec("RCX")
StrlenW64 += x64.Repne + x64.ScasW()
StrlenW64 += x64.Not("RCX")
StrlenW64 += x64.Dec("RCX")
StrlenW64 += x64.Mov("RAX", "RCX")
StrlenW64 += x64.Pop("RDI")
StrlenW64 += x64.Pop("RCX")
StrlenW64 += x64.Ret()


StrlenA64  = x64.MultipleInstr()
StrlenA64 += x64.Label(":FUNC_STRLENA64")
StrlenA64 += x64.Push("RCX")
StrlenA64 += x64.Push("RDI")
StrlenA64 += x64.Mov("RDI", "RCX")
StrlenA64 += x64.Xor("RAX", "rax")
StrlenA64 += x64.Xor("RCX", "RCX")
StrlenA64 += x64.Dec("RCX")
StrlenA64 += x64.Repne + x64.ScasB()
StrlenA64 += x64.Not("RCX")
StrlenA64 += x64.Dec("RCX")
StrlenA64 += x64.Mov("RAX", "RCX")
StrlenA64 += x64.Pop("RDI")
StrlenA64 += x64.Pop("RCX")
StrlenA64 += x64.Ret()


GetProcAddress64  = x64.MultipleInstr()
GetProcAddress64 += x64.Label(":FUNC_GETPROCADDRESS64")
GetProcAddress64 += x64.Push("RBX")
GetProcAddress64 += x64.Push("RCX")
GetProcAddress64 += x64.Push("RDX")
GetProcAddress64 += x64.Push("RSI")
GetProcAddress64 += x64.Push("RDI")
GetProcAddress64 += x64.Push("R8")
GetProcAddress64 += x64.Push("R9")
GetProcAddress64 += x64.Push("R10")
GetProcAddress64 += x64.Push("R11")
GetProcAddress64 += x64.Push("R12")
GetProcAddress64 += x64.Push("R13")
# Params : RCX -> libname
# Params : RDX -> API Name
GetProcAddress64 += x64.Mov("R11", "RCX")
GetProcAddress64 += x64.Mov("R12", "RDX")
GetProcAddress64 += x64.Mov("RAX", x64.mem("GS:[0x60]")) #PEB !
GetProcAddress64 += x64.Mov("RAX", x64.mem("[RAX + 24] ")) # ; RAX = ldr (+ 6 for 64 cause of 2 ptr)
GetProcAddress64 += x64.Mov("RAX", x64.mem("[RAX + 32]")) # ; RAX on the first elt of the list (first module)
GetProcAddress64 += x64.Mov("RDX", "RAX")
GetProcAddress64 += x64.Label(":a_dest")
GetProcAddress64 +=     x64.Mov("RAX", "RDX")
GetProcAddress64 +=     x64.Mov("RBX", x64.mem("[RAX + 32]")) # RBX : first base ! (base of current module)
#GetProcAddress64 +=     x64.Mov("RBX ", x64.mem("[RAX + 32]")) # RBX : first base ! (base of current module)
GetProcAddress64 +=     x64.Cmp("RBX", 0)
GetProcAddress64 +=     x64.Jz(":NOT_FOUND")
GetProcAddress64 +=     x64.Mov("RCX", x64.mem("[RAX + 80]")) # RCX = NAME (UNICODE_STRING.Buffer)
GetProcAddress64 +=     x64.Call(":FUNC_STRLENW64")
GetProcAddress64 +=     x64.Mov("RDI", "RCX")
GetProcAddress64 +=     x64.Mov("RCX", "RAX")
GetProcAddress64 +=     x64.Mov("RSI", "R11")
#GetProcAddress64 +=     x64.Int3()
GetProcAddress64 +=     x64.Rep + x64.CmpsW() #;cmp with current dll name (unicode)
GetProcAddress64 +=     x64.Test("RCX", "RCX")
GetProcAddress64 +=     x64.Jz(":DLL_FOUND")
GetProcAddress64 +=     x64.Mov("RDX", x64.mem("[RDX]"))
GetProcAddress64 += x64.Jmp(":a_dest")
GetProcAddress64 += x64.Label(":DLL_FOUND") # here rbx = base
GetProcAddress64 += x64.Mov("EAX",  x64.mem("[RBX + 60]")) # rax = PEBASE RVA
GetProcAddress64 += x64.Add("RAX",  "RBX") # RAX = PEBASE
GetProcAddress64 += x64.Add("RAX",  24) # ;OPTIONAL HEADER
GetProcAddress64 += x64.Mov("ECX",  x64.mem("[rax + 112]")) # ;rcx = RVA export dir
GetProcAddress64 += x64.Add("RCX",  "RBX") # ;rcx = export_dir
GetProcAddress64 += x64.Mov("RAX", "RCX") # ;RAX = export_dir
GetProcAddress64 += x64.Push("RAX") # ;Save it for after function search
# ; EBX = BASE | EAX = EXPORT DIR
GetProcAddress64 += x64.Mov("ECX",  x64.mem("[RAX  + 24] ")) # rax = PEBASE RVA
GetProcAddress64 += x64.Mov("R13", "RCX") # ;r13 = NB names
GetProcAddress64 += x64.Mov("EDX",  x64.mem("[RAX  + 32] ")) # EDX = names array RVA
GetProcAddress64 += x64.Add("RDX",  "RBX") #  RDX = names array
GetProcAddress64 += x64.Xor("RCX",  "RCX")
GetProcAddress64 += x64.Label(":SEARCH_LOOP")
GetProcAddress64 +=     x64.Mov("ESI", x64.mem("[RDX + RCX * 4]")) # ;Get function name RVA
GetProcAddress64 +=     x64.Add("RSI", "RBX") # ;Get name addr
GetProcAddress64 +=     x64.Push("RCX") # ;Save current index (could use x64 register)
GetProcAddress64 +=     x64.Mov("RCX", "R12")
GetProcAddress64 +=     x64.Call(":FUNC_STRLENA64") # TODO: mov outside the loop :D
GetProcAddress64 +=     x64.Mov("RCX", "RAX")
GetProcAddress64 +=     x64.Mov("RDI", "R12")
GetProcAddress64 +=     x64.Rep + x64.CmpsB()
GetProcAddress64 +=     x64.Mov("EAX", "ECX")
GetProcAddress64 +=     x64.Pop("RCX")
GetProcAddress64 +=     x64.Inc("RCX")
GetProcAddress64 +=     x64.Test("RAX", "RAX")
GetProcAddress64 += x64.Jnz(":SEARCH_LOOP")
# Func FOUND !
GetProcAddress64 += x64.Dec("RCX")
GetProcAddress64 += x64.Pop("RAX") # ;Restore export_dir addr
GetProcAddress64 += x64.Mov("EDX", x64.mem("[RAX + 36]")) # ;EDX = AddressOfNameOrdinals RVX
GetProcAddress64 += x64.Add("RDX", "RBX")
GetProcAddress64 += x64.OperandSizeOverride + x64.Mov("ECX", x64.mem("[rdx + rcx * 2]")) # ; ecx = Ieme ordinal (short array)
GetProcAddress64 += x64.And('RCX', 0xffff)
GetProcAddress64 += x64.Mov("EDX", x64.mem("[RAX + 28]")) # ; AddressOfFunctions RVA
GetProcAddress64 += x64.Add("RDX", "RBX")
GetProcAddress64 += x64.Mov("EDX", x64.mem("[RDX + RCX * 4]"))
GetProcAddress64 += x64.Add("RDX", "RBX")
GetProcAddress64 += x64.Mov("RAX", "RDX")
GetProcAddress64 += x64.Pop("R13")
GetProcAddress64 += x64.Pop("R12")
GetProcAddress64 += x64.Pop("R11")
GetProcAddress64 += x64.Pop("R10")
GetProcAddress64 += x64.Pop("R9")
GetProcAddress64 += x64.Pop("R8")
GetProcAddress64 += x64.Pop("RDI")
GetProcAddress64 += x64.Pop("RSI")
GetProcAddress64 += x64.Pop("RDX")
GetProcAddress64 += x64.Pop("RCX")
GetProcAddress64 += x64.Pop("RBX")
GetProcAddress64 += x64.Ret()
GetProcAddress64 += x64.Label(":NOT_FOUND")
GetProcAddress64 += x64.Xor("RAX", "RAX")
GetProcAddress64 += x64.Ret()
# Ajout des dependances
GetProcAddress64 += StrlenW64
GetProcAddress64 += StrlenA64


