import windows

import windows.native_exec.simple_x64 as x64
import windows.native_exec.simple_x86 as x86
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
StrlenA64 += x64.Xor("RAX", "RAX")
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
GetProcAddress64 +=     x64.Jz(":DLL_NOT_FOUND")
GetProcAddress64 +=     x64.Mov("RCX", x64.mem("[RAX + 80]")) # RCX = NAME (UNICODE_STRING.Buffer)
GetProcAddress64 +=     x64.Call(":FUNC_STRLENW64")
GetProcAddress64 +=     x64.Mov("RDI", "RCX")
GetProcAddress64 +=     x64.Mov("RCX", "RAX")
GetProcAddress64 +=     x64.Mov("RSI", "R11")
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
GetProcAddress64 += x64.Mov("ECX",  x64.mem("[RAX  + 24] "))
GetProcAddress64 += x64.Mov("R13", "RCX") # ;r13 = NB names
GetProcAddress64 += x64.Mov("EDX",  x64.mem("[RAX  + 32] ")) # EDX = names array RVA
GetProcAddress64 += x64.Add("RDX",  "RBX") #  RDX = names array
GetProcAddress64 += x64.Xor("RCX",  "RCX")
GetProcAddress64 += x64.Label(":SEARCH_LOOP")
GetProcAddress64 +=     x64.Cmp("RCX", "R13")
GetProcAddress64 +=     x64.Jz(":API_NOT_FOUND")
GetProcAddress64 +=     x64.Mov("ESI", x64.mem("[RDX + RCX * 4]")) # ;Get function name RVA
GetProcAddress64 +=     x64.Add("RSI", "RBX") # ;Get name addr
GetProcAddress64 +=     x64.Push("RCX") # ;Save current index (could use x64 register)
GetProcAddress64 +=     x64.Mov("RCX", "R12")
GetProcAddress64 +=     x64.Call(":FUNC_STRLENA64") # TODO: mov outside the loop :D
GetProcAddress64 +=     x64.Mov("RCX", "RAX")
GetProcAddress64 +=     x64.Mov("RDI", "R12")
GetProcAddress64 +=     x64.Inc("RCX")
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
GetProcAddress64 += x64.Label(":RETURN")
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
GetProcAddress64 += x64.Label(":DLL_NOT_FOUND")
GetProcAddress64 += x64.Mov("RAX", 0xfffffffffffffffe)
GetProcAddress64 += x64.Jmp(":RETURN")
GetProcAddress64 += x64.Label(":API_NOT_FOUND")
GetProcAddress64 += x64.Pop("RAX")
GetProcAddress64 += x64.Mov("RAX", 0xffffffffffffffff)
GetProcAddress64 += x64.Jmp(":RETURN")
# Ajout des dependances
GetProcAddress64 += StrlenW64
GetProcAddress64 += StrlenA64



###### 32 bits #######


StrlenW32  = x86.MultipleInstr()
StrlenW32 += x86.Label(":FUNC_STRLENW32")
StrlenW32 += x86.Push("EDI")
StrlenW32 += x86.Mov("EDI", x86.mem("[ESP + 8]"))
StrlenW32 += x86.Push("ECX")
StrlenW32 += x86.Xor("EAX", "EAX")
StrlenW32 += x86.Xor("ECX", "ECX")
StrlenW32 += x86.Dec("ECX")
StrlenW32 += x86.Repne + x86.ScasW()
StrlenW32 += x86.Not("ECX")
StrlenW32 += x86.Dec("ECX")
StrlenW32 += x86.Mov("EAX", "ECX")
StrlenW32 += x86.Pop("ECX")
StrlenW32 += x86.Pop("EDI")
StrlenW32 += x86.Ret()


StrlenA32  = x86.MultipleInstr()
StrlenA32 += x86.Label(":FUNC_STRLENA32")
StrlenA32 += x86.Push("EDI")
StrlenA32 += x86.Mov("EDI", x86.mem("[ESP + 8]"))
StrlenA32 += x86.Push("ECX")
StrlenA32 += x86.Xor("EAX", "EAX")
StrlenA32 += x86.Xor("ECX", "ECX")
StrlenA32 += x86.Dec("ECX")
StrlenA32 += x86.Repne + x86.ScasB()
StrlenA32 += x86.Not("ECX")
StrlenA32 += x86.Dec("ECX")
StrlenA32 += x86.Mov("EAX", "ECX")
StrlenA32 += x86.Pop("ECX")
StrlenA32 += x86.Pop("EDI")
StrlenA32 += x86.Ret()


GetProcAddress32  = x86.MultipleInstr()
GetProcAddress32 += x86.Label(":FUNC_GETPROCADDRESS32")
GetProcAddress32 += x86.Push("EBX")
GetProcAddress32 += x86.Push("ECX")
GetProcAddress32 += x86.Push("EDI")
GetProcAddress32 += x86.Push("ESI")
GetProcAddress32 += x86.Push("EBP")
GetProcAddress32 += x86.Mov("EAX", x86.mem("FS:[0x30]"))
GetProcAddress32 += x86.Mov("EAX", x86.mem("[EAX + 0xC]"))
GetProcAddress32 += x86.Mov("EAX", x86.mem("[EAX + 0xC]")) # ; RAX on the first elt of the list (first module)
GetProcAddress32 += x86.Mov("EDX", "EAX")
GetProcAddress32 += x86.Label(":a_dest")
GetProcAddress32 +=     x86.Mov("EAX", "EDX")
GetProcAddress32 +=     x86.Mov("EBX", x86.mem("[EAX + 0x18]")) # EBX : first base ! (base of current module)
GetProcAddress32 +=     x86.Cmp("EBX", 0)
GetProcAddress32 +=     x86.Jz(":DLL_NOT_FOUND")
GetProcAddress32 +=     x86.Mov("ECX", x86.mem("[EAX + 0x30]")) # RCX = NAME (UNICODE_STRING.Buffer)
GetProcAddress32 +=     x86.Push("ECX")
GetProcAddress32 +=     x86.Call(":FUNC_STRLENW32")
GetProcAddress32 +=     x86.Pop("EDI") # Current name
GetProcAddress32 +=     x86.Mov("ECX", "EAX")
GetProcAddress32 +=     x86.Mov("ESI", x86.mem("[ESP + 0x18]"))
GetProcAddress32 +=     x86.Rep + x86.CmpsW()
GetProcAddress32 +=     x86.Test("ECX", "ECX")
GetProcAddress32 +=     x86.Jz(":DLL_FOUND")
GetProcAddress32 +=     x86.Mov("EDX", x86.mem("[EDX]"))
GetProcAddress32 += x86.Jmp(":a_dest")
GetProcAddress32 += x86.Label(":DLL_FOUND")
GetProcAddress32 += x86.Mov("EAX",  x86.mem("[EBX + 0x3c]")) # rax = PEBASE RVA
GetProcAddress32 += x86.Add("EAX",  "EBX") # RAX = PEBASE
GetProcAddress32 += x86.Add("EAX",  0x18) # ;OPTIONAL HEADER
GetProcAddress32 += x86.Mov("ECX",  x86.mem("[EAX + 0x60]")) # ;ecx = RVA export dir
GetProcAddress32 += x86.Add("ECX",  "EBX") # ;ecx = export_dir
GetProcAddress32 += x86.Mov("EAX",  "ECX")
GetProcAddress32 += x86.Push("EAX") # Save it
# ; EBX = BASE | EAX = EXPORT DIR
GetProcAddress32 += x86.Mov("ECX",  x86.mem("[EAX  + 24] "))
GetProcAddress32 += x86.Mov("EBP", "ECX") # ;EBP = NB names
GetProcAddress32 += x86.Mov("EDX",  x86.mem("[EAX  + 32] ")) # EDX = names array RVA
GetProcAddress32 += x86.Add("EDX",  "EBX") #  RDX = names array
GetProcAddress32 += x86.Xor("ECX",  "ECX")
GetProcAddress32 +=     x86.Mov("ESI", x86.mem("[ESP + 0x20]"))
GetProcAddress32 += x86.Label(":SEARCH_LOOP")
GetProcAddress32 +=     x86.Cmp("ECX", "EBP")
GetProcAddress32 +=     x86.Jz(":API_NOT_FOUND")
GetProcAddress32 +=     x86.Mov("EDI", x86.mem("[EDX + ECX * 4]")) # ;Get function name RVA
GetProcAddress32 +=     x86.Add("EDI", "EBX") # ;Get name addr
GetProcAddress32 +=     x86.Push("ECX") # Save current index
GetProcAddress32 +=     x86.Push("ESI")
GetProcAddress32 +=     x86.Call(":FUNC_STRLENA32")
GetProcAddress32 +=     x86.Mov("ECX", "EAX")
GetProcAddress32 +=     x86.Push("EDI")
GetProcAddress32 +=     x86.Call(":FUNC_STRLENA32")
GetProcAddress32 +=     x86.Pop("EDI")
GetProcAddress32 +=     x86.Cmp("EAX", "ECX")
GetProcAddress32 += x86.Jnz(":ABORT_STRCMP")
GetProcAddress32 += x86.Inc("ECX")
GetProcAddress32 +=     x86.Rep + x86.CmpsB()
GetProcAddress32 += x86.Label(":ABORT_STRCMP")
GetProcAddress32 +=     x86.Pop("ESI")
GetProcAddress32 +=     x86.Mov("EAX", "ECX")
GetProcAddress32 +=     x86.Pop("ECX")
GetProcAddress32 +=     x86.Inc("ECX")
GetProcAddress32 +=     x86.Test("EAX", "EAX")
GetProcAddress32 += x86.Jnz(":SEARCH_LOOP")

GetProcAddress32 += x86.Dec("ECX")
#GetProcAddress32 += x86.Int3() # da poi(edx + (ecx * 4)) + ebx; da esi
GetProcAddress32 += x86.Pop("EAX") # ;Restore export_dir addr
GetProcAddress32 += x86.Mov("EDX", x86.mem("[EAX + 36]")) # ;EDX = AddressOfNameOrdinals RVX
GetProcAddress32 += x86.Add("EDX", "EBX")
#GetProcAddress32 += x86.Mov("ECX", x86.mem("[EDX + ECX * 2]"))
GetProcAddress32 += x86.OperandSizeOverride + x86.Mov("ECX", x86.mem("[EDX + ECX * 2]"))
# ; ecx = Ieme ordinal (short array)
GetProcAddress32 += x86.And('ECX', 0xffff)
GetProcAddress32 += x86.Mov("EDX", x86.mem("[EAX + 28]")) # ; AddressOfFunctions RVA
GetProcAddress32 += x86.Add("EDX", "EBX")
GetProcAddress32 += x86.Mov("EDX", x86.mem("[EDX + ECX * 4]"))
GetProcAddress32 += x86.Add("EDX", "EBX")
GetProcAddress32 += x86.Mov("EAX", "EDX")
GetProcAddress32 += x86.Label(":RETURN")
GetProcAddress32 += x86.Pop("EBP")
GetProcAddress32 += x86.Pop("ESI")
GetProcAddress32 += x86.Pop("EDI")
GetProcAddress32 += x86.Pop("ECX")
GetProcAddress32 += x86.Pop("EBX")
GetProcAddress32 += x86.Ret()
GetProcAddress32 += x86.Label(":DLL_NOT_FOUND")
GetProcAddress32 += x86.Mov("EAX", 0xfffffffe)
GetProcAddress32 += x86.Jmp(":RETURN")
GetProcAddress32 += x86.Label(":API_NOT_FOUND")
GetProcAddress32 += x86.Pop("EAX")
GetProcAddress32 += x86.Mov("EAX", 0xffffffff)
GetProcAddress32 += x86.Jmp(":RETURN")
GetProcAddress32 += StrlenW32
GetProcAddress32 += StrlenA32