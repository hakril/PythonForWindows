import struct
import ctypes
import windows
import windows.native_exec.simple_x64 as x64
from generated_def.winstructs import *

# Special code for syswow64 process

CS_32bits = 0x23
CS_64bits = 0x33

# See assembly into doc/NtCreateThreadStub_64b.asm
Pretty_NtCreateThreadStub = """
50 50 53 51 52 56 57 41  50 41 51 41 52 41 53 41
54 41 55 48 C7 C0 00 00  00 00 50 48 B8 54 68 72
65 61 64 45 78 50 48 B8  4E 74 43 72 65 61 74 65
50 4C 8B DC 48 C7 C3 61  72 79 41 53 48 BB 4C 6F
61 64 4C 69 62 72 53 4C  8B E4 65 48 8B 04 25 60
00 00 00 48 8B 40 18 48  8B 40 20 48 8B D0 48 8B
C2 48 8B 58 20 48 23 DB  74 14 48 8B 48 50 48 8B
09 81 F9 6E 00 74 00 74  0B 48 8B 10 EB E0 68 42
42 42 42 C3 8B 43 3C 48  03 C3 48 83 C0 18 8B 48
70 48 03 CB 48 8B C1 50  8B 48 18 4C 8B E9 8B 50
20 48 03 D3 48 33 C9 8B  34 8A 48 03 F3 51 49 8B
FB 48 C7 C1 11 00 00 00  F3 A6 8B C1 59 48 FF C1
85 C0 75 E3 48 FF C9 58  8B 50 24 48 03 D3 66 8B
0C 4A 48 81 E1 FF FF 00  00 8B 50 1C 48 03 D3 8B
14 8A 48 03 D3 4C 8B EA  6A 00 48 8B CC 48 C7 C2
FF FF 1F 00 49 C7 C0 00  00 00 00 49 B9 40 40 40
40 40 40 40 40 48 C7 C0  00 00 00 00 50 50 50 50
50 48 B8 42 42 42 42 42  42 42 42 50 48 B8 41 41
41 41 41 41 41 41 50 41  51 41 50 52 51 41 FF D5
48 89 84 24 E8 00 00 00  48 83 C4 40 48 83 C4 28
48 83 C4 20 41 5D 41 5C  41 5B 41 5A 41 59 41 58
5F 5E 5A 59 5B 58 58
"""
NtCreateThreadStub = Pretty_NtCreateThreadStub.replace(" ", "").replace("\n", "").decode('hex')

def genere_return_32bits_stub(ret_addr):
    ret_32b = x64.MultipleInstr()
    ret_32b += x64.Mov('RCX', (CS_32bits << 32) + ret_addr)
    ret_32b += x64.Push('RCX')
    ret_32b += x64.Retf32() #32 bits return addr
    return ret_32b.get_code()

# The format of a jump to 64bits mode
dummy_jump = "\xea" + struct.pack("<I", 0) + chr(CS_64bits) + "\x00\x00"

def execute_64bits_code_from_syswow(shellcode):
    if not windows.current_process.is_wow_64:
        raise ValueError("Calling execute_64bits_code_from_syswow from non-syswow process")
    addr = windows.k32testing.VirtualAlloc(dwSize=0x1000)
    # post-exec 32bits stub (xor eax, eax; ret)
    ret = "\xC3"
    ret_addr = addr
    shell_code_addr = ret_addr + len(ret) + len(dummy_jump)
    # ljmp
    jump = "\xea" + struct.pack("<I", shell_code_addr) + chr(CS_64bits) + "\x00\x00"
    jump_addr = ret_addr + len(ret)
    # Return to 32bits stub
    shellcode += genere_return_32bits_stub(ret_addr)
    # WRITE ALL THE STUBS
    windows.current_process.write_memory(ret_addr, ret)
    windows.current_process.write_memory(jump_addr, jump)
    windows.current_process.write_memory(shell_code_addr, shellcode)
    # Execute
    exec_stub = ctypes.CFUNCTYPE(HRESULT)(jump_addr)
    return exec_stub()

def NtCreateThreadEx_32_to_64(process, addr, param):
    shellcode = NtCreateThreadStub.replace("\x40" * 8, struct.pack("<Q", process.handle))
    shellcode = shellcode.replace("\x41" * 8, struct.pack("<Q", addr))
    shellcode = shellcode.replace("\x42" * 8, struct.pack("<Q", param))
    return execute_64bits_code_from_syswow(shellcode)


# TODO : implem remote PEB parsing
class RemotePointerBase(ULONG64):
    pass

class Remote_wchar_p(RemotePointerBase):
    def __init__(self, *args):
        self.proc = None
        super(RemotePointerImp, self).__init__(*args)

    def str(self):
        addr = self.value
        buffer = (ctypes.c_wchar * 255)()
        self.proc.read_memory_into(self.value, buffer)
        return str(ctypes.c_wchar_p(buffer[:]).value)

class Remote_LIST_ENTRY_PTR(RemotePointerBase):
    def __init__(self, *args):
        self.proc = None
        super(RemotePointerImp, self).__init__(*args)

    def TO_LDR_ENTRY(self):
        v = RemotePointer(LDR_DATA_TABLE_ENTRY64)(self.value - sizeof(ULONG64) *  2)
        v.proc = self.proc
        return v

def RemotePointer(struct):
    class RemotePointerImp(RemotePointerBase):
        def __init__(self, *args):
            self.proc = None
            super(RemotePointerImp, self).__init__(*args)

        def contents(self):
            if self.proc is None:
                raise ValueError("Non binded :(")
            s = struct(self.proc)
            self.proc.read_memory_into(self.value, s)
            print("set proc via contents for {0}".format(s))
            return s
    return RemotePointerImp

class RemoteStructure(Structure):
    def __init__(self, proc):
        self.proc = proc

    def __getattribute__(self, value):
        print(value)
        if value in ["_fields_", "proc"]:
            return super(RemoteStructure, self).__getattribute__(value)
        d = dict(self._fields_)
        t = d.get(value, type(None))
        field = super(RemoteStructure, self).__getattribute__(value)

        if isinstance(field, (RemoteStructure, RemotePointerBase)):
            print("Set proc for {0}".format(field))
            field.proc = self.proc
        return field

# Struct _LSA_UNICODE_STRING definitions
class _LSA_UNICODE_STRING(RemoteStructure):
        _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", Remote_wchar_p),
    ]

PUNICODE_STRING = POINTER(_LSA_UNICODE_STRING)
UNICODE_STRING = _LSA_UNICODE_STRING
LSA_UNICODE_STRING = _LSA_UNICODE_STRING
PLSA_UNICODE_STRING = POINTER(_LSA_UNICODE_STRING)


class _LIST_ENTRY64(RemoteStructure): pass
_LIST_ENTRY64._fields_ = [
    ("Flink", Remote_LIST_ENTRY_PTR),
    ("Blink", Remote_LIST_ENTRY_PTR),
]
LIST_ENTRY64 = _LIST_ENTRY64


# Struct _LDR_DATA_TABLE_ENTRY definitions
class _LDR_DATA_TABLE_ENTRY64(RemoteStructure):
        _fields_ = [
        ("Reserved1", ULONG64 * 2),
        ("InMemoryOrderLinks", _LIST_ENTRY64),
        ("Reserved2", ULONG64 * 2),
        ("DllBase", ULONG64),
        ("EntryPoint", ULONG64),
        ("Reserved3", ULONG64),
        ("FullDllName", UNICODE_STRING),
        ("BaseDllName", UNICODE_STRING),
        ("Reserved5", ULONG64 * 3),
        ("CheckSum", ULONG),
        ("TimeDateStamp", ULONG),
    ]
LDR_DATA_TABLE_ENTRY64 = _LDR_DATA_TABLE_ENTRY64


class _PEB_LDR_DATA64(RemoteStructure):
        _fields_ = [
        ("Reserved1", BYTE * 8),
        ("Reserved2", ULONG64 * 3),
        ("InMemoryOrderModuleList", LIST_ENTRY64),
    ]

class _PEB64(RemoteStructure):
        _fields_ = [
        ("Reserved1", BYTE * 2),
        ("BeingDebugged", BYTE),
        ("Reserved2", BYTE * 1),
        ("Reserved3", ULONG64 * 2),
        ("Ldr", RemotePointer(_PEB_LDR_DATA64)),
        ("ProcessParameters", ULONG64),
        ("Reserved4", BYTE * 104),
        ("Reserved5", ULONG64 * 52),
        ("PostProcessInitRoutine", ULONG64),
        ("Reserved6", BYTE * 128),
        ("Reserved7", ULONG64 * 1),
        ("SessionId", ULONG),
    ]

PEB64 = _PEB64





