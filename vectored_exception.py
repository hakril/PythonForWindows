import windows

import ctypes
import windows
from windows.generated_def.winstructs import *
import windows.generated_def.windef as windef
import time

EXCEPTION_CONTINUE_SEARCH  = (0x0)
EXCEPTION_CONTINUE_EXECUTION  = (0xffffffff)


exception_type = [
"EXCEPTION_ACCESS_VIOLATION",
"EXCEPTION_DATATYPE_MISALIGNMENT",
"EXCEPTION_BREAKPOINT",
"EXCEPTION_SINGLE_STEP",
"EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
"EXCEPTION_FLT_DENORMAL_OPERAND",
"EXCEPTION_FLT_DIVIDE_BY_ZERO",
"EXCEPTION_FLT_INEXACT_RESULT",
"EXCEPTION_FLT_INVALID_OPERATION",
"EXCEPTION_FLT_OVERFLOW",
"EXCEPTION_FLT_STACK_CHECK",
"EXCEPTION_FLT_UNDERFLOW",
"EXCEPTION_INT_DIVIDE_BY_ZERO",
"EXCEPTION_INT_OVERFLOW",
"EXCEPTION_PRIV_INSTRUCTION",
"EXCEPTION_IN_PAGE_ERROR",
"EXCEPTION_ILLEGAL_INSTRUCTION",
"EXCEPTION_NONCONTINUABLE_EXCEPTION",
"EXCEPTION_STACK_OVERFLOW",
"EXCEPTION_INVALID_DISPOSITION",
"EXCEPTION_GUARD_PAGE",
"EXCEPTION_INVALID_HANDLE",
"EXCEPTION_POSSIBLE_DEADLOCK",
]

# x -> x dict may seems strange but useful to get the Flags (with name) from the int
# exception_name_by_value[0x80000001] -> EXCEPTION_GUARD_PAGE(0x80000001L)
exception_name_by_value = dict([(x,x) for x in [getattr(windows.generated_def.windef, name) for name in exception_type]])


class EnhancedEXCEPTION_RECORD(EXCEPTION_RECORD):
    @property
    def ExceptionCode(self):
        real_code = super(EnhancedEXCEPTION_RECORD, self).ExceptionCode
        return exception_name_by_value.get(real_code, 'UNKNOW_EXCEPTION({0})'.format(hex(real_code)))

class EnhancedCONTEXTBase(CONTEXT):
    default_dump = ()

    def regs(self, to_dump=None):
        res = []
        if to_dump is None:
            to_dump = self.default_dump
        for name in to_dump:
            res.append((name, getattr(self, name)))
        return res

    def dump(self, to_dump=None):
        regs = self.regs()
        for name, value in regs:
            print("{0} -> {1}".format(name, hex(value)))

class EnhancedCONTEXT32(EnhancedCONTEXTBase):
    default_dump = ('Eip', 'Esp', 'Eax', 'Ebx', 'Ecx', 'Ebp', 'Edi', 'Esi')

class EnhancedCONTEXT64(EnhancedCONTEXTBase):
    default_dump = ('Rip', 'Rsp', 'Rax', 'Rbx', 'Rcx', 'Rbp', 'Rdi', 'Rsi',
                    'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15')

if windows.current_process.bitness == 32:
    EnhancedCONTEXT = EnhancedCONTEXT32
else:
    EnhancedCONTEXT = EnhancedCONTEXT64

class EnhancedEXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", ctypes.POINTER(EnhancedEXCEPTION_RECORD)),
        ("ContextRecord", ctypes.POINTER(EnhancedCONTEXT)),
    ]

    def dump(self):
        record = self.ExceptionRecord[0]
        print("Dumping Exception: ")
        print("    ExceptionCode = {0} at {1}".format(record.ExceptionCode, hex(record.ExceptionAddress)))
        regs = self.ContextRecord[0].regs()
        for name, value in regs:
            print("    {0} -> {1}".format(name, hex(value)))


class VectoredException(object):
    func_type = ctypes.WINFUNCTYPE(ctypes.c_uint, ctypes.POINTER(EnhancedEXCEPTION_POINTERS))

    def __init__(self):
        pass

    def __call__(self, func):
        self.func = func
        return self.func_type(self.decorator)

    def decorator(self, exception_pointers):
        print("IN DAT DECORATOR")
        try:
            x = self.func(exception_pointers)
            print("PROUT")
            return x
        except BaseException as e:
            print("Ignored Python Exception in Vectored Exception: {0}".format(e))
            return windef.EXCEPTION_CONTINUE_SEARCH


class WithExceptionHandler(object):
    def __init__(self, handler):
        self.handler = handler

    def __enter__(self):
        self.value = windows.k32testing.AddVectoredExceptionHandler(0, self.handler)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        windows.k32testing.RemoveVectoredExceptionHandler(self.value)
        return False