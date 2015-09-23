import ctypes
import windows
from windows.generated_def.winstructs import *
import windows.generated_def.windef as windef

EXCEPTION_CONTINUE_SEARCH = (0x0)
EXCEPTION_CONTINUE_EXECUTION = (0xffffffff)

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
exception_name_by_value = dict([(x, x) for x in [getattr(windows.generated_def.windef, name) for name in exception_type]])


class EnhancedEXCEPTION_RECORD(EXCEPTION_RECORD):
    @property
    def ExceptionCode(self):
        real_code = super(EnhancedEXCEPTION_RECORD, self).ExceptionCode
        return exception_name_by_value.get(real_code, 'UNKNOW_EXCEPTION({0})'.format(hex(real_code)))

    @property
    def ExceptionAddress(self):
        x = super(EnhancedEXCEPTION_RECORD, self).ExceptionAddress
        if x is None:
            return 0x0
        return x


class Eflags(int):
    _flags_ = [("CF", 1),
               ("RES_1", 1),
               ("PF", 1),
               ("RES_3", 1),
               ("AF", 1),
               ("RES_5", 1),
               ("ZF", 1),
               ("SF", 1),
               ("TF", 1),
               ("IF", 1),
               ("DF", 1),
               ("OF", 1),
               ("IOPL_1", 1),
               ("IOPL_2", 1),
               ("NT", 1),
               ("RES_15", 1),
               ("RF", 1),
               ("VM", 1),
               ("AC", 1),
               ("VIF", 1),
               ("VIP", 1),
               ("ID", 1),
               ]

    _flag_mask_ = dict([(name, 1 << i) for i, (name, size) in enumerate(_flags_)])

    def __getattr__(self, name):
        if name in self._flag_mask_:
            return bool(self & self._flag_mask_[name])
        return super(Eflags, self).__getattr_(name)

    def dump(self):
        res = []
        for name in self._flag_mask_:
            if name.startswith("RES_"):
                continue
            if getattr(self, name):
                res.append(name)
        return "|".join(res)

    def __repr__(self):
        return "{0}({1})".format(type(self).__name__, self.dump())

    __str__ = __repr__

    def __hex__(self):
        return "{0}({1}:{2})".format(type(self).__name__, int.__hex__(self), self.dump())


class EnhancedCONTEXTBase(CONTEXT):
    default_dump = ()
    pc_reg = ''
    special_reg_type = {}

    def regs(self, to_dump=None):
        res = []
        if to_dump is None:
            to_dump = self.default_dump
        for name in to_dump:
            value = getattr(self, name)
            if name in self.special_reg_type:
                value = self.special_reg_type[name](value)
            res.append((name, value))
        return res

    def dump(self, to_dump=None):
        regs = self.regs()
        for name, value in regs:
                print("{0} -> {1}".format(name, hex(value)))
        return None

    def get_pc(self):
        return getattr(self, self.pc_reg)

    def set_pc(self, value):
        return setattr(self, self.pc_reg, value)

    pc = property(get_pc, set_pc, None, "Program Counter register (EIP or RIP)")


class EnhancedCONTEXT32(EnhancedCONTEXTBase):
    default_dump = ('Eip', 'Esp', 'Eax', 'Ebx', 'Ecx', 'Edx', 'Ebp', 'Edi', 'Esi', 'EFlags')
    pc_reg = 'Eip'
    special_reg_type = {'EFlags': Eflags}


class EnhancedCONTEXT64(EnhancedCONTEXTBase):
    default_dump = ('Rip', 'Rsp', 'Rax', 'Rbx', 'Rcx', 'Rdx', 'Rbp', 'Rdi', 'Rsi',
                    'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'EFlags')
    pc_reg = 'Rip'
    special_reg_type = {'EFlags': Eflags}

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

    def __new__(cls, func):
        self = object.__new__(cls)
        self.func = func
        return self.func_type(self.decorator)

    def decorator(self, exception_pointers):
        try:
            return self.func(exception_pointers)
        except BaseException as e:
            print("Ignored Python Exception in Vectored Exception: {0}".format(e))
            return windef.EXCEPTION_CONTINUE_SEARCH


class WithExceptionHandler(object):
    def __init__(self, handler):
        self.handler = VectoredException(handler)

    def __enter__(self):
        self.value = windows.winproxy.AddVectoredExceptionHandler(0, self.handler)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        windows.winproxy.RemoveVectoredExceptionHandler(self.value)
        return False
