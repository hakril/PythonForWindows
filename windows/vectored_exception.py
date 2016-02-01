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

def generate_enhanced_exception_record(base, name_suffix=""):
    class EnhancedEXCEPTION_RECORD(base):
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
    EnhancedEXCEPTION_RECORD.__name__ += name_suffix
    return EnhancedEXCEPTION_RECORD

EnhancedEXCEPTION_RECORD = generate_enhanced_exception_record(EXCEPTION_RECORD)
EnhancedEXCEPTION_RECORD32 = generate_enhanced_exception_record(EXCEPTION_RECORD32, "32")
EnhancedEXCEPTION_RECORD64 = generate_enhanced_exception_record(EXCEPTION_RECORD64, "64")


class EEXCEPTION_DEBUG_INFO32(ctypes.Structure):
    _fields_ = windows.utils.transform_ctypes_fields(EXCEPTION_DEBUG_INFO, {"ExceptionRecord": EnhancedEXCEPTION_RECORD32})

class EEXCEPTION_DEBUG_INFO64(ctypes.Structure):
    _fields_ = windows.utils.transform_ctypes_fields(EXCEPTION_DEBUG_INFO, {"ExceptionRecord": EnhancedEXCEPTION_RECORD64})

#class Eflags(int):
#    _flags_ = [("CF", 1),
#               ("RES_1", 1),
#               ("PF", 1),
#               ("RES_3", 1),
#               ("AF", 1),
#               ("RES_5", 1),
#               ("ZF", 1),
#               ("SF", 1),
#               ("TF", 1),
#               ("IF", 1),
#               ("DF", 1),
#               ("OF", 1),
#               ("IOPL_1", 1),
#               ("IOPL_2", 1),
#               ("NT", 1),
#               ("RES_15", 1),
#               ("RF", 1),
#               ("VM", 1),
#               ("AC", 1),
#               ("VIF", 1),
#               ("VIP", 1),
#               ("ID", 1),
#               ]
#
#    _flag_mask_ = dict([(name, 1 << i) for i, (name, size) in enumerate(_flags_)])
#
#    def __getattr__(self, name):
#        if name in self._flag_mask_:
#            return bool(self & self._flag_mask_[name])
#        return super(Eflags, self).__getattr_(name)
#
#    def dump(self):
#        res = []
#        for name in self._flag_mask_:
#            if name.startswith("RES_"):
#                continue
#            if getattr(self, name):
#                res.append(name)
#        return "|".join(res)
#
#    def __repr__(self):
#        return "{0}({1})".format(type(self).__name__, self.dump())
#
#    __str__ = __repr__
#
#    def __hex__(self):
#        return "{0}({1}:{2})".format(type(self).__name__, int.__hex__(self), self.dump())

class EEflags(ctypes.Structure):
    _fields_ = [("CF", DWORD, 1),
               ("RES_1", DWORD, 1),
               ("PF", DWORD, 1),
               ("RES_3", DWORD, 1),
               ("AF", DWORD, 1),
               ("RES_5", DWORD, 1),
               ("ZF", DWORD, 1),
               ("SF", DWORD, 1),
               ("TF", DWORD, 1),
               ("IF", DWORD, 1),
               ("DF", DWORD, 1),
               ("OF", DWORD, 1),
               ("IOPL_1", DWORD, 1),
               ("IOPL_2", DWORD, 1),
               ("NT", DWORD, 1),
               ("RES_15", DWORD, 1),
               ("RF", DWORD, 1),
               ("VM", DWORD, 1),
               ("AC", DWORD, 1),
               ("VIF", DWORD, 1),
               ("VIP", DWORD, 1),
               ("ID", DWORD, 1),
               ]

    def get_raw(self):
        x = DWORD.from_address(ctypes.addressof(self))
        return x.value

    def set_raw(self, value):
        x = DWORD.from_address(ctypes.addressof(self))
        x.value = value
        return None

    def dump(self):
        res = []
        for name in [x[0] for x in self._fields_]:
            if name.startswith("RES_"):
                continue
            if getattr(self, name):
                res.append(name)
        return "|".join(res)

    def __repr__(self):
        return hex(self)

    def __hex__(self):
        if self.raw == 0:
                return "{0}({1})".format(type(self).__name__, hex(self.raw))
        return "{0}({1}:{2})".format(type(self).__name__, hex(self.raw), self.dump())

    raw = property(get_raw, set_raw)

class EDr7(ctypes.Structure):
    _fields_ = [("L0", DWORD, 1),
               ("G0", DWORD, 1),
               ("L1", DWORD, 1),
               ("G1", DWORD, 1),
               ("L2", DWORD, 1),
               ("G2", DWORD, 1),
               ("L3", DWORD, 1),
               ("G3", DWORD, 1),
               ("LE", DWORD, 1),
               ("GE", DWORD, 1),
               ("RES_1", DWORD, 3),
               ("GD", DWORD, 1),
               ("RES_1", DWORD, 2),
               ("RW0", DWORD, 2),
               ("LEN0", DWORD, 2),
               ("RW1", DWORD, 2),
               ("LEN1", DWORD, 2),
               ("RW2", DWORD, 2),
               ("LEN2", DWORD, 2),
               ("RW3", DWORD, 2),
               ("LEN3", DWORD, 2),
               ]

class EnhancedCONTEXTBase(object):
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

    @property
    def EEFlags(self):
        off = type(self).EFlags.offset
        x = EEflags.from_address(ctypes.addressof(self) + off)
        x.self = self
        return x

    @property
    def EDr7(self):
        off = type(self).Dr7.offset
        x = EDr7.from_address(ctypes.addressof(self) + off)
        x.self = self
        return x

class EnhancedCONTEXT32(EnhancedCONTEXTBase, (CONTEXT32)):
    default_dump = ('Eip', 'Esp', 'Eax', 'Ebx', 'Ecx', 'Edx', 'Ebp', 'Edi', 'Esi', 'EFlags')
    pc_reg = 'Eip'
    #special_reg_type = {'EFlags': Eflags}

class EnhancedCONTEXTWOW64(EnhancedCONTEXTBase, (WOW64_CONTEXT)):
    default_dump = ('Eip', 'Esp', 'Eax', 'Ebx', 'Ecx', 'Edx', 'Ebp', 'Edi', 'Esi', 'EFlags')
    pc_reg = 'Eip'
    #special_reg_type = {'EFlags': Eflags}


class EnhancedCONTEXT64(EnhancedCONTEXTBase, (CONTEXT64)):
    default_dump = ('Rip', 'Rsp', 'Rax', 'Rbx', 'Rcx', 'Rdx', 'Rbp', 'Rdi', 'Rsi',
                    'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'EFlags')
    pc_reg = 'Rip'
    #special_reg_type = {'EFlags': Eflags}

    @classmethod
    def new_aligned(cls):
        """Return a new EnhancedCONTEXT64 aligned on 16 bits
           temporary workaround or horrible hack ? choose your side
        """
        size = ctypes.sizeof(cls)
        nb_qword = (size + 8) / ctypes.sizeof(ULONGLONG)
        buffer = (nb_qword * ULONGLONG)()
        struct_address = ctypes.addressof(buffer)
        if (struct_address & 0xf) not in [0, 8]:
            raise ValueError("ULONGLONG array not aligned on 8")
        if (struct_address & 0xf) == 8:
            struct_address += 8
        self = cls.from_address(struct_address)
        # Keep the raw buffer alive
        self._buffer = buffer
        return self

def bitness():
    """Return 32 or 64"""
    import platform
    bits = platform.architecture()[0]
    return int(bits[:2])

if bitness() == 32:
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
        v = self.func_type(self.decorator)
        v.self = self
        return v

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

class DumpContextOnException(WithExceptionHandler):
        def __init__(self, exit=False):
            self.exit = exit
            super(DumpContextOnException, self).__init__(self.print_context_result)

        def print_context_result(self, exception_pointers):
            except_record = exception_pointers[0].ExceptionRecord[0]
            exception_pointers[0].dump()
            sys.stdout.flush()
            if self.exit:
                windows.current_process.exit()
            return 0

