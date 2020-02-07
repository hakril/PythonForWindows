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

class EEXCEPTION_RECORDBase(object):
        @property
        def ExceptionCode(self):
            """The Exception code

               :type: :class:`int`"""
            real_code = super(EEXCEPTION_RECORDBase, self).ExceptionCode
            return exception_name_by_value.get(real_code, windows.generated_def.windef.Flag("UNKNOW_EXCEPTION", real_code))

        @property
        def ExceptionAddress(self):
            """The Exception Address

            :type: :class:`int`"""
            x = super(EEXCEPTION_RECORDBase, self).ExceptionAddress
            if x is None:
                return 0x0
            return x

class EEXCEPTION_RECORD(EEXCEPTION_RECORDBase, EXCEPTION_RECORD):
    """Enhanced exception record"""

    fields = [f[0] for f in EXCEPTION_RECORD._fields_]
    """The fields of the structure"""

class EEXCEPTION_RECORD32(EEXCEPTION_RECORDBase, EXCEPTION_RECORD32):
    """Enhanced exception record (32bits)"""

    fields = [f[0] for f in EXCEPTION_RECORD32._fields_]
    """The fields of the structure"""

class EEXCEPTION_RECORD64(EEXCEPTION_RECORDBase, EXCEPTION_RECORD64):
    """Enhanced exception record (64bits)"""

    fields = [f[0] for f in EXCEPTION_RECORD64._fields_]
    """The fields of the structure"""


class EEXCEPTION_DEBUG_INFO32(ctypes.Structure):
    """Enhanced Debug info"""
    _fields_ = windows.utils.transform_ctypes_fields(EXCEPTION_DEBUG_INFO, {"ExceptionRecord": EEXCEPTION_RECORD32})

    fields = [f[0] for f in _fields_]
    """The fields of the structure"""

class EEXCEPTION_DEBUG_INFO64(ctypes.Structure):
    """Enhanced Debug info"""
    _fields_ = windows.utils.transform_ctypes_fields(EXCEPTION_DEBUG_INFO, {"ExceptionRecord": EEXCEPTION_RECORD64})

    fields = [f[0] for f in _fields_]
    """The fields of the structure"""


class EEflags(ctypes.Structure):
    "Flag view of the Eflags register"
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

    fields = [f[0] for f in _fields_]
    """The fields of the structure"""

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
    """Raw value of the eflags

       :type: :class:`int`
    """


class EDr7(ctypes.Structure):
    "Flag view of the DR7 register"
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

    fields = [f[0] for f in _fields_]
    """The fields of the structure"""

class ECONTEXTBase(object):
    """DAT CONTEXT"""
    default_dump = ()
    pc_reg = ''
    sp_reg = ''
    func_result_reg = ''
    special_reg_type = {}


    def regs(self, to_dump=None):
        """Return the name and values of the registers

        :returns: [(reg_name, value)] -- A :class:`list` of :class:`tuple`"""
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
        """Dump (print) the current context"""
        regs = self.regs()
        for name, value in regs:
                print("{0} -> {1}".format(name, hex(value)))
        return None

    def get_pc(self):
        return getattr(self, self.pc_reg)

    def set_pc(self, value):
        return setattr(self, self.pc_reg, value)

    def get_sp(self):
        return getattr(self, self.sp_reg)

    def set_sp(self, value):
        return setattr(self, self.sp_reg, value)

    def get_func_result(self):
        return getattr(self, self.func_result_reg)

    def set_func_result(self, value):
        return setattr(self, self.func_result_reg, value)

    pc = property(get_pc, set_pc, None, "Program Counter register (EIP or RIP)")
    sp = property(get_sp, set_sp, None, "Stack Pointer register (ESP or RSP)")
    func_result = property(get_func_result, set_func_result, None, "Function Resultat register (EAX or RAX)")

    @property
    def EEFlags(self):
        """Enhanced view of the Eflags (you also have ``EFlags`` for the raw value)

            :type: :class:`EEflags`
        """
        off = type(self).EFlags.offset
        x = EEflags.from_address(ctypes.addressof(self) + off)
        x.self = self
        return x

    @property
    def EDr7(self):
        """Enhanced view of the DR7 register (you also have ``Dr7`` for the raw value)

            :type: :class:`EDr7`
        """
        off = type(self).Dr7.offset
        x = EDr7.from_address(ctypes.addressof(self) + off)
        x.self = self
        return x

class ECONTEXT32(ECONTEXTBase, CONTEXT32):
    default_dump = ('Eip', 'Esp', 'Eax', 'Ebx', 'Ecx', 'Edx', 'Ebp', 'Edi', 'Esi', 'EFlags')
    pc_reg = 'Eip'
    sp_reg = 'Esp'
    func_result_reg = 'Eax'
    fields = [f[0] for f in CONTEXT32._fields_]
    """The fields of the structure"""

class ECONTEXTWOW64(ECONTEXTBase, WOW64_CONTEXT):
    default_dump = ('Eip', 'Esp', 'Eax', 'Ebx', 'Ecx', 'Edx', 'Ebp', 'Edi', 'Esi', 'EFlags')
    pc_reg = 'Eip'
    sp_reg = 'Esp'
    func_result_reg = 'Eax'
    fields = [f[0] for f in WOW64_CONTEXT._fields_]
    """The fields of the structure"""


class ECONTEXT64(ECONTEXTBase, CONTEXT64):
    default_dump = ('Rip', 'Rsp', 'Rax', 'Rbx', 'Rcx', 'Rdx', 'Rbp', 'Rdi', 'Rsi',
                    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'EFlags')
    pc_reg = 'Rip'
    sp_reg = 'Rsp'
    func_result_reg = 'Rax'
    fields = [f[0] for f in CONTEXT64._fields_]
    """The fields of the structure"""

    @classmethod
    def new_aligned(cls):
        """Return a new :class:`ECONTEXT64` aligned on 16 bits

           temporary workaround or horrible hack ? choose your side
        """
        size = ctypes.sizeof(cls)
        nb_qword = int((size + 8) / ctypes.sizeof(ULONGLONG))
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
    ECONTEXT = ECONTEXT32
else:
    ECONTEXT = ECONTEXT64


class EEXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", ctypes.POINTER(EEXCEPTION_RECORD)),
        ("ContextRecord", ctypes.POINTER(ECONTEXT)),
    ]

    def dump(self):
        """Dump (print) the EEXCEPTION_POINTERS"""
        record = self.ExceptionRecord[0]
        print("Dumping Exception: ")
        print("    ExceptionCode = {0} at {1}".format(record.ExceptionCode, hex(record.ExceptionAddress)))
        regs = self.ContextRecord[0].regs()
        for name, value in regs:
            print("    {0} -> {1}".format(name, hex(value)))


class VectoredException(object):
    """A decorator that create a callable which can be passed to :func:`AddVectoredExceptionHandler`"""
    func_type = ctypes.WINFUNCTYPE(ctypes.c_uint, ctypes.POINTER(EEXCEPTION_POINTERS))

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
            import traceback
            print("Ignored Python Exception in Vectored Exception: {0}".format(e))
            traceback.print_exc()
            return windef.EXCEPTION_CONTINUE_SEARCH


class VectoredExceptionHandler(object):
    def __init__(self, pos, handler):
        self.handler = VectoredException(handler)
        self.pos = pos

    def __enter__(self):
        self.value = windows.winproxy.AddVectoredExceptionHandler(self.pos, self.handler)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        windows.winproxy.RemoveVectoredExceptionHandler(self.value)
        return False

class DumpContextOnException(VectoredExceptionHandler):
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

