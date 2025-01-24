import sys
import collections
import struct
import binascii
import operator


# py3
is_py3 = (sys.version_info.major >= 3)
if is_py3:
    basestring = str
    int_types = int
else:
    int_types = (int, long)

# https://documentation-service.arm.com/static/67581b3355451e3c38d97c22
# Chapter C4: A64 Instruction Set Encoding: :

## C2.1.3
# 32-bit variant (sf = 0).
# 64-bit variant (sf = 1).

## C2.1.5
# The following symbol conventions are used:
# <Xn> The 64-bit name of a general-purpose register (X0-X30) or the zero register (XZR).
# <Wn> The 32-bit name of a general-purpose register (W0-W30) or the zero register (WZR).
# <Xn|SP> The 64-bit name of a general-purpose register (X0-X30) or the current stack pointer (SP).
# <Wn|WSP> The 32-bit name of a general-purpose register (W0-W30) or the current stack pointer (WSP).
# <Bn>, <Hn>, <Sn>, <Dn>, <Qn>
# The 8, 16, 32, 64, or 128-bit name of a SIMD and floating-point register in a scalar context, as
# described in Register names.
# <Vn> The name of a SIMD and floating-point register in a vector context, as described in Register names.
# <Zn> The name of an SVE scalable vector register, as described in Treatment of SVE scalable vector
# registers.
# <Pn> The name of an SVE scalable predicate register, as described in Vector predication


# Make a special memoryview that match what is show in the ARM Chapter C4 ?

# A lot of hardcoded bits are filled this way:

## self.bits[24:32] = reversed(bytearray(XXX))

# This allow to write the bits in the same order as the ARM manual which is describe with most significant bit first
# Whereas our internal structure is reverse for simplicity of mapping it on list index

XREGISTER = {'X0', 'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7', 'X8', 'X9', 'X10', 'X11', 'X12', 'X13', 'X14', 'X15', 'X16', 'X17', 'X18', 'X19', 'X20', 'X21', 'X22', 'X23', 'X24', 'X25', 'X26', 'X27', 'X28', 'X29', 'X30'}
WREGISTER = {'W0', 'W1', 'W2', 'W3', 'W4', 'W5', 'W6', 'W7', 'W8', 'W9', 'W10', 'W11', 'W12', 'W13', 'W14', 'W15', 'W16', 'W17', 'W18', 'W19', 'W20', 'W21', 'W22', 'W23', 'W24', 'W25', 'W26', 'W27', 'W28', 'W29', 'W30'}
ALL_REGISTER = XREGISTER | WREGISTER
SP = "SP"
WSP = "WSP"


class InstructionEncoding(object):
    # Sub classes can force 32/64 only instrs by setting this to 32 or 64
    BITNESS = None

    def __init__(self):
        super(InstructionEncoding, self).__init__()
        # Bits are in
        # 0 1 2 3 4 ... 31
        # Translation to real little-endian is done last
        self.bytearray = bytearray(32)
        self.bits = memoryview(self.bytearray)

        self.bitness = self.BITNESS

    @classmethod
    def is_register(self, arg, accept_sp):
        arg = arg.upper()
        return (accept_sp and (arg in [SP, WSP])) or arg in ALL_REGISTER

    @classmethod
    def is_imm12(self, arg):
        try:
            value = int(arg)
        except (ValueError, TypeError):
            return False
        return True # Check size max ?

    @classmethod
    def is_shift(self, arg):
        return True

    @classmethod
    def gen(cls, **encoding_array):
        class GeneratedEncoding(cls):
            ENCODING_VALUES = encoding_array
        return GeneratedEncoding

    # Instruction filing at instanciation

    def setup_fixed_values(self):
        # Setup the values registered by InstructionEncoding.gen(x=1, y=2)
        for name, value in self.ENCODING_VALUES.items():
            assert isinstance(value, int)
            self.setup_immediat(getattr(self, name), value)

    def binencode_imm(self, immediat, outsize):
        binstr = "{:0{outsize}b}".format(immediat, outsize=outsize)
        if len(binstr) != outsize:
            raise ValueError("Could not encode immediat {0} in {1} bits. Value take {2} bits".format(immediat, outsize, len(binstr)))

        binlist = [int(c) for c in reversed(binstr)]
        return bytearray(binlist)

    def setup_bitness(self, bitness):
        assert bitness in (32, 64)
        if self.bitness is None:
            self.bitness = bitness
            if bitness == 32:
                self.sf[:] = b"\x00"
            else: # bitness == 64:
                self.sf[:] = b"\x01"
        if self.bitness != bitness:
            raise ValueError("Bitness mismatch on <{0}> encoding, instruction is alredy {1} cannot set as {2}".format(type(self).__name__, self.bitness, bitness))

    def encode_register(self, register, outsize=5):
        register = register.upper()
        assert register in ALL_REGISTER
        if register in XREGISTER:
            self.setup_bitness(64)
        else:
            self.setup_bitness(32)
        return self.binencode_imm(int(register[1:]), outsize)

    def setup_register(self, regfield, register):
        encoded = self.encode_register(register)
        regfield[:] = encoded

    # Instruction filing at instanciation
    def setup_immediat(self, immfield, value):
        immsize = len(immfield)
        immfield[:] = self.binencode_imm(value, immsize)
        return True



# C4.1.93 Data Processing - Immediate

class DataProcessingImmediate(InstructionEncoding):
    def __init__(self):
        super(DataProcessingImmediate, self).__init__()
        self.bits[26:29] = bytearray((0,0,1))
        self.op0 = self.bits[29:31]
        self.op1 = self.bits[22:26]

class AddSubtractImmediate(DataProcessingImmediate):
    def __init__(self, argsdict):
        super(AddSubtractImmediate, self).__init__()
        self.sf = self.bits[31:32] # Keep it a memoryview
        self.op = self.bits[30:31] # Keep it a memoryview
        self.S = self.bits[29:30] # Keep it a memoryview
        self.bits[23:29] = bytearray((0, 1, 0, 0, 0, 1))
        self.sh = self.bits[22:23]
        self.imm12 = self.bits[10:22]
        self.rn = self.bits[5:10]
        self.rd = self.bits[0:5]


        self.setup_fixed_values()
        # Change instruction based of parameter
        self.setup_register(self.rd, argsdict[0])
        self.setup_register(self.rn, argsdict[1])
        self.setup_immediat(self.imm12, argsdict[2])

        assert argsdict.get(3) is None, "SHIFT NOT IMPLEMENTED YET"


    @classmethod
    def accept_arg(cls, argsdict):
        return (cls.is_register(argsdict[0], accept_sp=True) and
                cls.is_register(argsdict[1], accept_sp=True) and
                cls.is_imm12(argsdict[2]) and
                cls.is_shift(argsdict.get(3)))


### C4.1.94.13 Unconditional branch (register)

class UnconditionalBranchRegister(InstructionEncoding):
    BITNESS = 64

    def __init__(self, argsdict):
        super(UnconditionalBranchRegister, self).__init__()
        # Allow to fill it in the same order as the ARM manual
        self.bits[25:32] = bytearray(reversed((1, 1, 0, 1, 0, 1, 1)))
        self.opc = self.bits[21:25]
        self.op2 = self.bits[16:21]
        self.op3 = self.bits[10:16]
        self.rn = self.bits[5:10]
        self.op4 = self.bits[0:5]

        self.setup_fixed_values()
        self.setup_register(self.rn, argsdict[0])

    @classmethod
    def accept_arg(cls, argsdict):
        return (cls.is_register(argsdict[0], accept_sp=True))


class RetEncoding(UnconditionalBranchRegister.gen(opc=0b10, op2=0b11111, op3=0, op4=0)):
    # Ret can accept no register and default to X30
    def __init__(self, argsdict):
        if not argsdict:
            argsdict[0] = "X30"
        super(RetEncoding, self).__init__(argsdict)

    @classmethod
    def accept_arg(cls, argsdict):
        return not argsdict or cls.is_register(argsdict[0], accept_sp=True)

class Instruction(object):
    encoding = []

    def __init__(self, *args):
        argsdict = dict(enumerate(args)) # Like a list but allow arg.get(4)
        for encodcls in self.encoding:
            if encodcls.accept_arg(argsdict):
                self.encoded = encodcls(argsdict)
                return
        raise ValueError("Cannot encode <{0} {1}>:(".format(type(self).__name__, args))

    def get_code(self):
        intlist = list(self.encoded.bits)
        if not is_py3:
            intlist = [ord(x) for x in intlist]
        # Our encoding to real little-endian
        encoding_getter = operator.itemgetter(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24)
        dword = 0
        for bit in encoding_getter(intlist):
            assert bit in (0, 1), "Unexpected bite value in encoding of {0} : {1} in {2}".format(type(self).__name__, bit, intlist)
            dword = (dword << 1) | bit
        return struct.pack(">I", dword) # We already have handled endianess



        # Fix endianned


class Add(Instruction):
    encoding = [AddSubtractImmediate.gen(op=0, S=0)]

class Subs(Instruction):
    encoding = [AddSubtractImmediate.gen(op=1, S=1)]

### C6.2.307 RET (page 2203) (11010110010111110000000000000000)

class Ret(Instruction):
    encoding = [RetEncoding]