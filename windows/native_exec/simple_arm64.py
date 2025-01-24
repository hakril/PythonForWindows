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

# Argument class
class Shift(object):
    """Represent a shift parameter of an instruction.
    Allow to JIT shift at instruction crafting time without string manipulation for the #XXX"""
    def __init__(self, type, value):
        assert isinstance(type, str)
        assert isinstance(value, int)
        type = type.upper()
        assert type in ("LSL", "LSR", "ASR", "ROR")
        self.type = type
        self.value = value

    def __eq__(self, other):
        if not isinstance(other, Shift): # Allow compare to tuple & iterable
            return ((len(other) == 2) and
                    (self.type == other[0]) and
                    (self.value == other[1]))
        return (self.type == other.type) and (self.value == other.value)

    def __repr__(self):
        return """{0}(type={1}, value={2})""".format(type(self).__name__, self.type, self.value)

    @classmethod
    def parse(cls, shiftstr):
        if not isinstance(shiftstr, str):
            return None
        if not shiftstr.count(" ") == 1:
            return None
        stype, svalue = shiftstr.split(" ", 1)
        stype = stype.upper()
        if stype not in ("LSL", "LSR", "ASR", "ROR"):
            return None
        if len(svalue) <= 1:
            return None
        if not svalue.startswith("#"):
            return None
        try:
            intvalue = int(svalue[1:])
        except ValueError:
            return None
        return cls(stype, intvalue)
# instruction Encoding

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
    def is_imm(self, arg):
        try:
            value = int(arg)
        except (ValueError, TypeError):
            return False
        return True # Check size max ?

    @classmethod
    def is_shift(self, arg):
        return (arg is None) or isinstance(arg, Shift) or Shift.parse(arg)


    @classmethod
    def gen(cls, **encoding_array):
        class GeneratedEncodingCls(cls):
            ENCODING_VALUES = encoding_array
        return GeneratedEncodingCls

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

        shift = Shift.parse(argsdict.get(3))
        if not shift:
            return

        if shift not in [("LSL", 0), ("LSL", 12)]:
            raise ValueError("Invalid shift for instruction: {0}".format(shift))
        if shift == ("LSL", 12):
            self.sh[:] = bytearray((1,))


    @classmethod
    def accept_arg(cls, argsdict):
        return (cls.is_register(argsdict[0], accept_sp=True) and
                cls.is_register(argsdict[1], accept_sp=True) and
                cls.is_imm(argsdict[2]) and
                cls.is_shift(argsdict.get(3)))


# C4.1.93.6 Logical (immediate)
# Wtf : https://kddnewton.com/2022/08/11/aarch64-bitmask-immediates.html

class DataProcessingLogicalImmediate(DataProcessingImmediate):
    def __init__(self, argsdict):
        super(DataProcessingLogicalImmediate, self).__init__()
        self.sf = self.bits[31:32]
        self.opc = self.bits[29:31]
        self.bits[23:29] = bytearray(reversed((1, 0, 0, 1, 0, 0)))
        self.N = self.bits[22:23]
        self.immr = self.bits[16:22]
        self.imms = self.bits[10:16]
        self.rn = self.bits[5:10]
        self.rd = self.bits[0:5]

        self.setup_fixed_values()
        # Change instruction based of parameter
        self.setup_register(self.rd, argsdict[0])
        self.setup_register(self.rn, argsdict[1])
        self.setup_bitmask_imm(self.imm12, argsdict[2])

    @classmethod
    def accept_arg(cls, argsdict):
        return (cls.is_register(argsdict[0], accept_sp=True) and
                cls.is_register(argsdict[1], accept_sp=True) and
                cls.is_bitmask_imm(argsdict[2]))

    @classmethod
    def is_bitmask_imm(*args, **kwargs):
        raise NotImplementedError("is_bitmask_imm")

    def setup_bitmask_imm(*args, **kwargs):
        raise NotImplementedError("setup_bitmask_imm")


class MovWideImmediat(DataProcessingImmediate):
    def __init__(self, argsdict):
        super(MovWideImmediat, self).__init__()
        self.sf = self.bits[31:32]
        self.opc = self.bits[29:31]
        self.bits[23:29] = bytearray(reversed((1, 0, 0, 1, 0, 1)))
        self.hw = self.bits[21:23]
        self.imm16 = self.bits[5:21]
        self.rd = self.bits[0:5]


        self.setup_fixed_values()
        # Change instruction based of parameter
        self.setup_register(self.rd, argsdict[0])
        self.setup_immediat(self.imm16, argsdict[1])

        shift = Shift.parse(argsdict.get(2))
        if not shift:
            return
        if shift.type != "LSL":
            raise ValueError("Invalid shift type for {0} : {1}".format(type(self).__name__, shift.value))
        if shift.value not in (0, 16 ,32, 48):
            raise ValueError("Invalid shift value for {0} : {1}".format(type(self).__name__, shift.value))
        if self.bitness == 32 and shift.value > 16:
            raise ValueError("Invalid shift value for 32bits encoding of {0} : {1}".format(type(self).__name__, shift.value))

        self.setup_immediat(self.hw, shift.value // 16)


    @classmethod
    def accept_arg(cls, argsdict):
        return (cls.is_register(argsdict[0], accept_sp=True) and
                cls.is_imm(argsdict[1]) and
                cls.is_shift(argsdict.get(2)))



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


# C4.1.95 Data Processing – Register

class DataProcessingRegister(InstructionEncoding):
    def __init__(self):
        super(DataProcessingRegister, self).__init__()
        self.op0 = self.bits[30:31]
        self.op1 = self.bits[28:29]
        self.bits[25:28] = bytearray(reversed((1, 0, 1)))
        self.op2 = self.bits[21:25]
        self.op3 = self.bits[10:16]

class DataProcessingLogicalShiftedRegister(DataProcessingRegister):
    def __init__(self, argsdict):
        super(DataProcessingLogicalShiftedRegister, self).__init__()
        self.sf = self.bits[31:32]
        self.opc = self.bits[29:31]
        self.bits[24:29] = bytearray(reversed((0, 1, 0, 1, 0)))
        self.shift = self.bits[22:24]
        self.N = self.bits[21:22]
        self.rm = self.bits[16:21]
        self.imm6 = self.bits[10:16]
        self.rn = self.bits[5:10]
        self.rd = self.bits[0:5]

        self.setup_fixed_values()
        # Change instruction based of parameter
        self.setup_register(self.rd, argsdict[0])
        self.setup_register(self.rn, argsdict[1])
        self.setup_register(self.rm, argsdict[2])

        shift = Shift.parse(argsdict.get(3))
        if not shift:
            return
        # Is this mapping generic ? Store ir somewhere ?
        # Is the shift size logic repeatable and factorisable ?
        if self.bitness == 32 and shift.value > 31:
            raise ValueError("Invalid shift value for 32bits encoding of {0} : {1}".format(type(self).__name__, shift.value))

        SHIFT_MAPPING = {"LSL": 0b00, "LSR": 0b01, "ASR": 0b10, "ROR": 0b11}
        self.setup_immediat(self.shift, SHIFT_MAPPING[shift.type])
        self.setup_immediat(self.imm6, shift.value)


    @classmethod
    def accept_arg(cls, argsdict):
        return (cls.is_register(argsdict[0]) and
                cls.is_register(argsdict[1]) and
                cls.is_register(argsdict[2]) and
                cls.is_shift(argsdict.get(3)))

# An instruction is a Name that can have multiple encoding
# It's the class we instanciate to assemble instructions
# C6.2.270 ORR (immediate)
# C6.2.271 ORR (shifted register)

# there also seem to exist "alias instructions" like "mov"
# That just map to others instruction when specific condition are met on the params


class Instruction(object):
    encoding = []

    def __init__(self, *args):
        argsdict = dict(enumerate(args)) # Like a list but allow arg.get(4)
        for i, encodcls in enumerate(self.encoding):
            # Late rewrite of GeneratedEncodingCls classname for better message error
            if encodcls.__name__ == "GeneratedEncodingCls":
                encodcls.__name__ = "{0}Encoding{1}".format(type(self).__name__, i)


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

#  C6.2.254

class Movz(Instruction):
    encoding = [MovWideImmediat.gen(opc=0b10)]

class Movk(Instruction):
    encoding = [MovWideImmediat.gen(opc=0b11)]

# The encoding for "mov reg, reg" :D
# C6.2.271
# Todo: Instruction like "mov" that dispatch to other instruction encoding based on more precise condition on param ?
class Orr(Instruction):
    encoding = [DataProcessingLogicalShiftedRegister.gen(opc=0b01)]

class MultipleInstr(object):
    INSTRUCTION_SIZE = 4

    def __init__(self, init_instrs=()):
        self.instrs = {}
        self.labels = {}
        self.expected_labels = {}
        # List of all labeled jump already resolved
        # Will be used for 'relocation'
        self.computed_jump = []
        self.size = 0
        for i in init_instrs:
            self += i

    def get_code(self):
        if self.expected_labels:
            raise ValueError("Unresolved labels: {0}".format(self.expected_labels.keys()))
        return b"".join([x[1].get_code() for x in sorted(self.instrs.items())])

    def add_instruction(self, instruction):
        # if isinstance(instruction, Label):
        #     return self.add_label(instruction)
        # # Change DelayedJump to LabeledJump ?
        # if isinstance(instruction, DelayedJump):
        #     return self.add_delayed_jump(instruction)
        if isinstance(instruction, Instruction):
            self.instrs[self.size] = instruction
            self.size += self.INSTRUCTION_SIZE
            return
        raise ValueError("Don't know what to do with {0} of type {1}".format(instruction, type(instruction)))

    def add_label(self, label):
        if label.name not in self.expected_labels:
            # Label that have no jump before definition
            # Just registed the address of the label
            self.labels[label.name] = self.size
            return
        # Label with jmp before definition
        # Lot of stuff todo:
            # Find all delayed jump that refer to this jump
            # Replace them with real jump
            # If size of jump < JUMP_SIZE: relocate everything we can
            # Update expected_labels
        for jump_to_label in self.expected_labels[label.name]:
            if jump_to_label.offset in self.instrs:
                raise ValueError("WTF REPLACE EXISTING INSTR...")
            distance = self.size - jump_to_label.offset
            real_jump = jump_to_label.type(distance)
            self.instrs[jump_to_label.offset] = real_jump
            self.computed_jump.append((jump_to_label.offset, self.size))
            for i in range(self.JUMP_SIZE - len(real_jump.get_code())):
                self.instrs[jump_to_label.offset + len(real_jump.get_code()) + i] = _NopArtifact()
        del self.expected_labels[label.name]
        self.labels[label.name] = self.size
        if not self.expected_labels:
            # No more un-resolved label (for now): time to reduce the shellcode
            self._reduce_shellcode()

    def add_delayed_jump(self, jump):
        dst = jump.label
        if dst in self.labels:
            # Jump to already defined labels
            # Nothing fancy: get offset of label and jump to it !
            distance = self.size - self.labels[dst]
            jump_instruction = jump.type(-distance)
            self.computed_jump.append((self.size, self.labels[dst]))
            return self.add_instruction(jump_instruction)
        # Jump to undefined label
        # Add label to expected ones
        # Add jump info -> offset of jump | type
        # Reserve space for call !
        jump.offset = self.size
        self.expected_labels.setdefault(dst, []).append(jump)
        self.size += self.JUMP_SIZE
        return

    def merge_shellcode(self, other):
        shared_labels = set(self.labels) & set(other.labels)
        if shared_labels:
            raise ValueError("Cannot merge shellcode: shared labels {0}".format(shared_labels))
        for offset, instr in sorted(other.instrs.items()):
            for label_name in [name for name, label_offset in other.labels.items() if label_offset == offset]:
                self.add_instruction(Label(label_name))
            self.add_instruction(instr)

    def __iadd__(self, other):
        if isinstance(other, MultipleInstr):
            self.merge_shellcode(other)
        elif isinstance(other, basestring):
            self.assemble(other)
        else:
            self.add_instruction(other)
        return self

    def assemble(self, code):
        for instr in assemble_instructions_generator(code):
            self.add_instruction(instr)


def split_in_instruction(str):
    for line in str.split("\n"):
        if not line:
            continue
        for instr in line.split(";"):
            if not instr:
                continue
            yield instr.strip()

def assemble_instructions_generator(str):
    for instr in split_in_instruction(str):
        data = instr.split(" ", 1)
        mnemo, args_raw = data[0], data[1:]
        try:
            instr_object = globals()[mnemo.capitalize()]
        except:
            raise ValueError("Unknow mnemonic <{0}>".format(mnemo))

        # if issubclass(instr_object, Raw):
        #     # Raw should received the raw buffer as it expect encoded hex
        #     # The transformation may transform 'raw 9090' (nopnop) as 0n9090
        #     # If other fake-instr need this : make a class attribute
        #     yield instr_object(*args_raw)
        #     continue

        args = []
        if args_raw:
            for arg in args_raw[0].split(","):
                arg = arg.strip()
                try:
                    arg = int(arg, 0)
                except ValueError:
                    pass
                args.append(arg)
        yield instr_object(*args)

def assemble(str):
    """Play test"""
    shellcode = MultipleInstr()
    shellcode += str
    return shellcode.get_code()