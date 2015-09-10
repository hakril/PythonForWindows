import collections
import struct
import sys

# TODO: fix immediat signed/unsigned assembly

class BitArray(object):
    def __init__(self, size, bits):
        self.size = size
        if len(bits) > size:
            raise ValueError("size > len(bits)")

        bits_list = []
        for bit in bits:
            x = int(bit)
            if x not in [0, 1]:
                raise ValueError("Not expected bits value {0}".format(x))
            bits_list.append(x)

        self.array = bits_list
        if size > len(self.array):
            self.array = ([0] * (size - len(self.array))) + self.array

    def dump(self):
        res = []
        for i in range(self.size // 8):
            c = 0
            for x in (self.array[i * 8: (i + 1) * 8]):
                c = (c << 1) + x
            res.append(c)
        return bytearray((res))

    def __getitem__(self, slice):
        return self.array[slice]

    def __setitem__(self, slice, value):
        self.array[slice] = value
        return True

    def __repr__(self):
        return repr(self.array)

    def __add__(self, other):
        if not isinstance(other, BitArray):
            return NotImplemented
        return BitArray(self.size + other.size, self.array + other.array)

    def __or__(self, other):
        if not isinstance(other, BitArray):
            return NotImplemented
        if self.size != other.size:
            raise ValueError("OR ON DIFF SIZE")
        new_array = [(x | y) for x,y in zip(self.array, other.array)]
        return BitArray(self.size, new_array)

    def to_int(self):
        return int("".join([str(i) for i in self.array]), 2)

    @classmethod
    def from_string(cls):
        l = []
        for c in bytearray(reversed(str_base)):
            for i in range(8):
                l.append(c & 1)
                c = c >> 1
        self.array = l

    @classmethod
    def from_int(cls, size, x):
        if x < 0:
            x = x & ((2 ** size) - 1)
        return cls(size, bin(x)[2:])

# Rules: bytes only !!!!

reg_order = ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI']
new_reg_order = ['R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']


x64_regs = reg_order + new_reg_order
mem_access = collections.namedtuple('mem_access', ['base', 'index', 'scale', 'disp'])


def create_displacement(base=None, index=None, scale=None, disp=0):
    if index is not None and scale is None:
        scale = 1
    return mem_access(base, index, scale, disp)

def mem(data):
    """Parse a memory access string"""
    if not isinstance(data, str):
        raise TypeError("mem need a string to parse")
    data = data.strip()
    if not (data.startswith("[") and data.endswith("]")):
        raise ValueError("mem acces expect <[EXPR]>")
    # A l'arrache.. j'aime pas le parsing de trucs
    data = data[1:-1]
    items = data.split("+")
    parsed_items = {}
    for item in items:
        item = item.strip()
        # Index * scale
        if "*" in item:
            if 'index' in parsed_items:
                raise ValueError("Multiple index / index*scale in mem expression <{0}>".format(data))
            sub_items = item.split("*")
            if len(sub_items) != 2:
                raise ValueError("Invalid item <{0}> in mem access".format(item))
            index, scale = sub_items
            index, scale = index.strip(), scale.strip()
            if not X64.is_reg(index):
                raise ValueError("Invalid index <{0}> in mem access".format(index))
            try:
                scale = int(scale, 0)
            except ValueError as e:
                raise ValueError("Invalid scale <{0}> in mem access".format(scale))
            parsed_items['scale'] = scale
            parsed_items['index'] = index
        else:
            # displacement / base / index alone
            if X64.is_reg(item):
                if not 'base' in parsed_items:
                    parsed_items['base'] = item
                    continue
                # Already have base + index -> cannot avec another register in expression
                if 'index' in parsed_items:
                    raise ValueError("Multiple index / index*scale in mem expression <{0}>".format(data))
                parsed_items['index'] = item
                continue
            try:
                disp = int(item, 0)
            except ValueError as e:
                raise ValueError("Invalid base/index or displacement <{0}> in mem access".format(item))
            if 'disp' in parsed_items:
                raise ValueError("Multiple displacement in mem expression <{0}>".format(data))
            parsed_items['disp'] = disp
    return create_displacement(**parsed_items)


class X64RegisterSelector(object):

    reg_opcode = {v : BitArray.from_int(size=3, x=i) for i, v in enumerate(reg_order)}
    new_reg_opcode = {v : BitArray.from_int(size=3, x=i) for i, v in enumerate(new_reg_order)}

    def accept_arg(self, previous, args):
        x = args[0]
        try:
            return (1, self.reg_opcode[x.upper()], None)
        except (KeyError, AttributeError):
            pass
        try:
            return (1, self.new_reg_opcode[x.upper()], BitArray.from_int(8, 0x41))
        except (KeyError, AttributeError):
            return (None, None, None)

    @classmethod
    def get_reg_bits(cls, name):
        try:
            return cls.reg_opcode[name.upper()]
        except KeyError:
            return cls.new_reg_opcode[name.upper()]

class RawBits(BitArray):
    def accept_arg(self, previous, args):
        return (0, self, None)


class Immediat(object):
    def __init__(self, add=0):
        self.add = add

    def __add__(self, x):
        return type(self)(self.add + x)

class Imm32(Immediat):
    def accept_arg(self, previous, args):
        try:
            x = int(args[0]) + self.add
        except (ValueError, TypeError):
            return (None, None, None)
        return (1, BitArray.from_int(32, X64.to_little_endian(x, size=32)), None)

class Imm8(Immediat):
    def accept_arg(self, previous, args):
        try:
            x = int(args[0]) + self.add
        except (ValueError, TypeError):
            return (None, None)
        if not -128 <= x <= 127:
            return (None, None, None)
        return (1, BitArray.from_int(8, X64.to_little_endian(x, size=8)), None)

class Imm64(Immediat):
    def accept_arg(self, previous, args):
        try:
            x = int(args[0]) + self.add
            return (1, BitArray.from_int(64, X64.to_little_endian(x, size=64)), None)
        except (ValueError, TypeError):
            return (None, None, None)

class Mov_RAX_OFF64(object):
    def accept_arg(self, previous, args):
        if RegisterRax().accept_arg(previous, args) == (None, None, None):
            return (None, None, None)
        arg2 = args[1]
        if not (X64.is_mem_acces(arg2) and X64.mem_access_has_only(arg2, ["disp"])):
            return (None, None, None)
        return (2, BitArray.from_int(8, 0xa1) + BitArray.from_int(64, X64.to_little_endian(arg2.disp)) , BitArray.from_int(8, 0x48))

class Mov_OFF64_RAX(object):
    def accept_arg(self, previous, args):
        if args[1] != "RAX":
            return (None, None, None)
        arg2 = args[0]
        if not (X64.is_mem_acces(arg2) and X64.mem_access_has_only(arg2, ["disp"])):
            return (None, None, None)
        return (2, BitArray.from_int(8, 0xa3) + BitArray.from_int(64, X64.to_little_endian(arg2.disp)) , BitArray.from_int(8, 0x48))

class RegisterRax(object):
    def accept_arg(self, previous, args):
        x = args[0]
        if isinstance(x, str) and x.upper() == 'RAX':
            return (1, BitArray(0, []), None)
        return None, None, None

class FixedRegister(object):
    def __init__(self, register):
        self.reg = register.upper()

    def accept_arg(self, previous, args):
        x = args[0]
        if isinstance(x, str) and x.upper() == self.reg:
            return 1, BitArray(0, []), None
        return None, None, None

class ModRM(object):
    size = 8

    def __init__(self, *sub_modrm):
        self.sub = sub_modrm

    def accept_arg(self, previous, args):
        if len(args) < 2:
            raise ValueError("Missing arg for modrm")
        arg1 = args[0]
        arg2 = args[1]
        for sub in self.sub:
            #import pdb;pdb.set_trace()
            if sub.match(arg1, arg2):
                d = sub(arg1, arg2, 0)
                previous[0][-2] = d.direction
                rex = d.rex if d.is_rex_needed else None
                return (2, d.mod + d.reg + d.rm + d.after, rex)
            elif (not hasattr(sub, "refuse_reverse")) and sub.match(arg2, arg1):
                d = sub(arg2, arg1, 1)
                previous[0][-2] = d.direction
                rex = d.rex if d.is_rex_needed else None
                return (2, d.mod + d.reg + d.rm + d.after, rex)
        return (None, None, None)

class RexByte(BitArray):
        def __init__(self):
            super(RexByte, self).__init__(8, "")
            self.is_needed = False

class X64(object):

    @staticmethod
    def is_reg(name):
        try:
            return (name.upper() in reg_order) or X64.is_new_reg(name)
        except AttributeError: # Not a string
            return False

    @staticmethod
    def is_new_reg(name):
        try:
            return name.upper() in new_reg_order
        except AttributeError: # Not a string
            return False

    @staticmethod
    def is_mem_acces(data):
        return isinstance(data, mem_access)

    @staticmethod
    def mem_access_has_only(mem_access, names):
        if not X64.is_mem_acces(mem_access):
            raise ValueError("mem_access_has_only")
        for f in mem_access._fields:
            if getattr(mem_access, f) and f not in names:
                return False
        if "base" in names and mem_access.base is None:
            return False
        return True

    @staticmethod
    def to_little_endian(i, size=64):
        pack = {8: 'B', 16 : 'H', 32 : 'I', 64 : 'Q'}
        s = pack[size]
        mask = (1 << size) - 1
        i = i & mask
        return struct.unpack("<" + s, struct.pack(">" + s, i))[0]

# Sub ModRM encoding

class RexByte(object):
    def __init__(self):
        self.is_needed = False
        self.pattern = BitArray(4, "0100")
        self.w = BitArray(1, "0")
        self.r = BitArray(1, "0")
        self.x = BitArray(1, "0")
        self.b = BitArray(1, "0")


class SubModRM(object):
    def __init__(self):
        self.mod = BitArray(2, "")
        self.reg = BitArray(3, "")
        self.rm = BitArray(3, "")
        self.after = BitArray(0, "")
        self.rex = BitArray(8, "01000000")
        self.is_rex_needed = False
        self.direction = 0

    def setup_reg_as_register(self, name):
        self.reg = X64RegisterSelector.get_reg_bits(name)
        if X64.is_new_reg(name):
            self.is_rex_needed = True
            self.rex[5] = 1

    def setup_rm_as_register(self, name):
        self.rm = X64RegisterSelector.get_reg_bits(name)
        if X64.is_new_reg(name):
            self.is_rex_needed = True
            self.rex[7] = 1


class ModRM_REG64__REG64(SubModRM):
    @classmethod
    def match(cls, arg1, arg2):
        return (X64.is_reg(arg1) or X64.is_new_reg(arg1)) and (X64.is_reg(arg2) or X64.is_new_reg(arg2))

    def __init__(self, arg1, arg2, reversed):
        super(ModRM_REG64__REG64, self).__init__()
        self.mod = BitArray(2, "11")
        self.is_rex_needed = True
        self.rex[4] = 1
        self.setup_reg_as_register(arg2)
        self.setup_rm_as_register(arg1)
        self.direction = 0


class ModRM_REG__DEREF_REG(SubModRM):
    @classmethod
    def match(cls, arg1, arg2):
        return (X64.is_reg(arg1) or X64.is_new_reg(arg1)) and X64.is_mem_acces(arg2) and X64.mem_access_has_only(arg2, ["base"]) and arg2.base not in ["RSP", "RBP"]

    def __init__(self, arg1, arg2, reversed):
        super(ModRM_REG__DEREF_REG, self).__init__()
        self.mod = BitArray(2, "00")
        self.is_rex_needed = True
        self.rex[4] = 1
        self.setup_reg_as_register(arg1)
        self.setup_rm_as_register(arg2.base)
        self.after = BitArray(0, "")
        self.direction = not reversed
#
class ModRM_REG__DEREF_REG_IMM(SubModRM):
    @classmethod
    def match(cls, arg1, arg2):
        return X64.is_reg(arg1) and X64.is_mem_acces(arg2) and X64.mem_access_has_only(arg2, ["base", "disp"]) and arg2.base.upper() not in ['RSP', 'RBP']

    def __init__(self, arg1, arg2, reversed):
        super(ModRM_REG__DEREF_REG_IMM, self).__init__()
        import pdb;pdb.set_trace()
        self.mod = BitArray(2, "10")
        self.is_rex_needed = True
        self.rex[4] = 1
        self.setup_reg_as_register(arg1)
        self.setup_rm_as_register(arg2.base)
        self.after = BitArray.from_int(32, X64.to_little_endian(arg2.disp, size=32))
        self.direction = not reversed

class ModRM_REG__DEREF_BASE_INDEX(SubModRM):
    """Only handle [BASE + INDEX]"""
    @classmethod
    def match(cls, arg1, arg2):
        return X64.is_reg(arg1) and X64.is_mem_acces(arg2) and X64.mem_access_has_only(arg2, ["base", "index", "scale"])

    def __init__(self, arg1, arg2, reversed):
        super(ModRM_REG__DEREF_BASE_INDEX, self).__init__()
        #import pdb;pdb.set_trace()
        self.mod = BitArray(2, "00")
        self.rm = BitArray(3, "100")
        self.is_rex_needed = True
        self.rex[4] = 1
        self.setup_reg_as_register(arg1)
        self.after = self.create_sib(arg2)
        self.direction = not reversed

    def create_sib(self, mem_access):
        scale = {1: 0, 2 : 1, 4: 2, 8 : 3}
        if mem_access.disp:
            raise NotImplementedError("SIB WITH DISPLACEMENT")
        if mem_access.scale not in scale:
            raise ValueError("Invalid scale for mem access <{0}>".format(mem_access.scale))
        scale_bits = BitArray.from_int(2, scale[mem_access.scale])
        base_bits = X64RegisterSelector.get_reg_bits(mem_access.base)
        if X64.is_new_reg(mem_access.base):
            self.rex[7] = 1
        index_bits = X64RegisterSelector.get_reg_bits(mem_access.index)
        if X64.is_new_reg(mem_access.index):
            self.rex[6] = 1
        return scale_bits + index_bits + base_bits

class ModRM_REG__DEREF_SIB(SubModRM):
    """Only handle [BASE + INDEX]"""
    @classmethod
    def match(cls, arg1, arg2):
        return X64.is_reg(arg1) and X64.is_mem_acces(arg2)# and X64.mem_access_has_only(arg2, ["base", "index", "scale", '])

    def __init__(self, arg1, arg2, reversed):
        super(ModRM_REG__DEREF_SIB, self).__init__()
        self.mod = BitArray(2, "10")
        #import pdb;pdb.set_trace()
        self.rm = BitArray(3, "100")
        self.is_rex_needed = True
        self.rex[4] = 1
        self.setup_reg_as_register(arg1)
        self.after = self.create_sib(arg2) + BitArray.from_int(32, X64.to_little_endian(arg2.disp, size=32))
        self.direction = not reversed

    def create_sib(self, mem_access):
        scale = {None:0, 1: 0, 2 : 1, 4: 2, 8 : 3}
        #if mem_access.disp:
        #    raise NotImplementedError("SIB WITH DISPLACEMENT")
        if mem_access.scale not in scale:
            raise ValueError("Invalid scale for mem access <{0}>".format(mem_access.scale))
        scale_bits = BitArray.from_int(2, scale[mem_access.scale])
        base_bits = X64RegisterSelector.get_reg_bits(mem_access.base)
        if X64.is_new_reg(mem_access.base):
            self.rex[7] = 1
        if mem_access.index is None:
            index_bits = BitArray(3, "100")
        else:
            index_bits = X64RegisterSelector.get_reg_bits(mem_access.index)
        if X64.is_new_reg(mem_access.index):
            self.rex[6] = 1
        return scale_bits + index_bits + base_bits


class Slash(object):
    "No idea for the name: represent the modRM for single args + encoding in reg (/7 in cmp in man intel)"

    def __init__(self, reg):
        "reg = 7 for /7"
        self.mod = None
        self.reg = BitArray.from_int(3, reg)

        self.rm = None

    def accept_arg(self, previous, args):
        x = args[0]
        ok, bits, rex = X64RegisterSelector().accept_arg(None, [x])
        if ok is not None:
            self.mod = BitArray(2, "11")
            self.rm = bits
            return 1, self.mod + self.reg + self.rm, rex
        # TODO: register !
        if X64.mem_access_has_only(x, ["base"]) and x.base not in ['ESP', 'EBP']:
            self.mod = BitArray(2, "00")
            ok, bits = X86RegisterSelector().accept_arg(None, [x.base])
            self.rm = bits
            return 1, self.mod + self.reg + self.rm, rex
        # TODO: Other
        if X64.mem_access_has_only(x, ["base", "disp"]):
            self.mod = BitArray(2, "10")
            ok, bits, rex = X64RegisterSelector().accept_arg(None, [x.base])
            self.rm = bits
            return 1, self.mod + self.reg + self.rm + BitArray.from_int(32, X64.to_little_endian(x.disp, size=32)), rex
        return None, None

class Instruction(object):
    encoding = []

    def __init__(self, *initial_args):
        for type_encoding in self.encoding:
            args = list(initial_args)
            res = []
            full_rex = BitArray(8, "")
            if hasattr(self, "default_32_bits") and self.default_32_bits:
                full_rex = BitArray.from_int(8, 0x48)
            for element in type_encoding:
                arg_consum, value, rex = element.accept_arg(res, args)
                if arg_consum is None:
                    break
                res.append(value)
                del args[:arg_consum]
                if rex is not None:
                    full_rex = full_rex | rex
            else: # if no break
                if args: # if still args: fail
                    continue
                self.value = sum(res, BitArray(0, ""))
                if any(full_rex.array):
                    self.value = full_rex + self.value
                return
        raise ValueError("Cannot encode <{0} {1}>:(".format(type(self).__name__, initial_args))

    def get_code(self):
        return self.value.dump()

class DelayedJump(object):
    def __init__(self, type, label):
        self.type = type
        self.label = label

class JmpType(Instruction):
    def __new__(cls, *initial_args):
        if len(initial_args) == 1:
            arg = initial_args[0]
            if isinstance(arg, str) and arg[0] == ":":
                return DelayedJump(cls, arg)
        return super(JmpType, cls).__new__(cls, *initial_args)

#
#
class Push(Instruction):
    encoding = [(RawBits.from_int(5, 0x50 >> 3), X64RegisterSelector()),
                (RawBits.from_int(8, 0x68), Imm32())]

class Pop(Instruction):
    encoding = [(RawBits.from_int(5, 0x58 >> 3), X64RegisterSelector())]

class Call(Instruction):
    encoding = [(RawBits.from_int(13, 0xffd0 >> 3), X64RegisterSelector())]

class Ret(Instruction):
    encoding = [(RawBits.from_int(8, 0xc3),)]

class Int3(Instruction):
    encoding = [(RawBits.from_int(8, 0xcc),)]

class Dec(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0xff), Slash(1))]

class Inc(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0xff), Slash(0))]

class Add(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0x05), RegisterRax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(0), Imm32()),
                (RawBits.from_int(8, 0x01), ModRM(ModRM_REG64__REG64, ModRM_REG__DEREF_REG, ModRM_REG__DEREF_REG_IMM, ModRM_REG__DEREF_BASE_INDEX, )),]

class Sub(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0x2D), RegisterRax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(5), Imm32())]

class Out(Instruction):
    encoding = [(RawBits.from_int(8, 0xee), FixedRegister('DX'), FixedRegister('AL')),
                (RawBits.from_int(16, 0x66ef), FixedRegister('DX'), FixedRegister('AX')), # Fuck-it hardcoded prefix for now
                (RawBits.from_int(8, 0xef), FixedRegister('DX'), FixedRegister('EAX'))]

class In(Instruction):
    encoding = [(RawBits.from_int(8, 0xec), FixedRegister('AL'), FixedRegister('DX')),
                (RawBits.from_int(16, 0x66ed), FixedRegister('AX'), FixedRegister('DX')), # Fuck-it hardcoded prefix for now
                (RawBits.from_int(8, 0xed), FixedRegister('EAX'), FixedRegister('DX'))]

class JmpImm8(Immediat):
    def __init__(self, sub):
        self.sub = sub
    def accept_arg(self, previous, args):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None, None)
        if not (-128 + self.sub) <= x <= 127:
            return (None, None, None)
        x -= self.sub
        return (1, BitArray.from_int(8, X64.to_little_endian(x, size=8)), None)

class JmpImm32(Immediat):
    def __init__(self, sub):
        self.sub = sub
    def accept_arg(self, previous, args):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None, None)
        #if not (-128 + self.ADD) <= x <= 127:
        #    return (None, None)
        x -= self.sub
        return (1, BitArray.from_int(32, X64.to_little_endian(x, size=32)), None)

class Jmp(JmpType):
    encoding = [(RawBits.from_int(8, 0xeb), JmpImm8(2)),
                (RawBits.from_int(8, 0xe9), JmpImm32(5)),
                (RawBits.from_int(13, 0xffe0 >> 3), X64RegisterSelector())]

class Jz(JmpType):
    encoding = [(RawBits.from_int(8, 0x74), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f84), JmpImm32(6))]

class Jnz(JmpType):
    encoding = [(RawBits.from_int(8, 0x75), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f85), JmpImm32(6))]

class Jb(JmpType):
    encoding = [(RawBits.from_int(8, 0x72), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f82), JmpImm32(6))]

class Jbe(JmpType):
    encoding = [(RawBits.from_int(8, 0x76), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f86), JmpImm32(6))]

class Jnb(JmpType):
    encoding = [(RawBits.from_int(8, 0x73), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f83), JmpImm32(6))]

class Mov(Instruction):
   default_32_bits = True
   encoding = [(RawBits.from_int(8, 0x89), ModRM(ModRM_REG64__REG64, ModRM_REG__DEREF_REG, ModRM_REG__DEREF_REG_IMM, ModRM_REG__DEREF_BASE_INDEX, ModRM_REG__DEREF_SIB)),
                (RawBits.from_int(5, 0xb8 >> 3), X64RegisterSelector(), Imm64()),
                (Mov_RAX_OFF64(),), (Mov_OFF64_RAX(),)]

class Cmp(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0x3d), RegisterRax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(7), Imm32()),
                (RawBits.from_int(8, 0x3b), ModRM(ModRM_REG64__REG64, ModRM_REG__DEREF_REG)),]

class Xor(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0x31), ModRM(ModRM_REG64__REG64))]

class Nop(Instruction):
    encoding = [(RawBits.from_int(8, 0x90),)]

class Retf(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0xcb),)]

class Retf32(Instruction):
    encoding = [(RawBits.from_int(8, 0xcb),)]

class _NopArtifact(Nop):
    pass

def JmpAt(addr):
    code = MultipleInstr()
    code += Mov('RAX', addr)
    code += Jmp('RAX')
    return code

class Label(object):
    def __init__(self, name):
        self.name = name

class MultipleInstr(object):
    JUMP_SIZE = 6
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
            raise ValueError("Unresolved labels: {self.expected_labels}".format(self=self))
        return "".join([str(x[1].get_code()) for x in sorted(self.instrs.items())])

    def add_instruction(self, instruction):
        if isinstance(instruction, Label):
            return self.add_label(instruction)
        # Change DelayedJump to LabeledJump ?
        if isinstance(instruction, DelayedJump):
            return self.add_delayed_jump(instruction)
        if isinstance(instruction, Instruction):
            self.instrs[self.size] = instruction
            self.size += len(instruction.get_code())
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

    def _reduce_shellcode(self):
        to_remove = [offset for offset,instr in self.instrs.items() if type(instr) == _NopArtifact]
        while to_remove:
            self._remove_nop_artifact(to_remove[0])
            # _remove_nop_artifact will change the offsets of the nop
            # Need to refresh these offset
            to_remove = [offset for offset,instr in self.instrs.items() if type(instr) == _NopArtifact]

    def _remove_nop_artifact(self, offset):
        # Remove a NOP from the shellcode
        for src, dst in self.computed_jump:
            # Reduce size of Jump over the nop (both sens)
            if src < offset < dst or dst < offset < src:
                old_jmp = self.instrs[src]
                old_jump_size = len(old_jmp.get_code())
                if src < offset < dst:
                    new_jmp = type(old_jmp)(dst - src - 1)
                else:
                    new_jmp = type(old_jmp)(dst - src + 1)
                new_jmp_size = len(new_jmp.get_code())
                if new_jmp_size > old_jump_size:
                    raise ValueError("Wtf jump of smaller size of bigger.. ABORT")
                self.instrs[src] = new_jmp
                # Add other _NopArtifact if jump instruction size is reduced
                for i in range(old_jump_size - new_jmp_size):
                    self.instrs[src + new_jmp_size + i] = _NopArtifact()

        # dec offset of all Label after the NOP
        for name, labeloffset in self.labels.items():
            if labeloffset > offset:
                   self.labels[name] = labeloffset - 1

        # dec offset of all instr after the NOP
        new_instr = {}
        for instroffset, instr in self.instrs.items():
            if instroffset == offset:
                continue
            if instroffset > offset:
                instroffset -= 1
            new_instr[instroffset] = instr
        self.instrs = new_instr
        # Update all computed jump
        new_computed_jump = []
        for src, dst in self.computed_jump:
            if src > offset:
                src -= 1
            if dst > offset:
                dst -= 1
            new_computed_jump.append((src, dst))
        self.computed_jump = new_computed_jump
        # dec size of the shellcode
        self.size -= 1

    def merge_shellcode(self, other):
        for offset, instr in sorted(other.instrs.items()):
            self.add_instruction(instr)

    def __iadd__(self, other):
        if isinstance(other, MultipleInstr):
            self.merge_shellcode(other)
        else:
            self.add_instruction(other)
        return self


# import windows.native_exec.simple_x64 as x64
try:
    import midap
    import idc
    in_IDA = True
except ImportError:
    in_IDA = False


def test_code():
    s = MultipleInstr()
    s += Mov('r8', 'r14')
    s += Label(':SUCE')
    s += Jnz(':END')
    s += Add('r14', 0x12345678)
    s += Dec('r9')
    s += Dec('rax')
    s += Jnz(':END')
    s += Mov('r8', 'rdx')
    s += Jnz(':END')
    s += Mov('r8', 'rdx')
    s += Jnz(':SUCE')
    s += Mov('r9', 'r10')
    s += Label(':END')
    s += Ret()
    return s



if in_IDA:
    def reset():
        idc.MakeUnknown(idc.MinEA(), 0x1000, 0)
        for i in range(0x1000):
            idc.PatchByte(idc.MinEA() + i, 0)

    s = test_code()

    def tst():
        reset()
        midap.here(idc.MinEA()).write(s.get_code())
        idc.MakeFunction(idc.MinEA())

    #tst()

