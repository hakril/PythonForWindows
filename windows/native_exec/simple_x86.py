import sys
import collections
import struct
import binascii

# py3
is_py3 = (sys.version_info.major >= 3)
if is_py3:
    basestring = str
    int_types = int
else:
    int_types = (int, long)

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

    def copy(self):
        new = type(self)(0, "")
        new.size = self.size
        new.array = list(self.array)
        return new

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

    def to_int(self):
        return int("".join([str(i) for i in self.array]), 2)

    @classmethod
    def from_string(cls, str_base):
        l = []
        for c in bytearray(reversed(str_base)):
            for i in range(8):
                l.append(c & 1)
                c = c >> 1
        return cls(len(str_base) * 8, list(reversed(l)))

    @classmethod
    def from_int(cls, size, x):
        if x < 0:
            x = x & ((2 ** size) - 1)
        return cls(size, bin(x)[2:])


# Prefix
class Prefix(object):
    PREFIX_VALUE = None

    def __init__(self, next=None):
        self.next = next

    def __add__(self, other):
        return type(self)(other)

    def get_code_py3(self):
        return bytes([self.PREFIX_VALUE]) + self.next.get_code()

    def get_code(self):
        return chr(self.PREFIX_VALUE) + self.next.get_code()

    if is_py3:
        get_code = get_code_py3


def create_prefix(name, value):
    prefix_type = type(name + "Type", (Prefix,), {'PREFIX_VALUE': value})
    return prefix_type()

LockPrefix = create_prefix('LockPrefix', 0xf0)
Repne = create_prefix('Repne', 0xf2)
Rep = create_prefix('Rep', 0xf3)
SSPrefix = create_prefix('SSPrefix', 0x36)
CSPrefix = create_prefix('CSPrefix', 0x2e)
DSPrefix = create_prefix('DSPrefix', 0x3e)
ESPrefix = create_prefix('ESPrefix', 0x26)
FSPrefix = create_prefix('FSPrefix', 0x64)
GSPrefix = create_prefix('GSPrefix', 0x65)
OperandSizeOverride = create_prefix('OperandSizeOverride', 0x66)
AddressSizeOverride = create_prefix('AddressSizeOverride', 0x67)

# Main informations about X86
mem_access = collections.namedtuple('mem_access', ['base', 'index', 'scale', 'disp', 'prefix'])
x86_regs = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']
x86_16bits_regs = ['AX', 'CX', 'DX', 'BX', 'SP', 'BP', 'SI', 'DI']

x86_segment_selectors = {'CS': CSPrefix, 'DS': DSPrefix, 'ES': ESPrefix, 'SS': SSPrefix,
                         'FS': FSPrefix, 'GS': GSPrefix}

# Man intel -> Sreg (Vol 2.a 3-6)
x86_segment_selectors_number = {
    "ES": "000",
    "CS": "001",
    "SS": "010",
    "DS": "011",
    "FS": "100",
    "GS": "101",
 }

class X86(object):
    @staticmethod
    def is_reg(name):
        try:
            return name.upper() in x86_regs + x86_16bits_regs
        except AttributeError:  # Not a string
            return False

    @staticmethod
    def is_seg_reg(name):
        try:
            return name.upper() in x86_segment_selectors_number
        except AttributeError:
            return False

    @staticmethod
    def reg_size(name):
        if name.upper() in x86_regs:
            return 32
        elif name.upper() in x86_16bits_regs:
            return 16
        else:
            raise ValueError("Unknow register <{0}>".format(name))

    @staticmethod
    def is_mem_acces(data):
        return isinstance(data, mem_access)

    @staticmethod
    def mem_access_has_only(mem_access, names):
        if not X86.is_mem_acces(mem_access):
            raise ValueError("mem_access_has_only")
        for f in mem_access._fields:
            v = getattr(mem_access, f)
            if v and f != 'prefix' and f not in names:
                return False
            if v is None and f in names:
                return False
        return True


def create_displacement(base=None, index=None, scale=None, disp=0, prefix=None):
    """Creates a X86 memory access description"""
    if index is not None and scale is None:
        scale = 1
    if scale and index is None:
        raise ValueError("Cannot create displacement with scale and no index")
    if scale and index.upper() == "ESP":
        raise ValueError("Cannot create displacement with index == ESP")
    return mem_access(base, index, scale, disp, prefix)


def deref(disp):
    """Create a memory access for an immediate value ``Ex: [0x42424242]``"""
    return create_displacement(disp=disp)


def mem(data):
    """Parse a memory access string of format ``[EXPR]`` or ``seg:[EXPR]``

       ``EXPR`` may describe: ``BASE | INDEX * SCALE | DISPLACEMENT`` or any combinaison (in this order)
    """
    if not isinstance(data, str):
        raise TypeError("mem need a string to parse")
    data = data.strip()
    prefix = None
    if not (data.startswith("[") and data.endswith("]")):
        if data[2] != ":":
            raise ValueError("mem acces expect <[EXPR]> or <seg:[EXPR]")
        prefix_name = data[:2].upper()
        if prefix_name not in x86_segment_selectors:
            raise ValueError("Unknow segment selector {0}".format(prefix_name))
        prefix = prefix_name
        data = data[3:]
    if not (data.startswith("[") and data.endswith("]")):
        raise ValueError("mem acces expect <[EXPR]> or <seg:[EXPR]")
    # A l'arrache.. j'aime pas le parsing de trucs
    data = data[1:-1]
    items = data.split("+")
    parsed_items = {'prefix': prefix}
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
            if not X86.is_reg(index):
                raise ValueError("Invalid index <{0}> in mem access".format(index))
            if X86.reg_size(index) == 16:
                raise NotImplementedError("16bits modrm")
            try:
                scale = int(scale, 0)
            except ValueError:
                raise ValueError("Invalid scale <{0}> in mem access".format(scale))
            parsed_items['scale'] = scale
            parsed_items['index'] = index
        else:
            # displacement / base / index alone
            if X86.is_reg(item):
                if X86.reg_size(item) == 16:
                    raise NotImplementedError("16bits modrm")
                if 'base' not in parsed_items:
                    parsed_items['base'] = item
                    continue
                # Already have base + index -> cannot avec another register in expression
                if 'index' in parsed_items:
                    raise ValueError("Multiple index / index*scale in mem expression <{0}>".format(data))
                parsed_items['index'] = item
                continue
            try:
                disp = int(item, 0)
            except ValueError:
                raise ValueError("Invalid base/index or displacement <{0}> in mem access".format(item))
            if 'disp' in parsed_items:
                raise ValueError("Multiple displacement in mem expression <{0}>".format(data))
            parsed_items['disp'] = disp
    return create_displacement(**parsed_items)


# Helper to get the BitArray associated to a register
class X86RegisterSelector(object):
    size = 3  # bits
    reg_opcode = {v: BitArray.from_int(size=3, x=i) for i, v in enumerate(x86_regs)}
    reg_opcode.update({v: BitArray.from_int(size=3, x=i) for i, v in enumerate(x86_16bits_regs)})

    def accept_arg(self, args, instr_state):
        x = args[0]
        try:
            return (1, self.reg_opcode[x.upper()])
        except (KeyError, AttributeError):
            return (None, None)

    @classmethod
    def get_reg_bits(cls, name):
        return cls.reg_opcode[name.upper()]


# Instruction Parameters
class FixedRegister(object):
    def __init__(self, register):
        self.reg = register.upper()

    def accept_arg(self, args, instr_state):
        x = args[0]
        if isinstance(x, str) and x.upper() == self.reg:
            return (1, BitArray(0, []))
        return None, None

RegisterEax = lambda: FixedRegister('EAX')


class RawBits(BitArray):
    def accept_arg(self, args, instr_state):
        return (0, self.copy())


# Immediat value logic
# All 8/16 bits stuff are sign extended
class ImmediatOverflow(ValueError):
    pass


def accept_as_8immediat(x):
    try:
        return struct.pack("<b", x)
    except struct.error:
        raise ImmediatOverflow("8bits signed Immediat overflow")


def accept_as_unsigned_8immediat(x):
    try:
        return struct.pack("<B", x)
    except struct.error:
        raise ImmediatOverflow("8bits signed Immediat overflow")


def accept_as_16immediat(x):
    try:
        return struct.pack("<h", x)
    except struct.error:
        raise ImmediatOverflow("16bits signed Immediat overflow")


def accept_as_unsigned_16immediat(x):
    try:
        return struct.pack("<H", x)
    except struct.error:
        raise ImmediatOverflow("16bits unsigned Immediat overflow")

def accept_as_32immediat(x):
    try:
        return struct.pack("<i", x)
    except struct.error:
        pass
    try:
        return struct.pack("<I", x)
    except struct.error:
        raise ImmediatOverflow("32bits signed Immediat overflow")


class Imm8(object):
    def accept_arg(self, args, instr_state):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None)
        try:
            imm8 = accept_as_8immediat(x)
        except ImmediatOverflow:
            return None, None
        return (1, BitArray.from_string(imm8))

class UImm8(object):
    def accept_arg(self, args, instr_state):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None)
        try:
            imm8 = accept_as_unsigned_8immediat(x)
        except ImmediatOverflow:
            return None, None
        return (1, BitArray.from_string(imm8))


class Imm16(object):
    def accept_arg(self, args, instr_state):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None)
        try:
            imm16 = accept_as_16immediat(x)
        except ImmediatOverflow:
            return None, None
        return (1, BitArray.from_string(imm16))

class UImm16(object):
    def accept_arg(self, args, instr_state):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None)
        try:
            imm16 = accept_as_unsigned_16immediat(x)
        except ImmediatOverflow:
            return None, None
        return (1, BitArray.from_string(imm16))


class Imm32(object):
    def accept_arg(self, args, instr_state):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None)
        try:
            imm32 = accept_as_32immediat(x)
        except ImmediatOverflow:
            return None, None
        return (1, BitArray.from_string(imm32))

class SegmentSelectorAbsoluteAddr(object):
    def accept_arg(self, args, instr_state):
        sizess, datass = UImm16().accept_arg(args, instr_state)
        if sizess is None:
            return None, None
        sizeabs, dataabs = Imm32().accept_arg(args[1:], instr_state)
        if sizeabs is None:
            return None, None
        return (sizess + sizeabs, dataabs + datass)



class ModRM(object):
    def __init__(self, sub_modrm, accept_reverse=True, has_direction_bit=True):
        self.accept_reverse = accept_reverse
        self.has_direction_bit = has_direction_bit
        self.sub = sub_modrm

    def accept_arg(self, args, instr_state):
        if len(args) < 2:
            raise ValueError("Missing arg for modrm")
        arg1 = args[0]
        arg2 = args[1]
        for sub in self.sub:
            # Problem in reverse sens -> need to fix it
            if sub.match(arg1, arg2):
                d = sub(arg1, arg2, 0, instr_state)
                if self.has_direction_bit:
                    instr_state.previous[0][-2] = d.direction
                return (2, d.mod + d.reg + d.rm + d.after)
            elif self.accept_reverse and sub.match(arg2, arg1):
                d = sub(arg2, arg1, 1, instr_state)
                if self.has_direction_bit:
                    instr_state.previous[0][-2] = d.direction
                return (2, d.mod + d.reg + d.rm + d.after)
        return (None, None)


class ModRM_REG__REG(object):

    @classmethod
    def match(cls, arg1, arg2):
        return X86.is_reg(arg1) and X86.is_reg(arg2)

    def __init__(self, arg1, arg2, reversed, instr_state):
        self.mod = BitArray(2, "11")
        if X86.reg_size(arg1) != X86.reg_size(arg2):
            raise ValueError("Register size mitmatch between {0} and {1}".format(arg1, arg2))
        if X86.reg_size(arg1) == 16:
            instr_state.prefixes.append(OperandSizeOverride)
        self.reg = X86RegisterSelector.get_reg_bits(arg2)
        self.rm = X86RegisterSelector.get_reg_bits(arg1)
        self.after = BitArray(0, "")
        self.direction = 0

class ModRM_REG__SEGREG(object):
    @classmethod
    def match(cls, arg1, arg2):
        return X86.is_reg(arg1) and X86.is_seg_reg(arg2)

    def __init__(self, arg1, arg2, reversed, instr_state):
        self.mod = BitArray(2, "11")
        self.rm = X86RegisterSelector.get_reg_bits(arg1)
        self.reg = BitArray(3, x86_segment_selectors_number[arg2.upper()])
        self.after = BitArray(0, "")
        self.direction = reversed


class ModRM_REG__MEM(object):

    @classmethod
    def match(cls, arg1, arg2):
        return X86.is_reg(arg1) and X86.is_mem_acces(arg2)

    def setup_reg_as_register(self, regname, instr_state):
        self.reg = X86RegisterSelector.get_reg_bits(regname)
        if X86.reg_size(regname) == 16:
            instr_state.prefixes.append(OperandSizeOverride)

    def __init__(self, arg1, arg2, reversed, instr_state):
        # ARG1 : REG
        # ARG2 : prefix:[MEM]
        # Handle prefix:
        if arg2.prefix is not None:
            instr_state.prefixes.append(x86_segment_selectors[arg2.prefix])
        if X86.mem_access_has_only(arg2, ["disp"]):
            self.mod = BitArray(2, "00")
            self.setup_reg_as_register(arg1, instr_state)
            self.rm = BitArray(3, "101")
            try:
                self.after = BitArray.from_string(accept_as_32immediat(arg2.disp))
            except ImmediatOverflow:
                raise ImmediatOverflow("Interger32 overflow for displacement {0}".format(hex(arg2.disp)))
            self.direction = not reversed
            return
        # Those registers cannot be addressed without SIB
        # No index -> no scale -> no SIB
        FIRE_UP_SIB = (arg2.base and arg2.base.upper() in ["ESP", "EBP"]) or arg2.index
        if not FIRE_UP_SIB:
            self.setup_reg_as_register(arg1, instr_state)
            self.rm = X86RegisterSelector.get_reg_bits(arg2.base)
            self.compute_displacement(arg2.disp)
            self.direction = not reversed
            return
        # FIRE UP THE SIB
        # Handle no base and base == EBP special case
        if not arg2.base:
            force_displacement = 4
        elif arg2.base.upper() == "EBP":
            force_displacement = 1
        else:
            force_displacement = 0

        self.setup_reg_as_register(arg1, instr_state)
        self.rm = BitArray(3, "100")
        self.compute_displacement(arg2.disp, force_displacement)
        self.after = self.compute_sib(arg2) + self.after
        if not arg2.base:
            self.mod = BitArray(2, "00")
        self.direction = not reversed

    def compute_displacement(self, displacement, force_displacement=0):
        if not displacement and not force_displacement:
            self.mod = BitArray(2, "00")
            self.after = BitArray(0, "")
            return
        # Pack in a byte
        try:
            v = accept_as_8immediat(displacement)
        except ImmediatOverflow:
            v = None
        if v is not None and force_displacement <= 1:
            self.mod = BitArray(2, "01")
            self.after = BitArray.from_string(v)
            return
        # Pack in a dword
        try:
            v = accept_as_32immediat(displacement)
        except ImmediatOverflow:
            v = None
        if v is not None and force_displacement <= 4:
            self.mod = BitArray(2, "10")
            self.after = BitArray.from_string(v)
            return
        raise ValueError("Displacement {0} is too big".format(hex(displacement)))

    def compute_sib(self, mem_access):
        scale = {1: 0, 2: 1, 4: 2, 8: 3}
        if mem_access.index is None:
            return BitArray(2, "00") + BitArray(3, "100") + X86RegisterSelector.get_reg_bits(mem_access.base)
        if mem_access.scale not in scale:
            raise ValueError("Invalid scale for mem access <{0}>".format(mem_access.scale))
        if mem_access.base is None:
            return BitArray.from_int(2, scale[mem_access.scale]) + X86RegisterSelector.get_reg_bits(mem_access.index) + BitArray(3, "101")
        return BitArray.from_int(2, scale[mem_access.scale]) + X86RegisterSelector.get_reg_bits(mem_access.index) + X86RegisterSelector.get_reg_bits(mem_access.base)


class Slash(object):
    "No idea for the name: represent the modRM for single args + encoding in reg (/7 in cmp in man intel)"

    def __init__(self, reg_num):
        "reg = 7 for /7"
        self.reg = x86_regs[reg_num]

    def accept_arg(self, args, instr_state):
        if len(args) < 1:
            raise ValueError("Missing arg for Slash")
        # Reuse all the MODRm logique with the reg as our self.reg
        # The sens of param is strange I need to fix the `reversed` logique
        arg_consum, value = ModRM([ModRM_REG__REG, ModRM_REG__MEM], has_direction_bit=False).accept_arg(args[:1] + [self.reg] + args[1:], instr_state)
        if value is None:
            return arg_consum, value
        return arg_consum - 1, value

class ControlRegisterModRM(object):
    def __init__(self, writecr = False):
        self.writecr = writecr

    def accept_arg(self, args, instr_state):
        writecr = self.writecr
        if len(args) < 2:
            return None, None
        reg = args[writecr]
        cr = args[not writecr]
        if not isinstance(cr, str):
            return None, None
        if not cr.lower().startswith("cr"):
            return None, None
        try:
            cr_number = int(cr[2:], 10)
        except ValueError as e:
            raise ValueError("Invalid ControlRegister {0}".format(cr))
        if cr_number > 7:
            raise ValueError("Invalid ControlRegister {0}".format(cr))

        modrm_params = [reg, x86_regs[cr_number]] + args[2:]
        return ModRM([ModRM_REG__REG], has_direction_bit=False).accept_arg(modrm_params, instr_state)


instr_state = collections.namedtuple('instr_state', ['previous', 'prefixes'])

class Instruction(object):
    """Base class of instructions, use `encoding` to find a valid way to assemble the instruction"""
    encoding = []

    def __init__(self, *initial_args):
        # print(self, initial_args)
        for type_encoding in self.encoding:
            args = list(initial_args)
            prefix = []
            res = []
            for element in type_encoding:
                arg_consum, value = element.accept_arg(args, instr_state(res, prefix))
                if arg_consum is None:
                    break
                res.append(value)
                del args[:arg_consum]
            else:  # if no break
                if args:  # if still args: fail
                    continue
                self.value = sum(res, BitArray(0, ""))
                self.prefix = prefix
                return
        raise ValueError("Cannot encode <{0} {1}>:(".format(type(self).__name__, initial_args))

    def get_code(self):
        # print(self.value)
        prefix_opcode = b"".join(chr(p.PREFIX_VALUE) for p in self.prefix)
        return prefix_opcode + bytes(self.value.dump())

    def get_code_py3(self):
        prefix_opcode = b"".join(bytes([p.PREFIX_VALUE]) for p in self.prefix)
        return prefix_opcode + bytes(self.value.dump())

    if is_py3:
        get_code = get_code_py3

    #def __add__(self, other):
    #    res = MultipleInstr()
    #    res += self
    #    res += other
    #    return res

    def __mul__(self, value):
        if not isinstance(value, int_types):
            return NotImplemented
        res = MultipleInstr()
        for i in range(value):
            res += self
        return res


# Jump helpers
class DelayedJump(object):
    """A jump to a label :NAME"""

    def __init__(self, type, label):
        self.type = type
        self.label = label


class JmpType(Instruction):
    """Dispatcher between a real jump or DelayedJump if parameters is a label"""

    def __new__(cls, *initial_args):
        if len(initial_args) == 1:
            arg = initial_args[0]
            if isinstance(arg, str) and arg[0] == ":":
                return DelayedJump(cls, arg)
        return super(JmpType, cls).__new__(cls)


class JmpImm(object):
    """Immediat parameters for Jump instruction
       Sub a specified size from the size to jump to `emulate` a jump from the begin address of the instruction"""
    accept_as_Ximmediat = None

    def __init__(self, sub):
        self.sub = sub

    def accept_arg(self, args, instr_state):
        try:
            jump_size = int(args[0])
        except (ValueError, TypeError):
            return (None, None)
        jump_size -= self.sub
        try:
            jmp_imm = self.accept_as_Ximmediat(jump_size)
        except ImmediatOverflow:
            return (None, None)
        return (1, BitArray.from_string(jmp_imm))


class JmpImm8(JmpImm):
    accept_as_Ximmediat = staticmethod(accept_as_8immediat)


class JmpImm32(JmpImm):
    accept_as_Ximmediat = staticmethod(accept_as_32immediat)


# Instructions

class Call(JmpType):
    encoding = [(RawBits.from_int(8, 0xe8), JmpImm32(5)),
                (RawBits.from_int(8, 0xff), Slash(2)),
                (RawBits.from_int(8, 0x9a), SegmentSelectorAbsoluteAddr())]

class Jmp(JmpType):
    encoding = [(RawBits.from_int(8, 0xeb), JmpImm8(2)),
                (RawBits.from_int(8, 0xe9), JmpImm32(5)),
                (RawBits.from_int(8, 0xea), SegmentSelectorAbsoluteAddr())]


class Jz(JmpType):
    encoding = [(RawBits.from_int(8, 0x74), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f84), JmpImm32(6))]


Je = Jz


class Jnz(JmpType):
    encoding = [(RawBits.from_int(8, 0x75), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f85), JmpImm32(6))]


class Jbe(JmpType):
    encoding = [(RawBits.from_int(8, 0x76), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f86), JmpImm32(6))]


class Jnb(JmpType):
    encoding = [(RawBits.from_int(8, 0x73), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f83), JmpImm32(6))]


class Push(Instruction):
    encoding = [(RawBits.from_int(5, 0x50 >> 3), X86RegisterSelector()),
                (RawBits.from_int(8, 0x68), Imm32()),
                (RawBits.from_int(8, 0xff), Slash(6))]


class Pop(Instruction):
    encoding = [(RawBits.from_int(5, 0x58 >> 3), X86RegisterSelector())]


class Dec(Instruction):
    encoding = [(RawBits.from_int(5, 0x48 >> 3), X86RegisterSelector())]


class Inc(Instruction):
    encoding = [(RawBits.from_int(5, 0x40 >> 3), X86RegisterSelector()),
                (RawBits.from_int(8, 0xff), Slash(0))]


class Add(Instruction):
    encoding = [(RawBits.from_int(8, 0x05), RegisterEax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(0), Imm32()),
                (RawBits.from_int(8, 0x01), ModRM([ModRM_REG__REG, ModRM_REG__MEM]))]

class And(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0x25), RegisterEax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(4), Imm32()),
                (RawBits.from_int(8, 0x21), ModRM([ModRM_REG__REG, ModRM_REG__MEM]))]


class Or(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0x0d), RegisterEax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(1), Imm32()),
                (RawBits.from_int(8, 0x09), ModRM([ModRM_REG__REG, ModRM_REG__MEM]))]


class Sub(Instruction):
    encoding = [(RawBits.from_int(8, 0x2D), RegisterEax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(5), Imm32()),
                (RawBits.from_int(8, 0x29), ModRM([ModRM_REG__REG, ModRM_REG__MEM]))]


class Mov(Instruction):
    encoding = [(RawBits.from_int(8, 0x89), ModRM([ModRM_REG__REG, ModRM_REG__MEM])),
                (RawBits.from_int(8, 0xc7), Slash(0), Imm32()),
                (RawBits.from_int(5, 0xB8 >> 3), X86RegisterSelector(), Imm32()),
                (RawBits.from_int(8, 0x8C), ModRM([ModRM_REG__SEGREG])),
                (RawBits.from_int(16, 0x0f20), ControlRegisterModRM(writecr=False)),
                (RawBits.from_int(16, 0x0f22), ControlRegisterModRM(writecr=True))]


class Movsb(Instruction):
    encoding = [(RawBits.from_int(8, 0xa4),)]


class Movsd(Instruction):
    encoding = [(RawBits.from_int(8, 0xa5),)]


class Pushfd(Instruction):
    encoding = [(RawBits.from_int(8, 0x9c),)]


class Pushad(Instruction):
    encoding = [(RawBits.from_int(8, 0x60),)]


class Popfd(Instruction):
    encoding = [(RawBits.from_int(8, 0x9d),)]


class Popad(Instruction):
    encoding = [(RawBits.from_int(8, 0x61),)]


class Lea(Instruction):
    encoding = [(RawBits.from_int(8, 0x8d), ModRM([ModRM_REG__MEM], accept_reverse=False, has_direction_bit=False))]


class Cmp(Instruction):
    encoding = [(RawBits.from_int(8, 0x3d), RegisterEax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(7), Imm32()),
                (RawBits.from_int(8, 0x3b), ModRM([ModRM_REG__REG, ModRM_REG__MEM]))]


class Test(Instruction):
    encoding = [(RawBits.from_int(8, 0xf7), Slash(0), Imm32()),
                (RawBits.from_int(8, 0x85), ModRM([ModRM_REG__REG, ModRM_REG__MEM], has_direction_bit=False))]


class Out(Instruction):
    encoding = [(RawBits.from_int(8, 0xee), FixedRegister('DX'), FixedRegister('AL')),
                (RawBits.from_int(16, 0x66ef), FixedRegister('DX'), FixedRegister('AX')),  # Fuck-it hardcoded prefix for now
                (RawBits.from_int(8, 0xef), FixedRegister('DX'), FixedRegister('EAX'))]


class In(Instruction):
    encoding = [(RawBits.from_int(8, 0xec), FixedRegister('AL'), FixedRegister('DX')),
                (RawBits.from_int(16, 0x66ed), FixedRegister('AX'), FixedRegister('DX')),  # Fuck-it hardcoded prefix for now
                (RawBits.from_int(8, 0xed), FixedRegister('EAX'), FixedRegister('DX'))]


class Xor(Instruction):
    encoding = [(RawBits.from_int(8, 0x31), ModRM([ModRM_REG__REG]))]


class Xchg(Instruction):
    encoding = [(RawBits.from_int(5, 0x90 >> 3), RegisterEax(), X86RegisterSelector()), (RawBits.from_int(5, 0x90 >> 3), X86RegisterSelector(), RegisterEax())]


class Rol(Instruction):
    encoding = [(RawBits.from_int(8, 0xC1), Slash(0), Imm8())]

class Ror(Instruction):
    encoding = [(RawBits.from_int(8, 0xC1), Slash(1), Imm8())]

class Shr(Instruction):
    encoding = [(RawBits.from_int(8, 0xC1), Slash(5), Imm8())]

class Shl(Instruction):
    encoding = [(RawBits.from_int(8, 0xC1), Slash(4), Imm8())]

class Cpuid(Instruction):
    encoding = [(RawBits.from_int(16, 0x0fa2),)]


class Ret(Instruction):
    encoding = [(RawBits.from_int(8, 0xc3),),
                (RawBits.from_int(8, 0xc2), UImm16())]


class ScasB(Instruction):
    encoding = [(RawBits.from_int(8, 0xAE),)]

class ScasW(Instruction):
    encoding = [(RawBits.from_int(16,  0x66AF),)]

class ScasD(Instruction):
    encoding = [(RawBits.from_int(8, 0xAF),)]


class StosB(Instruction):
    encoding = [(RawBits.from_int(8, 0xAA),)]

class StosW(Instruction):
    encoding = [(RawBits.from_int(16,  0x66AB),)]

class StosD(Instruction):
    encoding = [(RawBits.from_int(8, 0xAB),)]


class CmpsB(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0xa6),)]


class CmpsW(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(16, 0x66A7),)]


class CmpsD(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0xa7),)]


class Nop(Instruction):
    encoding = [(RawBits.from_int(8, 0x90),)]

class Not(Instruction):
    encoding = [(RawBits.from_int(8, 0xF7), Slash(2))]

class Retf(Instruction):
    encoding = [(RawBits.from_int(8, 0xcb),)]

class Int(Instruction):
    encoding = [(RawBits.from_int(8, 0xcd), UImm8())]

class Int3(Instruction):
    encoding = [(RawBits.from_int(8, 0xcc),)]

class Iret(Instruction):
    encoding = [(RawBits.from_int(8, 0xcf),)]


class _NopArtifact(Nop):
    """Special NOP used in shellcode reduction"""
    pass


class Byte(Instruction):
    """Output a raw byte"""
    encoding = [(UImm8(),)]


class Raw(Instruction):
    """Output raw data"""
    def __init__(self, *initial_args):
        if len(initial_args) != 1:
            raise ValueError("raw 'opcode' only accept one argument")
        # Accept space
        self.data = binascii.unhexlify(initial_args[0].replace(" ", ""))

    def get_code(self):
        return self.data




class Label(object):
    def __init__(self, name):
        self.name = name


def JmpAt(addr):
    code = MultipleInstr()
    code += Push(addr)
    code += Ret()
    return code


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
            raise ValueError("Unresolved labels: {0}".format(self.expected_labels.keys()))
        return b"".join([x[1].get_code() for x in sorted(self.instrs.items())])

    def add_instruction(self, instruction):
        if isinstance(instruction, Label):
            return self.add_label(instruction)
        # Change DelayedJump to LabeledJump ?
        if isinstance(instruction, DelayedJump):
            return self.add_delayed_jump(instruction)
        if isinstance(instruction, (Instruction, Prefix)):
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
        to_remove = [offset for offset, instr in self.instrs.items() if type(instr) == _NopArtifact]
        while to_remove:
            self._remove_nop_artifact(to_remove[0])
            # _remove_nop_artifact will change the offsets of the nop
            # Need to refresh these offset
            to_remove = [offset for offset, instr in self.instrs.items() if type(instr) == _NopArtifact]

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
                    raise ValueError("Wtf jump of smaller size is bigger.. ABORT")
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

        args = []
        if args_raw:
            for arg in args_raw[0].split(","):
                arg = arg.strip()
                if (arg[0] == "[" or arg[2:4] == ":[") and arg[-1] == "]":
                    arg = mem(arg)
                else:
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

def shellcode(str):
    shellcode = MultipleInstr()
    shellcode += str
    return shellcode

# IDA : import windows.native_exec.simple_x86 as x86
# IDA testing

try:
    import midap
    import idc
    in_IDA = True
except ImportError:
    in_IDA = False


if in_IDA:
    def test_code():
        s = MultipleInstr()
        s += Mov("Eax", "ESI")
        s += Inc("Ecx")
        s += Dec("edi")
        s += Ret()
        return s

    def reset():
        idc.MakeUnknown(idc.MinEA(), 0x1000, 0)
        for i in range(0x1000):
            idc.PatchByte(idc.MinEA() + i, 0)

    s = test_code()

    def tst():
        reset()
        midap.here(idc.MinEA()).write(s.get_code())
        idc.MakeFunction(idc.MinEA())
