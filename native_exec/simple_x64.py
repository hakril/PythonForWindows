import collections
import struct


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
        new_array = [(x | y) for x, y in zip(self.array, other.array)]
        return BitArray(self.size, new_array)

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

    def copy(self):
        return type(self)(self.size, self.array)


# Prefix
class Prefix(object):
    PREFIX_VALUE = None

    def __init__(self, next=None):
        self.next = next

    def __add__(self, other):
        return type(self)(other)

    def get_code(self):
        return chr(self.PREFIX_VALUE) + self.next.get_code()


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

mem_access = collections.namedtuple('mem_access', ['base', 'index', 'scale', 'disp', 'prefix'])

reg_order = ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI']
new_reg_order = ['R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']
x64_regs = reg_order + new_reg_order

x64_segment_selectors = {'CS': CSPrefix, 'DS': DSPrefix, 'ES': ESPrefix, 'SS': SSPrefix,
                         'FS': FSPrefix, 'GS': GSPrefix}


class X64(object):
    @staticmethod
    def is_reg(name):
        try:
            return (name.upper() in reg_order) or X64.is_new_reg(name)
        except AttributeError:  # Not a string
            return False

    @staticmethod
    def is_new_reg(name):
        try:
            return name.upper() in new_reg_order
        except AttributeError:  # Not a string
            return False

    @staticmethod
    def is_mem_acces(data):
        return isinstance(data, mem_access)

    @staticmethod
    def mem_access_has_only(mem_access, names):
        if not X64.is_mem_acces(mem_access):
            raise ValueError("mem_access_has_only")
        for f in mem_access._fields:
            if f != "prefix" and getattr(mem_access, f) and f not in names:
                return False
        if "base" in names and mem_access.base is None:
            return False
        return True

    @staticmethod
    def to_little_endian(i, size=64):
        pack = {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}
        s = pack[size]
        mask = (1 << size) - 1
        i = i & mask
        return struct.unpack("<" + s, struct.pack(">" + s, i))[0]


def create_displacement(base=None, index=None, scale=None, disp=0, prefix=None):
    if index is not None and scale is None:
        scale = 1
    if scale and index is None:
        raise ValueError("Cannot create displacement with scale and no index")
    if scale and index.upper() == "RSP":
        raise ValueError("Cannot create displacement with index == RSP")
    return mem_access(base, index, scale, disp, prefix)


def deref(disp):
    return create_displacement(disp=disp)


def mem(data):
    """Parse a memory access string of format [EXPR] or seg:[EXPR]
       EXPR may describe: BASE | INDEX * SCALE | DISPLACEMENT or any combinaison (in this order)
    """
    if not isinstance(data, str):
        raise TypeError("mem need a string to parse")
    data = data.strip()
    prefix = None
    if not (data.startswith("[") and data.endswith("]")):
        if data[2] != ":":
            raise ValueError("mem acces expect <[EXPR]> or <seg:[EXPR]")
        prefix_name = data[:2].upper()
        if prefix_name not in x64_segment_selectors:
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
            if not X64.is_reg(index):
                raise ValueError("Invalid index <{0}> in mem access".format(index))
            try:
                scale = int(scale, 0)
            except ValueError:
                raise ValueError("Invalid scale <{0}> in mem access".format(scale))
            parsed_items['scale'] = scale
            parsed_items['index'] = index
        else:
            # displacement / base / index alone
            if X64.is_reg(item):
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


class X64RegisterSelector(object):

    reg_opcode = {v: BitArray.from_int(size=3, x=i) for i, v in enumerate(reg_order)}
    new_reg_opcode = {v: BitArray.from_int(size=3, x=i) for i, v in enumerate(new_reg_order)}

    def accept_arg(self, args, instr_state):
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


class FixedRegister(object):
    def __init__(self, register):
        self.reg = register.upper()

    def accept_arg(self, args, instr_state):
        x = args[0]
        if isinstance(x, str) and x.upper() == self.reg:
            return 1, BitArray(0, []), None
        return None, None, None

RegisterRax = lambda: FixedRegister('RAX')


class RawBits(BitArray):
    def accept_arg(self, args, instr_state):
        return (0, self.copy(), None)


class ImmediatOverflow(ValueError):
    pass


def accept_as_8immediat(x):
    try:
        return struct.pack("<b", x)
    except struct.error:
        raise ImmediatOverflow("8bits signed Immediat overflow")


def accept_as_16immediat(x):
    try:
        return struct.pack("<h", x)
    except struct.error:
        raise ImmediatOverflow("16bits signed Immediat overflow")


def accept_as_32immediat(x):
    try:
        return struct.pack("<i", x)
    except struct.error:
        raise ImmediatOverflow("32bits signed Immediat overflow")


def accept_as_64immediat(x):
    try:
        return struct.pack("<q", x)
    except struct.error:
        pass
    try:
        return struct.pack("<Q", x)
    except struct.error:
        raise ImmediatOverflow("64bits signed Immediat overflow")


class Imm8(object):
    def accept_arg(self, args, instr_state):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return None, None, None
        try:
            imm8 = accept_as_16immediat(x)
        except ImmediatOverflow:
            return None, None, None
        return (1, BitArray.from_string(imm8), None)


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
        return (1, BitArray.from_string(imm16), None)


class Imm32(object):
    def accept_arg(self, args, instr_state):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None, None)
        try:
            imm32 = accept_as_32immediat(x)
        except ImmediatOverflow:
            return None, None, None
        return (1, BitArray.from_string(imm32), None)


class Imm64(object):
    def accept_arg(self, args, instr_state):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None, None)
        try:
            imm64 = accept_as_64immediat(x)
        except ImmediatOverflow:
            return None, None, None
        return (1, BitArray.from_string(imm64), None)


class Mov_RAX_OFF64(object):
    def accept_arg(self, args, instr_state):
        if RegisterRax().accept_arg(args, instr_state) == (None, None, None):
            return (None, None, None)
        arg2 = args[1]
        if not (X64.is_mem_acces(arg2) and X64.mem_access_has_only(arg2, ["disp"])):
            return (None, None, None)
        # Migth Raise an ImmediatOverflow bu no other encoding for this so precise error is cool
        if arg2.prefix is not None:
            instr_state.prefixes.append(x64_segment_selectors[arg2.prefix])
        return (2, BitArray.from_int(8, 0xa1) + BitArray.from_string(accept_as_64immediat(arg2.disp)), BitArray.from_int(8, 0x48))


class Mov_OFF64_RAX(object):
    def accept_arg(self, args, instr_state):
        if RegisterRax().accept_arg(args[1:], instr_state) == (None, None, None):
            return (None, None, None)
        arg2 = args[0]
        if not (X64.is_mem_acces(arg2) and X64.mem_access_has_only(arg2, ["disp"])):
            return (None, None, None)
        if arg2.prefix is not None:
            instr_state.prefixes.append(x64_segment_selectors[arg2.prefix])
        return (2, BitArray.from_int(8, 0xa3) + BitArray.from_string(accept_as_64immediat(arg2.disp)), BitArray.from_int(8, 0x48))


class ModRM(object):
    size = 8

    def __init__(self, sub_modrm, accept_reverse=True, has_direction_bit=True):
        self.sub = sub_modrm
        self.accept_reverse = accept_reverse
        self.has_direction_bit = has_direction_bit

    def accept_arg(self, args, instr_state):
        if len(args) < 2:
            raise ValueError("Missing arg for modrm")
        arg1 = args[0]
        arg2 = args[1]
        for sub in self.sub:
            if sub.match(arg1, arg2):
                d = sub(arg1, arg2, 0, instr_state)
                if self.has_direction_bit:
                    instr_state.previous[0][-2] = d.direction
                rex = d.rex if d.is_rex_needed else None
                return (2, d.mod + d.reg + d.rm + d.after, rex)
            elif self.accept_reverse and sub.match(arg2, arg1):
                d = sub(arg2, arg1, 1, instr_state)
                if self.has_direction_bit:
                    instr_state.previous[0][-2] = d.direction
                rex = d.rex if d.is_rex_needed else None
                return (2, d.mod + d.reg + d.rm + d.after, rex)
        return (None, None, None)


# Sub ModRM encoding
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

    def setup_sib_base_rex(self, baseregister):
        if X64.is_new_reg(baseregister):
            self.is_rex_needed = True
            self.rex[7] = 1
        return X64RegisterSelector.get_reg_bits(baseregister)

    def setup_sib_index_rex(self, indexregister):
        if X64.is_new_reg(indexregister):
            self.is_rex_needed = True
            self.rex[6] = 1
        return X64RegisterSelector.get_reg_bits(indexregister)


class ModRM_REG64__REG64(SubModRM):
    @classmethod
    def match(cls, arg1, arg2):
        return (X64.is_reg(arg1) or X64.is_new_reg(arg1)) and (X64.is_reg(arg2) or X64.is_new_reg(arg2))

    def __init__(self, arg1, arg2, reversed, instr_state):
        super(ModRM_REG64__REG64, self).__init__()
        self.mod = BitArray(2, "11")
        self.is_rex_needed = True
        self.rex[4] = 1
        self.setup_reg_as_register(arg2)
        self.setup_rm_as_register(arg1)
        self.direction = 0


class ModRM_REG64__MEM(SubModRM):
    @classmethod
    def match(cls, arg1, arg2):
        return (X64.is_reg(arg1) or X64.is_new_reg(arg1)) and X64.is_mem_acces(arg2)

    def __init__(self, arg1, arg2, reversed, instr_state):
        super(ModRM_REG64__MEM, self).__init__()
        if arg2.prefix is not None:
            instr_state.prefixes.append(x64_segment_selectors[arg2.prefix])
        # # ARG1 : REG
        # # ARG2 : [MEM]
        # # this encode [rip + disp]
        # # TODO :)
        # if X64.mem_access_has_only(arg2, ["disp"]):
        #     self.mod = BitArray(2, "00")
        #     self.setup_reg_as_register(arg1)
        #     self.rm = BitArray(3, "101")
        #     try:
        #         self.after = BitArray.from_string(accept_as_32immediat(arg2.disp))
        #     except ImmediatOverflow:
        #         raise ImmediatOverflow("Interger32 overflow for displacement {0}".format(hex(arg2.disp)))
        #     self.direction = not reversed
        #     return

        # Those registers cannot be addressed without SIB
        FIRE_UP_SIB = not arg2.base or arg2.base.upper() in ["RSP", "RBP"] or arg2.index

        if not FIRE_UP_SIB:
            self.is_rex_needed = True
            self.rex[4] = 1
            self.setup_reg_as_register(arg1)
            self.setup_rm_as_register(arg2.base)
            self.compute_displacement(arg2.disp)
            self.direction = not reversed
            return
        # FIRE UP THE SIB
        # Handle no base and base == EBP special case
        if not arg2.base:
            force_displacement = 4
        elif arg2.base.upper() == "RBP":
            force_displacement = 1
        else:
            force_displacement = 0

        self.setup_reg_as_register(arg1)
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
        if mem_access.index is None and mem_access.base is None:
            return BitArray(2, "00") + BitArray(3, "100") + BitArray(3, "101")
        if mem_access.index is None:
            return BitArray(2, "00") + BitArray(3, "100") + self.setup_sib_base_rex(mem_access.base)
        if mem_access.scale not in scale:
            raise ValueError("Invalid scale for mem access <{0}>".format(mem_access.scale))
        if mem_access.base is None:
            return BitArray.from_int(2, scale[mem_access.scale]) + self.setup_sib_index_rex(mem_access.index) + BitArray(3, "101")
        return BitArray.from_int(2, scale[mem_access.scale]) + self.setup_sib_index_rex(mem_access.index) + self.setup_sib_base_rex(mem_access.base)


class Slash(object):
    "No idea for the name: represent the modRM for single args + encoding in reg (/7 in cmp in man intel)"

    def __init__(self, reg_num):
        "reg = 7 for /7"
        self.reg = reg_order[reg_num]

    def accept_arg(self, args, instr_state):
        if len(args) < 1:
            raise ValueError("Missing arg for Slash")
        # Reuse all the MODRm logique with the reg as our self.reg
        # The sens of param is strange I need to fix the `reversed` logique
        arg_consum, value, rex = ModRM([ModRM_REG64__REG64, ModRM_REG64__MEM], has_direction_bit=False).accept_arg(args[:1] + [self.reg] + args[1:], instr_state)
        if value is None:
            return arg_consum, value, rex
        return arg_consum - 1, value, rex

instr_state = collections.namedtuple('instr_state', ['previous', 'prefixes'])


class Instruction(object):
    encoding = []
    default_rex = BitArray(8, "")

    def __init__(self, *initial_args):
        for type_encoding in self.encoding:
            args = list(initial_args)
            res = []
            prefix = []
            full_rex = self.default_rex
            if hasattr(self, "default_32_bits") and self.default_32_bits:
                full_rex = BitArray.from_int(8, 0x48)
            for element in type_encoding:
                arg_consum, value, rex = element.accept_arg(args, instr_state(res, prefix))
                if arg_consum is None:
                    break
                res.append(value)
                del args[:arg_consum]
                if rex is not None:
                    full_rex = full_rex | rex
            else:  # if no break
                if args:  # if still args: fail
                    continue
                self.prefix = prefix
                self.value = sum(res, BitArray(0, ""))
                if any(full_rex.array):
                    self.value = full_rex + self.value
                return
        raise ValueError("Cannot encode <{0} {1}>:(".format(type(self).__name__, initial_args))

    def get_code(self):
        prefix_opcode = b"".join(chr(p.PREFIX_VALUE) for p in self.prefix)
        return prefix_opcode + bytes(self.value.dump())


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


class Push(Instruction):
    encoding = [(RawBits.from_int(5, 0x50 >> 3), X64RegisterSelector()),
                (RawBits.from_int(8, 0x68), Imm32())]


class Pop(Instruction):
    encoding = [(RawBits.from_int(5, 0x58 >> 3), X64RegisterSelector())]


class Call(Instruction):
    encoding = [(RawBits.from_int(8, 0xff), Slash(2))]


class Xchg(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(5, 0x90 >> 3), RegisterRax(), X64RegisterSelector()),
                (RawBits.from_int(5, 0x90 >> 3), X64RegisterSelector(), RegisterRax())]


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
                (RawBits.from_int(8, 0x01), ModRM([ModRM_REG64__REG64, ModRM_REG64__MEM]))]


class Sub(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0x2D), RegisterRax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(5), Imm32())]


class Out(Instruction):
    encoding = [(RawBits.from_int(8, 0xee), FixedRegister('DX'), FixedRegister('AL')),
                (RawBits.from_int(16, 0x66ef), FixedRegister('DX'), FixedRegister('AX')),  # Fuck-it hardcoded prefix for now
                (RawBits.from_int(8, 0xef), FixedRegister('DX'), FixedRegister('EAX'))]


class In(Instruction):
    encoding = [(RawBits.from_int(8, 0xec), FixedRegister('AL'), FixedRegister('DX')),
                (RawBits.from_int(16, 0x66ed), FixedRegister('AX'), FixedRegister('DX')),  # Fuck-it hardcoded prefix for now
                (RawBits.from_int(8, 0xed), FixedRegister('EAX'), FixedRegister('DX'))]


class Cpuid(Instruction):
    encoding = [(RawBits.from_int(16, 0x0fa2),)]


class JmpImm(object):
    accept_as_Ximmediat = (None)

    def __init__(self, sub):
        self.sub = sub

    def accept_arg(self, args, instr_state):
        try:
            jump_size = int(args[0])
        except (ValueError, TypeError):
            return (None, None, None)
        jump_size -= self.sub
        try:
            jmp_imm = self.accept_as_Ximmediat(jump_size)
        except ImmediatOverflow:
            return (None, None, None)
        return (1, BitArray.from_string(jmp_imm), None)


class JmpImm8(JmpImm):
    accept_as_Ximmediat = staticmethod(accept_as_8immediat)


class JmpImm32(JmpImm):
    accept_as_Ximmediat = staticmethod(accept_as_32immediat)


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


class Lea(Instruction):
    refuse_reverse = True
    encoding = [(RawBits.from_int(8, 0x8d), ModRM([ModRM_REG64__MEM], accept_reverse=False, has_direction_bit=False))]


class Mov(Instruction):
    default_32_bits = True
    encoding = [(Mov_RAX_OFF64(),), (Mov_OFF64_RAX(),), (RawBits.from_int(8, 0x89), ModRM([ModRM_REG64__REG64, ModRM_REG64__MEM])),
                (RawBits.from_int(5, 0xb8 >> 3), X64RegisterSelector(), Imm64())]


class Cmp(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0x3d), RegisterRax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(7), Imm32()),
                (RawBits.from_int(8, 0x3b), ModRM([ModRM_REG64__REG64, ModRM_REG64__MEM]))]


class Xor(Instruction):
    default_32_bits = True
    encoding = [(RawBits.from_int(8, 0x31), ModRM([ModRM_REG64__REG64, ModRM_REG64__MEM]))]


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
        return b"".join([bytes(x[1].get_code()) for x in sorted(self.instrs.items())])

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
        """Remove a NOP from the shellcode, adjust jump and labels"""
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

if in_IDA:
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

    def reset():
        idc.MakeUnknown(idc.MinEA(), 0x1000, 0)
        for i in range(0x1000):
            idc.PatchByte(idc.MinEA() + i, 0)

    s = test_code()

    def tst():
        reset()
        midap.here(idc.MinEA()).write(s.get_code())
        idc.MakeFunction(idc.MinEA())

    # tst()
