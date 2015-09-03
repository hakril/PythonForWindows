import collections
import struct
import sys

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

mem_access = collections.namedtuple('mem_access', ['base', 'index', 'scale', 'disp'])
x86_regs = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']

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
            if not X86.is_reg(index):
                raise ValueError("Invalid index <{0}> in mem access".format(index))
            try:
                scale = int(scale, 0)
            except ValueError as e:
                raise ValueError("Invalid scale <{0}> in mem access".format(scale))
            parsed_items['scale'] = scale
            parsed_items['index'] = index
        else:
            # displacement / base / index alone
            if X86.is_reg(item):
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
            
    
class X86RegisterSelector(object):
    size = 3 # bits
    reg_order = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']
    reg_opcode = {v : BitArray.from_int(size=3, x=i) for i, v in enumerate(reg_order)}
    
    def accept_arg(self, previous, args):
        x = args[0]
        try:
            return (1, self.reg_opcode[x.upper()])
        except (KeyError, AttributeError):
            return (None, None)
        
    @classmethod    
    def get_reg_bits(cls, name):
        return cls.reg_opcode[name.upper()]
       
class RegisterEax(object):
    def accept_arg(self, previous, args):
        x = args[0]
        if isinstance(x, str) and x.upper() == 'EAX':
            return (1, BitArray(0, []))
        return None, None
        
class FixedRegister(object):
    def __init__(self, register):
        self.reg = register.upper()
        
    def accept_arg(self, previous, args):
        x = args[0]
        if isinstance(x, str) and x.upper() == self.reg:
            return (1, BitArray(0, []))
        return None, None
    
        
class RawBits(BitArray):
    def accept_arg(self, previous, args):
        return (0, self)
        
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
            return (None, None)
        return (1, BitArray.from_int(32, X86.to_little_endian(x, size=32)))
        
class Imm8(Immediat):
    def accept_arg(self, previous, args):
        try:
            x = int(args[0]) + self.add
        except (ValueError, TypeError):
            return (None, None)
        if not -128 <= x <= 127:
            return (None, None)
        return (1, BitArray.from_int(8, X86.to_little_endian(x, size=8)))

class ModRM(object):
    size = 8
    
    def __init__(self, sub_modrm, accept_reverse=True, has_direction_bit=True):
        self.accept_reverse = accept_reverse
        self.has_direction_bit = has_direction_bit
        self.sub = sub_modrm
        
    def accept_arg(self, previous, args):
        if len(args) < 2:
            raise ValueError("Missing arg for modrm")
        arg1 = args[0]
        arg2 = args[1]
        for sub in self.sub:
            # Problem in reverse sens -> need to fix it
            #import pdb;pdb.set_trace()
            if sub.match(arg1, arg2):
                d = sub(arg1, arg2, 0)
                if self.has_direction_bit:
                    previous[0][-2] = d.direction
                return (2, d.mod + d.reg + d.rm + d.after)
            elif self.accept_reverse and sub.match(arg2, arg1):
                d = sub(arg2, arg1, 1)
                if self.has_direction_bit:
                    previous[0][-2] = d.direction
                return (2, d.mod + d.reg + d.rm + d.after)
        return (None, None)
        
class X86(object):
    @staticmethod
    def is_reg(name):
        try:
            return name.upper() in x86_regs
        except AttributeError: # Not a string
            return False
        
    @staticmethod 
    def is_mem_acces(data):
        return isinstance(data, mem_access)
    
    @staticmethod
    def mem_access_has_only(mem_access, names):
        if not X86.is_mem_acces(mem_access):
            raise ValueError("mem_access_has_only")
        for f in mem_access._fields:
            v = getattr(mem_access, f)
            if v and f not in names:
                return False
            if v is None and f in names:
                return False
        return True
      
    @staticmethod
    def to_little_endian(i, size=32):
        pack = {8: 'B', 16 : 'H', 32 : 'I'} 
        s = pack[size]
        mask = (1 << size) - 1
        i = i & mask
        return struct.unpack("<" + s, struct.pack(">" + s, i))[0]
    
 
class ModRM_REG__REG(object):
    @classmethod
    def match(cls, arg1, arg2):
        return X86.is_reg(arg1) and X86.is_reg(arg2)
        
    def __init__(self, arg1, arg2, reversed):
        self.mod = BitArray(2, "11")
        self.reg = X86RegisterSelector.get_reg_bits(arg2)
        self.rm = X86RegisterSelector.get_reg_bits(arg1)
        self.after = BitArray(0, "")
        self.direction = 0
        
class ModRM_REG__DEREF_REG(object):
    @classmethod
    def match(cls, arg1, arg2):
        return X86.is_reg(arg1) and arg1 not in ["ESP", "EBP"] and X86.is_mem_acces(arg2) and X86.mem_access_has_only(arg2, ["base"])
        
    def __init__(self, arg1, arg2, reversed):
        self.mod = BitArray(2, "00")
        self.reg = X86RegisterSelector.get_reg_bits(arg1)
        self.rm = X86RegisterSelector.get_reg_bits(arg2.base)
        self.after = BitArray(0, "")
        self.direction = not reversed        
        
class ModRM_REG__DEREF_REG_IMM(object):
    @classmethod
    def match(cls, arg1, arg2):
        return X86.is_reg(arg1) and X86.is_mem_acces(arg2) and X86.mem_access_has_only(arg2, ["base", "disp"]) and arg2.base != "ESP"
        
    def __init__(self, arg1, arg2, reversed):
        self.mod = BitArray(2, "10")
        self.reg = X86RegisterSelector.get_reg_bits(arg1)
        self.rm = X86RegisterSelector.get_reg_bits(arg2.base)
        self.after = BitArray.from_int(32, X86.to_little_endian(arg2.disp))
        self.direction = not reversed
        
def sib_from_mem_access(mem_access):
    scale = {1: 0, 2 : 1, 4: 2, 8 : 3}
    if mem_access.scale is None and mem_access.index is None:
        return BitArray.from_int(2, 0) + BitArray.from_int(3, 0b100) + X86RegisterSelector.get_reg_bits(mem_access.base)
    if mem_access.scale not in scale:
        raise ValueError("Invalid scale for mem access <{0}>".format(mem_access.scale))
    return BitArray.from_int(2, scale[mem_access.scale]) + X86RegisterSelector.get_reg_bits(mem_access.index) + X86RegisterSelector.get_reg_bits(mem_access.base)
    
        
class ModRM_REG__DEREF_SIB(object):
    # Only handle reg, [esp+x] now :(
    @classmethod
    def match(cls, arg1, arg2):
        return X86.is_reg(arg1) and X86.is_mem_acces(arg2)
        
    def __init__(self, arg1, arg2, reversed):
        if not arg2.disp:
            self.mod = BitArray(2, "00")
        else:
            self.mod = BitArray(2, "10")
        self.reg = X86RegisterSelector.get_reg_bits(arg1)
        self.rm = BitArray(3, "100")
        # Todo -> def sib_from_displacement
        sib = sib_from_mem_access(arg2)
        if arg2.disp:
            self.after = sib + BitArray.from_int(32, X86.to_little_endian(arg2.disp))
        else:
            self.after = sib
        self.direction = not reversed
        
#class ModRM_REG_IMM(object):
#    @classmethod
#    def match(cls, arg1, arg2):
#        return arg1 in x86_regs and arg2 in x86_regs
#        
#    def __init__(self, arg1, arg2):
#        self.mod = BitArray(2, "11")
#        self.reg = X86RegisterSelector.get_reg_bits(arg2)
#        self.rm = X86RegisterSelector.get_reg_bits(arg1)
#        self.direction = 0
        
class ModRM_REG__DEREF_IMM(object):
    @classmethod
    def match(cls, arg1, arg2):
        return X86.is_reg(arg1) and X86.is_mem_acces(arg2) and X86.mem_access_has_only(arg2, ["disp"])
        
    def __init__(self, arg1, arg2, reversed):
        self.mod = BitArray(2, "00")
        self.reg = X86RegisterSelector.get_reg_bits(arg1)
        self.rm = BitArray(3, "101")
        self.after = BitArray.from_int(32, X86.to_little_endian(arg2.disp))
        self.direction = not reversed
        
class Slash(object):
    "No idea for the name: represent the modRM for single args + encoding in reg (/7 in cmp in man intel)"
    
    def __init__(self, reg):
        "reg = 7 for /7"
        self.mod = None
        self.reg = BitArray.from_int(3, reg)
        self.rm = None
        
    def accept_arg(self, previous, args):
        x = args[0]
        ok, bits = X86RegisterSelector().accept_arg(None, [x])
        if ok is not None:
            self.mod = BitArray(2, "11")
            self.rm = bits
            return 1, self.mod + self.reg + self.rm
        if X86.mem_access_has_only(x, ["base"]) and x.base not in ['ESP', 'EBP']:
            self.mod = BitArray(2, "00")
            ok, bits = X86RegisterSelector().accept_arg(None, [x.base])
            self.rm = bits
            return 1, self.mod + self.reg + self.rm
        # TODO: Other
        
        if X86.mem_access_has_only(x, ["base", "disp"]):
            self.mod = BitArray(2, "10")
            ok, bits = X86RegisterSelector().accept_arg(None, [x.base])
            self.rm = bits
            return 1, self.mod + self.reg + self.rm + BitArray.from_int(32, X86.to_little_endian(x.disp))
        return None, None
    
         
class Instruction(object):
    encoding = []
    
    def __init__(self, *initial_args):
        for type_encoding in self.encoding:
            args = list(initial_args)
            res = []
            for element in type_encoding:
                arg_consum, value = element.accept_arg(res, args)
                if arg_consum is None:
                    break
                res.append(value)
                del args[:arg_consum]
            else: # if no break
                if args: # if still args: fail
                    continue
                self.value = sum(res, BitArray(0, ""))
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


class Push(Instruction):
    encoding = [(RawBits.from_int(5, 0x50 >> 3), X86RegisterSelector()),
                (RawBits.from_int(8, 0x68), Imm32())]
    
class Pop(Instruction):
    encoding = [(RawBits.from_int(5, 0x58 >> 3), X86RegisterSelector())]
    
class Dec(Instruction):
    encoding = [(RawBits.from_int(5, 0x48 >> 3), X86RegisterSelector())]
    
class Inc(Instruction):
    encoding = [(RawBits.from_int(5, 0x40 >> 3), X86RegisterSelector())]
    
class Add(Instruction):
    encoding = [(RawBits.from_int(8, 0x05), RegisterEax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(0), Imm32()),
                (RawBits.from_int(8, 0x01), ModRM([ModRM_REG__REG, ModRM_REG__DEREF_REG, ModRM_REG__DEREF_REG_IMM, ModRM_REG__DEREF_IMM, ModRM_REG__DEREF_SIB])),]
                
class Sub(Instruction):
    encoding = [(RawBits.from_int(8, 0x2D), RegisterEax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(5), Imm32())]
    
class Mov(Instruction):
    encoding = [(RawBits.from_int(8, 0x89), ModRM([ModRM_REG__REG, ModRM_REG__DEREF_REG, ModRM_REG__DEREF_REG_IMM, ModRM_REG__DEREF_IMM, ModRM_REG__DEREF_SIB])),
                (RawBits.from_int(5, 0xb8 >> 3), X86RegisterSelector(), Imm32())]
                
class Lea(Instruction):
    encoding = [(RawBits.from_int(8, 0x8d), ModRM([ModRM_REG__DEREF_REG, ModRM_REG__DEREF_REG_IMM, ModRM_REG__DEREF_IMM, ModRM_REG__DEREF_SIB], accept_reverse=False, has_direction_bit=False))]
    
class Call(Instruction):
    encoding = [(RawBits.from_int(13, 0xffd0 >> 3), X86RegisterSelector())]
    
class Cmp(Instruction):
    encoding = [(RawBits.from_int(8, 0x3d), RegisterEax(), Imm32()),
                (RawBits.from_int(8, 0x81), Slash(7), Imm32()), 
                (RawBits.from_int(8, 0x3b), ModRM([ModRM_REG__REG, ModRM_REG__DEREF_REG, ModRM_REG__DEREF_REG_IMM, ModRM_REG__DEREF_IMM, ModRM_REG__DEREF_SIB])), ]
                
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
            return (None, None)
        if not (-128 + self.sub) <= x <= 127:
            return (None, None)
        x -= self.sub
        return (1, BitArray.from_int(8, X86.to_little_endian(x, size=8)))
        
class JmpImm32(Immediat):
    def __init__(self, sub):
        self.sub = sub
    def accept_arg(self, previous, args):
        try:
            x = int(args[0])
        except (ValueError, TypeError):
            return (None, None)
        #if not (-128 + self.ADD) <= x <= 127:
        #    return (None, None)
        x -= self.sub
        return (1, BitArray.from_int(32, X86.to_little_endian(x, size=32)))
                
class Jmp(JmpType):
    encoding = [(RawBits.from_int(8, 0xeb), JmpImm8(2)),
                (RawBits.from_int(8, 0xe9), JmpImm32(5))]
                
class Jz(JmpType):
    encoding = [(RawBits.from_int(8, 0x74), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f84), JmpImm32(6))]
  
class Jnz(JmpType):
    encoding = [(RawBits.from_int(8, 0x75), JmpImm8(2)),
                (RawBits.from_int(16, 0x0f85), JmpImm32(6))]
                
class Xor(Instruction):
    encoding = [(RawBits.from_int(8, 0x31), ModRM([ModRM_REG__REG]))]
    
class Ret(Instruction):
    encoding = [(RawBits.from_int(8, 0xc3),)]
    
class Nop(Instruction):
    encoding = [(RawBits.from_int(8, 0x90),)]
    
class Retf(Instruction):
    encoding = [(RawBits.from_int(8, 0xcb),)]
    
class _NopArtifact(Nop):
    pass
    
class Int3(Instruction):
    encoding = [(RawBits.from_int(8, 0xcc),)]
    
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
        
# IDA : import windows.native_exec.simple_x86 as x86

# IDA testing

try:
    import midap
    import idc
    in_IDA = True
except ImportError:
    in_IDA = False
 
#def test_code():
#    s = MultipleInstr()
#    s += Mov('EAX', 'EAX')
#    s += Mov('EAX', 'EAX')
#    s += Jnz(":SUCE")
#    s += Mov('EAX', 'EAX')
#    s += Cmp("Eax", "ESI")
#    s += Jnz(":SUCE")
#    s += Mov("ECX", "ECX")
#    s += Label(":SUCE")
#    s += Jnz(":LOL")
#    s += Jnz(":BITE")
#    s += Mov("EDX", "EDX")
#    s += Label(":LOL")
#    s += Mov('EDI', 'EDI')
#    s += Label(":BITE")
#    s += Mov('EDI', 'EDI')
#    s += Jnz(":SUCE")
#    s += Push("ECX")
#    s += Pop("EAX")
#    s += Ret()
#    return s
    
def test_code():
    s = MultipleInstr()
    s += Mov("Eax", "ESI")
    s += Inc("Ecx")
    s += Dec("edi")
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