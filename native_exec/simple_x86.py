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

mem_access = collections.namedtuple('mem_access', ['base', 'index', 'squale', 'disp'])
x86_regs = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']

def create_displacement(base=None, index=None, squale=None, disp=0):
    return mem_access(base, index, squale, disp)
     

class X86RegisterSelector(object):
    size = 3 # bits
    reg_order = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']
    reg_opcode = {v : BitArray.from_int(size=3, x=i) for i, v in enumerate(reg_order)}
    
    def accept_arg(self, previous, args):
        x = args[0]
        try:
            return (1, self.reg_opcode[x])
        except KeyError:
            return (None, None)
        
    @classmethod    
    def get_reg_bits(cls, name):
        return cls.reg_opcode[name]
        
class RawBits(BitArray):
    def accept_arg(self, previous, args):
        return (0, self)
        
class Imm32(object):
    def accept_arg(self, previous, args):
        try:
            x = int(args[0])
        except TypeError:
            return (None, None)
        return (1, BitArray.from_int(32, X86.to_little_endian(x)))

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
                return (2, d.mod + d.reg + d.rm + d.after)
            elif sub.match(arg2, arg1):
                d = sub(arg2, arg1, 1)
                previous[0][-2] = d.direction
                return (2, d.mod + d.reg + d.rm + d.after)
        return (None, None)
        
class X86(object):
    @staticmethod
    def is_reg(name):
        return name in x86_regs
        
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
    def to_little_endian(i):
        i = i & 0xffffffff
        return struct.unpack("<I", struct.pack(">I", i))[0]
    
 
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
        
class ModRM_REG__DEREF_SIB(object):
    # Only handle reg, [esp+x] now :(
    @classmethod
    def match(cls, arg1, arg2):
        return X86.is_reg(arg1) and X86.is_mem_acces(arg2) and X86.mem_access_has_only(arg2, ["base", "disp"]) and arg2.base == "ESP"
        
    def __init__(self, arg1, arg2, reversed):
        self.mod = BitArray(2, "10")
        self.reg = X86RegisterSelector.get_reg_bits(arg1)
        self.rm = BitArray(3, "100")
        
        # Todo -> def sib_from_displacement
        sib = BitArray(8, "00100100")
        
        self.after = sib + BitArray.from_int(32, X86.to_little_endian(arg2.disp))
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
        raise ValueError("Cannot encode :(")
            
    
class Push(Instruction):
    encoding = [(RawBits.from_int(5, 0x50 >> 3), X86RegisterSelector()),
                (RawBits.from_int(8, 0x68), Imm32())]
    
class Pop(Instruction):
    encoding = [(RawBits.from_int(5, 0x58 >> 3), X86RegisterSelector())]
    
class Mov(Instruction):
    encoding = [(RawBits.from_int(8, 0x89), ModRM(ModRM_REG__REG, ModRM_REG__DEREF_REG, ModRM_REG__DEREF_REG_IMM, ModRM_REG__DEREF_IMM, ModRM_REG__DEREF_SIB)),
                (RawBits.from_int(5, 0xb8 >> 3), X86RegisterSelector(), Imm32())]
    
class Call(Instruction):
    encoding = [(RawBits.from_int(13, 0xffd0 >> 3), X86RegisterSelector())]
    
class Ret(Instruction):
    encoding = [(RawBits.from_int(8, 0xc3),)]
    
class Int3(Instruction):
    encoding = [(RawBits.from_int(8, 0xcc),)]
    
        
class MultipleInstr(object):

    def __init__(self):
        self.instrs = []
        
    def __iadd__(self, value):
        if type(value) == MultipleInstr:
            self.instrs.extend(value.instrs)
            return self
        self.instrs.append(value)
        return self
        
    def get_code(self):
        if sys.version_info.major == 3:
            return b"".join([x.value.dump() for x in self.instrs])
        return "".join([str(x.value.dump()) for x in self.instrs])

