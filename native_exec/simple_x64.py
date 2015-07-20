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

mem_access = collections.namedtuple('mem_access', ['base', 'index', 'squale', 'disp'])



def create_displacement(base=None, index=None, squale=None, disp=0):
    return mem_access(base, index, squale, disp)
     

class X64RegisterSelector(object):

    reg_opcode = {v : BitArray.from_int(size=3, x=i) for i, v in enumerate(reg_order)}
    new_reg_opcode = {v : BitArray.from_int(size=3, x=i) for i, v in enumerate(new_reg_order)}
    
    def accept_arg(self, previous, args):
        x = args[0]
        try:
            return (1, self.reg_opcode[x], None)
        except KeyError:
            pass
        try:
            return (1, self.new_reg_opcode[x], BitArray.from_int(8, 0x41))
        except KeyError:
            return (None, None, None)
        
    @classmethod    
    def get_reg_bits(cls, name):
        try:
            return cls.reg_opcode[name]
        except KeyError:
            return cls.new_reg_opcode[name]
        
class RawBits(BitArray):
    def accept_arg(self, previous, args):
        return (0, self, None)
        
class Imm64(object):
    def accept_arg(self, previous, args):
        try:
            x = int(args[0])
            return (1, BitArray.from_int(64, X64.to_little_endian(x)), None)
        except TypeError:
            return (None, None, None)
            
class Mov_RAX_OFF64(object):
    def accept_arg(self, previous, args):
        if args[0] != "RAX":
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
        return name in x64_regs
        
    @staticmethod
    def is_new_reg(name):
        return name in new_reg_order
        
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
    def to_little_endian(i):
        i = i & 0xffffffffffffffff
        return struct.unpack("<Q", struct.pack(">Q", i))[0]
    
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
        return X64.is_reg(arg1) and X64.is_reg(arg2)
        
    def __init__(self, arg1, arg2, reversed):
        super(ModRM_REG64__REG64, self).__init__()
        self.mod = BitArray(2, "11")
        self.is_rex_needed = True
        self.rex[4] = 1
        self.setup_reg_as_register(arg2)
        self.setup_rm_as_register(arg1)
        self.direction = 0
        
#class ModRM_REG__DEREF_IMM(SubModRM):
#    @classmethod
#    def match(cls, arg1, arg2):
#        return X64.is_reg(arg1) and X64.is_mem_acces(arg2) and X64.mem_access_has_only(arg2, ["disp"])
#        
#    def __init__(self, arg1, arg2, reversed):
#        super(ModRM_REG__DEREF_IMM, self).__init__()
#        self.mod = BitArray(2, "00")
#        self.setup_reg_as_register(arg1)
#        self.rm = BitArray(3, "101")
#        self.after = BitArray.from_int(64, X64.to_little_endian(arg2.disp))
#        self.direction = not reversed
        
        
class ModRM_REG__DEREF_REG(SubModRM):
    @classmethod
    def match(cls, arg1, arg2):
        return X64.is_reg(arg1) and X64.is_mem_acces(arg2) and X64.mem_access_has_only(arg2, ["base"]) and arg2.base not in ["RSP", "RBP"]
        
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
#class ModRM_REG__DEREF_REG_IMM(object):
#    @classmethod
#    def match(cls, arg1, arg2):
#        return X86.is_reg(arg1) and X86.is_mem_acces(arg2) and X86.mem_access_has_only(arg2, ["base", "disp"])
#        
#    def __init__(self, arg1, arg2, reversed):
#        self.mod = BitArray(2, "10")
#        self.reg = X86RegisterSelector.get_reg_bits(arg1)
#        self.rm = X86RegisterSelector.get_reg_bits(arg2.base)
#        self.after = BitArray.from_int(32, X86.to_little_endian(arg2.disp))
#        self.direction = not reversed
#        

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
        raise ValueError("Cannot encode :(")
#            
#    
class Push(Instruction):
    encoding = [(RawBits.from_int(5, 0x50 >> 3), X64RegisterSelector()),]
#                (RawBits.from_int(8, 0x68), Imm32())]
   
class Pop(Instruction):
    encoding = [(RawBits.from_int(5, 0x58 >> 3), X64RegisterSelector())]
   
class Call(Instruction):
    encoding = [(RawBits.from_int(13, 0xffd0 >> 3), X64RegisterSelector())]
    
class Ret(Instruction):
    encoding = [(RawBits.from_int(8, 0xc3),)]
    
class Int3(Instruction):
    encoding = [(RawBits.from_int(8, 0xcc),)]
    
class Mov(Instruction):
   default_32_bits = True
   encoding = [(RawBits.from_int(8, 0x89), ModRM(ModRM_REG64__REG64, ModRM_REG__DEREF_REG)), (RawBits.from_int(5, 0xb8 >> 3), X64RegisterSelector(), Imm64()),       
                (Mov_RAX_OFF64(),), (Mov_OFF64_RAX(),)]
       
class MultipleInstr(object):

    def __init__(self, instrs=()):
        self.instrs = list(instrs)
        
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

