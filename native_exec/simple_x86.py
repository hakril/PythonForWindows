import struct
import sys
# This code should really be rewritten..

this_module = sys.modules[__name__]

generated_instruction = []


def add_instruction(name, instruction):
    generated_instruction.append((name, instruction))
    setattr(this_module, name, instruction)

def generate_module_doc():
    doc_lines = ["Here is the list of instruction in the modules:\n\n"]
    for name, instruction in generated_instruction:
        doc_lines.append("    | {0} -> <{1}>".format(name, instruction.mnemo))
        
    this_module.__doc__ = "\n".join(doc_lines)
    
reg_order = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']
reg_opcode = {v : format(i, "03b") for i, v in enumerate(reg_order)}


class X86Instruction(object):
    mnemo = ""
    code = ""
    biding = 0
    
    def __init__(self, *bind_values):
        if len(bind_values) != self.biding:
            raise ValueError("{0} expect {1} values got {2}".format(self.__class__.__name__, self.biding, len(bind_values)))
        self.bind_values = bind_values
        for i, v  in enumerate(bind_values):
            if not isinstance(v, (int, long)):
                raise ValueError("{0} bindings must be 'int' got '{1}' instead".format(self.__class__.__name__, type(v).__name__))
            if not 0 <= v <= 0xffffffff:
                raise ValueError("{0} bindings must be between 0 and 0xffffffff".format(self.__class__.__name__))
                
    def get_unbinded_code(self):
        return self.code.replace(" ", "").decode('hex')
        
    def get_code(self):
        code = self.get_unbinded_code()
        for i in range(self.biding):
            code = code.replace((str(i + 1) * 8).decode('hex'), struct.pack("<I", self.bind_values[i]))
        return code
        
    def get_mnemo(self):
        return self.mnemo.format(*(hex(v) for v in self.bind_values))

        
class Ret(X86Instruction):
    mnemo = "ret"
    code = "C3"
    
generated_instruction.append(("Ret", Ret))
    
class Int3(X86Instruction):
    mnemo = "int3"
    code = "CC"
 
generated_instruction.append(("Int3", Int3)) 
            
class SimpleRegInstructionGenerator(object):
    name = ""
    instruction_bits = ''
    

class OneBindX86Instruction(X86Instruction):
    biding = 1


class Push_X(OneBindX86Instruction):
    mnemo = "push    {0}"
    code = "68 11 11 11 11"

generated_instruction.append(("Push_X", Push_X))     

def generate_simple_reg_instruction(instr_cls):
    for reg_name, reg_bits in reg_opcode.items():
        class SimpleRegInstruction(X86Instruction):
            mnemo = "{0}    {1}".format(instr_cls.mnemo, reg_name)
            code = format(int(instr_cls.instruction_bits + reg_bits, 2), 'x')
            
        SimpleRegInstruction.__name__ = "{0}_{1}".format(instr_cls.name, reg_name)
        add_instruction(SimpleRegInstruction.__name__, SimpleRegInstruction)  
    
    
class Push_Reg(object):
    name = 'Push'
    mnemo = "push"
    instruction_bits = '01010'

generate_simple_reg_instruction(Push_Reg)
    
class Pop_Reg(object):
    name = 'Pop'
    mnemo = "pop"
    instruction_bits = '01011'
    
generate_simple_reg_instruction(Pop_Reg)

class Call_Reg(object):
    name = 'Call'
    mnemo = "call"
    instruction_bits = '1111111111010'
    
generate_simple_reg_instruction(Call_Reg)



def generate_reg_instruction_onebind(instr_cls):
    for reg_name, reg_bits in reg_opcode.items():
        class OneBindRegInstruction(OneBindX86Instruction):
            mnemo = instr_cls.mnemo.format(reg_name)
            code = chr(int(instr_cls.instruction_bits + reg_bits, 2)).encode('hex')  + '11 11 11 11' # the biding
            
        OneBindRegInstruction.__name__ = instr_cls.name.format(reg_name)
        add_instruction(OneBindRegInstruction.__name__, OneBindRegInstruction)

class Mov_Reg_X(object):
    name = 'Mov_{0}_X'
    mnemo = 'mov {0}, {{0}}'
    instruction_bits = '10111'
    
generate_reg_instruction_onebind(Mov_Reg_X)

def get_immediat_modr_byte(register_bits):
    "Generate a modr-reg-r/m indicating a register and an immediat"
    str_bits = "11000{0}".format(register_bits)
    return chr(int(str_bits, 2)).encode('hex')
    
def generate_reg_immediat_modr(instr_cls):
    for reg_name, reg_bits in reg_opcode.items():
        class Reg_MEM_Instruction(OneBindX86Instruction):
            mnemo = instr_cls.mnemo.format(reg_name)
            code = instr_cls.instruction_bits + get_immediat_modr_byte(reg_bits) + '11 11 11 11' # the biding
            
        Reg_MEM_Instruction.__name__ = instr_cls.name.format(reg_name)
        add_instruction(Reg_MEM_Instruction.__name__, Reg_MEM_Instruction)
        
class Add_Reg_X(object):
    name = 'Add_{0}_X'
    mnemo = 'add {0}, {{0}}'
    instruction_bits = '81'
    
generate_reg_immediat_modr(Add_Reg_X)        
 

def get_simple_modr_byte(register_bits):
    "Generate a simple modr-reg-r/m for a displacement only mode"
    str_bits = "00{0}101".format(register_bits)
    return chr(int(str_bits, 2)).encode('hex')


def generate_reg_modr(instr_cls):
    for reg_name, reg_bits in reg_opcode.items():
        class Reg_MEM_Instruction(OneBindX86Instruction):
            mnemo = instr_cls.mnemo.format(reg_name)
            code = instr_cls.instruction_bits + get_simple_modr_byte(reg_bits) + '11 11 11 11' # the biding
            
        Reg_MEM_Instruction.__name__ = instr_cls.name.format(reg_name)
        add_instruction(Reg_MEM_Instruction.__name__, Reg_MEM_Instruction)
        

 
        
class Mov_Reg_DX(object):
    name = 'Mov_{0}_DX'
    mnemo = 'mov {0}, [{{0}}]'
    instruction_bits = '8B'
    
generate_reg_modr(Mov_Reg_DX)

class Mov_DX_Reg(object):
    name = 'Mov_DX_{0}'
    mnemo = 'mov [{{0}}], {0}'
    instruction_bits = '89'

generate_reg_modr(Mov_DX_Reg)

def generate_reg_indirect_modr_byte(reg_dst_bits, reg_src_bits):
    # reg, [reg] or [reg], reg
    return "00{0}{1}".format(reg_dst_bits, reg_src_bits)
    
def generate_reg_reg_deref(instr_cls, src_first=True):
    "generate the Mov_Reg_DReg and Mov_DReg_Reg"
    for reg_src_name, reg_src_bits in reg_opcode.items():
        for reg_dst_name, reg_dst_bits in reg_opcode.items():
            if reg_dst_name in ("EBP", "ESP") or reg_src_name in ("EBP", "ESP"):
                # Not same encoding -> Not implemented
                continue
            class Reg_DReg_instruction(X86Instruction):
                mnemo = instr_cls.mnemo.format(reg_dst_name, reg_src_name)
                name = instr_cls.name.format(reg_dst_name, reg_src_name)
                if src_first:
                    modr_code = generate_reg_indirect_modr_byte(reg_src_bits, reg_dst_bits)
                else:
                    modr_code = generate_reg_indirect_modr_byte(reg_dst_bits, reg_src_bits)
                code = instr_cls.instruction_bits + chr(int(modr_code, 2)).encode("hex")
            Reg_DReg_instruction.__name__ = Reg_DReg_instruction.name
            add_instruction(Reg_DReg_instruction.__name__, Reg_DReg_instruction)
    
    
class Mov_Reg_DReg(object):
    name = 'Mov_{0}_D{1}'
    mnemo = 'mov [{0}], {1}'
    instruction_bits = '8B'
    
generate_reg_reg_deref(Mov_Reg_DReg, False)

class Mov_DReg_Reg(object):
    name = 'Mov_D{0}_{1}'
    mnemo = 'mov {0}, [{1}]'
    instruction_bits = '89'
    
generate_reg_reg_deref(Mov_DReg_Reg, True)


def generate_reg_reg_modr_byte(reg_dst_bits, reg_src_bits):
    # reg, reg
    return "11{0}{1}".format(reg_src_bits, reg_dst_bits)
    
        
def generate_reg_reg_modr(instr_cls):  
    for reg_src_name, reg_src_bits in reg_opcode.items():
        for reg_dst_name, reg_dst_bits in reg_opcode.items():
            class Reg_Reg_instruction(X86Instruction):
                mnemo = "{0} {1},{2}".format(instr_cls.mnemo, reg_dst_name, reg_src_name)
                modr_code = format(int(generate_reg_reg_modr_byte(reg_dst_bits, reg_src_bits) , 2), 'x')
                code = instr_cls.instruction_bits + modr_code
            Reg_Reg_instruction.__name__ = "{0}_{1}_{2}".format(instr_cls.name, reg_dst_name, reg_src_name)
            add_instruction(Reg_Reg_instruction.__name__, Reg_Reg_instruction)
            
class Test_Reg_Reg(object):
    mnemo = "tst"
    name = "Tst"
    instruction_bits = "85"
    
generate_reg_reg_modr(Test_Reg_Reg)

#### JUMP ####

class JZ(OneBindX86Instruction):
    code = "0F 84 11 11 11 11"
    
    def __init__(self, instr_block):
        self.instr_block = instr_block
        instr_block_size = len(instr_block.get_code())
        super(JZ, self).__init__(instr_block_size)
        
    def get_code(self):
        return super(JZ, self).get_code() + self.instr_block.get_code()
        
class JNZ(OneBindX86Instruction):
    code = "0F 85 11 11 11 11"
    
    def __init__(self, instr_block):
        self.instr_block = instr_block
        instr_block_size = len(instr_block.get_code())
        super(JNZ, self).__init__(instr_block_size)
        
    def get_code(self):
        return super(JNZ, self).get_code() + self.instr_block.get_code()
        
        

class MultipleInstr(object):

    def __init__(self, init_instrs=()):
        self.instrs = list(init_instrs)
        
    def __iadd__(self, value):
        if type(value) == MultipleInstr:
            self.instrs.extend(value.instrs)
            return self
        self.instrs.append(value)
        return self
        
    def get_code(self):
        return "".join(i.get_code() for i in self.instrs)
        
    def get_mnemo(self):
        return "\n".join(i.get_mnemo() for i in self.instrs)
        

              
generate_module_doc()
    