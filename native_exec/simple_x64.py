# You are going to see the most shameful code ever !
# Yes this a a copy of x86 :D

import struct
import sys
from simple_x86 import MultipleInstr

# This code should really be rewritten..

this_module = sys.modules[__name__]

def add_instruction(name, instruction):
    setattr(this_module, name, instruction)
    
reg_order = ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI']
reg_opcode = {v : format(i, "03b") for i, v in enumerate(reg_order)}

new_reg_order = ['R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']
new_reg_opcode = {v : format(i, "03b") for i, v in enumerate(new_reg_order)}

all_regs = dict(reg_opcode)
all_regs.update(new_reg_opcode)

bin_h48 = bin(0x48)[2:]
class X64Instruction(object):
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
            if not 0 <= v <= 0xffffffffffffffff:
                raise ValueError("{0} bindings must be between 0 and 0xffffffffffffffff".format(self.__class__.__name__))
                
    def get_unbinded_code(self):
        return self.code.replace(" ", "").decode('hex')
        
    def get_code(self):
        code = self.get_unbinded_code()
        for i in range(self.biding):
            code = code.replace((str(i + 1) * 16).decode('hex'), struct.pack("<Q", self.bind_values[i]))
        return code
        
    def get_mnemo(self):
        return self.mnemo.format(*(hex(v) for v in self.bind_values))
        
        
class Ret(X64Instruction):
    mnemo = "ret"
    code = "C3"
    
class Int3(X64Instruction):
    mnemo = "int3"
    code = "CC"
    
class Retf(X64Instruction):
    mnemo = "retf"
    code = "CB"
    
    
class SimpleRegInstructionGenerator(object):
    name = ""
    instruction_bits = ''
    
class OneBindX64Instruction(X64Instruction):
    biding = 1
    
class Mov_RAX_DX(OneBindX64Instruction):
    name = 'Mov_RAX_DX'
    mnemo = 'mov rax, [{0}]'
    code = "48 a1 11 11 11 11 11 11 11 11"
    
class Mov_DX_RAX(OneBindX64Instruction):
    name = 'Mov_DX_RAX'
    mnemo = 'mov [{0}], rax'
    code = "48 a3 11 11 11 11 11 11 11 11"
    
def generate_simple_reg_instruction(instr_cls, include_new_reg=False):
    for reg_name, reg_bits in reg_opcode.items():
        class SimpleRegInstruction(X64Instruction):
            mnemo = "{0}    {1}".format(instr_cls.mnemo, reg_name)
            code = format(int(instr_cls.instruction_bits + reg_bits, 2), 'x')
        SimpleRegInstruction.__name__ = "{0}_{1}".format(instr_cls.name, reg_name)
        add_instruction(SimpleRegInstruction.__name__, SimpleRegInstruction)    

    if not include_new_reg:
        return None
    for reg_name, reg_bits in new_reg_opcode.items():
        class SimpleRegInstruction(X64Instruction):
            mnemo = "{0}    {1}".format(instr_cls.mnemo, reg_name)
            code = instr_cls.new_reg_prefix + format(int(instr_cls.instruction_bits + reg_bits, 2), 'x')
        SimpleRegInstruction.__name__ = "{0}_{1}".format(instr_cls.name, reg_name)
        add_instruction(SimpleRegInstruction.__name__, SimpleRegInstruction)  
        
    
class Push_Reg(object):
    name = 'Push'
    mnemo = "push"
    instruction_bits = '01010'
    new_reg_prefix = "41"

generate_simple_reg_instruction(Push_Reg, True)
    
class Pop_Reg(object):
    name = 'Pop'
    mnemo = "pop"
    instruction_bits = '01011'
    new_reg_prefix = "41"
    
generate_simple_reg_instruction(Pop_Reg, True)

class Call_Reg(object):
    name = 'Call'
    mnemo = "call"
    instruction_bits = '1111111111010'
    
generate_simple_reg_instruction(Call_Reg)



def generate_reg_instruction_onebind(instr_cls):
    for reg_name, reg_bits in reg_opcode.items():
        class OneBindRegInstruction(OneBindX64Instruction):
            mnemo = instr_cls.mnemo.format(reg_name)
            code = chr(int(instr_cls.instruction_bits + reg_bits, 2)).encode('hex')  + '11 11 11 11 11 11 11 11' # the biding
            if instr_cls.prefix_bin_h48:
                code = "48" + code
        OneBindRegInstruction.__name__ = instr_cls.name.format(reg_name)
        add_instruction(OneBindRegInstruction.__name__, OneBindRegInstruction)
        
class Mov_Reg_X(object):
    name = 'Mov_{0}_X'
    mnemo = 'mov {0}, {{0}}'
    instruction_bits = '10111'
    prefix_bin_h48 = True
    
generate_reg_instruction_onebind(Mov_Reg_X)

def get_immediat_modr_byte(register_bits):
    "Generate a modr-reg-r/m indicating a register and an immediat"
    str_bits = "11000{0}".format(register_bits)
    return chr(int(str_bits, 2)).encode('hex')
  
def get_simple_modr_byte(register_bits):
    "Generate a simple modr-reg-r/m for a displacement only mode"
    str_bits = "00{0}101".format(register_bits)
    return chr(int(str_bits, 2)).encode('hex')
 

#def generate_reg_indirect_modr_byte(reg_dst_bits, reg_src_bits):
#    # reg, [reg] or [reg], reg
#    return "00{0}{1}".format(reg_dst_bits, reg_src_bits)
#    
#def generate_reg_reg_deref(instr_cls, src_first=True):
#    "generate the Mov_Reg_DReg and Mov_DReg_Reg"
#    for reg_src_name, reg_src_bits in reg_opcode.items():
#        for reg_dst_name, reg_dst_bits in reg_opcode.items():
#            if reg_dst_name in ("RBP", "RSP") or reg_src_name in ("RBP", "RSP"):
#                # Not same encoding -> Not implemented
#                continue
#            class Reg_DReg_instruction(X64Instruction):
#                mnemo = instr_cls.mnemo.format(reg_dst_name, reg_src_name)
#                name = instr_cls.name.format(reg_dst_name, reg_src_name)
#                if src_first:
#                    modr_code = generate_reg_indirect_modr_byte(reg_src_bits, reg_dst_bits)
#                else:
#                    modr_code = generate_reg_indirect_modr_byte(reg_dst_bits, reg_src_bits)
#                code = instr_cls.instruction_bits + chr(int(modr_code, 2)).encode("hex")
#            Reg_DReg_instruction.__name__ = Reg_DReg_instruction.name
#            add_instruction(Reg_DReg_instruction.__name__, Reg_DReg_instruction)
    
    


def generate_reg_indirect_modr_byte(reg_dst_bits, reg_src_bits, deref_first):
    # reg, [reg] or [reg], reg
    if deref_first:
        return chr(int("00{0}{1}".format(reg_dst_bits, reg_src_bits), 2)).encode('hex')
    else:
        return chr(int("00{0}{1}".format(reg_src_bits, reg_dst_bits), 2)).encode('hex')
    
def generate_reg_reg_deref():
    for reg1_name, reg1_bits in all_regs.items():
        for reg2_name, reg2_bits in all_regs.items():
            if reg1_name in ("RBP", "RSP", "R12", "R13") or reg2_name in ("RBP", "RSP", "R12", "R13"):
                continue
            is_reg1_new = reg1_name in new_reg_opcode
            is_reg2_new = reg2_name in new_reg_opcode
            
            first_byte = chr(int("1001{0}0{1}".format(int(is_reg1_new), int(is_reg2_new)), 2)).encode('hex')
            
            class DReg_Reg_instruction(X64Instruction):
                mnemo = "mov [{0}], {1}".format(reg1_name, reg2_name)
                name  = 'Mov_D{0}_{1}'.format(reg1_name, reg2_name)
                modr_code = generate_reg_indirect_modr_byte(reg1_bits, reg2_bits, False)
                code = first_byte + "89" + modr_code
                
            DReg_Reg_instruction.__name__ = DReg_Reg_instruction.name    
            add_instruction(DReg_Reg_instruction.__name__, DReg_Reg_instruction)
                
            class Reg_DReg_instruction(X64Instruction):
                mnemo = "mov {0}, [{1}]".format(reg1_name, reg2_name)
                name  = 'Mov_{0}_D{1}'.format(reg1_name, reg2_name)
                modr_code = generate_reg_indirect_modr_byte(reg1_bits, reg2_bits, True)
                code = first_byte + "8B" + modr_code
                
            Reg_DReg_instruction.__name__ = Reg_DReg_instruction.name    
            add_instruction(Reg_DReg_instruction.__name__, Reg_DReg_instruction)
    
    
generate_reg_reg_deref()    
   
