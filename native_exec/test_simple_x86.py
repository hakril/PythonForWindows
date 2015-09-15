import capstone
from simple_x86 import *

disassembleur = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
disassembleur.detail = True

def disas(x):
    return list(disassembleur.disasm(x, 0))

    
class TestInstr(object):
    def __init__(self, instr_to_test):
        self.instr_to_test = instr_to_test
        
    def __call__(self, *args):
        res = bytes(self.instr_to_test(*args).get_code())
        capres_list = disas(res)
        if len(capres_list) != 1:
            raise AssertionError("Trying to disas an instruction resulted in multiple disassembled instrs") 
        capres = capres_list[0]
        print("{0} {1}".format(capres.mnemonic, capres.op_str))
        if len(res) != len(capres.bytes):
            raise AssertionError("Not all bytes have been used by the disassembler")
        self.compare_mnemo(capres)
        self.compare_args(args, capres)
        
    def compare_mnemo(self, capres):
        expected = self.instr_to_test.__name__.lower()
        if expected != str(capres.mnemonic):
            raise AssertionError("Expected menmo {0} got {1}".format(expected, str(capres.mnemonic)))
        return True
        
    def compare_args(self, args, capres):
        capres_op = list(capres.operands)
        if len(args) != len(capres_op):
            raise AssertionError("Expected {0} operands got {1}".format(len(args), len(capres_op)))
        for op_args, cap_op in zip(args, capres_op):
            if isinstance(op_args, str): # Register
                if cap_op.type != capstone.x86.X86_OP_REG:
                    raise AssertionError("Expected args {0} operands got {1}".format(op_args, capres_op))
                if op_args.lower() != capres.reg_name(cap_op.reg).lower():
                    raise AssertionError("Expected register <{0}> got {1}".format(op_args.lower(), capres.reg_name(cap_op.reg).lower()))
            elif isinstance(op_args, (int, long)):
                if op_args != cap_op.imm:
                    raise AssertionError("Expected Immediat <{0}> got {1}".format(op_args, cap_op.imm))
            elif isinstance(op_args, mem_access):
                self.compare_mem_access(op_args, capres, cap_op)
            else:
                raise ValueError("Unknow argument {0} of type {1}".format(op_args, type(op_args)))
                
    def compare_mem_access(self, memaccess, capres, cap_op):
        if cap_op.type != capstone.x86.X86_OP_MEM:
            raise AssertionError("Expected Memaccess <{0}> got {1}".format(memaccess, cap_op))
        cap_mem = cap_op.mem
        if memaccess.base is None and cap_mem.base != capstone.x86.X86_REG_INVALID:
            raise AssertionError("Unexpected memaccess base <{0}>".format(capres.reg_name(cap_mem.base)))
        if memaccess.base is not None and capres.reg_name(cap_mem.base) != memaccess.base.lower():
            raise AssertionError("Expected mem.base {0} got {1}".format(memaccess.base.lower(), capres.reg_name(cap_mem.base)))
        if memaccess.index is None and cap_mem.index != capstone.x86.X86_REG_INVALID:
            raise AssertionError("Unexpected memaccess index <{0}>".format(capres.reg_name(cap_mem.base)))
        if memaccess.index is not None and capres.reg_name(cap_mem.index) != memaccess.index.lower():
            raise AssertionError("Expected mem.index {0} got {1}".format(memaccess.index.lower(), capres.reg_name(cap_mem.index)))    
        if memaccess.scale != cap_mem.scale and not (memaccess.scale is None and cap_mem.scale == 1):
            raise AssertionError("Expected mem.scale {0} got {1}".format(memaccess.scale, cap_mem.scale))
        if memaccess.disp != cap_mem.disp:
            raise AssertionError("Expected mem.disp {0} got {1}".format(memaccess.disp, cap_mem.disp))
                   
            
TestInstr(Mov)('EAX', 'ESP')
TestInstr(Mov)('ECX', mem('[EAX]'))
TestInstr(Mov)('EDX', mem('[ECX + 0x10]'))
TestInstr(Mov)('EDX', mem('[EDI * 8 + 0xffff]'))
TestInstr(Mov)('EDX', mem('[0x11223344]'))
TestInstr(Mov)('EDX', mem('[ESP + EBP * 2 + 0x223344]'))
TestInstr(Mov)(mem('[EBP + EBP * 2 + 0x223344]'), 'ESP')
TestInstr(Mov)('ESI', mem('[ESI + EDI * 1]'))
TestInstr(Add)('EAX', 8)
TestInstr(Add)('EAX', 0xffffffff)

TestInstr(Lea)('EAX', mem('[EAX + 1]'))
TestInstr(Lea)('ECX', mem('[EDI + -0xff]'))

TestInstr(Call)('EAX')
TestInstr(Call)(mem('[EAX + ECX * 8]'))

TestInstr(Xchg)('EAX', 'ESP')
assert Xchg('EAX', 'ECX').get_code() == Xchg('ECX', 'EAX').get_code()
