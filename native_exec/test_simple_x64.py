import capstone
from simple_x64 import *

disassembleur = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
disassembleur.detail = True


def disas(x):
    return list(disassembleur.disasm(x, 0))

mnemonic_name_exception = {'movabs': 'mov'}


class TestInstr(object):
    def __init__(self, instr_to_test, immediat_accepted=None):
        self.instr_to_test = instr_to_test
        self.immediat_accepted = immediat_accepted

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
        cap_mnemo = mnemonic_name_exception.get(str(capres.mnemonic), str(capres.mnemonic))
        if expected != cap_mnemo:
            raise AssertionError("Expected menmo {0} got {1}".format(expected, str(capres.mnemonic)))
        return True

    def compare_args(self, args, capres):
        capres_op = list(capres.operands)
        if len(args) != len(capres_op):
            raise AssertionError("Expected {0} operands got {1}".format(len(args), len(capres_op)))
        for op_args, cap_op in zip(args, capres_op):
            if isinstance(op_args, str):  # Register
                if cap_op.type != capstone.x86.X86_OP_REG:
                    raise AssertionError("Expected args {0} operands got {1}".format(op_args, capres_op))
                if op_args.lower() != capres.reg_name(cap_op.reg).lower():
                    raise AssertionError("Expected register <{0}> got {1}".format(op_args.lower(), capres.reg_name(cap_op.reg).lower()))
            elif isinstance(op_args, (int, long)):
                if (op_args != cap_op.imm) and not (self.immediat_accepted and self.immediat_accepted == cap_op.imm):
                    raise AssertionError("Expected Immediat <{0}> got {1}".format(op_args, cap_op.imm))
            elif isinstance(op_args, mem_access):
                self.compare_mem_access(op_args, capres, cap_op)
            else:
                raise ValueError("Unknow argument {0} of type {1}".format(op_args, type(op_args)))

    def compare_mem_access(self, memaccess, capres, cap_op):
        if cap_op.type != capstone.x86.X86_OP_MEM:
            raise AssertionError("Expected Memaccess <{0}> got {1}".format(memaccess, cap_op))
        if memaccess.prefix is not None and capres.prefix[1] != x64_segment_selectors[memaccess.prefix].PREFIX_VALUE:
            try:
                get_prefix = [n for n, x in x64_segment_selectors.items() if x.PREFIX_VALUE == capres.prefix[1]][0]
            except IndexError:
                get_prefix = None
            raise AssertionError("Expected Segment overide <{0}> got {1}".format(memaccess.prefix, get_prefix))
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


TestInstr(Add)('RAX', 'RSP')
TestInstr(Add)('RAX', mem('[RCX]'))
TestInstr(Add)('RAX', mem('[RDI + 0x10]'))
TestInstr(Add)('RAX', mem('[RSI + 0x7fffffff]'))
TestInstr(Add)('RAX', mem('[RSI + -0x1]'))
TestInstr(Add)('RAX', mem('[0x10]'))
TestInstr(Add)('RAX', mem('fs:[0x10]'))
TestInstr(Add)('RAX', mem('[RSI + RDI * 2]'))
TestInstr(Add)('RAX', mem('[RSI + RDI * 2 + 0x10]'))
TestInstr(Add)('RAX', mem('gs:[RSI + RDI * 2 + 0x10]'))
TestInstr(Add)('RAX', mem('[R15 * 8 + 0x10]'))
TestInstr(Add)('RAX', mem('[R9 + R8 * 2 + 0x7fffffff]'))
TestInstr(Add)('RAX', mem('[R9 + R8 * 2 + -0x80000000]'))
TestInstr(Add)('RAX', mem('[-1]'))
TestInstr(Add)('RAX', mem('[0x7fffffff]'))
TestInstr(Xor)('R15', mem('[RAX + R8 * 2 + 0x11223344]'))
TestInstr(Xor)('RAX', 'RAX')
TestInstr(Cmp)('RAX', -1)
TestInstr(Lea)('RAX', mem('[RAX + 1]'))
TestInstr(Lea)('RAX', mem('fs:[RAX + 1]'))
TestInstr(Mov)('RAX', mem('[0x1122334455667788]'))
TestInstr(Mov)('RAX', mem('gs:[0x1122334455667788]'))
TestInstr(Mov)('RAX', mem('gs:[0x60]'))
TestInstr(Mov)('RCX', 0x1122334455667788)
TestInstr(Mov)('RCX', -1)
TestInstr(Mov, immediat_accepted=-1)('RCX', 0xffffffffffffffff)
TestInstr(Mov)(mem('gs:[0x1122334455667788]'), 'RAX')
TestInstr(Push)('R15')
TestInstr(Push)(0x42)
TestInstr(Push)(-1)
TestInstr(Call)('RAX')
TestInstr(Call)(mem('[RAX + RCX * 8]'))
TestInstr(Cpuid)()
TestInstr(Xchg)('RAX', 'RSP')
assert Xchg('RAX', 'RCX').get_code() == Xchg('RCX', 'RAX').get_code()

code = MultipleInstr()
code += Nop()
code += Rep + Nop()
code += Ret()
print(repr(code.get_code()))
assert code.get_code() == "\x90\xf3\x90\xc3"
