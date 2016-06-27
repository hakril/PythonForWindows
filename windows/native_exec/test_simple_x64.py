import capstone
import simple_x64 as x64
from simple_x64 import *

disassembleur = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
disassembleur.detail = True


def disas(x):
    return list(disassembleur.disasm(x, 0))

mnemonic_name_exception = {'movabs': 'mov'}


class TestInstr(object):
    def __init__(self, instr_to_test, expected_result=None, immediat_accepted=None, must_fail=None, debug=False):
        self.instr_to_test = instr_to_test
        self.immediat_accepted = immediat_accepted
        self.expected_result = expected_result
        self.must_fail = must_fail
        self.debug = debug

    def __call__(self, *args):
        try:
            if self.debug:
                import pdb;pdb.set_trace()
                pdb.DONE = True
            x64.DEBUG = self.debug
            res = bytes(self.instr_to_test(*args).get_code())
            if self.debug:
                print(repr(res))
        except ValueError as e:
            if self.must_fail == True:
                return True
            else:
                raise
        else:
            if self.must_fail:
                raise ValueError("Instruction did not failed as expected")
        capres_list = disas(res)
        if len(capres_list) != 1:
            raise AssertionError("Trying to disas an instruction resulted in multiple disassembled instrs")
        capres = capres_list[0]
        print("{0} {1}".format(capres.mnemonic, capres.op_str))
        if self.expected_result is not None:
            if "{0} {1}".format(capres.mnemonic, capres.op_str) == self.expected_result:
                return True
            else:
                raise AssertionError("Expected result <{0}> got <{1}>".format(self.expected_result, "{0} {1}".format(capres.mnemonic, capres.op_str)))
        if len(res) != len(capres.bytes):
            print("<{0}> vs <{1}>".format(repr(res), repr(capres.bytes)))
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
TestInstr(Add)('RAX', -1)


TestInstr(Sub)('RCX', 'RSP')
TestInstr(Sub)('RCX', mem('[RSP]'))

TestInstr(Xor)('R15', mem('[RAX + R8 * 2 + 0x11223344]'))
TestInstr(Xor)('RAX', 'RAX')
TestInstr(Cmp)('RAX', -1)
#TestInstr(Cmp, immediat_accepted=-1)('RAX', 0xffffffff)
TestInstr(Lea)('RAX', mem('[RAX + 1]'))
TestInstr(Lea)('RAX', mem('fs:[RAX + 1]'))
TestInstr(Mov)('RAX', mem('[0x1122334455667788]'))
TestInstr(Mov)('RAX', mem('gs:[0x1122334455667788]'))
TestInstr(Mov)('RAX', mem('gs:[0x60]'))
TestInstr(Mov)('RCX', 0x1122334455667788)
TestInstr(Mov)('R8', 0x1122334455667788)
TestInstr(Mov)('RCX', -1)
TestInstr(Mov, immediat_accepted=-1)('RCX', 0xffffffffffffffff)
TestInstr(Mov)(mem('gs:[0x1122334455667788]'), 'RAX')
TestInstr(Mov)(mem('[RAX]'), 0x11223344)
TestInstr(Mov)(mem('[EAX]'), 0x11223344)
TestInstr(Mov)(mem('[RBX]'), 0x11223344)
TestInstr(Mov)("R12", mem("[RAX]"))
TestInstr(Mov)("RAX", mem("[R12]"))
TestInstr(Mov)("RAX", mem("[RAX + R12]"))
TestInstr(Mov)("RAX", mem("[R12 + R12]"))
#TestInstr(Mov)("RSI", mem("[R12]"))

TestInstr(And)('RCX', 'RBX')
TestInstr(And)('RAX', 0x11223344)
TestInstr(And)('EAX', 0x11223344)
TestInstr(And)('EAX', 0xffffffff)
TestInstr(And)('RAX', mem('[RAX + 1]'))
TestInstr(And)(mem('[RAX + 1]'), 'R8')
TestInstr(And)(mem('[EAX + 1]'), 'R8')
TestInstr(And)(mem('[RAX + 1]'), 'EAX')

TestInstr(Or)('RCX', 'RBX')
TestInstr(Or)('RAX', 0x11223344)
TestInstr(Or)('RAX', mem('[RAX + 1]'))
TestInstr(Or)(mem('[RAX + 1]'), 'R8')
TestInstr(Or)(mem('[EAX + 1]'), 'R8')
TestInstr(Or)(mem('[RAX + 1]'), 'EAX')

TestInstr(Shr)('RAX', 8)
TestInstr(Shr)('R15', 0x12)
TestInstr(Shl)('RAX', 8)
TestInstr(Shl)('R15', 0x12)

# I really don't know why it's the inverse
# But I don't care, it's Test dude..
TestInstr(Test, expected_result="test r11, rax")('RAX', 'R11')
TestInstr(Test, expected_result="test edi, eax")('EAX', 'EDI')
TestInstr(Test)('RCX', 'RCX')

TestInstr(Test)(mem('[RDI + 0x100]'), 'RCX')

assert Test(mem('[RDI + 0x100]'), 'RCX').get_code() == Test('RCX', mem('[RDI + 0x100]')).get_code()


TestInstr(Push)('RAX')
assert len(Push("RAX").get_code()) == 1
TestInstr(Push)('R15')
TestInstr(Push)(0x42)
TestInstr(Push)(-1)
TestInstr(Push)(mem("[ECX]"))
TestInstr(Push)(mem("[RCX]"))


TestInstr(Pop)('RAX')
assert len(Pop("RAX").get_code()) == 1


TestInstr(Call)('RAX')
TestInstr(Call)(mem('[RAX + RCX * 8]'))
TestInstr(Cpuid)()
TestInstr(Xchg)('RAX', 'RSP')
assert Xchg('RAX', 'RCX').get_code() == Xchg('RCX', 'RAX').get_code()

# 32 / 64 bits register mixing
TestInstr(Mov)('ECX', 'EBX')
TestInstr(Mov)('RCX', mem('[EBX]'))
TestInstr(Mov)('ECX', mem('[RBX]'))
TestInstr(Mov)('ECX', mem('[EBX]'))
TestInstr(Mov)('RCX', mem('[EBX + EBX]'))
TestInstr(Mov)('RCX', mem('[ESP + EBX + 0x10]'))
TestInstr(Mov)('ECX', mem('[ESP + EBX + 0x10]'))
TestInstr(Mov)('ECX', mem('[RBX + RCX + 0x10]'))

TestInstr(Mov)(mem('[RBX + RCX + 0x10]'), 'ECX')
TestInstr(Mov)(mem('[EBX + ECX + 0x10]'), 'ECX')
TestInstr(Mov)(mem('[EBX + ECX + 0x10]'), 'R8')

TestInstr(Not)('RAX')
TestInstr(Not)(mem('[RAX]'))


TestInstr(ScasB, expected_result="scasb al, byte ptr [rdi]")()
TestInstr(ScasW, expected_result="scasw ax, word ptr [rdi]")()
TestInstr(ScasD, expected_result="scasd eax, dword ptr [rdi]")()
TestInstr(ScasQ, expected_result="scasq rax, qword ptr [rdi]")()

TestInstr(CmpsB, expected_result="cmpsb byte ptr [rsi], byte ptr [rdi]")()
TestInstr(CmpsW, expected_result="cmpsw word ptr [rsi], word ptr [rdi]")()
TestInstr(CmpsD, expected_result="cmpsd dword ptr [rsi], dword ptr [rdi]")()
TestInstr(CmpsQ, expected_result="cmpsq qword ptr [rsi], qword ptr [rdi]")()



TestInstr(Mov, must_fail=True)('RCX', 'ECX')
TestInstr(Mov, must_fail=True)('RCX', mem('[ECX + RCX]'))
TestInstr(Mov, must_fail=True)('RCX', mem('[RBX + ECX]'))
TestInstr(Mov, must_fail=True)('ECX', mem('[ECX + RCX]'))
TestInstr(Mov, must_fail=True)('ECX', mem('[RBX + ECX]'))
TestInstr(Add, must_fail=True)('RAX', 0xffffffff)


code = MultipleInstr()
code += Nop()
code += Rep + Nop()
code += Ret()
print(repr(code.get_code()))
assert code.get_code() == "\x90\xf3\x90\xc3"
