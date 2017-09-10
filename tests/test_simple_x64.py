try:
    import capstone
except ImportError as e:
    capstone = None
import pytest

import windows.native_exec.simple_x64 as x64
from windows.native_exec.simple_x64 import *
del Test # Prevent pytest warning

if capstone:
    disassembleur = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembleur.detail = True


def disas(x):
    return list(disassembleur.disasm(x, 0))

mnemonic_name_exception = {'movabs': 'mov'}




class CheckInstr(object):
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


def test_assembler():
    CheckInstr(Add)('RAX', 'RSP')
    CheckInstr(Add)('RAX', mem('[RCX]'))
    CheckInstr(Add)('RAX', mem('[RDI + 0x10]'))
    CheckInstr(Add)('RAX', mem('[RSI + 0x7fffffff]'))
    CheckInstr(Add)('RAX', mem('[RSI + -0x1]'))
    CheckInstr(Add)('RAX', mem('[0x10]'))
    CheckInstr(Add)('RAX', mem('fs:[0x10]'))
    CheckInstr(Add)('RAX', mem('[RSI + RDI * 2]'))
    CheckInstr(Add)('RAX', mem('[RSI + RDI * 2 + 0x10]'))
    CheckInstr(Add)('RAX', mem('gs:[RSI + RDI * 2 + 0x10]'))
    CheckInstr(Add)('RAX', mem('[R15 * 8 + 0x10]'))
    CheckInstr(Add)('RAX', mem('[R9 + R8 * 2 + 0x7fffffff]'))
    CheckInstr(Add)('RAX', mem('[R9 + R8 * 2 + -0x80000000]'))
    CheckInstr(Add)('RAX', mem('[-1]'))
    CheckInstr(Add)('RAX', mem('[0x7fffffff]'))
    CheckInstr(Add)('RAX', -1)


    CheckInstr(Sub)('RCX', 'RSP')
    CheckInstr(Sub)('RCX', mem('[RSP]'))

    CheckInstr(Xor)('R15', mem('[RAX + R8 * 2 + 0x11223344]'))
    CheckInstr(Xor)('RAX', 'RAX')
    CheckInstr(Cmp)('RAX', -1)
    #CheckInstr(Cmp, immediat_accepted=-1)('RAX', 0xffffffff)
    CheckInstr(Lea)('RAX', mem('[RAX + 1]'))
    CheckInstr(Lea)('RAX', mem('fs:[RAX + 1]'))
    CheckInstr(Mov)('RAX', mem('[0x1122334455667788]'))
    CheckInstr(Mov)('RAX', mem('gs:[0x1122334455667788]'))
    CheckInstr(Mov)('RAX', mem('gs:[0x60]'))
    CheckInstr(Mov)('RCX', 0x1122334455667788)
    CheckInstr(Mov)('RCX', -1)
    CheckInstr(Mov)('RCX', -0x1000)
    CheckInstr(Mov)('RCX', 0xffffffff)
    CheckInstr(Mov)('RAX', 0xffffffff)
    CheckInstr(Mov)('R8', 0x1122334455667788)
    CheckInstr(Mov)('RCX', -1)
    CheckInstr(Mov, immediat_accepted=-1)('RCX', 0xffffffffffffffff)
    CheckInstr(Mov)(mem('gs:[0x1122334455667788]'), 'RAX')
    CheckInstr(Mov)(mem('[RAX]'), 0x11223344)
    CheckInstr(Mov)(mem('[EAX]'), 0x11223344)
    CheckInstr(Mov)(mem('[RBX]'), 0x11223344)
    CheckInstr(Mov)("R12", mem("[RAX]"))
    CheckInstr(Mov)("RAX", mem("[R12]"))
    CheckInstr(Mov)("RAX", mem("[RAX + R12]"))
    CheckInstr(Mov)("RAX", mem("[R12 + R12]"))
    CheckInstr(Mov)("RAX", mem("[R12 + R15]"))

    CheckInstr(Mov)("RAX", mem("[R10]"))
    CheckInstr(Mov)("RAX", mem("[R11]"))
    CheckInstr(Mov)("RAX", mem("[R12]"))
    CheckInstr(Mov)("RAX", mem("[R13]"))
    CheckInstr(Mov)("RAX", mem("[R14]"))
    CheckInstr(Mov)("RAX", mem("[R15]"))

    #CheckInstr(Mov)("RSI", mem("[R12]"))

    CheckInstr(And)('RCX', 'RBX')
    CheckInstr(And)('RAX', 0x11223344)
    CheckInstr(And)('EAX', 0x11223344)
    CheckInstr(And)('EAX', 0xffffffff)
    CheckInstr(And)('RAX', mem('[RAX + 1]'))
    CheckInstr(And)(mem('[RAX + 1]'), 'R8')
    CheckInstr(And)(mem('[EAX + 1]'), 'R8')
    CheckInstr(And)(mem('[RAX + 1]'), 'EAX')

    CheckInstr(Or)('RCX', 'RBX')
    CheckInstr(Or)('RAX', 0x11223344)
    CheckInstr(Or)('RAX', mem('[RAX + 1]'))
    CheckInstr(Or)(mem('[RAX + 1]'), 'R8')
    CheckInstr(Or)(mem('[EAX + 1]'), 'R8')
    CheckInstr(Or)(mem('[RAX + 1]'), 'EAX')

    CheckInstr(Shr)('RAX', 8)
    CheckInstr(Shr)('R15', 0x12)
    CheckInstr(Shl)('RAX', 8)
    CheckInstr(Shl)('R15', 0x12)

    # I really don't know why it's the inverse
    # But I don't care, it's Test dude..
    CheckInstr(x64.Test, expected_result="test r11, rax")('RAX', 'R11')
    CheckInstr(x64.Test, expected_result="test edi, eax")('EAX', 'EDI')
    CheckInstr(x64.Test)('RCX', 'RCX')

    CheckInstr(x64.Test)(mem('[RDI + 0x100]'), 'RCX')

    assert x64.Test(mem('[RDI + 0x100]'), 'RCX').get_code() == x64.Test('RCX', mem('[RDI + 0x100]')).get_code()


    CheckInstr(Push)('RAX')
    assert len(Push("RAX").get_code()) == 1
    CheckInstr(Push)('R15')
    CheckInstr(Push)(0x42)
    CheckInstr(Push)(-1)
    CheckInstr(Push)(mem("[ECX]"))
    CheckInstr(Push)(mem("[RCX]"))


    CheckInstr(Pop)('RAX')
    assert len(Pop("RAX").get_code()) == 1


    CheckInstr(Call)('RAX')
    CheckInstr(Call)(mem('[RAX + RCX * 8]'))
    CheckInstr(Cpuid)()
    CheckInstr(Xchg)('RAX', 'RSP')
    assert Xchg('RAX', 'RCX').get_code() == Xchg('RCX', 'RAX').get_code()

    # 32 / 64 bits register mixing
    CheckInstr(Mov)('ECX', 'EBX')
    CheckInstr(Mov)('RCX', mem('[EBX]'))
    CheckInstr(Mov)('ECX', mem('[RBX]'))
    CheckInstr(Mov)('ECX', mem('[EBX]'))
    CheckInstr(Mov)('RCX', mem('[EBX + EBX]'))
    CheckInstr(Mov)('RCX', mem('[ESP + EBX + 0x10]'))
    CheckInstr(Mov)('ECX', mem('[ESP + EBX + 0x10]'))
    CheckInstr(Mov)('ECX', mem('[RBX + RCX + 0x10]'))

    CheckInstr(Mov)(mem('[RBX + RCX + 0x10]'), 'ECX')
    CheckInstr(Mov)(mem('[EBX + ECX + 0x10]'), 'ECX')
    CheckInstr(Mov)(mem('[EBX + ECX + 0x10]'), 'R8')

    CheckInstr(Not)('RAX')
    CheckInstr(Not)(mem('[RAX]'))


    CheckInstr(ScasB, expected_result="scasb al, byte ptr [rdi]")()
    CheckInstr(ScasW, expected_result="scasw ax, word ptr [rdi]")()
    CheckInstr(ScasD, expected_result="scasd eax, dword ptr [rdi]")()
    CheckInstr(ScasQ, expected_result="scasq rax, qword ptr [rdi]")()

    CheckInstr(CmpsB, expected_result="cmpsb byte ptr [rsi], byte ptr [rdi]")()
    CheckInstr(CmpsW, expected_result="cmpsw word ptr [rsi], word ptr [rdi]")()
    CheckInstr(CmpsD, expected_result="cmpsd dword ptr [rsi], dword ptr [rdi]")()
    CheckInstr(CmpsQ, expected_result="cmpsq qword ptr [rsi], qword ptr [rdi]")()



    CheckInstr(Mov, must_fail=True)('RCX', 'ECX')
    CheckInstr(Mov, must_fail=True)('RCX', mem('[ECX + RCX]'))
    CheckInstr(Mov, must_fail=True)('RCX', mem('[RBX + ECX]'))
    CheckInstr(Mov, must_fail=True)('ECX', mem('[ECX + RCX]'))
    CheckInstr(Mov, must_fail=True)('ECX', mem('[RBX + ECX]'))
    CheckInstr(Add, must_fail=True)('RAX', 0xffffffff)


    code = MultipleInstr()
    code += Nop()
    code += Rep + Nop()
    code += Ret()
    print(repr(code.get_code()))
    assert code.get_code() == "\x90\xf3\x90\xc3"

if capstone is None:
    test_assembler = pytest.mark.skip("Capstone not installed")(test_assembler)

# pytestmark = pytest.mark.skip("YOLO")

if __name__ == "__main__":
    test_assembler()
