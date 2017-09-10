try:
    import capstone
except ImportError as e:
    capstone = None

import pytest

import windows.native_exec.simple_x86 as x86
from windows.native_exec.simple_x86 import *
del Test # Prevent pytest warning

if capstone:
    disassembleur = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    disassembleur.detail = True


def disas(x):
    return list(disassembleur.disasm(x, 0))



class CheckInstr(object):
    def __init__(self, instr_to_test, immediat_accepted=None, expected_result=None, debug=False):
        self.instr_to_test = instr_to_test
        self.expected_result = expected_result
        self.immediat_accepted = immediat_accepted
        self.debug = debug

    def __call__(self, *args):
        if self.debug:
            import pdb;pdb.set_trace()
            pdb.DONE = True
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
        if self.expected_result is not None:
            result = "{0} {1}".format(capres.mnemonic, capres.op_str)
            if result != self.expected_result:
                raise AssertionError("Bad expected result expect <{0}> got <{1}>".format(self.expected_result, result))
            return

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
        if memaccess.prefix is not None and capres.prefix[1] != x86_segment_selectors[memaccess.prefix].PREFIX_VALUE:
            try:
                get_prefix = [n for n, x in x86_segment_selectors.items() if x.PREFIX_VALUE == capres.prefix[1]][0]
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
        if memaccess.disp & 0xffffffff != cap_mem.disp & 0xffffffff:
            raise AssertionError("Expected mem.disp {0} got {1}".format(memaccess.disp, cap_mem.disp))


def test_assembler():
    CheckInstr(Mov)('EAX', 'CR3')
    CheckInstr(Mov)('EDX', 'CR0')
    CheckInstr(Mov)('EDI', 'CR7')

    CheckInstr(Mov)('CR3', 'EAX')
    CheckInstr(Mov)('CR0', 'EDX')
    CheckInstr(Mov)('CR7', 'EDI')

    CheckInstr(Mov)('EAX', 'ESP')
    CheckInstr(Mov)('ECX', mem('[EAX]'))
    CheckInstr(Mov)('EDX', mem('[ECX + 0x10]'))
    CheckInstr(Mov)('EDX', mem('[EDI * 8 + 0xffff]'))
    CheckInstr(Mov)('EDX', mem('[0x11223344]'))
    CheckInstr(Mov)('EDX', mem('[ESP + EBP * 2 + 0x223344]'))
    CheckInstr(Mov)(mem('[EBP + EBP * 2 + 0x223344]'), 'ESP')
    CheckInstr(Mov)('ESI', mem('[ESI + EDI * 1]'))
    CheckInstr(Mov)('EAX', mem('fs:[0x30]'))
    CheckInstr(Mov)('EDI', mem('gs:[EAX + ECX * 4]'))
    CheckInstr(Mov)('AX', 'AX')
    CheckInstr(Mov)('SI', 'DI')
    CheckInstr(Mov)('AX', 'AX')
    CheckInstr(Mov)('AX', mem('fs:[0x30]'))
    CheckInstr(Mov)('AX', mem('fs:[EAX + 0x30]'))
    CheckInstr(Mov)('AX', mem('fs:[EAX + ECX * 4+0x30]'))
    CheckInstr(Add)('EAX', 8)
    CheckInstr(Add)('EAX', 0xffffffff)
    CheckInstr(Add)("ECX", mem("[EAX + 0xff]"))
    CheckInstr(Add)("ECX", mem("[EAX + 0xffffffff]"))

    CheckInstr(Add)(mem('[EAX]'), 10)
    CheckInstr(Mov)('EAX', mem('fs:[0xfffc]'))
    CheckInstr(Mov)(mem('fs:[0xfffc]'), 0)

    CheckInstr(Push)('ECX')
    CheckInstr(Push)(mem('[ECX + 8]'))

    CheckInstr(Sub)('ECX', 'ESP')
    CheckInstr(Sub)('ECX', mem('[ESP]'))

    CheckInstr(Inc)('EAX')
    CheckInstr(Inc)(mem('[0x42424242]'))
    CheckInstr(Lea)('EAX', mem('[EAX + 1]'))
    CheckInstr(Lea)('ECX', mem('[EDI + -0xff]'))
    CheckInstr(Call)('EAX')
    CheckInstr(Call)(mem('[EAX + ECX * 8]'))
    CheckInstr(Cpuid)()
    CheckInstr(Movsb, expected_result='movsb byte ptr es:[edi], byte ptr [esi]')()
    CheckInstr(Movsd, expected_result='movsd dword ptr es:[edi], dword ptr [esi]')()
    CheckInstr(Xchg)('EAX', 'ESP')

    CheckInstr(Rol)('EAX', 7)
    CheckInstr(Rol)('ECX', 0)

    CheckInstr(Ror)('ECX', 0)
    CheckInstr(Ror)('EDI', 7)
    CheckInstr(Ror)('EDI', -128)

    CheckInstr(Cmp, immediat_accepted=0xffffffff)('EAX', -1)
    CheckInstr(Cmp)('EAX', 0xffffffff)

    CheckInstr(And)('ECX', 'EBX')
    CheckInstr(And)('EAX', 0x11223344)
    CheckInstr(And)('EAX', mem('[EAX + 1]'))
    CheckInstr(And)(mem('[EAX + EAX]'), 'EDX')

    CheckInstr(Or)('ECX', 'EBX')
    CheckInstr(Or)('EAX', 0x11223344)
    CheckInstr(Or)('EAX', mem('[EAX + 1]'))
    CheckInstr(Or)(mem('[EAX + EAX]'), 'EDX')

    CheckInstr(Shr)('EAX', 8)
    CheckInstr(Shr)('EDX', 0x12)
    CheckInstr(Shl)('EAX', 8)
    CheckInstr(Shl)('EDX', 0x12)

    CheckInstr(Not)('EAX')
    CheckInstr(Not)(mem('[EAX]'))

    CheckInstr(ScasB, expected_result="scasb al, byte ptr es:[edi]")()
    CheckInstr(ScasW, expected_result="scasw ax, word ptr es:[edi]")()
    CheckInstr(ScasD, expected_result="scasd eax, dword ptr es:[edi]")()

    CheckInstr(CmpsB, expected_result="cmpsb byte ptr [esi], byte ptr es:[edi]")()
    CheckInstr(CmpsW, expected_result="cmpsw word ptr [esi], word ptr es:[edi]")()
    CheckInstr(CmpsD, expected_result="cmpsd dword ptr [esi], dword ptr es:[edi]")()


    CheckInstr(x86.Test)('EAX', 'EAX')
    CheckInstr(x86.Test, expected_result="test edi, ecx")('ECX', 'EDI')

    CheckInstr(x86.Test)(mem('[ECX + 0x100]'), 'ECX')

    assert x86.Test(mem('[ECX + 0x100]'), 'ECX').get_code() == x86.Test('ECX', mem('[ECX + 0x100]')).get_code()
    assert Xchg('EAX', 'ECX').get_code() == Xchg('ECX', 'EAX').get_code()

    code = MultipleInstr()
    code += Nop()
    code += Rep + Nop()
    code += Ret()
    print(repr(code.get_code()))
    assert code.get_code() == "\x90\xf3\x90\xc3"

if capstone is None:
    test_assembler = pytest.mark.skip("Capstone not installed")(test_assembler)

if __name__ == "__main__":
    test_assembler()
