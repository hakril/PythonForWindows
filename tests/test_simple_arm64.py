try:
    import capstone
except ImportError as e:
    capstone = None
import pytest

import windows.native_exec.simple_arm64 as arm64
from windows.native_exec.simple_arm64 import *

from windows.pycompat import int_types

if capstone:
    disassembleur = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    disassembleur.detail = True

@pytest.fixture
def need_capstone():
    if capstone is None:
        raise pytest.skip("Capstone is not installed")
    return True

pytestmark = pytest.mark.usefixtures("need_capstone")


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
            arm64.DEBUG = self.debug
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
                if cap_op.type != capstone.arm64.ARM64_OP_REG:
                    raise AssertionError("Expected args {0} operands got {1}".format(op_args, capres_op))
                if op_args.lower() != capres.reg_name(cap_op.reg).lower():
                    raise AssertionError("Expected register <{0}> got {1}".format(op_args.lower(), capres.reg_name(cap_op.reg).lower()))
            elif isinstance(op_args, int_types):
                if (op_args != cap_op.imm) and not (self.immediat_accepted and self.immediat_accepted == cap_op.imm):
                    raise AssertionError("Expected Immediat <{0}> got {1}".format(op_args, cap_op.imm))
            else:
                raise ValueError("Unknow argument {0} of type {1}".format(op_args, type(op_args)))

def test_assembler():
    CheckInstr(Add)('W0', 'W0', 0)
    CheckInstr(Add)('W1', 'W0', 0)
    CheckInstr(Add)('W30', 'W12', 0)
    CheckInstr(Add)('W0', 'W0', 1)

    CheckInstr(Add)('X0', 'X0', 0)
    CheckInstr(Add)('X30', 'X12', 0)
    CheckInstr(Add)('X0', 'X0', 1)
    CheckInstr(Add)('X11', 'X12', 0x123)

    # Error test todo
    # CheckInstr(Add)('X11', 'W12', 0x123)
    CheckInstr(Add)('X11', 'X12', 0x12345678)