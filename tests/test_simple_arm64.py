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


class CheckInstr(object):
    def __init__(self, instr_to_test, expected_result=None, immediat_accepted=None, must_fail=None, debug=False):
        self.instr_to_test = instr_to_test
        self.immediat_accepted = immediat_accepted
        self.expected_result = expected_result
        self.must_fail = must_fail
        self.debug = debug
        self.callargs = None


    def __call__(self, *args):
        assert args is not None
        self.callargs = args
        return self

    def __repr__(self):
        if self.must_fail:
            return "MustFail:{0}{1}".format(self.instr_to_test.__name__, self.callargs)
        return "{0}{1}".format(self.instr_to_test.__name__, self.callargs)

    def dotest(self):
        assert self.callargs is not None
        args = self.callargs
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
        if not capres_list:
            raise AssertionError("Trying to disas an instruction resulted no disassembled instr")
        if len(capres_list) != 1:
            raise AssertionError("Trying to disas an instruction resulted in multiple disassembled instrs: {0}".format(capres_list))
        capres = capres_list[0]
        print("{0} {1}".format(capres.mnemonic, capres.op_str))
        if self.expected_result is not None:
            if "{0} {1}".format(capres.mnemonic, capres.op_str).strip() == self.expected_result:
                return True
            else:
                raise AssertionError("Expected result <{0}> got <{1}>".format(self.expected_result, "{0} {1}".format(capres.mnemonic, capres.op_str)))
        if len(res) != len(capres.bytes):
            print("<{0}> vs <{1}>".format(repr(res), repr(capres.bytes)))
            raise AssertionError("Not all bytes have been used by the disassembler")
        self.compare_mnemo(capres)
        self.compare_args(args, capres)
        return True

    def compare_mnemo(self, capres):
        expected = self.instr_to_test.__name__.lower()
        if expected != capres.mnemonic:
            raise AssertionError("Expected menmo {0} got {1}".format(expected, str(capres.mnemonic)))
        return True

    def compare_args(self, args, capres):
        capres_op = list(capres.operands)
        # We may have != number of operand as shift are:
        #    - arguments for simple_arm64
        #    - atribute of immediat for capstone
        if not len(capres_op) <= len(args):
            raise AssertionError("Expected at most {0} operands got {1}".format(len(args), len(capres_op)))

        opargit = iter(args) # allow manually using next() to get next simple_arm64 arg for shift compare
        # capres_op must be first in zip (as its smaller) or last next(opargit) will be consommed by zip
        for cap_op, op_args in zip(capres_op, opargit):
            if isinstance(op_args, str):  # Register
                if cap_op.type != capstone.arm64.ARM64_OP_REG:
                    raise AssertionError("Expected args {0} operands got {1}".format(op_args, capres_op))
                if op_args.lower() != capres.reg_name(cap_op.reg).lower():
                    raise AssertionError("Expected register <{0}> got {1}".format(op_args.lower(), capres.reg_name(cap_op.reg).lower()))
            elif isinstance(op_args, int_types):
                if (op_args != cap_op.imm) and not (self.immediat_accepted and self.immediat_accepted == cap_op.imm):
                    raise AssertionError("Expected Immediat <{0}> got {1}".format(op_args, cap_op.imm))
                cap_shift = cap_op.shift
                if not (cap_shift.type == cap_shift.value == 0):
                    self.compare_shift(next(opargit), cap_shift)
            else:
                raise ValueError("Unknow argument {0} of type {1}".format(op_args, type(op_args)))

        # Check that no argument were unused in args
        # As args + shift should perfectly match the capres_op
        sentinel = object()
        nextarg = next(opargit, sentinel)
        if nextarg != sentinel:
            # Ignore a leading LSL #0 shift, as it should be authorized but not displayed by disassembler
            shift = Shift.parse(nextarg)
            if not (shift.type == "LSL" and shift.value == 0):
                raise ValueError("Non consomated argument: {0} (probable non-encoded shift)".format(nextarg))

    if capstone:
        SHIFT_TYPE_TO_CAPSTONE = {
            "LSL": capstone.arm64.ARM64_SFT_LSL,
            "LSR": capstone.arm64.ARM64_SFT_LSR,
            "ASR": capstone.arm64.ARM64_SFT_ASR,
            "ROR": capstone.arm64.ARM64_SFT_ROR,
            # "MSL": apstone.arm64.ARM64_SFT_MSL # Not yet used in PFW
        }

    def compare_shift(self, shiftstr, cap_shift):
        shift = Shift.parse(shiftstr)
        if not self.SHIFT_TYPE_TO_CAPSTONE[shift.type] == cap_shift.type:
            raise ValueError("Shift type mismatch: expected {0} got {1}".format(shift.type, cap_shift.type))
        if not shift.value == cap_shift.value:
            raise ValueError("Shift value mismatch: expected {0} got {1}".format(shift.value, cap_shift.value))
        return True


def test_shift_parsing():
    assert Shift.parse("LSL #0")
    assert Shift.parse("LSL #12")
    assert Shift.parse("LSL #1")
    assert Shift.parse("LSR #1")

    assert Shift.parse("ROR #0").type == "ROR"
    assert Shift.parse("LSL #0").type == "LSL"
    assert Shift.parse("LSL #0").value == 0
    assert Shift.parse("LSL #1").type == "LSL"
    assert Shift.parse("LSL #1").value == 1

    assert not Shift.parse("LSX #1")
    assert not Shift.parse("LSX ##1")
    assert not Shift.parse("LSX #")

@pytest.mark.parametrize("checkinstr", [
    CheckInstr(Add)('W0', 'W0', 0),
    CheckInstr(Add)('W1', 'W0', 0),
    CheckInstr(Add)('W30', 'W12', 0),
    CheckInstr(Add)('W0', 'W0', 1),
    CheckInstr(Add)('X0', 'X0', 0),
    CheckInstr(Add)('X30', 'X12', 0),
    CheckInstr(Add)('X0', 'X0', 1),
    CheckInstr(Add)('X11', 'X12', 0x123),
    CheckInstr(Add)('X11', 'X12', 0x123, "LSL #0"),
    CheckInstr(Add)('X11', 'X12', 0x123, "LSL #12"),
    CheckInstr(Add, must_fail=True)('X11', 'W12', 0x123), # Bitness mismatch
    CheckInstr(Add, must_fail=True)('BADREG', 'X12', 0),
    CheckInstr(Add, must_fail=True)('X11', 'X12', 0x123, "LSL #1234"),
    CheckInstr(Add, must_fail=True)('X11', 'X12', 0x12345678),

    CheckInstr(Movz)('X0', 0),
    CheckInstr(Movz)('X0', 0, "LSL #32"),
    CheckInstr(Movz)('X18', 0, "LSL #48"),
    CheckInstr(Movz)('W18', 0, "LSL #16"),
    CheckInstr(Movz, must_fail=True)('X0', 0, "LSL #12"), # Invalid LSL for MovWideImmediat
    CheckInstr(Movz, must_fail=True)('W0', 0, "LSL #32"),
    CheckInstr(Movz, must_fail=True)('X0', 0, "ROR #32"),


    CheckInstr(Orr)('X0', 'X18', 'XZR'),
    # Official encoding for this in ARM64 ref
    CheckInstr(Orr, expected_result="mov x0, x18")('X0', 'XZR', 'X18'),
    CheckInstr(Orr, must_fail=True)('X0', 'WZR', 'X18'), # Size mismatch
    CheckInstr(Orr, must_fail=True)('W0', 'XZR', 'W18'), # Size mismatch

    CheckInstr(Movk)('X0', 0x1234, "LSL #32"),
    CheckInstr(Movk)('X18', 0x5678, "LSL #48"),

    CheckInstr(Ret)("X0"),
    CheckInstr(Ret, expected_result="ret")("X30"),
    CheckInstr(Ret)(),

    # Virtual instruction that dispatch to something else:
    # Ex: "mov reg1, re2" -> "orr reg1, xzr, reg2"

    CheckInstr(Mov)('X0', 'X18'),
    CheckInstr(Mov)('W0', 'W18'),
    CheckInstr(Mov, must_fail=True)('X0', 'W18'),
    CheckInstr(Mov, must_fail=True)('X0', 'X18', 'X12'),


], ids=CheckInstr.__repr__)
def test_instruction_assembling(checkinstr):
    assert checkinstr.dotest()