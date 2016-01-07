import ctypes
import struct

import native_function
import simple_x86 as x86
import simple_x64 as x64
from windows.generated_def.winstructs import *


def _bitness():
    """Returns 32 or 64"""
    import platform
    bits = platform.architecture()[0]
    return int(bits[:2])


class X86CpuidResult(ctypes.Structure):
    """Raw result of the CPUID instruction"""
    _fields_ = [("EAX", DWORD),
                ("EBX", DWORD),
                ("ECX", DWORD),
                ("EDX", DWORD)]
    fields = [f[0] for f in _fields_]
    """Fields of the Structure"""

class X64CpuidResult(ctypes.Structure):
    _fields_ = [("RAX", ULONG64),
                ("RBX", ULONG64),
                ("RCX", ULONG64),
                ("RDX", ULONG64)]


class X86IntelCpuidFamilly(ctypes.Structure):
    _fields_ = [("SteppingID", DWORD, 4),
                ("ModelID", DWORD, 4),
                ("FamilyID", DWORD, 4),
                ("ProcessorType", DWORD, 2),
                ("Reserved2", DWORD, 2),
                ("ExtendedModel", DWORD, 4),
                ("ExtendedFamily", DWORD, 8),
                ("Reserved", DWORD, 2)]
    fields = [f[0] for f in _fields_]
    """Fields of the Structure"""


class X86AmdCpuidFamilly(ctypes.Structure):
    _fields_ = [("SteppingID", DWORD, 4),
                ("ModelID", DWORD, 4),
                ("FamilyID", DWORD, 4),
                ("Reserved2", DWORD, 4),
                ("ExtendedModel", DWORD, 4),
                ("ExtendedFamily", DWORD, 8),
                ("Reserved", DWORD, 2)]
    fields = [f[0] for f in _fields_]
    """Fields of the Structure"""

cpuid32_code = x86.MultipleInstr()
cpuid32_code += x86.Push('EDI')
cpuid32_code += x86.Mov('EAX', x86.mem('[ESP + 0x8]'))
cpuid32_code += x86.Mov('EDI', x86.mem('[ESP + 0xc]'))
cpuid32_code += x86.Cpuid()
cpuid32_code += x86.Mov(x86.mem('[EDI + 0x0]'), 'EAX')
cpuid32_code += x86.Mov(x86.mem('[EDI + 0x4]'), 'EBX')
cpuid32_code += x86.Mov(x86.mem('[EDI + 0x8]'), 'ECX')
cpuid32_code += x86.Mov(x86.mem('[EDI + 0xc]'), 'EDX')
cpuid32_code += x86.Pop('EDI')
cpuid32_code += x86.Ret()
do_cpuid32 = native_function.create_function(cpuid32_code.get_code(), [DWORD, DWORD, PVOID])


cpuid64_code = x64.MultipleInstr()
cpuid64_code += x64.Mov('RAX', 'RCX')
cpuid64_code += x64.Mov('R10', 'RDX')
cpuid64_code += x64.Cpuid()
# For now assembler cannot do 32bits register in x64
cpuid64_code += x64.Mov(x64.mem('[R10 + 0x00]'), 'RAX')
cpuid64_code += x64.Mov(x64.mem('[R10 + 0x08]'), 'RBX')
cpuid64_code += x64.Mov(x64.mem('[R10 + 0x10]'), 'RCX')
cpuid64_code += x64.Mov(x64.mem('[R10 + 0x18]'), 'RDX')
cpuid64_code += x64.Ret()
do_cpuid64 = native_function.create_function(cpuid64_code.get_code(), [DWORD, DWORD, PVOID])


def x86_cpuid(req):
    """Performs a CPUID in 32bits mode

        :rtype: :class:`X86CpuidResult`
    """
    cpuid_res = X86CpuidResult()
    do_cpuid32(req, ctypes.addressof(cpuid_res))
    return cpuid_res


def x64_cpuid(req):
    """Performs a CPUID in 64bits mode

        :rtype: :class:`X86CpuidResult`
    """
    cpuid_res = X64CpuidResult()
    do_cpuid64(req, ctypes.addressof(cpuid_res))
    # For now assembler cannot do 32bits register in x64
    return X86CpuidResult(cpuid_res.RAX, cpuid_res.RBX, cpuid_res.RCX, cpuid_res.RDX)


if _bitness() == 32:
    _do_cpuid = x86_cpuid
else:
    _do_cpuid = x64_cpuid

def do_cpuid(req):
    """Performs a CPUID for the current process bitness

        :rtype: :class:`X86CpuidResult`
    """
    return _do_cpuid(req)


def get_vendor_id():
    """Extracts the VendorId string from CPUID

        :rtype: :class:`str`
    """
    cpuid_res = do_cpuid(0)
    return struct.pack("<III", cpuid_res.EBX, cpuid_res.EDX, cpuid_res.ECX)


# platform.processor() could do the trick
def is_intel_proc():
    """get_vendor_id() == 'GenuineIntel'"""
    return get_vendor_id() == "GenuineIntel"


def is_amd_proc():
    """get_vendor_id() == 'AuthenticAMD'"""
    return get_vendor_id() == "AuthenticAMD"


def get_proc_family_model():
    """Extracts the family and model based on vendorId

        :rtype: (ComputedFamily, ComputedModel)
    """
    cpuid_res = do_cpuid(1)
    if is_intel_proc():
        format = X86IntelCpuidFamilly
    elif is_amd_proc():
        format = X86AmdCpuidFamilly
    else:
        raise NotImplementedError("Cannot get familly information of proc <{0}>".format(get_vendor_id()))
    infos = format.from_buffer_copy(struct.pack("<I", cpuid_res.EAX))
    if infos.FamilyID == 0x6 or infos.FamilyID == 0x0F:
        ComputedModel = infos.ModelID + (infos.ExtendedModel << 4)
    else:
        ComputedModel = infos.ModelID
    if infos.FamilyID == 0x0F:
        ComputedFamily = infos.FamilyID + infos.ExtendedFamily
    else:
        ComputedFamily = infos.FamilyID
    return ComputedFamily, ComputedModel
