import ctypes
import struct

import native_function
import simple_x86 as x86
import simple_x64 as x64
from windows.generated_def.winstructs import *


def bitness():
    """Return 32 or 64"""
    import platform
    bits = platform.architecture()[0]
    return int(bits[:2])


class X86CpuidResult(ctypes.Structure):
    _fields_ = [("EAX", DWORD),
                ("EBX", DWORD),
                ("ECX", DWORD),
                ("EDX", DWORD)]


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


class X86AmdCpuidFamilly(ctypes.Structure):
    _fields_ = [("SteppingID", DWORD, 4),
                ("ModelID", DWORD, 4),
                ("FamilyID", DWORD, 4),
                ("Reserved2", DWORD, 4),
                ("ExtendedModel", DWORD, 4),
                ("ExtendedFamily", DWORD, 8),
                ("Reserved", DWORD, 2)]


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
    cpuid_res = X86CpuidResult()
    do_cpuid32(req, ctypes.addressof(cpuid_res))
    return cpuid_res


def x64_cpuid(req):
    cpuid_res = X64CpuidResult()
    do_cpuid64(req, ctypes.addressof(cpuid_res))
    # For now assembler cannot do 32bits register in x64
    return X86CpuidResult(cpuid_res.RAX, cpuid_res.RBX, cpuid_res.RCX, cpuid_res.RDX)


if bitness() == 32:
    do_cpuid = x86_cpuid
else:
    do_cpuid = x64_cpuid


def get_vendor_id():
    cpuid_res = do_cpuid(0)
    return struct.pack("<III", cpuid_res.EBX, cpuid_res.EDX, cpuid_res.ECX)


# platform.processor() could do the trick
def is_intel_proc():
    return get_vendor_id() == "GenuineIntel"


def is_amd_proc():
    return get_vendor_id() == "AuthenticAMD"


def get_proc_family_model():
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
