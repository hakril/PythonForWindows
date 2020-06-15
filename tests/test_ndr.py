import pytest

from windows.rpc import ndr
from .pfwtest import *

from tests.test_rpc import UACParameters

# Memo: Padding byte is 'P' in ndr.py

# 20 Bytes structures alignes on 4 butees
DoubleDwordStructure = ndr.make_structure([ndr.NdrLong] * 5)

# Struct with some specificities
# Start Must be aligned on 4 (even if it begin with a short)
# full size == 13 -> usefull to test afterward padding as well
# Pack format ah follow:
#    SSBPLLLLBPSSB
InternalAlignementStructure = ndr.make_structure([ndr.NdrShort, ndr.NdrByte, ndr.NdrLong,  ndr.NdrByte, ndr.NdrShort, ndr.NdrByte])
# IDL code:
# typedef struct InternalAlignementStructure
# {
     #short 	sfield0;
     #byte 	bfield1;
     #long 	lfield2;
     #byte 	bfield3;
     #short 	sfield4;
     #byte 	bfield5;
# }InternalAlignementStructure;


# NdrObject, Values, result
NDR_PACK_TEST_CASE = [
    # Simple case
    (ndr.make_structure([ndr.NdrLong, ndr.NdrLong]), (2, 2), b"\x02\x00\x00\x00\x02\x00\x00\x00"),
    # Check alignement on small native types (dword aligned)
    (ndr.make_structure([ndr.NdrShort, ndr.NdrByte]), (0x0101, 2), b"\x01\x01\x02"),
    # Check alignement on small native types (dword aligned)
    (ndr.make_structure([ndr.NdrShort, ndr.NdrShort]), (0x0101, 0x0202), b"\x01\x01\x02\x02"),
    # Same check on parameters
    (ndr.make_parameters([ndr.NdrShort, ndr.NdrByte]), (0x0101, 2), b"\x01\x01\x02"),
    # Test some Hyper
    (ndr.make_parameters([ndr.NdrByte, ndr.NdrHyper, ndr.NdrByte, ndr.NdrLong, ndr.NdrHyper]),
        (0x01, 0x4141414141414141, 0x42, 0x43434343, 0x4444444444444444 ),
        b"\x01PPPPPPPAAAAAAAABPPPCCCCDDDDDDDD"),
    # Complexe structure (with 4B alignement of 20B structure)
    (ndr.make_parameters([ndr.NdrShort, DoubleDwordStructure]),
        (0x0101, [0x41414141, 0x42424242, 0x43434343, 0x44444444, 0x45454545]),
        b"\x01\x01PPAAAABBBBCCCCDDDDEEEE"),
    # Same check on parameters
    (ndr.make_parameters([ndr.NdrShort, DoubleDwordStructure]),
        (0x0101, [0x41414141, 0x42424242, 0x43434343, 0x44444444, 0x45454545]),
        b"\x01\x01PPAAAABBBBCCCCDDDDEEEE"),

    # Check on InternalAlignementStructure before any nested test
    (InternalAlignementStructure,
        [0x4141, 0x42, 0x43434343, 0x44, 0x4545, 0x46],
        b"AABPCCCCDPEEF"),

    # Nested alignement
    # Alignement with a sub-structure that also have internal alignement
    (ndr.make_parameters([ndr.NdrShort, InternalAlignementStructure, ndr.NdrByte]),
        (0x0101, [0x4141, 0x42, 0x43434343, 0x44, 0x4545, 0x46], 0x47),
        # Verified with an actual RPC server
        b"\x01\x01PPAABPCCCCDPEEFG"),
    # Nested alignement
    # Alignement with a sub-structure that also have internal alignement
    # Afterward short should be aligned on 2
    (ndr.make_parameters([ndr.NdrShort, InternalAlignementStructure, ndr.NdrShort]),
        (0x0101, [0x4141, 0x42, 0x43434343, 0x44, 0x4545, 0x46], 0x4747),
        # Verified with an actual RPC server
        b"\x01\x01PPAABPCCCCDPEEFPGG"),

]

@pytest.mark.parametrize("ndrobj, values, result", NDR_PACK_TEST_CASE)
def test_ndr_packing(ndrobj, values, result):
     assert ndrobj.pack(values) == result

# Check the result of serializing a fixed 'EptMapAuthParameters' call known to works
# It allow to test for packing of real-complexe Parameter without relying on the whole ALPC/RPC stack
def test_ndr_packing_complex_epmapper_call():
    # Param from a real UAC endpoint resolution

    targetiid = gdef.GUID.from_string("201EF99A-7FA0-444C-9399-19BA84F12A1A")
    towerarray = bytearray(b'\x04\x00\x13\x00\r\x9a\xf9\x1e \xa0\x7fLD\x93\x99\x19\xba\x84\xf1*\x1a\x01\x00\x02\x00\x00\x00\x13\x00\r\x04]\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00+\x10H`\x02\x00\x02\x00\x00\x00\x01\x00\x0c\x02\x00\x00\x00\x01\x00\x10\x00\x00')
    local_system_psid = gdef.PSID.from_string("S-1-5-18")
    context = (0, 0, 0, 0, 0)
    nb_response = 1

    packed = windows.rpc.epmapper.EptMapAuthParameters.pack([bytearray(targetiid),
                                                    (len(towerarray), towerarray),
                                                    local_system_psid,
                                                    context,
                                                    nb_response])

    expected_result = b'\x9a\xf9\x1e \xa0\x7fLD\x93\x99\x19\xba\x84\xf1*\x1a@\x00\x00\x00@\x00\x00\x00\x04\x00\x13\x00\r\x9a\xf9\x1e \xa0\x7fLD\x93\x99\x19\xba\x84\xf1*\x1a\x01\x00\x02\x00\x00\x00\x13\x00\r\x04]\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00+\x10H`\x02\x00\x02\x00\x00\x00\x01\x00\x0c\x02\x00\x00\x00\x01\x00\x10\x00\x00\x02\x02\x02\x02\x01\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
    assert packed == packed


# Check the result of serializing a fixed 'UAC' call known to works
# It allow to test for packing of real-complexe Parameter without relying on the whole ALPC/RPC stack
def test_ndr_packing_complex_uac_call():
    parameters = UACParameters.pack([
        r"c:\windows\system32\notepad.exe", # Application Path
        "NOT_ALIGNED_STRINGXXX", # Commandline
        17, # UAC-Request Flag
        gdef.CREATE_UNICODE_ENVIRONMENT, # dwCreationFlags
        "", # StartDirectory
        "WinSta0\\Default\x00", # Station
            # Startup Info
            (None, # Title
            0, # dwX
            0, # dwY
            0, # dwXSize
            0, # dwYSize
            0, # dwXCountChars
            0, # dwYCountChars
            0, # dwFillAttribute
            0, # dwFlags
            5, # wShowWindow
            # Point structure: Use MonitorFromPoint to setup StartupInfo.hStdOutput
            (0, 0)),
        0, # Window-Handle to know if UAC can steal focus
        0xffffffff]) # UAC Timeout

    expected_result = b'\x02\x02\x02\x02 \x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00c\x00:\x00\\\x00w\x00i\x00n\x00d\x00o\x00w\x00s\x00\\\x00s\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00n\x00o\x00t\x00e\x00p\x00a\x00d\x00.\x00e\x00x\x00e\x00\x00\x00\x02\x02\x02\x02\x16\x00\x00\x00\x00\x00\x00\x00\x16\x00\x00\x00N\x00O\x00T\x00_\x00A\x00L\x00I\x00G\x00N\x00E\x00D\x00_\x00S\x00T\x00R\x00I\x00N\x00G\x00X\x00X\x00X\x00\x00\x00\x11\x00\x00\x00\x00\x04\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00PP\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00W\x00i\x00n\x00S\x00t\x00a\x000\x00\\\x00D\x00e\x00f\x00a\x00u\x00l\x00t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff'
    assert parameters == expected_result