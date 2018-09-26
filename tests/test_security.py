import windows.security
from windows.security import SecurityDescriptor
from pfwtest import *
import ctypes

# CC -> Create-Child -> 1
# GR -> Generic read -> 0x80000000L
# AN -> Anonymous -> S-1-5-7

TEST_SDDL = [
"O:ANG:AND:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)(D;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)",
"O:ANG:AND:(A;;GR;;;S-1-0-0)",
"O:ANG:AND:(OA;;CC;;00000042-0043-0044-0045-000000000000;S-1-0-0)",
"O:ANG:AND:(OA;;CCGR;00004242-0043-0044-0045-000000000000;00000042-0043-0044-0045-000000000000;S-1-0-0)",
]


@pytest.mark.parametrize("sddl", TEST_SDDL)
def test_security_descriptor_from_string(sddl):
    sd = SecurityDescriptor.from_string(sddl)


def test_pacl_object():
    SDDL = "O:ANG:S-1-2-3D:(A;;;;;S-1-42-42)(A;;;;;S-1-42-43)(A;;;;;S-1-42-44)"
    dacl = SecurityDescriptor.from_string(SDDL).dacl
    assert dacl is not None
    assert len(dacl) == 3 # __len__
    assert len(list(dacl)) == 3 # __iter__
    assert len(dacl.aces) == 3

    assert ctypes.addressof(dacl[0]) == ctypes.addressof(dacl[0]) # __getitem__
    assert len([ctypes.addressof(dacl[i])for i in range(3)]) == 3

    with pytest.raises(IndexError):
        x = dacl[3]

def test_sec_descrip_owner_group():
    SDDL = "O:ANG:S-1-2-3"
    sd = SecurityDescriptor.from_string(SDDL)
    assert sd.owner.to_string() == "S-1-5-7"
    assert sd.group.to_string() == "S-1-2-3"
    assert sd.dacl is None
    assert sd.sacl is None

def test_mask_sid_ace():
    SDDL = "D:(A;CIOI;CCGR;;;S-1-42-42)"
    # OBJECT_INHERIT_ACE(0x1L) | CONTAINER_INHERIT_ACE(0x2L)
    # Create-Child | GENERIC_READ(0x80000000L)
    sd = SecurityDescriptor.from_string(SDDL)
    dacl = sd.dacl
    assert dacl is not None
    ace = dacl[0]
    # Test the ACE
    assert ace.Header.AceType == gdef.ACCESS_ALLOWED_ACE_TYPE
    # flags + flags split
    assert ace.Header.AceFlags == gdef.OBJECT_INHERIT_ACE | gdef.CONTAINER_INHERIT_ACE
    assert set(ace.Header.flags) == {gdef.OBJECT_INHERIT_ACE, gdef.CONTAINER_INHERIT_ACE}
    # mask + mask split
    assert ace.Mask == 1 | gdef.GENERIC_READ
    assert set(ace.mask) == {1, gdef.GENERIC_READ}
    # SID
    assert ace.sid.to_string() == "S-1-42-42"


SGUID = gdef.GUID.from_string

COMPLEXE_SDDL_GUID = [
("D:(OA;;;00000042-0043-0044-0045-000000000001;;S-1-0-0)",
    SGUID("00000042-0043-0044-0045-000000000001"),
    None),
("D:(OA;;;;00000042-0043-0044-0045-000000000000;S-1-0-0)",
    None,
    SGUID("00000042-0043-0044-0045-000000000000")),
("D:(OA;;;00000042-0043-0044-0045-000000000002;00000042-0043-0044-0045-000000000003;S-1-0-0)",
    SGUID("00000042-0043-0044-0045-000000000002"),
    SGUID("00000042-0043-0044-0045-000000000003")),
("D:(OA;;;;;S-1-0-0)",
    None,
    None),
]

@pytest.mark.parametrize("sddl, obj_guid, inherited_object_guid", COMPLEXE_SDDL_GUID)
def test_complex_ace_guid_sid(sddl, obj_guid, inherited_object_guid):
    print(sddl)
    sd = SecurityDescriptor.from_string(sddl)
    assert sd.dacl is not None
    ace = sd.dacl[0]
    assert ace.sid.to_string() == "S-1-0-0"

    if obj_guid is None and inherited_object_guid is None:
        # No GUID -> transformed in ACCESS_ALLOWED_ACE_TYPE
        assert ace.Header.AceType == gdef.ACCESS_ALLOWED_ACE_TYPE
        return
    assert ace.object_type == obj_guid
    assert ace.inherited_object_type == inherited_object_guid

ALL_DACL_ACE_TYPES = [
("D:(A;;;;;S-1-2-3)", gdef.ACCESS_ALLOWED_ACE_TYPE),
("D:(D;;;;;S-1-2-3)", gdef.ACCESS_DENIED_ACE_TYPE),
("D:(OA;;;;00000042-0043-0044-0045-000000000000;S-1-0-0)",
    gdef.ACCESS_ALLOWED_OBJECT_ACE_TYPE),
("D:(OD;;;;00000042-0043-0044-0045-000000000001;S-1-0-0)",
    gdef.ACCESS_DENIED_OBJECT_ACE_TYPE),
("D:AI(XA;;GR;;;WD;(YOLO))", gdef.ACCESS_ALLOWED_CALLBACK_ACE_TYPE),
("D:AI(XD;;GR;;;WD;(YOLO))", gdef.ACCESS_DENIED_CALLBACK_ACE_TYPE),

("D:AI(ZA;;GR;;00000042-0043-0044-0045-000000000001;WD;(YOLO))", gdef.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE),
# NO SDDL DEFINE FOR :  gdef.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE)
]

@pytest.mark.parametrize("sddl, ace_type", ALL_DACL_ACE_TYPES)
def test_ace_dacl_subclass(sddl, ace_type):
    sd = SecurityDescriptor.from_string(sddl)
    dacl = sd.dacl
    assert len(dacl) == 1
    ace = dacl[0] # Will raise if AceHeader is not handled
    assert ace.Header.AceType == ace_type

# SACL STUFF

ALL_SACL_ACE_TYPES = [
("S:(AU;;;;;AN)", gdef.SYSTEM_AUDIT_ACE_TYPE),
("S:(ML;;;;;S-1-16-4000)", gdef.SYSTEM_MANDATORY_LABEL_ACE_TYPE),
# S-1-19-512-4096 what retrieved in a ACE from a directory in C:\Program Files\WindowsApps\
("S:(TL;;;;;S-1-19-512-4096)", gdef.SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE),
("S:(SP;;;;;S-1-17-1)", gdef.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE),
("S:(OU;;;;00000042-0043-0044-0045-000000000000;AN)", gdef.SYSTEM_AUDIT_OBJECT_ACE_TYPE),
("S:(XU;;;;;S-1-2-3;(YOLO))", gdef.SYSTEM_AUDIT_CALLBACK_ACE_TYPE),
## Reserved for futur use (RFS): not handled by ADVAPI.dll
# ("S:(AL;;;;;S-1-2-3)", gdef.SYSTEM_ALARM_OBJECT_ACE_TYPE),
#("S:(OL;;;;00000042-0043-0044-0045-000000000000;AN)", gdef.SYSTEM_ALARM_OBJECT_ACE_TYPE),
## NO SDDL FOR:
# SYSTEM_ALARM_CALLBACK_ACE_TYPE
# SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
# SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
]

@pytest.mark.parametrize("sddl, ace_type", ALL_SACL_ACE_TYPES)
def test_ace_sacl_subclass(sddl, ace_type):
    sd = SecurityDescriptor.from_string(sddl)
    sacl = sd.sacl
    assert len(sacl) == 1
    ace = sacl[0] # Will raise if AceHeader is not handled
    assert ace.Header.AceType == ace_type

RESOURCE_ATTRIBUTES_SDDLS = [
("""S:(RA;;;;;WD; ("TestName",TI,0,-2, -1, 0, 1, 2))""",
    (-2, -1, 0, 1, 2 )),

("""S:(RA;;;;;WD; ("TestName",TU,0,3,4,42))""",
    (3, 4, 42)),

("""S:(RA;;;;;WD; ("TestName",TS,0,"Windows","SQL", ""))""",
    ("Windows", "SQL", "")),

("""S:(RA;;;;;WD; ("TestName",TD,0, AN, S-1-2-3-4-5-6-7-8-9))""",
    (gdef.PSID.from_string("S-1-5-7"),
     gdef.PSID.from_string("S-1-2-3-4-5-6-7-8-9"))),

("""S:(RA;;;;;WD; ("TestName",TX,0, 42000042, 0123456789abcdef))""",
    ("B\x00\x00B", "\x01\x23\x45\x67\x89\xab\xcd\xef")),

("""S:(RA;;;;;WD; ("TestName",TB,0, 0, 1, 0, 0, 1))""",
    (False, True, False, False, True)),
]

@pytest.mark.parametrize("sddl, expected_values", RESOURCE_ATTRIBUTES_SDDLS)
def test_ace_resource_attribute(sddl, expected_values):
    sd = SecurityDescriptor.from_string(sddl)
    ra = sd.sacl[0]
    assert ra.Header.AceType == gdef.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE

    attr = ra.attribute
    assert attr.name == "TestName"
    assert attr.values == expected_values

CONDITIONAL_SDDLS = [
    ("D:AI(XA;;GR;;;WD;(ATTR1))", "ATTR1"),
    ("D:AI(XD;;GR;;;WD;(ATTR2))", "ATTR2"),
    ("S:AI(XU;;GR;;;WD;(ATTR3))", "ATTR3")
]

@pytest.mark.parametrize("sddl, expected_value", CONDITIONAL_SDDLS)
def test_conditional_ace_applicationdata(sddl, expected_value):
    sd = SecurityDescriptor.from_string(sddl)
    acl = sd.dacl
    if acl is None:
        acl = sd.sacl
    ace = acl[0]
    appdata = ace.application_data
    # https://msdn.microsoft.com/en-us/library/hh877860.aspx
    assert appdata.startswith("artx")
    assert expected_value in appdata.replace("\x00", "")


