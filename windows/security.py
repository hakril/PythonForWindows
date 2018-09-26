import ctypes
import sys

import windows
import windows.generated_def as gdef
from windows import winproxy

# Temporary ? real API ?
def lookup_sid(psid):
    usernamesize = gdef.DWORD(0x1000)
    computernamesize = gdef.DWORD(0x1000)
    username = ctypes.c_buffer(usernamesize.value)
    computername = ctypes.c_buffer(computernamesize.value)
    peUse = gdef.SID_NAME_USE()
    winproxy.LookupAccountSidA(None, psid, username, usernamesize, computername, computernamesize, peUse)
    return computername[:computernamesize.value], username[:usernamesize.value]


# ACE

ACE_FLAGS = gdef.FlagMapper(
    gdef.OBJECT_INHERIT_ACE        ,
    gdef.CONTAINER_INHERIT_ACE     ,
    gdef.NO_PROPAGATE_INHERIT_ACE  ,
    gdef.INHERIT_ONLY_ACE          ,
    gdef.INHERITED_ACE             ,
    gdef.VALID_INHERIT_FLAGS       ,
    gdef.SUCCESSFUL_ACCESS_ACE_FLAG,
    gdef.FAILED_ACCESS_ACE_FLAG
)

ACE_MASKS = gdef.FlagMapper(
    gdef.GENERIC_READ                     ,
    gdef.GENERIC_WRITE                    ,
    gdef.GENERIC_EXECUTE                  ,
    gdef.GENERIC_ALL                      ,
    gdef.READ_CONTROL                     ,
    gdef.DELETE                           ,
    gdef.WRITE_DAC                        ,
    gdef.WRITE_OWNER                      ,
)

class AceHeader(gdef.ACE_HEADER):
    """Improved ACE_HEADER"""
    def _to_ace_type(self, ace_type):
        return ctypes.cast(ctypes.byref(self), ctypes.POINTER(ace_type))[0]

    @property
    def AceType(self):
        raw_type = super(AceHeader, self).AceType
        return ACE_CLASS_TYPE_MAPPER[raw_type]

    @property
    def flags(self):
        return list(self._flags_generator())

    def _flags_generator(self):
        flags = self.AceFlags
        for i in range(8): # Sizeof(AceFlags) * 8
            v = flags & (1 << i)
            if v:
                yield ACE_FLAGS[v]

    def subclass(self):
        # ACE_CLASS_BY_ACE_TYPE is defined later in this file
        subcls =  ACE_CLASS_BY_ACE_TYPE[self.AceType]
        return self._to_ace_type(subcls)

    def __repr__(self):
        return "<{0} type={1}>".format(type(self).__name__, self.AceType)


class AceBase(object): # Ca ou mettre flags extraction dans le ctypes generated
    @property
    def Header(self): # Override the ctypes Header for the struct -> return extended header
        addr = ctypes.addressof(self)
        sheader = super(AceBase, type(self)).Header
        return AceHeader.from_address(addr + sheader.offset)


class MaskAndSidACE(AceBase):
    # "Virtual" ACE for ACE struct with
    # ACE_HEADER Header;
    # ACCESS_MASK Mask;
    # DWORD SidStart;

    def _sid_offset(self):
        return type(self).SidStart.offset

    @property
    def sid(self):
        return gdef.PSID(ctypes.addressof(self) + self._sid_offset())

    @property
    def mask(self):
        return list(self._mask_generator())

    def _mask_generator(self):
        mask = self.Mask
        for i in range(32): # sizeof ACCESS_MASK * 8
            v = mask & (1 << i)
            if v:
                yield ACE_MASKS[v]

    def __repr__(self):
        return "<{0} mask={1}>".format(type(self).__name__, self.Mask)


class CallbackACE(MaskAndSidACE):
    @property
    def application_data(self):
        """FROM : https://msdn.microsoft.com/en-us/library/hh877860.aspx"""
        selfptr = ctypes.cast(ctypes.addressof(self), gdef.PUCHAR)
        datastart = ctypes.sizeof(self) + self.sid.size - 4
        dataend = self.Header.AceSize
        return selfptr[datastart: dataend]


class ObjectRelatedACE(MaskAndSidACE):
    FLAGS_VALUES = (gdef.ACE_OBJECT_TYPE_PRESENT,
                        gdef.ACE_INHERITED_OBJECT_TYPE_PRESENT)

    @property
    def flags(self):
        flags = self.Flags
        return [x for x in self.FLAGS_VALUES if flags & x]

    @property
    def object_type(self):
        if not self.Flags & gdef.ACE_OBJECT_TYPE_PRESENT:
            return None
        return self.ObjectType

    @property
    def inherited_object_type(self):
        if not self.Flags & gdef.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            return None
        if self.Flags & gdef.ACE_OBJECT_TYPE_PRESENT:
            # There is an ObjectType so our offset is the good one
            return self.InheritedObjectType
        # No ObjectType -> InheritedObjectType is at ObjectType offset
        # Those are the same type so we can directly use ObjectType
        return self.ObjectType

    def _sid_offset(self):
        base_offset = type(self).SidStart.offset
        if not self.Flags & gdef.ACE_OBJECT_TYPE_PRESENT:
            base_offset -= ctypes.sizeof(gdef.GUID)
        if not self.Flags & gdef.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            base_offset -= ctypes.sizeof(gdef.GUID)
        return base_offset

# DACL related ACE

# Allow the resolution of Header first
class AccessAllowedACE(MaskAndSidACE, gdef.ACCESS_ALLOWED_ACE):
    ACE_TYPE = gdef.ACCESS_ALLOWED_ACE_TYPE

class AccessDeniedACE(MaskAndSidACE, gdef.ACCESS_DENIED_ACE):
    ACE_TYPE = gdef.ACCESS_DENIED_ACE_TYPE

class AccessAllowedCallbackACE(CallbackACE, gdef.ACCESS_ALLOWED_CALLBACK_ACE):
    ACE_TYPE = gdef.ACCESS_ALLOWED_CALLBACK_ACE_TYPE

class AccessDeniedCallbackACE(CallbackACE, gdef.ACCESS_DENIED_CALLBACK_ACE):
    ACE_TYPE = gdef.ACCESS_DENIED_CALLBACK_ACE_TYPE

class AccessAllowedObjectACE(ObjectRelatedACE, gdef.ACCESS_ALLOWED_OBJECT_ACE):
    ACE_TYPE = gdef.ACCESS_ALLOWED_OBJECT_ACE_TYPE

class AccessDeniedObjectACE(ObjectRelatedACE, gdef.ACCESS_DENIED_OBJECT_ACE):
    ACE_TYPE = gdef.ACCESS_DENIED_OBJECT_ACE_TYPE

class AccessAllowedCallbackObjectACE(CallbackACE, gdef.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE):
    ACE_TYPE = gdef.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE

# Strangly -> no SDDL for this one
class AccessDeniedCallbackObjectACE(CallbackACE, gdef.ACCESS_DENIED_CALLBACK_OBJECT_ACE):
    ACE_TYPE = gdef.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE


# SACL related ACE

class SystemAuditACE(MaskAndSidACE, gdef.SYSTEM_AUDIT_ACE):
    ACE_TYPE = gdef.SYSTEM_AUDIT_ACE_TYPE

class SystemAlarmACE(MaskAndSidACE, gdef.SYSTEM_ALARM_ACE):
    """reserved for future use."""
    ACE_TYPE = gdef.SYSTEM_ALARM_ACE_TYPE

class SystemAuditObjectACE(ObjectRelatedACE, gdef.SYSTEM_AUDIT_OBJECT_ACE):
    ACE_TYPE = gdef.SYSTEM_AUDIT_OBJECT_ACE_TYPE

class SystemAlarmObjectACE(ObjectRelatedACE, gdef.SYSTEM_ALARM_OBJECT_ACE):
    """reserved for future use."""
    ACE_TYPE = gdef.SYSTEM_ALARM_OBJECT_ACE_TYPE

class SystemAuditCallbackACE(CallbackACE, gdef.SYSTEM_AUDIT_CALLBACK_ACE):
    ACE_TYPE = gdef.SYSTEM_AUDIT_CALLBACK_ACE_TYPE

class SystemAlarmCallbackACE(CallbackACE, gdef.SYSTEM_ALARM_CALLBACK_ACE):
    """reserved for future use."""
    ACE_TYPE = gdef.SYSTEM_ALARM_CALLBACK_ACE_TYPE

class SystemAuditCallbackObjectACE(CallbackACE, gdef.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE):
    ACE_TYPE = gdef.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE

class SystemAlarmCallbackObjectACE(CallbackACE, gdef.SYSTEM_ALARM_CALLBACK_OBJECT_ACE):
    """Reserved for future use"""
    ACE_TYPE = gdef.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE

class SystemMandatoryLabelACE(MaskAndSidACE, gdef.SYSTEM_MANDATORY_LABEL_ACE):
    ACE_TYPE = gdef.SYSTEM_MANDATORY_LABEL_ACE_TYPE

class SystemResourceAttributeACE(MaskAndSidACE, gdef.SYSTEM_RESOURCE_ATTRIBUTE_ACE):
    ACE_TYPE = gdef.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE

    @property
    def attribute(self):
        # Sid-size not in the initial struct
        sid_size_over = self.sid.size - type(self).SidStart.size
        sec_attr_addr = ctypes.addressof(self) + ctypes.sizeof(self) + sid_size_over

        return ClaimSecurityAttributeRelativeV1.from_address(sec_attr_addr)

class SystemScopedPolicyIDACE(MaskAndSidACE, gdef.SYSTEM_SCOPED_POLICY_ID_ACE):
    ACE_TYPE = gdef.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE

class SystemProcessTrustLabelACE(MaskAndSidACE, gdef.SYSTEM_PROCESS_TRUST_LABEL_ACE):
    """Reserved. (from MSDC)"""
    ACE_TYPE = gdef.SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE


ACE_CLASS_BY_ACE_TYPE = {cls.ACE_TYPE: cls for cls in (
    # DACL
    AccessAllowedACE,
    AccessDeniedACE,
    AccessAllowedCallbackACE,
    AccessDeniedCallbackACE,
    AccessAllowedObjectACE,
    AccessDeniedObjectACE,
    AccessAllowedCallbackObjectACE,
    # SACL
    SystemAuditACE,
    SystemAlarmACE, # reserved for future use.
    SystemAuditObjectACE,
    SystemAlarmObjectACE, # reserved for future use.
    SystemAuditCallbackACE,
    SystemAlarmCallbackACE, # reserved for future use.
    SystemAuditCallbackObjectACE,
    SystemAlarmCallbackObjectACE, # reserved for future use.
    SystemMandatoryLabelACE,
    SystemResourceAttributeACE,
    SystemScopedPolicyIDACE,
    SystemProcessTrustLabelACE,

)}

ACE_CLASS_TYPE_MAPPER = gdef.FlagMapper(*ACE_CLASS_BY_ACE_TYPE.keys())


# CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 follow the SYSTEM_RESOURCE_ATTRIBUTE_ACE
# For ACE of type SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE

def retrieve_long64_from_addr(addr):
    return gdef.LONG64.from_address(addr).value

def retrieve_ulong64_from_addr(addr):
    return gdef.ULONG64.from_address(addr).value

def retrieve_wstr_from_addr(addr):
    return gdef.LPWSTR(addr).value

# https://msdn.microsoft.com/en-us/library/hh877847.aspx
def retrieve_psid_from_addr(addr):
    psid_addr = addr + gdef.CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE.OctetString.offset
    return gdef.PSID(psid_addr)

def retrieve_bool_from_addr(addr):
    return bool(gdef.ULONG64.from_address(addr).value)

def retrieve_octet_string_from_addr(addr):
    # Good doc: https://msdn.microsoft.com/en-us/library/hh877833.aspx
    # Doc broken in: https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_claim_security_attribute_relative_v1
    ostring = gdef.CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE.from_address(addr)
    # Bypass the array limit
    return ctypes.cast(ostring.OctetString, gdef.PUCHAR)[:ostring.Length]

class ClaimSecurityAttributeRelativeV1(gdef.CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1):
    VALUE_ARRAY_PTR_BY_TYPE = {
        gdef.CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
            ("pInt64", retrieve_long64_from_addr),
        gdef.CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
            ("pUint64", retrieve_ulong64_from_addr),
        gdef.CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
            ("ppString", retrieve_wstr_from_addr),
        gdef.CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
            # ppString is not the good one
            # But none is doc for PSID
            ("ppString", retrieve_psid_from_addr),
        gdef.CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
            ("pUint64", retrieve_bool_from_addr),
        gdef.CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
            ("pOctetString", retrieve_octet_string_from_addr),
    }

    @property
    def name(self):
        return gdef.LPWSTR(ctypes.addressof(self) + self.Name).value

    @property
    def values(self):
        array_name, get_value = self.VALUE_ARRAY_PTR_BY_TYPE[self.ValueType]
        base = ctypes.addressof(self)
        array = getattr(self.Values, array_name)
        # The pointer allow us to bypass the array _length_ of 1
        array_ptr = ctypes.cast(array, ctypes.POINTER(array._type_))
        offsets = array_ptr[:self.ValueCount]
        # Cast values
        return tuple(get_value(base + off) for off in offsets)


# ACL
class Acl(gdef.ACL):
    @property
    def size_info(self):
        size_info = gdef.ACL_SIZE_INFORMATION()
        winproxy.GetAclInformation(self, ctypes.byref(size_info), ctypes.sizeof(size_info), gdef.AclSizeInformation)
        return size_info

    def get_ace(self, i):
        ace = gdef.PVOID()
        winproxy.GetAce(self, i, ace)
        # TODO: subclass ACL
        return AceHeader.from_address(ace.value).subclass()

    @property
    def aces(self):
        return list(self)

    def __len__(self):
        return self.AceCount

    def __getitem__(self, i):
        try:
            return self.get_ace(i)
        except WindowsError as e:
            if e.winerror == gdef.ERROR_INVALID_PARAMETER:
                raise IndexError("Invalid ACL index {0}".format(i))
            raise

    def __iter__(self):
        for i in range(self.AceCount):
            yield self.get_ace(i)

    def __repr__(self):
        return "<Acl count={0}>".format(self.AceCount)


# Security descriptor

class SecurityDescriptor(gdef.PSECURITY_DESCRIPTOR):
    """TODO: free the underliying buffer when not needed anymore

    for now the underliying memory is never free
    """
    DEFAULT_SECURITY_INFORMATION = (
        gdef.OWNER_SECURITY_INFORMATION     |
        gdef.GROUP_SECURITY_INFORMATION     |
        gdef.DACL_SECURITY_INFORMATION      |
        gdef.ATTRIBUTE_SECURITY_INFORMATION |
        # gdef.SACL_SECURITY_INFORMATION  | # Need special rights
        gdef.SCOPE_SECURITY_INFORMATION     |
        gdef.PROCESS_TRUST_LABEL_SECURITY_INFORMATION
    )

    _close_function = winproxy.LocalFree

    # def __init__(self, needs_free=True):
        # self._needs_free = needs_free

    @property
    def control(self):
        lpdwRevision = gdef.DWORD()
        control = gdef.SECURITY_DESCRIPTOR_CONTROL()
        winproxy.GetSecurityDescriptorControl(self, control, lpdwRevision)
        return control.value

    @property
    def revision(self):
        lpdwRevision = gdef.DWORD()
        control = gdef.SECURITY_DESCRIPTOR_CONTROL()
        winproxy.GetSecurityDescriptorControl(self, control, lpdwRevision)
        return lpdwRevision.value

    @property
    def owner(self):
        owner = gdef.PSID()
        lpbOwnerDefaulted = gdef.BOOL()
        winproxy.GetSecurityDescriptorOwner(self, owner, lpbOwnerDefaulted)
        return owner

    @property
    def group(self):
        group = gdef.PSID()
        lpbGroupDefaulted = gdef.BOOL()
        winproxy.GetSecurityDescriptorGroup(self, group, lpbGroupDefaulted)
        return group


    @property
    def dacl(self):
        dacl_present = gdef.BOOL()
        pdacl = gdef.PACL()
        lpbDaclDefaulted = gdef.BOOL()
        winproxy.GetSecurityDescriptorDacl(self, dacl_present, pdacl, lpbDaclDefaulted)
        if not dacl_present or not pdacl:
            return None
        return ctypes.cast(pdacl, ctypes.POINTER(Acl))[0]

    @property
    def sacl(self):
        sacl_present = gdef.BOOL()
        psacl = gdef.PACL()
        lpbSaclDefaulted = gdef.BOOL()
        winproxy.GetSecurityDescriptorSacl(self, sacl_present, psacl, lpbSaclDefaulted)
        if not sacl_present or not psacl:
            return None
        return ctypes.cast(psacl, ctypes.POINTER(Acl))[0]

    # Constructors
    @classmethod
    def from_string(cls, sddl):
        self = cls()
        winproxy.ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl,
            gdef.SDDL_REVISION_1,
            self,
            None)
        # TODO: we need to free this buffer..
        # Keep track of Security Descritor state ?
        return self

    @classmethod
    def _from_name_and_type(cls, objname, objtype, query_sacl=False, security_infos=DEFAULT_SECURITY_INFORMATION):
        self = cls()

        if query_sacl:
            security_infos |= gdef.SACL_SECURITY_INFORMATION

        winproxy.GetNamedSecurityInfoA(
            objname,
            objtype,
            security_infos,
            None,
            None,
            None,
            None,
            self
        )
        return self

    @classmethod
    def from_filename(cls, filename, query_sacl=False):
        return cls._from_name_and_type(filename, gdef.SE_FILE_OBJECT, query_sacl=query_sacl)

    def to_string(self, security_information=DEFAULT_SECURITY_INFORMATION):
        result_cstr = gdef.LPSTR()
        winproxy.ConvertSecurityDescriptorToStringSecurityDescriptorA(
            self,
            gdef.SDDL_REVISION_1,
            security_information,
            result_cstr,
            None)
        result = result_cstr.value # Retrieve a python-str copy
        winproxy.LocalFree(result_cstr)
        return result

    # TST

    # def relative(self):
        # return bool(self.control & gdef.SE_SELF_RELATIVE)

    # If we want auto-free we need to handle relf-relative SD
    # We need to keep-track of sub-object of the SD
    # Just a ref to SD from SACL / DACL ?

    # def __del__(self):
        # if self._needs_free and sys.path is not None:
            # print("FREE SELF")
            # self._close_function(self)

