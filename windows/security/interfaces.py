import ctypes
import windows
import base64
from windows.generated_def import *
from windows.winproxy import *
from windows.security.winproxy import *
from windows.winobject.sid import *
from windows.generated_def.interfaces import generate_IID, IID
from windows.utils import enable_privilege


class ESECURITY_DESCRIPTOR_CONTROL(SECURITY_DESCRIPTOR_CONTROL):
    KNOWN_CONROL_FLAGS = (  SE_DACL_AUTO_INHERIT_REQ,
                            SE_DACL_AUTO_INHERITED,
                            SE_DACL_DEFAULTED,
                            SE_DACL_PRESENT,
                            SE_DACL_PROTECTED,
                            SE_GROUP_DEFAULTED,
                            SE_OWNER_DEFAULTED,
                            SE_RM_CONTROL_VALID,
                            SE_SACL_AUTO_INHERIT_REQ,
                            SE_SACL_AUTO_INHERITED,
                            SE_SACL_DEFAULTED,
                            SE_SACL_PRESENT,
                            SE_SACL_PROTECTED,
                            SE_SELF_RELATIVE
    )

    KNOWN_CONROL_FLAGS_MAPPING = {x:x for x in KNOWN_CONROL_FLAGS}

    def __init__(self):
        return super(SECURITY_DESCRIPTOR_CONTROL, self).__init__()
    
    def __repr__(self):
        return '<SECURITY_DESCRIPTOR_CONTROL "{0}">'.format(repr( self.flags ))
    
    @property
    def flags(self):
        attrs = []
        for mask in (1 << i for i in range(64)):
            if self.value & mask:
                attrs.append(mask)
        return [self.KNOWN_CONROL_FLAGS_MAPPING.get(x, x) for x in attrs]

class EACE(object):
    FLAGS = ( 
        ACE_OBJECT_TYPE_PRESENT,
        ACE_INHERITED_OBJECT_TYPE_PRESENT
    )

    FLAGS_MAPPING = {x:x for x in FLAGS}
    
    ACE_TYPES_MAPPING = {
        ACCESS_ALLOWED_ACE_TYPE           : SDDL_ACCESS_ALLOWED           ,
        ACCESS_DENIED_ACE_TYPE            : SDDL_ACCESS_DENIED            ,
        SYSTEM_AUDIT_ACE_TYPE             : SDDL_AUDIT             ,
        SYSTEM_ALARM_ACE_TYPE             : SDDL_ALARM             ,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE    : SDDL_OBJECT_ACCESS_ALLOWED    ,
        ACCESS_DENIED_OBJECT_ACE_TYPE     : SDDL_OBJECT_ACCESS_DENIED     ,
        SYSTEM_AUDIT_OBJECT_ACE_TYPE      : SDDL_OBJECT_AUDIT      ,
        SYSTEM_ALARM_OBJECT_ACE_TYPE      : SDDL_OBJECT_ALARM      ,
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE  : SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED  ,
        ACCESS_DENIED_CALLBACK_ACE_TYPE   : SDDL_CALLBACK_ACCESS_DENIED   ,
        SYSTEM_AUDIT_CALLBACK_ACE_TYPE    : SDDL_CALLBACK_AUDIT    ,
        SYSTEM_MANDATORY_LABEL_ACE_TYPE   : SDDL_MANDATORY_LABEL   ,
        SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: SDDL_RESOURCE_ATTRIBUTE,
        SYSTEM_SCOPED_POLICY_ID_ACE_TYPE  : SDDL_SCOPED_POLICY_ID  
    }
    
    ACE_HEADER_FLAGS_MAPPING = {
        OBJECT_INHERIT_ACE         : SDDL_OBJECT_INHERIT          ,
        CONTAINER_INHERIT_ACE      : SDDL_CONTAINER_INHERIT       ,
        NO_PROPAGATE_INHERIT_ACE   : SDDL_NO_PROPAGATE    ,
        INHERIT_ONLY_ACE           : SDDL_INHERIT_ONLY            ,
        INHERITED_ACE              : SDDL_INHERITED               ,
        SUCCESSFUL_ACCESS_ACE_FLAG : SDDL_AUDIT_SUCCESS           ,
        FAILED_ACCESS_ACE_FLAG     : SDDL_AUDIT_FAILURE      
    }
    
    ACE_MASKS = (
        GENERIC_READ                     ,
        GENERIC_WRITE                    ,
        GENERIC_EXECUTE                  ,
        GENERIC_ALL                      ,
        READ_CONTROL                     ,
        DELETE                           ,
        WRITE_DAC                        ,
        WRITE_OWNER                      ,
        ADS_RIGHT_DS_READ_PROP           ,
        ADS_RIGHT_DS_WRITE_PROP          ,
        ADS_RIGHT_DS_CREATE_CHILD        ,
        ADS_RIGHT_DS_DELETE_CHILD        ,
        ADS_RIGHT_ACTRL_DS_LIST          ,
        ADS_RIGHT_DS_SELF                ,
        ADS_RIGHT_DS_LIST_OBJECT         ,
        ADS_RIGHT_DS_DELETE_TREE         ,
        ADS_RIGHT_DS_CONTROL_ACCESS      ,
        ADS_RIGHT_DELETE                 ,
        ADS_RIGHT_READ_CONTROL           ,
        ADS_RIGHT_WRITE_DAC              ,
        ADS_RIGHT_WRITE_OWNER            ,
        ADS_RIGHT_SYNCHRONIZE            ,
        ADS_RIGHT_ACCESS_SYSTEM_SECURITY ,
        ADS_RIGHT_GENERIC_READ           ,
        ADS_RIGHT_GENERIC_WRITE          ,
        ADS_RIGHT_GENERIC_EXECUTE        ,
        ADS_RIGHT_GENERIC_ALL            
    )
    ACE_MASKS_MAPPING = {x:x for x in ACE_MASKS}
    
    ACE_MASKS_SDDL_MAPPING = {
        GENERIC_READ                         : SDDL_GENERIC_READ   ,
        GENERIC_WRITE                        : SDDL_GENERIC_WRITE  ,
        GENERIC_EXECUTE                      : SDDL_GENERIC_EXECUTE,
        GENERIC_ALL                          : SDDL_GENERIC_ALL    ,
        READ_CONTROL                         : SDDL_READ_CONTROL   ,
        DELETE                               : SDDL_STANDARD_DELETE,
        WRITE_DAC                            : SDDL_WRITE_DAC      ,
        WRITE_OWNER                          : SDDL_WRITE_OWNER    ,
        ADS_RIGHT_DS_READ_PROP               : SDDL_READ_PROPERTY  ,
        ADS_RIGHT_DS_WRITE_PROP              : SDDL_WRITE_PROPERTY ,
        ADS_RIGHT_DS_CREATE_CHILD            : SDDL_CREATE_CHILD   ,
        ADS_RIGHT_DS_DELETE_CHILD            : SDDL_DELETE_CHILD   ,
        ADS_RIGHT_ACTRL_DS_LIST              : SDDL_LIST_CHILDREN  ,
        ADS_RIGHT_DS_SELF                    : SDDL_SELF_WRITE     ,
        ADS_RIGHT_DS_LIST_OBJECT             : SDDL_LIST_OBJECT    ,
        ADS_RIGHT_DS_DELETE_TREE             : SDDL_DELETE_TREE    ,
        ADS_RIGHT_DS_CONTROL_ACCESS          : SDDL_CONTROL_ACCESS ,
        FILE_ALL_ACCESS                      : SDDL_FILE_ALL       ,
        FILE_GENERIC_READ                    : SDDL_FILE_READ      ,
        FILE_GENERIC_WRITE                   : SDDL_FILE_WRITE     ,
        FILE_GENERIC_EXECUTE                 : SDDL_FILE_EXECUTE   ,
        KEY_READ                             : SDDL_KEY_READ       ,
        KEY_WRITE                            : SDDL_KEY_WRITE      ,
        KEY_EXECUTE                          : SDDL_KEY_EXECUTE    ,
        KEY_ALL_ACCESS                       : SDDL_KEY_ALL        ,
        # SYSTEM_MANDATORY_LABEL_NO_WRITE_UP   : SDDL_NO_READ_UP     ,
        # SYSTEM_MANDATORY_LABEL_NO_READ_UP    : SDDL_NO_WRITE_UP    ,
        # SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP : SDDL_NO_EXECUTE_UP
    }
    
    ACE_KNOWN_SIDS_MAPPING = {
        SID_WORLD                           : SDDL_EVERYONE,
        SID_CREATOR_OWNER_ID                : SDDL_CREATOR_OWNER,
        SID_CREATOR_GROUP_ID                : SDDL_CREATOR_GROUP,
        SECURITY_NETWORK_RID                : SDDL_NETWORK,
        SECURITY_INTERACTIVE_RID            : SDDL_INTERACTIVE,
        SECURITY_SERVICE_RID                : SDDL_SERVICE,
        SECURITY_ANONYMOUS_LOGON_RID        : SDDL_ANONYMOUS,
        SECURITY_PRINCIPAL_SELF_RID         : SDDL_PERSONAL_SELF,
        SECURITY_AUTHENTICATED_USER_RID     : SDDL_AUTHENTICATED_USERS,
        SECURITY_RESTRICTED_CODE_RID        : SDDL_RESTRICTED_CODE,
        SECURITY_LOCAL_SYSTEM_RID           : SDDL_LOCAL_SYSTEM
    }
        
    def __repr__(self):
        result = '<ACE {0}\n\tMask: {1}\n\tSid: {2}\n'.format(self.header, self.mask, self.sid)
        
        if getattr(self, "Flags", None) is not None:
            result += "\tFlags: {0}\n".format(self.flags)
        
        if getattr(self, "ObjectType", None) is not None and self.has_object_type:
            result += "\tObjectType: {0}\n".format(self.object_type)
            
        if getattr(self, "InheritedObjectType", None) is not None and self.has_inherited_object_type:
            result += "\tInheritedObjectType: {0}\n".format(self.inherited_object_type)
        
        return result + ">"
    
    def __str__(self):
        fields = [
            self.ACE_TYPES_MAPPING[self.header.type],
            ''.join(sorted(self.ACE_HEADER_FLAGS_MAPPING[_] for _ in self.header.flags)),
            ''.join(self.ACE_MASKS_SDDL_MAPPING[_] for _ in self.mask)
        ]
        
        if getattr(self, "ObjectType", None) is not None and self.has_object_type:
            fields.append(self.object_type.to_string())
        else:
            fields.append("")
        if getattr(self, "InheritedObjectType", None) is not None and self.has_inherited_object_type:
            fields.append(self.inherited_object_type.to_string())
        else:
            fields.append("")
        
        fields.append(self.ACE_KNOWN_SIDS_MAPPING.get(str(self.sid), str(self.sid)))
        return "({0})".format(",".join(fields))
        
        
    
    @property
    def header(self):
        return cast(addressof(self) + type(self).Header.offset, POINTER(EACE_HEADER)).contents
    
    @property
    def mask(self):
        return self._extract_mask()
    
    @property
    def sid(self):
        if getattr(self, "ObjectType", None) is not None:
            baseaddress = addressof(self) + type(self).SidStart.offset
            if not self.has_object_type or not self.has_inherited_object_type:
                baseaddress = addressof(self) + type(self).InheritedObjectType.offset
            if not self.has_object_type and not self.has_inherited_object_type:
                baseaddress = addressof(self) + type(self).ObjectType.offset
            return cast(baseaddress, EPSID)
        return cast(addressof(self) + type(self).SidStart.offset, EPSID)
    
    @property
    def object_type(self):
        if getattr(self, "ObjectType", None) is not None:
            if not self.has_object_type:
                raise ValueError("The current ACE does not have an ObjectType")
            return cast(addressof(self) + type(self).ObjectType.offset, POINTER(IID)).contents
        return ""
    
    @property
    def inherited_object_type(self):
        if getattr(self, "InheritedObjectType", None) is not None:
            if not self.has_inherited_object_type:
                raise ValueError("The current ACE does not have an InheritedObjectType")
            baseaddress = addressof(self) + type(self).InheritedObjectType.offset
            if not self.has_object_type:
                baseaddress -= type(self).InheritedObjectType.offset
            return cast(baseaddress, POINTER(IID)).contents
        return ""
    
    @property
    def type(self):
        return self.header.type
    
    @property
    def flags(self):
        return self.header.flags
    
    @property
    def has_object_type(self):
        return ACE_OBJECT_TYPE_PRESENT in self.flags
    
    @property
    def has_inherited_object_type(self):
        return ACE_INHERITED_OBJECT_TYPE_PRESENT in self.flags
    
    def _extract_flags(self):
        attrs = []
        for mask in (1 << i for i in range(64)):
            if self.Flags & mask:
                attrs.append(mask)
        return [self.FLAGS_MAPPING.get(x, x) for x in attrs]
    
    def _extract_mask(self):
        attrs = []
        for mask in (1 << i for i in range(64)):
            if self.Mask & mask:
                attrs.append(mask)
        return [self.ACE_MASKS_MAPPING.get(x, x) for x in attrs]

class EACCESS_ALLOWED_ACE(ACCESS_ALLOWED_ACE, EACE):
    pass

class EACCESS_DENIED_ACE(ACCESS_DENIED_ACE, EACE):
    pass

class ESYSTEM_AUDIT_ACE(SYSTEM_AUDIT_ACE, EACE):
    pass

class ESYSTEM_ALARM_ACE(SYSTEM_ALARM_ACE, EACE):
    pass

class ESYSTEM_RESOURCE_ATTRIBUTE_ACE(SYSTEM_RESOURCE_ATTRIBUTE_ACE, EACE):
    pass

class ESYSTEM_SCOPED_POLICY_ID_ACE(SYSTEM_SCOPED_POLICY_ID_ACE, EACE):
    pass

class ESYSTEM_MANDATORY_LABEL_ACE(SYSTEM_MANDATORY_LABEL_ACE, EACE):
    pass

class ESYSTEM_PROCESS_TRUST_LABEL_ACE(SYSTEM_PROCESS_TRUST_LABEL_ACE, EACE):
    pass

class EACCESS_ALLOWED_OBJECT_ACE(ACCESS_ALLOWED_OBJECT_ACE, EACE):
    pass

class EACCESS_DENIED_OBJECT_ACE(ACCESS_DENIED_OBJECT_ACE, EACE):
    pass

class ESYSTEM_AUDIT_OBJECT_ACE(SYSTEM_AUDIT_OBJECT_ACE, EACE):
    pass

class ESYSTEM_ALARM_OBJECT_ACE(SYSTEM_ALARM_OBJECT_ACE, EACE):
    pass

class EACE_HEADER(ACE_HEADER):
    ACE_TYPES = (
            ACCESS_MIN_MS_ACE_TYPE                  ,
            ACCESS_ALLOWED_ACE_TYPE                 ,
            ACCESS_DENIED_ACE_TYPE                  ,
            SYSTEM_AUDIT_ACE_TYPE                   ,
            SYSTEM_ALARM_ACE_TYPE                   ,
            ACCESS_MAX_MS_V2_ACE_TYPE               ,
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE        ,
            ACCESS_MAX_MS_V3_ACE_TYPE               ,
            ACCESS_MIN_MS_OBJECT_ACE_TYPE           ,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE          ,
            ACCESS_DENIED_OBJECT_ACE_TYPE           ,
            SYSTEM_AUDIT_OBJECT_ACE_TYPE            ,
            SYSTEM_ALARM_OBJECT_ACE_TYPE            ,
            ACCESS_MAX_MS_OBJECT_ACE_TYPE           ,
            ACCESS_MAX_MS_V4_ACE_TYPE               ,
            ACCESS_MAX_MS_ACE_TYPE                  ,
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE        ,
            ACCESS_DENIED_CALLBACK_ACE_TYPE         ,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE ,
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  ,
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE          ,
            SYSTEM_ALARM_CALLBACK_ACE_TYPE          ,
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   ,
            SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   ,
            SYSTEM_MANDATORY_LABEL_ACE_TYPE         ,
            ACCESS_MAX_MS_V5_ACE_TYPE                   
    )
    
    ACE_TYPES_MAPPING = {x:x for x in ACE_TYPES}
    
    ACE_FLAGS = (
            OBJECT_INHERIT_ACE        ,
            CONTAINER_INHERIT_ACE     ,
            NO_PROPAGATE_INHERIT_ACE  ,
            INHERIT_ONLY_ACE          ,
            INHERITED_ACE             ,
            VALID_INHERIT_FLAGS       ,
            SUCCESSFUL_ACCESS_ACE_FLAG,
            FAILED_ACCESS_ACE_FLAG    
    )
    
    ACE_FLAGS_MAPPING = {x:x for x in ACE_FLAGS}
    
    ACE_STRUCTS_MAPPING = {
        ACCESS_ALLOWED_ACE_TYPE: EACCESS_ALLOWED_ACE,
        ACCESS_DENIED_ACE_TYPE: EACCESS_DENIED_ACE,
        SYSTEM_AUDIT_ACE_TYPE: ESYSTEM_AUDIT_ACE,
        SYSTEM_ALARM_ACE_TYPE: ESYSTEM_ALARM_ACE,
        SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: ESYSTEM_RESOURCE_ATTRIBUTE_ACE,
        SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: ESYSTEM_SCOPED_POLICY_ID_ACE,
        SYSTEM_MANDATORY_LABEL_ACE_TYPE: ESYSTEM_MANDATORY_LABEL_ACE,
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: ESYSTEM_PROCESS_TRUST_LABEL_ACE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE: EACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_DENIED_OBJECT_ACE_TYPE: EACCESS_DENIED_OBJECT_ACE,
        SYSTEM_ALARM_OBJECT_ACE_TYPE: ESYSTEM_AUDIT_OBJECT_ACE,
        SYSTEM_ALARM_OBJECT_ACE_TYPE: ESYSTEM_ALARM_OBJECT_ACE
    }

    def __init__(self):
        return super(ACE, self).__init__()

    def __repr__(self):
        return 'AceType: {0} - AceFlags: {1}'.format( 
                                        self.type,
                                        self.flags
                                    )

    def __len__(self):
        return self.AceSize
        
    @property
    def type(self):
        return self.ACE_TYPES_MAPPING[self.AceType]
    
    @property
    def flags(self):
        return self._extract_ace_flags()
    
    @property
    def ace(self):
        return cast(byref(self), POINTER(self.ACE_STRUCTS_MAPPING[self.type]))
    
    def _extract_ace_flags(self):
        attrs = []
        for mask in (1 << i for i in range(64)):
            if self.AceFlags & mask:
                attrs.append(mask)
        return [self.ACE_FLAGS_MAPPING.get(x, x) for x in attrs]

        
        
class EACL(ACL):
    def __init__(self):
        self.current = 0
        return super(ACL, self).__init__()
        
    def __repr__(self):
        return '<ACL "AclRevision: {0}, Sbz1: {1}, AclSize: {2}, Sbz2: {3}">'.format(self.AclRevision, self.Sbz1, self.AclSize, self.AceCount, self.Sbz2)
    
    def __len__(self):
        return self.AceCount
    
    def __iter__(self):
        for i in xrange(self.AceCount):
            yield self[i]
        
    def __getitem__(self, index):
        if isinstance(index, int):
            if index >= len(self):
                raise IndexError("list index out of range")
            if index < 0:
                index = index % len(self)
            return self._get_ace(index)                
        elif isinstance(index, slice):
            start, stop, step = index.indices(len(self))
            result = []
            for i in range(start, stop, step):
                result.append(self[i])
            return result
        else:
            raise TypeError("index must be int or slice")
        
    def _get_ace(self, index):
        pAce = PACE()
        retVal = GetAce(
            self,
            index,
            byref(pAce)
        )
        p_ace_header = ctypes.cast(pAce, ctypes.POINTER(EACE_HEADER))
        p_ace = p_ace_header.contents.ace
        return p_ace.contents
    
    
######### EXTENDED SECURITY DESCRIPTOR CLASS #############
class EPSECURITY_DESCRIPTOR(PSECURITY_DESCRIPTOR):
    def __init__(self,
                 string_security_descriptor = None, 
                 handle = None, 
                 name = None,
                 object_type = SE_UNKNOWN_OBJECT_TYPE, 
                 desired_access = OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION):
        self.initialized_from_string = False
        self.initialized_from_handle = False
        self.initialized_from_name = False
        self.desired_access = desired_access
        self.object_type = object_type

        if string_security_descriptor is not None:
            super(EPSECURITY_DESCRIPTOR, self).__init__()
            self.init_from_string(string_security_descriptor)
        elif handle is not None:
            super(EPSECURITY_DESCRIPTOR, self).__init__()
            self.init_from_handle(handle)
        elif name is not None:
            super(EPSECURITY_DESCRIPTOR, self).__init__()
            self.init_from_name(name)
        else:
            return super(EPSECURITY_DESCRIPTOR, self).__init__()

    def _init_called(self):
        notpresent = object()
        # Handle SECURITY_DESCRIPTOR created without '__init__' (like ctypes-ptr deref)
        return getattr(self, "raw_security_descriptor", notpresent) is not notpresent
    
    def __repr__(self):
        return '<SECURITY_DESCRIPTOR "{0}">'.format(self.to_string())
    
    def __str__(self):
        return self.to_string()
    
    def to_string(self):
        result = ctypes.c_char_p()
        result_len = ctypes.c_uint()
        retVal = ConvertSecurityDescriptorToStringSecurityDescriptorA(
            self,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION,
            result,
            result_len
        )
        string_security_descriptor = (result.value + ".")[:-1]
        LocalFree(result)
        return string_security_descriptor
    
    def to_raw(self):
        return bytearray((c_char*len(self)).from_address(self.value))
    
    def init_from_string(self, string_security_descriptor):
        security_descriptor = PSECURITY_DESCRIPTOR()
        security_descriptor_size = ctypes.c_uint()
        ConvertStringSecurityDescriptorToSecurityDescriptorA(
            string_security_descriptor,
            SDDL_REVISION_1,
            self,
            security_descriptor_size
        )
        self.security_descriptor_size = security_descriptor_size
        self.initialized_from_string = True
        return security_descriptor_size
    
    def init_from_handle(self, handle):
        winproxy.GetSecurityInfo(
            handle,
            self.object_type,
            self.desired_access,
            None,
            None,
            None,
            None,
            self
        )
        self.initialized_from_handle = True        
    
    def init_from_name(self, name):
        winproxy.GetNamedSecurityInfoA(
            name,
            self.object_type,
            self.desired_access,
            None,
            None,
            None,
            None,
            self        
        )
        self.init_from_name = True
    
    
    
    def init_from_bin(self, b64_security_descriptor):
        security_descriptor = base64.b64decode(b64_security_descriptor)
        self.security_descriptor_size = len(security_descriptor)
    
    def bin_dump(self):
        result = windows.current_process.read_memory(self.value, len(self))
        return base64.b64encode(result)
    
    def __len__(self):
        return GetSecurityDescriptorLength(self)

    @property
    def bytearray(self):
        return bytearray(ctypes.cast(self.value, ctypes.POINTER(BYTE*len(self))).contents[:len(self)])
    
    @property
    def valid(self):
        return bool(IsValidSecurityDescriptor(self))
    
    @property
    def control(self):
        control = ESECURITY_DESCRIPTOR_CONTROL()
        lpdwRevision = DWORD()
        GetSecurityDescriptorControl(
            self,
            byref(control),
            byref(lpdwRevision)
        )
        return control    
    
    @property
    def owner(self):
        p_owner = EPSID()
        p_owner_defaulted = ctypes.c_int()
        GetSecurityDescriptorOwner(
            self,
            ctypes.byref(p_owner),
            p_owner_defaulted
        )
        return p_owner
    
    @property
    def primary_group(self):
        p_group = EPSID()
        p_group_defaulted = ctypes.c_int()
        GetSecurityDescriptorGroup(
            self,
            ctypes.byref(p_group),
            p_group_defaulted
        )
        return p_group
    
    @property
    def dacl(self):
        p_dacl_present = ctypes.c_int()
        p_dacl_defaulted = ctypes.c_int()
        p_acl = ctypes.POINTER(EACL)()
        GetSecurityDescriptorDacl(
            self,
            byref(p_dacl_present),
            byref(p_acl),
            byref(p_dacl_defaulted)
        )
        return p_acl.contents
    
    @property
    def sacl(self):
        p_sacl_present = ctypes.c_int()
        p_sacl_defaulted = ctypes.c_int()
        p_acl = ctypes.POINTER(EACL)()
        GetSecurityDescriptorSacl(
            self,
            byref(p_sacl_present),
            byref(p_acl),
            byref(p_sacl_defaulted)
        )
        return p_acl.contents
    
    @classmethod
    def from_string(cls, string_security_descriptor):
        return cls(string_security_descriptor=string_security_descriptor)

    @classmethod
    def from_handle(cls, handle, object_type=SE_UNKNOWN_OBJECT_TYPE, desired_access=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION):
        return cls(handle=handle, object_type=object_type, desired_access=desired_access)

    @classmethod
    def from_name(cls, name, object_type=SE_UNKNOWN_OBJECT_TYPE, desired_access=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION):
        return cls(name=name, object_type=object_type, desired_access=desired_access)
    
    def __eq__(self, other):
        if not isinstance(other, (PSECURITY_DESCRIPTOR)):
            return NotImplemented
        return self.string_security_descriptor == other.string_security_descriptor

        