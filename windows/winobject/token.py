import ctypes

import windows
from windows import utils
from windows import winproxy
import windows.generated_def as gdef

import functools

# Move to windows.security ?
def lookup_privilege(luid, system_name=None):
    pass

# stolen from windows.utils :D (refactor !)
def lookup_privilege_name(privilege_value):
    if isinstance(privilege_value, tuple):
        luid = LUID(privilege_value[1], privilege_value[0])
        privilege_value = luid
    size = DWORD(0x100)
    buff = ctypes.c_buffer(size.value)
    winproxy.LookupPrivilegeNameA(None, privilege_value, buff, size)
    return buff[:size.value]

KNOW_INTEGRITY_LEVEL = [
gdef.SECURITY_MANDATORY_UNTRUSTED_RID,
gdef.SECURITY_MANDATORY_LOW_RID,
gdef.SECURITY_MANDATORY_MEDIUM_RID,
gdef.SECURITY_MANDATORY_MEDIUM_PLUS_RID,
gdef.SECURITY_MANDATORY_HIGH_RID,
gdef.SECURITY_MANDATORY_SYSTEM_RID,
gdef.SECURITY_MANDATORY_PROTECTED_PROCESS_RID
]

know_integrity_level_mapper = gdef.FlagMapper(*KNOW_INTEGRITY_LEVEL)


# Voodoo to fix lookup-strangeness in class declaration
def meta_craft(x):
    def partial_applier(infos_class, rtype):
        return property(functools.partial(x, infos_class=infos_class, rtype=rtype))
    return partial_applier


class TokenGroups(gdef.TOKEN_GROUPS):
    @property
    def _groups(self):
        return windows.utils.resized_array(self.Groups, self.GroupCount)

    @property
    def sids_and_attributes(self):
        return self._groups # Something else ?

    @property
    def sids(self):
        return [g.Sid for g in self._groups]

    def __repr__(self):
        return "<{0} count={1}>".format(type(self).__name__, self.GroupCount)

TokenGroupsType = TokenGroups # Prevent confusion with token.TokenGroups

class TokenPrivileges(gdef.TOKEN_PRIVILEGES):
    @property
    def _privileges(self):
        return windows.utils.resized_array(self.Privileges, self.PrivilegeCount)

    @property
    def all(self):
        return list(self._privileges)

TokenPrivilegesType = TokenPrivileges

class TokenSecurityAttributesInformation(gdef.TOKEN_SECURITY_ATTRIBUTES_INFORMATION):
    @property
    def attributes(self):
        tptr = ctypes.cast(self.Attribute.pAttributeV1, ctypes.POINTER(TokenSecurityAttributeV1))
        # Well look like this cast does NOT keep a ref to self.
        # Setup the base object ref ourself
        tptr._custom_base_ = self
        return tptr[:self.AttributeCount]


class TokenSecurityAttributeV1(gdef.TOKEN_SECURITY_ATTRIBUTE_V1):
    VALUE_ARRAY_PTR_BY_TYPE = {
        gdef.TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64: "pInt64",
        gdef.TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64: "pUint64",
        gdef.TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING: "pString",
        gdef.TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN: "pFqbn",
        # TOKEN_SECURITY_ATTRIBUTE_TYPE_SID
        # TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN
        gdef.TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING: "pOctetString",
    }

    @property
    def name(self):
        return self.Name.str

    @property
    def values(self):
        array_name = self.VALUE_ARRAY_PTR_BY_TYPE[self.ValueType]
        return getattr(self.Values, array_name)[:self.ValueCount]

    def __repr__(self):
        return """<{0} name="{1}">""".format(type(self).__name__, self.name)


# https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/access-tokens
class Token(utils.AutoHandle):
    """The token of a process"""
    def __init__(self, handle):
        self._handle = handle

    def _get_required_token_information_size(self, infos_class):
        cbsize = gdef.DWORD()
        try:
            winproxy.GetTokenInformation(self.handle, infos_class, None, 0, ctypes.byref(cbsize))
        except winproxy.WinproxyError as e:
             if not e.winerror in (gdef.ERROR_INSUFFICIENT_BUFFER, gdef.ERROR_BAD_LENGTH):
                raise
        return cbsize.value

    def _get_token_infomations(self, infos_class, rtype):
        required_size = self._get_required_token_information_size(infos_class)
        requested_size = max(required_size, ctypes.sizeof(rtype))
        buffer = utils.BUFFER(rtype, 1)(size=requested_size)
        cbsize = gdef.DWORD()
        winproxy.GetTokenInformation(self.handle, infos_class, buffer, buffer.real_size, cbsize)
        return buffer[0]


    craft = meta_craft(_get_token_infomations)
    # https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ne-winnt-_token_information_class
    TokenUser = craft(gdef.TokenUser, gdef.TOKEN_USER)
    TokenGroups = craft(gdef.TokenGroups , TokenGroupsType)
    TokenPrivileges = craft(gdef.TokenPrivileges , TokenPrivilegesType)
    TokenOwner = craft(gdef.TokenOwner, gdef.TOKEN_OWNER )
    TokenPrimaryGroup = craft(gdef.TokenPrimaryGroup, gdef.TOKEN_PRIMARY_GROUP)
    TokenDefaultDacl = craft(gdef.TokenDefaultDacl, gdef.TOKEN_DEFAULT_DACL )
    TokenSource = craft(gdef.TokenSource, gdef.TOKEN_SOURCE)
    TokenType = craft(gdef.TokenType, gdef.TOKEN_TYPE)
    TokenImpersonationLevel = craft(gdef.TokenImpersonationLevel, gdef.SECURITY_IMPERSONATION_LEVEL)
    TokenStatistics = craft(gdef.TokenStatistics, gdef.TOKEN_STATISTICS)
    TokenRestrictedSids = craft(gdef.TokenRestrictedSids, TokenGroupsType)
    TokenSessionId = craft(gdef.TokenSessionId, gdef.DWORD)
    TokenGroupsAndPrivileges = craft(gdef.TokenGroupsAndPrivileges, gdef.TOKEN_GROUPS_AND_PRIVILEGES)
    # TokenSessionReference = craft(gdef.TokenSessionReference, ???) # Reserved.
    TokenSandBoxInert = craft(gdef.TokenSandBoxInert, gdef.DWORD)
    # TokenAuditPolicy = craft(gdef.TokenAuditPolicy, ???) # Reserved.
    TokenOrigin = craft(gdef.TokenOrigin, gdef.TOKEN_ORIGIN)
    TokenElevationType = craft(gdef.TokenElevationType, gdef.TOKEN_ELEVATION_TYPE)
    TokenLinkedToken = craft(gdef.TokenLinkedToken, gdef.TOKEN_LINKED_TOKEN)
    TokenElevation = craft(gdef.TokenElevation, gdef.TOKEN_ELEVATION)
    TokenHasRestrictions = craft(gdef.TokenHasRestrictions, gdef.DWORD)
    TokenAccessInformation = craft(gdef.TokenAccessInformation, gdef.TOKEN_ACCESS_INFORMATION )
    TokenVirtualizationAllowed = craft(gdef.TokenVirtualizationAllowed, gdef.DWORD)
    TokenVirtualizationEnabled = craft(gdef.TokenVirtualizationEnabled, gdef.DWORD)
    TokenIntegrityLevel = craft(gdef.TokenIntegrityLevel, gdef.TOKEN_MANDATORY_LABEL )
    TokenUIAccess = craft(gdef.TokenUIAccess, gdef.DWORD)
    TokenMandatoryPolicy = craft(gdef.TokenMandatoryPolicy, gdef.TOKEN_MANDATORY_POLICY)
    TokenLogonSid = craft(gdef.TokenLogonSid, TokenGroupsType)
    TokenIsAppContainer = craft(gdef.TokenIsAppContainer, gdef.DWORD)
    TokenCapabilities = craft(gdef.TokenCapabilities, TokenGroupsType)
    TokenAppContainerSid = craft(gdef.TokenAppContainerSid, gdef.TOKEN_APPCONTAINER_INFORMATION)
    TokenAppContainerNumber = craft(gdef.TokenAppContainerNumber, gdef.DWORD)
    TokenUserClaimAttributes = craft(gdef.TokenUserClaimAttributes, gdef.CLAIM_SECURITY_ATTRIBUTES_INFORMATION)
    TokenDeviceClaimAttributes = craft(gdef.TokenDeviceClaimAttributes, gdef.CLAIM_SECURITY_ATTRIBUTES_INFORMATION)
    # TokenRestrictedUserClaimAttributes = craft(gdef.TokenRestrictedUserClaimAttributes, ???) # Reserved.
    # TokenRestrictedDeviceClaimAttributes = craft(gdef.TokenRestrictedDeviceClaimAttributes, ???) # Reserved.
    TokenDeviceGroups = craft(gdef.TokenDeviceGroups, TokenGroups)
    TokenRestrictedDeviceGroups = craft(gdef.TokenRestrictedDeviceGroups, gdef.TOKEN_GROUPS)
    # Reserved.
    # Structure found in ntseapi.h (thx internet)
    TokenSecurityAttributes = craft(gdef.TokenSecurityAttributes, TokenSecurityAttributesInformation)
    # TokenIsRestricted = craft(gdef.TokenIsRestricted, ???) # Reserved.
    # TokenProcessTrustLevel = craft(gdef.TokenProcessTrustLevel, ???) # Reserved.
    # TokenPrivateNameSpace = craft(gdef.TokenPrivateNameSpace, ???) # Reserved.
    # TokenSingletonAttributes = craft(gdef.TokenSingletonAttributes, ???) # Reserved.
    # TokenBnoIsolation = craft(gdef.TokenBnoIsolation, ???) # Reserved.
    # TokenChildProcessFlags = craft(gdef.TokenChildProcessFlags, ???) # Reserved.
    # TokenIsLessPrivilegedAppContainer = craft(gdef.TokenIsLessPrivilegedAppContainer, ???) # Reserved.

    # property arround raw 'GetTokenInformation'

    @property
    def user(self):
        return self.TokenUser.User.Sid

    groups = TokenGroups # The property not the ctypes Struct

    @property
    def owner(self):
        return self.TokenOwner.Owner

    @property
    def primary_group(self):
        return self.TokenPrimaryGroup.PrimaryGroup

    @property
    def default_dacl(self):
        return self._get_token_infomations(gdef.TokenDefaultDacl, windows.security.PAcl)[0]

    # def source(self): (tok.TokenSource) ??

    @property
    def type(self):
        return self.TokenType.value

    @property
    def impersonation_level(self):
        return self.TokenImpersonationLevel.value

    statistics = TokenStatistics
    restricted_sids = TokenRestrictedSids
    session_id = TokenSessionId

    @property
    def groups_and_privileges(self):
        # Return enhanced 'TOKEN_GROUPS_AND_PRIVILEGES' ?
        raise NotImplementedError("Token.groups_and_privileges")

    sandbox_inert = TokenSandBoxInert

    # audit_policy

    @property
    def origin(self):
        # Make a enhanced LUID ?
        origin_logon_session = self.TokenOrigin.OriginatingLogonSession
        return gdef.ULONG64.from_buffer(origin_logon_session).value

    @property
    def elevation_type(self):
        return self.TokenElevationType.value

    @property
    def linked_token(self):
        return Token(self.TokenLinkedToken.LinkedToken)

    @property
    def elevation(self):
        return bool(self.TokenElevation.TokenIsElevated)

    is_elevated = elevation # Keep this old name ?
    has_restriction = TokenHasRestrictions

    @property
    def access_information(self):
        # Return enhanced subclass ?
        raise NotImplementedError("Token.access_information")
        # return self.TokenAccessInformation

    virtualization_allowed = TokenVirtualizationAllowed
    virtualization_enabled = TokenVirtualizationEnabled

    @property
    def integrity_level(self):
        # Return SID_AND_ATTRIBUTES ? Only SID ?
        return self.TokenIntegrityLevel.Label # SID_AND_ATTRIBUTES

    ui_access = TokenUIAccess

    VALID_TOKEN_POLICIES = gdef.FlagMapper(
        gdef.TOKEN_MANDATORY_POLICY_OFF,
        gdef.TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        gdef.TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
        gdef.TOKEN_MANDATORY_POLICY_VALID_MASK,
    )

    @property
    def mandatory_policy(self):
        return self.VALID_TOKEN_POLICIES[self.TokenMandatoryPolicy.Policy]

    @property
    def logon_sid(self):
        rgroups = self.TokenLogonSid
        assert rgroups.GroupCount == 1, "More than 1 TokenLogonSid"
        return rgroups.Groups[0]

    is_appcontainer = TokenIsAppContainer
    capabilities = TokenCapabilities

    @property
    def appcontainer_sid(self):
        return self.TokenAppContainerSid.TokenAppContainer

    appcontainer_number = TokenAppContainerNumber

    # def security_attribute:
        # see PTOKEN_SECURITY_ATTRIBUTES_INFORMATION
        # https://github.com/wj32/Backup/blob/59aa77379f9f7ca57f27265e796dd2fe4dae9fab/include/phnt/ntseapi.h
        # blablabla :)


    def duplicate(self, access_rigth=0, attributes=None, impersonation_level=gdef.SecurityImpersonation, toktype=gdef.TokenPrimary):
        newtoken = gdef.HANDLE()
        winproxy.DuplicateTokenEx(self.handle, access_rigth, attributes, impersonation_level, toktype, newtoken)
        return type(self)(newtoken.value)



    ### OLD CODE

    def get_integrity(self):
        """Return the integrity level of a token

        :type: :class:`int`
		"""
        buffer_size = self.get_required_information_size(gdef.TokenIntegrityLevel)
        buffer = ctypes.c_buffer(buffer_size)
        self.get_informations(gdef.TokenIntegrityLevel, buffer)
        sid = ctypes.cast(buffer, ctypes.POINTER(gdef.TOKEN_MANDATORY_LABEL))[0].Label.Sid
        count = winproxy.GetSidSubAuthorityCount(sid)
        integrity = winproxy.GetSidSubAuthority(sid, count[0] - 1)[0]
        return know_integrity_level_mapper[integrity]

    def set_integrity(self, integrity):
        """Set the integrity level of a token

        :param type: :class:`int`
		"""
        mandatory_label = gdef.TOKEN_MANDATORY_LABEL()
        mandatory_label.Label.Attributes = 0x60
        mandatory_label.Label.Sid = gdef.PSID.from_string("S-1-16-{0}".format(integrity))
        self.set_informations(gdef.TokenIntegrityLevel, mandatory_label)

    integrity = property(get_integrity, set_integrity)

    @property
    def is_elevated(self):
        """``True`` if process is Admin"""
        elevation = gdef.TOKEN_ELEVATION()
        self.get_informations(gdef.TokenElevation, elevation)
        return bool(elevation.TokenIsElevated)

    @property
    def token_user(self):
        buffer_size = self.get_required_information_size(gdef.TokenUser)
        buffer = ctypes.c_buffer(buffer_size)
        self.get_informations(gdef.TokenUser, buffer)
        return ctypes.cast(buffer, ctypes.POINTER(gdef.TOKEN_USER))[0]

    @property
    def computername(self):
        """The computername of the token"""
        return self._user_and_computer_name()[1]

    @property
    def username(self):
        """The username of the token"""
        return self._user_and_computer_name()[0]



    def _user_and_computer_name(self):
        tok_usr = self.token_user
        sid = tok_usr.User.Sid
        usernamesize = gdef.DWORD(0x1000)
        computernamesize = gdef.DWORD(0x1000)
        username = ctypes.c_buffer(usernamesize.value)
        computername = ctypes.c_buffer(computernamesize.value)
        peUse = gdef.SID_NAME_USE()
        winproxy.LookupAccountSidA(None, sid, username, usernamesize, computername, computernamesize, peUse)
        return username[:usernamesize.value], computername[:computernamesize.value]

    def get_informations(self, info_type, data):
        cbsize = gdef.DWORD()
        winproxy.GetTokenInformation(self.handle, info_type, ctypes.byref(data), ctypes.sizeof(data), ctypes.byref(cbsize))
        return cbsize.value

    def get_required_information_size(self, info_type):
        cbsize = gdef.DWORD()
        try:
            winproxy.GetTokenInformation(self.handle, info_type, None, 0, ctypes.byref(cbsize))
        except WindowsError as e:
            if not e.winerror == gdef.ERROR_INSUFFICIENT_BUFFER:
                raise
        return cbsize.value

    #TODO: TEST + DOC
    def set_informations(self, info_type, infos):
        return winproxy.SetTokenInformation(self.handle, info_type, ctypes.byref(infos), ctypes.sizeof(infos))

    # TEST
    def dacl(self):
        """TEST CODE"""
        buffer_size = self.get_required_information_size(TokenDefaultDacl)
        buffer = ctypes.c_buffer(buffer_size)
        self.get_informations(gdef.TokenDefaultDacl, buffer)
        # TODO: use windows.security.Acl
        return ctypes.cast(buffer, POINTER(TOKEN_DEFAULT_DACL))[0]



    def __repr__(self):
        tid_int = gdef.ULONG64.from_buffer(self.TokenStatistics.TokenId).value
        return "<{0} TokenId={1:#x}>".format(type(self).__name__, tid_int)
