import ctypes
import functools

import windows
from windows import utils
from windows import winproxy
import windows.generated_def as gdef
# import windows.security # at the end of this file (loop import)

bltn_type = type

KNOW_INTEGRITY_LEVEL = gdef.FlagMapper(
    gdef.SECURITY_MANDATORY_UNTRUSTED_RID,
    gdef.SECURITY_MANDATORY_LOW_RID,
    gdef.SECURITY_MANDATORY_MEDIUM_RID,
    gdef.SECURITY_MANDATORY_MEDIUM_PLUS_RID,
    gdef.SECURITY_MANDATORY_HIGH_RID,
    gdef.SECURITY_MANDATORY_SYSTEM_RID,
    gdef.SECURITY_MANDATORY_PROTECTED_PROCESS_RID
)

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
        """The sids and attributes of each group

        :type: [:class:`~windows.generated_def.winstructs.SID_AND_ATTRIBUTES`] - A list of :class:`~windows.generated_def.winstructs.SID_AND_ATTRIBUTES`
        """
        return self._groups # Something else ?

    @property
    def sids(self):
        """The sids of each group

        :type: [:class:`~windows.generated_def.winstructs.PSID`] - A list of :class:`~windows.generated_def.winstructs.PSID`
        """
        return [g.Sid for g in self._groups]

    def __repr__(self):
        return "<{0} count={1}>".format(type(self).__name__, self.GroupCount)

TokenGroupsType = TokenGroups # Prevent confusion with token.TokenGroups

class TokenPrivileges(gdef.TOKEN_PRIVILEGES):
    """Improved ``TOKEN_PRIVILEGES`` usable like a mapping"""
    @property
    def _privileges(self):
        return windows.utils.resized_array(self.Privileges, self.PrivilegeCount)

    def all(self):
        """The list of all privileges

        :returns: [:class:`~windows.generated_def.winstructs.LUID_AND_ATTRIBUTES`] - A list of :class:`~windows.generated_def.winstructs.LUID_AND_ATTRIBUTES`
        """
        return list(self._privileges)

    def keys(self):
        """The name of all privileges in the TokenPrivileges

        :returns: [:class:`str`] - A list of name
        """
        return [self._lookup_name(p.Luid) for p in self._privileges]

    __iter__ = keys

    def items(self):
        """The (name, Attribute) of all privileges in the TokenPrivileges

        :returns: [(:class:`str`, :class:`int`)] - A list of (name, Attribute) tuple
        """
        return [(self._lookup_name(p.Luid), p.Attributes) for p in self._privileges]

    def _get_priv_by_name(self, name):
        luid = self._lookup_value(name)
        x = [p for p in self._privileges if p.Luid == luid]
        if not x:
            return None
        assert len(x) == 1
        return x[0]

    def __getitem__(self, name):
        """Retrieve the attribute value for privilege ``name``

        :raises: KeyError if privilege ``name`` not in the TokenPrivileges
        :returns: :class:`int`
        """
        priv = self._get_priv_by_name(name)
        if not priv:
            raise KeyError(name)
        return priv.Attributes

    def __setitem__(self, name, value):
        """Set the attribute value for privilege ``name``

        :raises: KeyError if privilege ``name`` not in the TokenPrivileges
        """
        priv = self._get_priv_by_name(name)
        if not priv:
            raise KeyError(name)
        priv.Attributes = value

    # __delitem__ that set SE_PRIVILEGE_REMOVED ?

    def _lookup_name(self, luid):
        size = gdef.DWORD(0x100)
        buff = ctypes.create_unicode_buffer(size.value)
        winproxy.LookupPrivilegeNameW(None, luid, buff, size)
        return buff[:size.value]

    def _lookup_value(self, name):
        luid = gdef.LUID()
        winproxy.LookupPrivilegeValueW(None, name, ctypes.byref(luid))
        return luid



TokenPrivilegesType = TokenPrivileges

class TokenSecurityAttributesInformation(gdef.TOKEN_SECURITY_ATTRIBUTES_INFORMATION):
    @property
    def attributes(self):
        """Return all the attributes as :class:`TokenSecurityAttributeV1`

        :type: [:class:`TokenSecurityAttributeV1`] - A list of token security attributes
        """
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
        """The name of the security attribute"""
        return self.Name.str

    @property
    def values(self):
        """The values of the security attribute"""
        array_name = self.VALUE_ARRAY_PTR_BY_TYPE[self.ValueType]
        return getattr(self.Values, array_name)[:self.ValueCount]

    def __repr__(self):
        return """<{0} name="{1}">""".format(type(self).__name__, self.name)



# https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/access-tokens
class Token(utils.AutoHandle):
    """Represent a Windows Token.
    The attributes only documented by a type are from the :class:`~windows.generated_def.winstructs.TOKEN_INFORMATION_CLASS`, such return values may be improved version of the structure.

    .. note::

        see `[MSDN] TOKEN_INFORMATION_CLASS <https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ne-winnt-_token_information_class>`_
    """
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

    def get_token_infomations(self, infos_class, rtype):
        required_size = self._get_required_token_information_size(infos_class)
        requested_size = max(required_size, ctypes.sizeof(rtype))
        buffer = utils.BUFFER(rtype, 1)(size=requested_size)
        cbsize = gdef.DWORD()
        winproxy.GetTokenInformation(self.handle, infos_class, buffer, buffer.real_size, cbsize)
        return buffer[0]


    def set_informations(self, info_type, infos):
        return winproxy.SetTokenInformation(self.handle, info_type, ctypes.byref(infos), ctypes.sizeof(infos))


    craft = meta_craft(get_token_infomations)
    # https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ne-winnt-_token_information_class
    TokenUser = craft(gdef.TokenUser, gdef.TOKEN_USER) #: :class:`~windows.generated_def.winstructs.TOKEN_USER`
    TokenGroups = craft(gdef.TokenGroups , TokenGroupsType) #: :class:`TokenGroups`
    TokenPrivileges = craft(gdef.TokenPrivileges , TokenPrivilegesType) #: :class:`TokenPrivileges`
    TokenOwner = craft(gdef.TokenOwner, gdef.TOKEN_OWNER) #: :class:`~windows.generated_def.winstructs.TOKEN_OWNER`
    TokenPrimaryGroup = craft(gdef.TokenPrimaryGroup, gdef.TOKEN_PRIMARY_GROUP) #: :class:`~windows.generated_def.winstructs.TOKEN_PRIMARY_GROUP`
    TokenDefaultDacl = craft(gdef.TokenDefaultDacl, gdef.TOKEN_DEFAULT_DACL) #: :class:`~windows.generated_def.winstructs.TOKEN_DEFAULT_DACL`
    TokenSource = craft(gdef.TokenSource, gdef.TOKEN_SOURCE) #: :class:`~windows.generated_def.winstructs.TOKEN_SOURCE`
    TokenType = craft(gdef.TokenType, gdef.TOKEN_TYPE) #: :class:`~windows.generated_def.winstructs.TOKEN_TYPE`
    TokenImpersonationLevel = craft(gdef.TokenImpersonationLevel, gdef.SECURITY_IMPERSONATION_LEVEL) #: :class:`~windows.generated_def.winstructs.SECURITY_IMPERSONATION_LEVEL`
    TokenStatistics = craft(gdef.TokenStatistics, gdef.TOKEN_STATISTICS) #: :class:`~windows.generated_def.winstructs.TOKEN_STATISTICS`
    TokenRestrictedSids = craft(gdef.TokenRestrictedSids, TokenGroupsType) #: :class:`~windows.generated_def.winstructs.TokenGroups`
    TokenSessionId = craft(gdef.TokenSessionId, gdef.DWORD) #: :class:`~windows.generated_def.winstructs.DWORD`
    TokenGroupsAndPrivileges = craft(gdef.TokenGroupsAndPrivileges, gdef.TOKEN_GROUPS_AND_PRIVILEGES) #: :class:`~windows.generated_def.winstructs.TOKEN_GROUPS_AND_PRIVILEGES`
    # TokenSessionReference = craft(gdef.TokenSessionReference, ???) # Reserved.
    TokenSandBoxInert = craft(gdef.TokenSandBoxInert, gdef.DWORD) #: :class:`~windows.generated_def.winstructs.DWORD`
    # TokenAuditPolicy = craft(gdef.TokenAuditPolicy, ???) # Reserved.
    TokenOrigin = craft(gdef.TokenOrigin, gdef.TOKEN_ORIGIN) #: :class:`~windows.generated_def.winstructs.TOKEN_ORIGIN`
    TokenElevationType = craft(gdef.TokenElevationType, gdef.TOKEN_ELEVATION_TYPE) #: :class:`~windows.generated_def.winstructs.TOKEN_ELEVATION_TYPE`
    TokenLinkedToken = craft(gdef.TokenLinkedToken, gdef.TOKEN_LINKED_TOKEN) #: :class:`~windows.generated_def.winstructs.TOKEN_LINKED_TOKEN`
    TokenElevation = craft(gdef.TokenElevation, gdef.TOKEN_ELEVATION) #: :class:`~windows.generated_def.winstructs.TOKEN_ELEVATION`
    TokenHasRestrictions = craft(gdef.TokenHasRestrictions, gdef.DWORD) #: :class:`~windows.generated_def.winstructs.DWORD`
    TokenAccessInformation = craft(gdef.TokenAccessInformation, gdef.TOKEN_ACCESS_INFORMATION) #: :class:`~windows.generated_def.winstructs.TOKEN_ACCESS_INFORMATION`
    TokenVirtualizationAllowed = craft(gdef.TokenVirtualizationAllowed, gdef.DWORD) #: :class:`~windows.generated_def.winstructs.DWORD`
    TokenVirtualizationEnabled = craft(gdef.TokenVirtualizationEnabled, gdef.DWORD) #: :class:`~windows.generated_def.winstructs.DWORD`
    TokenIntegrityLevel = craft(gdef.TokenIntegrityLevel, gdef.TOKEN_MANDATORY_LABEL) #: :class:`~windows.generated_def.winstructs.TOKEN_MANDATORY_LABEL`
    TokenUIAccess = craft(gdef.TokenUIAccess, gdef.DWORD) #: :class:`~windows.generated_def.winstructs.DWORD`
    TokenMandatoryPolicy = craft(gdef.TokenMandatoryPolicy, gdef.TOKEN_MANDATORY_POLICY) #: :class:`~windows.generated_def.winstructs.TOKEN_MANDATORY_POLICY`
    TokenLogonSid = craft(gdef.TokenLogonSid, TokenGroupsType) #: :class:`TokenGroups`
    TokenIsAppContainer = craft(gdef.TokenIsAppContainer, gdef.DWORD) #: :class:`~windows.generated_def.winstructs.DWORD`
    TokenCapabilities = craft(gdef.TokenCapabilities, TokenGroupsType) #: :class:`TokenGroups`
    TokenAppContainerSid = craft(gdef.TokenAppContainerSid, gdef.TOKEN_APPCONTAINER_INFORMATION) #: :class:`~windows.generated_def.winstructs.TOKEN_APPCONTAINER_INFORMATION`
    TokenAppContainerNumber = craft(gdef.TokenAppContainerNumber, gdef.DWORD) #: :class:`~windows.generated_def.winstructs.DWORD`
    TokenUserClaimAttributes = craft(gdef.TokenUserClaimAttributes, gdef.CLAIM_SECURITY_ATTRIBUTES_INFORMATION) #: :class:`~windows.generated_def.winstructs.CLAIM_SECURITY_ATTRIBUTES_INFORMATION`
    TokenDeviceClaimAttributes = craft(gdef.TokenDeviceClaimAttributes, gdef.CLAIM_SECURITY_ATTRIBUTES_INFORMATION) #: :class:`~windows.generated_def.winstructs.CLAIM_SECURITY_ATTRIBUTES_INFORMATION`
    # TokenRestrictedUserClaimAttributes = craft(gdef.TokenRestrictedUserClaimAttributes, ???) # Reserved.
    # TokenRestrictedDeviceClaimAttributes = craft(gdef.TokenRestrictedDeviceClaimAttributes, ???) # Reserved.
    TokenDeviceGroups = craft(gdef.TokenDeviceGroups, TokenGroupsType) #: :class:`TokenGroups`
    TokenRestrictedDeviceGroups = craft(gdef.TokenRestrictedDeviceGroups, gdef.TOKEN_GROUPS) #: :class:`~windows.generated_def.winstructs.TOKEN_GROUPS`
    # Reserved.
    # Structure found in ntseapi.h (thx internet)
    TokenSecurityAttributes = craft(gdef.TokenSecurityAttributes, TokenSecurityAttributesInformation) #: :class:`TokenSecurityAttributesInformation`
    # Help would be appreciated for the structures of the following query type

    # TokenIsRestricted = craft(gdef.TokenIsRestricted, ???) # Reserved.
    TokenProcessTrustLevel = craft(gdef.TokenProcessTrustLevel, gdef.PSID) #: :class:`~windows.generated_def.winstructs.PSID`
    # TokenPrivateNameSpace = craft(gdef.TokenPrivateNameSpace, gdef.ULONG) # Reserved.
    # TokenSingletonAttributes = craft(gdef.TokenSingletonAttributes, ???) # Reserved.
    # TokenBnoIsolation = craft(gdef.TokenBnoIsolation, ???) # Reserved.
    # TokenChildProcessFlags = craft(gdef.TokenChildProcessFlags, ???) # Reserved.
    # TokenIsLessPrivilegedAppContainer = craft(gdef.TokenIsLessPrivilegedAppContainer, ???) # Reserved.

    # High level properties

    @property
    def user(self):
        """The user sid of the token

        :type: :class:`~windows.generated_def.winstructs.PSID`
        """
        return self.TokenUser.User.Sid

    @property
    def username(self):
        """The username of the token

        :type: :class:`str`
        """
        return self._user_and_computer_name()[1]

    @property
    def computername(self):
        """The computername of the token

        :type: :class:`str`
        """
        return self._user_and_computer_name()[0]

    def _user_and_computer_name(self):
        return windows.utils.lookup_sid(self.user)


    groups = TokenGroups #: Alias for TokenGroups (type may change in the future for improved struct)

    @property
    def owner(self):
        """The owner sid of the token

        :type: :class:`~windows.generated_def.winstructs.PSID`
        """
        return self.TokenOwner.Owner

    @property
    def primary_group(self):
        """The sid of the primary group of the token

        :type: :class:`~windows.generated_def.winstructs.PSID`
        """
        return self.TokenPrimaryGroup.PrimaryGroup

    @property
    def default_dacl(self):
        """The defaul DACL of the token

        :type: :class:`windows.security.Acl`
        """
        return self.get_token_infomations(gdef.TokenDefaultDacl, windows.security.PAcl)[0]

    # def source(self): (tok.TokenSource) ??

    @property
    def type(self):
        """The type (Primary / Impersonation) of the token


        """
        return self.TokenType.value

    @property
    def impersonation_level(self):
        """The impersonation level of a ``TokenImpersonation`` token.

        :raises: :class:`WindowsError` if token is not a ``TokenImpersonation``
        :type: :class:`int` -- Enum value from :class:`~windows.generated_def.winstructs.SECURITY_IMPERSONATION_LEVEL`
        """
        try:
            return self.TokenImpersonationLevel.value
        except WindowsError as e:
            if (e.winerror == gdef.ERROR_INVALID_PARAMETER and
                    self.type != gdef.TokenImpersonation):
                # raise ValueError ?
                e.strerror += " This Token is not an Impersonation token"
            raise

    statistics = TokenStatistics #: Alias for TokenStatistics (type may change in the future for improved struct)

    @property
    def id(self):
        """The TokenId Specifies an unique identifier that identifies this instance of the token object.

        :type: :class:`int`
        """
        return int(self.TokenStatistics.TokenId)

    @property
    def authentication_id(self):
        """The AuthenticationId Specifies an unique identifier assigned to the session this token represents.
        There can be many tokens representing a single logon session.

        :type: :class:`int`
        """
        return int(self.TokenStatistics.AuthenticationId)

    @property
    def modified_id(self):
        """The ModifiedId Specifies an unique identifier that changes each time the token is modified.

        :type: :class:`int`
        """
        return int(self.TokenStatistics.ModifiedId)

    restricted_sids = TokenRestrictedSids #: Alias for TokenRestrictedSids (type may change in the future for improved struct)
    session_id = TokenSessionId #: Alias for TokenSessionId (type may change in the future for improved struct)

    @property
    def groups_and_privileges(self):
        """Alias for TokenGroupsAndPrivileges (type may change in the future for improved struct)"""
        # Return enhanced 'TOKEN_GROUPS_AND_PRIVILEGES' ?
        return self.TokenGroupsAndPrivileges

    @property
    def privileges(self):
        """Alias for ``TokenPrivileges``

        :type: :class:`TokenPrivileges`
        """
        return self.TokenPrivileges

    sandbox_inert = TokenSandBoxInert #: Alias for TokenSandBoxInert (type may change in the future for improved struct)

    # def audit_policy(self):
        # raise NotImplementedError("Need to find the type of TokenAuditPolicy")

    @property
    def origin(self):
        """The originating logon session of the token.

        :type: :class:`int`
        """
        origin_logon_session = self.TokenOrigin.OriginatingLogonSession
        return int(origin_logon_session) # improved LUID implem __int__ :)

    @property
    def elevation_type(self):
        """The elevation type of the token.

        :type: :class:`int` -- Enum value from :class:`~windows.generated_def.winstructs.TOKEN_ELEVATION_TYPE`
        """
        return self.TokenElevationType.value

    @property
    def linked_token(self):
        """The token linked to our token if present (may raise else)

        :type: :class:`Token`
        """
        # TODO: return None if not present ?
        return Token(self.TokenLinkedToken.LinkedToken)

    @property
    def elevated(self):
        """``True`` if token is an elevated token"""
        return bool(self.TokenElevation.TokenIsElevated)

    is_elevated = elevated #: Alias for ``elevated`` deprecated and may disapear
    has_restriction = TokenHasRestrictions #: Alias for TokenHasRestrictions (type may change in the future for improved struct)

    @property
    def access_information(self):
        """Alias for TokenAccessInformation (type may change in the future for improved struct)"""
        # Return enhanced subclass ?
        return self.TokenAccessInformation

    @property
    def trust_level(self):
        """The trust level of the process if present else ``None``.

        :type: :class:`~windows.generated_def.winstructs.PSID`
        """
        tl = self.TokenProcessTrustLevel
        if not tl: # NULL:
            return None
        return tl

    virtualization_allowed = TokenVirtualizationAllowed #: Alias for TokenVirtualizationAllowed (type may change in the future for improved struct)
    virtualization_enabled = TokenVirtualizationEnabled #: Alias for TokenVirtualizationEnabled (type may change in the future for improved struct)

    @property
    def integrity_level(self):
        """The integrity level and attributes of the token

        :type: :class:`windows.generated_def.winstructs.SID_AND_ATTRIBUTES`
        """
        return self.TokenIntegrityLevel.Label # SID_AND_ATTRIBUTES

    def get_integrity(self):
        """Return the integrity level of the token

        :type: :class:`int`
		"""
        sid = self.integrity_level.Sid
        count = winproxy.GetSidSubAuthorityCount(sid)
        integrity = winproxy.GetSidSubAuthority(sid, count[0] - 1)[0]
        return KNOW_INTEGRITY_LEVEL[integrity]

    def set_integrity(self, integrity):
        """Set the integrity level of a token

        :param type: :class:`int`
		"""
        mandatory_label = gdef.TOKEN_MANDATORY_LABEL()
        mandatory_label.Label.Attributes = 0x60
        # cast integrity to int to accept SECURITY_MANDATORY_LOW_RID & other Flags
        mandatory_label.Label.Sid = gdef.PSID.from_string("S-1-16-{0}".format(int(integrity)))
        return self.set_informations(gdef.TokenIntegrityLevel, mandatory_label)

    _INTEGRITY_PROPERTY_DOC = """The integrity of the token as an int (extracted from integrity PSID)

    :getter: :func:`get_integrity`
    :setter: :func:`set_integrity`
    """

    integrity = property(get_integrity, set_integrity, doc=_INTEGRITY_PROPERTY_DOC)

    ui_access = TokenUIAccess #: Alias for TokenUIAccess (type may change in the future for improved struct)

    VALID_TOKEN_POLICIES = gdef.FlagMapper(
        gdef.TOKEN_MANDATORY_POLICY_OFF,
        gdef.TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        gdef.TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
        gdef.TOKEN_MANDATORY_POLICY_VALID_MASK,
    )

    @property
    def mandatory_policy(self):
        """mandatory integrity access policy for the associated token

        :type: :class:`int` -- see `[MSDN] mandatory policy <https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_token_mandatory_policy>`_
        """
        return self.VALID_TOKEN_POLICIES[self.TokenMandatoryPolicy.Policy]

    @property
    def logon_sid(self):
        """The logon sid of the token. (Case of multiple logon sid not handled and will raise AssertionError)

        :type: :class:`windows.generated_def.winstructs.SID_AND_ATTRIBUTES`
        """
        rgroups = self.TokenLogonSid
        assert rgroups.GroupCount == 1, "More than 1 TokenLogonSid"
        return rgroups.Groups[0]

    is_appcontainer = TokenIsAppContainer #: Alias for TokenIsAppContainer (type may change in the future for improved struct)
    capabilities = TokenCapabilities #: Alias for TokenCapabilities (type may change in the future for improved struct)

    @property
    def appcontainer_sid(self):
        """The sid of the TokenAppContainerSid if present else ``None``

        :type: :class:`~windows.generated_def.winstructs.PSID`
        """
        sid = self.TokenAppContainerSid.TokenAppContainer
        if not sid: # NULL
            return None
        return sid

    appcontainer_number = TokenAppContainerNumber #: Alias for TokenAppContainerNumber (type may change in the future for improved struct)

    @property
    def security_attributes(self):
        """The security attributes of the token

        :type: [:class:`TokenSecurityAttributeV1`] - A list of token security attributes
        """
        return self.TokenSecurityAttributes.attributes


    ## Token Methods
    def duplicate(self, access_rigth=gdef.MAXIMUM_ALLOWED, attributes=None, type=None, impersonation_level=None):
        """Duplicate the token into a new :class:`Token`.

        :param type: The type of token: ``TokenPrimary(0x1L)`` or ``TokenImpersonation(0x2L)``
        :param impersonation_level: The :class:`~windows.generated_def.winstructs.SECURITY_IMPERSONATION_LEVEL` for a ``TokenImpersonation(0x2L)``:

            - If ``type`` is ``TokenPrimary(0x1L)`` this parameter is ignored if ``None`` or used as-is.
            - If ``type`` is ``TokenImpersonation(0x2L)`` and this parameter is None, ``self.impersonation_level`` is used.
            - If ``type`` is ``TokenImpersonation(0x2L)`` and our Token is a ``TokenPrimary(0x1L)`` this parameter MUST be provided

        :returns: :class:`Token` - The duplicate token

        Example:

            >>> tok
            <Token TokenId=0x39d6dde5 Type=TokenPrimary(0x1L)>
            >>> tok.duplicate()
            <Token TokenId=0x39d7b206 Type=TokenPrimary(0x1L)>
            >>> tok.duplicate(type=gdef.TokenImpersonation)
            ...
            ValueError: Duplicating a PrimaryToken as a TokenImpersonation require explicit <impersonation_level> parameter
            >>> tok.duplicate(type=gdef.TokenImpersonation, impersonation_level=gdef.SecurityImpersonation)
            <Token TokenId=0x39dadbf8 Type=TokenImpersonation(0x2L) ImpersonationLevel=SecurityImpersonation(0x2L)>
        """
        newtoken = gdef.HANDLE()
        if type is None:
            type = self.type
        if impersonation_level is None:
            if self.type == gdef.TokenImpersonation:
                impersonation_level = self.impersonation_level
            elif type != gdef.TokenImpersonation:
                impersonation_level = 0 #: ignored
            else:
                raise ValueError("Duplicating a PrimaryToken as a TokenImpersonation require explicit <impersonation_level> parameter")
        winproxy.DuplicateTokenEx(self.handle, access_rigth, attributes, impersonation_level, type, newtoken)
        return bltn_type(self)(newtoken.value)

    def adjust_privileges(self, privileges):
        """Adjust the token privileges according to ``privileges``.
        This API is the `complex one` to adjust multiple privileges at once.

        To simply enable one privilege see :func:`enable_privilege`.

        :param privileges: :class:`~windows.generated_def.winstructs.TOKEN_PRIVILEGES` (or subclass as :class:`TokenPrivileges`). To easily update your token privileges use the result of :data:`privileges`.

        Example:

            >>> tok = windows.current_process.token
            >>> privs = tok.privileges
            >>> privs["SeShutdownPrivilege"] = gdef.SE_PRIVILEGE_ENABLED
            >>> privs["SeUndockPrivilege"] = gdef.SE_PRIVILEGE_ENABLED
            >>> tok.adjust_privileges(privs)

        """
        buffsize = None
        if isinstance(privileges, TokenPrivilegesType):
            # The TokenPrivilegesType should come from a PTR via Improved buffer
            try:
                buffsize = privileges._b_base_.real_size
            except AttributeError as e:
                pass
        if buffsize is None:
            buffsize = ctypes.sizeof(privileges)
        winproxy.AdjustTokenPrivileges(self.handle, False, privileges, buffsize, None, None)
        if winproxy.GetLastError() == gdef.ERROR_NOT_ALL_ASSIGNED:
            # Transform this in a real WindowsError
            raise WindowsError(gdef.ERROR_NOT_ALL_ASSIGNED, "Failed to adjust all privileges")

    def enable_privilege(self, name):
        """Enable privilege ``name`` in the token

        :raises: :class:`ValueError` if :class:`Token` has no privilege ``name``
        """
        privs = self.privileges
        try:
            privs[name] = gdef.SE_PRIVILEGE_ENABLED
        except KeyError as e:
            # Emulate the WindowsError that would be triggered in 'adjust_privileges' ?
            raise ValueError("{0} has no privilege <{1}>".format(self, name))
        return self.adjust_privileges(privs)

    def __repr__(self):
        flag_repr = gdef.Flag.__repr__
        try:
            tid_int = int(self.TokenStatistics.TokenId) # May raise -> which is bad as __repr__ may be called on __del__...
        except WindowsError as e:
            return object.__repr__(self)
        toktype = self.type
        if toktype == gdef.TokenPrimary:
            return "<{0} TokenId={1:#x} Type={2}>".format(type(self).__name__, tid_int, flag_repr(toktype))
        return "<{0} TokenId={1:#x} Type={2} ImpersonationLevel={3}>".format(type(self).__name__, tid_int, flag_repr(toktype), flag_repr(self.impersonation_level))


import windows.security
