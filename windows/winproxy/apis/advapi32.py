import ctypes
import windows.generated_def as gdef
import windows.pycompat

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero, succeed_on_zero, result_is_error_code, result_is_handle, no_error_check, result_is_ntstatus

class Advapi32Proxy(ApiProxy):
    APIDLL = "advapi32"
    default_error_check = staticmethod(fail_on_zero)

# Process

@Advapi32Proxy()
def CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False,
                            dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None):
    if lpStartupInfo is None:
        StartupInfo = gdef.STARTUPINFOA()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = 0
        # StartupInfo.wShowWindow = gdef.SW_HIDE
        lpStartupInfo = ctypes.byref(StartupInfo)
    if lpProcessInformation is None:
        lpProcessInformation = ctypes.byref(gdef.PROCESS_INFORMATION())
    return CreateProcessAsUserA.ctypes_function(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

    return CreateProcessAsUserA.ctypes_function(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

@Advapi32Proxy()
def CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
    return CreateProcessAsUserW.ctypes_function(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)


# Token

@Advapi32Proxy()
def OpenProcessToken(ProcessHandle=None, DesiredAccess=NeededParameter, TokenHandle=NeededParameter):
    """If ProcessHandle is None: take the current process"""
    if ProcessHandle is None:
        # TODO: FAIL
        ProcessHandle = GetCurrentProcess()
    return OpenProcessToken.ctypes_function(ProcessHandle, DesiredAccess, TokenHandle)

@Advapi32Proxy()
def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle):
    return OpenThreadToken.ctypes_function(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle)

@Advapi32Proxy()
def SetThreadToken(Thread, Token):
    if isinstance(Thread, (int, long)):
        Thread = gdef.HANDLE(Thread)
    return SetThreadToken.ctypes_function(Thread, Token)

@Advapi32Proxy()
def DuplicateToken(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle):
    return DuplicateToken.ctypes_function(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle)

@Advapi32Proxy()
def DuplicateTokenEx(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken):
    return DuplicateTokenEx.ctypes_function(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken)

@Advapi32Proxy()
def GetTokenInformation(TokenHandle=NeededParameter, TokenInformationClass=NeededParameter, TokenInformation=None, TokenInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = ctypes.byref(gdef.DWORD())
    return GetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength)

@Advapi32Proxy()
def SetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength):
    return SetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength)


# Token - Privilege

@Advapi32Proxy()
def LookupPrivilegeValueA(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter):
    return LookupPrivilegeValueA.ctypes_function(lpSystemName, lpName, lpLuid)


@Advapi32Proxy()
def LookupPrivilegeValueW(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter):
    return LookupPrivilegeValueW.ctypes_function(lpSystemName, lpName, lpLuid)

@Advapi32Proxy()
def LookupPrivilegeNameA(lpSystemName, lpLuid, lpName, cchName):
    return LookupPrivilegeNameA.ctypes_function(lpSystemName, lpLuid, lpName, cchName)

@Advapi32Proxy()
def LookupPrivilegeNameW(lpSystemName, lpLuid, lpName, cchName):
    return LookupPrivilegeNameW.ctypes_function(lpSystemName, lpLuid, lpName, cchName)


@Advapi32Proxy()
def AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges=False, NewState=NeededParameter, BufferLength=None, PreviousState=None, ReturnLength=None):
    if BufferLength is None:
        BufferLength = ctypes.sizeof(NewState)
    return AdjustTokenPrivileges.ctypes_function(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength)

# Access check

@Advapi32Proxy()
def MapGenericMask(AccessMask, GenericMapping):
    return MapGenericMask.ctypes_function(AccessMask, GenericMapping)

@Advapi32Proxy()
def AccessCheck(pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus):
    return AccessCheck.ctypes_function(pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus)

# Sid

@Advapi32Proxy()
def LookupAccountSidA(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
    return LookupAccountSidA.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)


@Advapi32Proxy()
def LookupAccountSidW(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
    return LookupAccountSidW.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)


@Advapi32Proxy()
def LookupAccountNameA(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse):
    return LookupAccountNameA.ctypes_function(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse)

@Advapi32Proxy()
def LookupAccountNameW(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse):
   return LookupAccountNameW.ctypes_function(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse)


@Advapi32Proxy()
def CreateWellKnownSid(WellKnownSidType, DomainSid=None, pSid=None, cbSid=NeededParameter):
    return CreateWellKnownSid.ctypes_function(WellKnownSidType, DomainSid, pSid, cbSid)

@Advapi32Proxy()
def GetLengthSid(pSid):
    return GetLengthSid.ctypes_function(pSid)


@Advapi32Proxy(error_check=no_error_check)
def EqualSid(pSid1, pSid2):
    return EqualSid.ctypes_function(pSid1, pSid2)

@Advapi32Proxy()
def GetSidSubAuthority(pSid, nSubAuthority):
    return GetSidSubAuthority.ctypes_function(pSid, nSubAuthority)

@Advapi32Proxy()
def GetSidSubAuthorityCount(pSid):
    return GetSidSubAuthorityCount.ctypes_function(pSid)

@Advapi32Proxy()
def ConvertStringSidToSidA(StringSid, Sid):
    return ConvertStringSidToSidA.ctypes_function(StringSid, Sid)

@Advapi32Proxy()
def ConvertStringSidToSidW(StringSid, Sid):
    return ConvertStringSidToSidW.ctypes_function(StringSid, Sid)

@Advapi32Proxy()
def ConvertSidToStringSidA(Sid, StringSid):
    return ConvertSidToStringSidA.ctypes_function(Sid, StringSid)

@Advapi32Proxy()
def ConvertSidToStringSidW(Sid, StringSid):
    return ConvertSidToStringSidW.ctypes_function(Sid, StringSid)

@Advapi32Proxy()
def CopySid(nDestinationSidLength, pDestinationSid, pSourceSid):
    return CopySid.ctypes_function(nDestinationSidLength, pDestinationSid, pSourceSid)


# Security descriptor

@Advapi32Proxy(error_check=result_is_error_code)
def GetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None):
    return GetNamedSecurityInfoA.ctypes_function(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)

@Advapi32Proxy(error_check=result_is_error_code)
def GetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None):
    return GetNamedSecurityInfoW.ctypes_function(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)

@Advapi32Proxy(error_check=result_is_error_code)
def GetSecurityInfo(handle, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None):
    return GetSecurityInfo.ctypes_function(handle, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)

@Advapi32Proxy(error_check=result_is_error_code)
def SetSecurityInfo(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl):
    return SetSecurityInfo.ctypes_function(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl)

@Advapi32Proxy(error_check=result_is_error_code)
def SetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl):
    return SetNamedSecurityInfoA.ctypes_function(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl)

@Advapi32Proxy(error_check=result_is_error_code)
def SetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl):
    return SetNamedSecurityInfoW.ctypes_function(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl)


@Advapi32Proxy()
def InitializeSecurityDescriptor(pSecurityDescriptor, dwRevision):
   return InitializeSecurityDescriptor.ctypes_function(pSecurityDescriptor, dwRevision)

@Advapi32Proxy()
def IsValidSecurityDescriptor(pSecurityDescriptor):
   return IsValidSecurityDescriptor.ctypes_function(pSecurityDescriptor)

@Advapi32Proxy()
def ConvertStringSecurityDescriptorToSecurityDescriptorA(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize):
   return ConvertStringSecurityDescriptorToSecurityDescriptorA.ctypes_function(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)

@Advapi32Proxy()
def ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize):
   return ConvertStringSecurityDescriptorToSecurityDescriptorW.ctypes_function(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)

@Advapi32Proxy()
def ConvertSecurityDescriptorToStringSecurityDescriptorA(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen):
   return ConvertSecurityDescriptorToStringSecurityDescriptorA.ctypes_function(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)

@Advapi32Proxy()
def ConvertSecurityDescriptorToStringSecurityDescriptorW(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen):
   return ConvertSecurityDescriptorToStringSecurityDescriptorW.ctypes_function(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)

@Advapi32Proxy()
def GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted):
   return GetSecurityDescriptorDacl.ctypes_function(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted)

@Advapi32Proxy()
def GetSecurityDescriptorLength(pSecurityDescriptor):
   return GetSecurityDescriptorLength.ctypes_function(pSecurityDescriptor)

@Advapi32Proxy()
def GetSecurityDescriptorControl(pSecurityDescriptor, pControl, lpdwRevision):
   return GetSecurityDescriptorControl.ctypes_function(pSecurityDescriptor, pControl, lpdwRevision)

@Advapi32Proxy()
def GetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, lpbOwnerDefaulted):
   return GetSecurityDescriptorOwner.ctypes_function(pSecurityDescriptor, pOwner, lpbOwnerDefaulted)

@Advapi32Proxy()
def SetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, bOwnerDefaulted):
   return SetSecurityDescriptorOwner.ctypes_function(pSecurityDescriptor, pOwner, bOwnerDefaulted)

@Advapi32Proxy()
def GetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, lpbGroupDefaulted):
   return GetSecurityDescriptorGroup.ctypes_function(pSecurityDescriptor, pGroup, lpbGroupDefaulted)

@Advapi32Proxy()
def GetSecurityDescriptorSacl(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted):
   return GetSecurityDescriptorSacl.ctypes_function(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted)

@Advapi32Proxy()
def MakeAbsoluteSD(pSelfRelativeSecurityDescriptor, pAbsoluteSecurityDescriptor, lpdwAbsoluteSecurityDescriptorSize, pDacl, lpdwDaclSize, pSacl, lpdwSaclSize, pOwner, lpdwOwnerSize, pPrimaryGroup, lpdwPrimaryGroupSize):
   return MakeAbsoluteSD.ctypes_function(pSelfRelativeSecurityDescriptor, pAbsoluteSecurityDescriptor, lpdwAbsoluteSecurityDescriptorSize, pDacl, lpdwDaclSize, pSacl, lpdwSaclSize, pOwner, lpdwOwnerSize, pPrimaryGroup, lpdwPrimaryGroupSize)

@Advapi32Proxy()
def MakeSelfRelativeSD(pAbsoluteSecurityDescriptor, pSelfRelativeSecurityDescriptor, lpdwBufferLength):
   return MakeSelfRelativeSD.ctypes_function(pAbsoluteSecurityDescriptor, pSelfRelativeSecurityDescriptor, lpdwBufferLength)

# ACE - ACL

@Advapi32Proxy()
def GetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass):
    return GetAclInformation.ctypes_function(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass)

@Advapi32Proxy()
def GetAce(pAcl, dwAceIndex, pAce):
   return GetAce.ctypes_function(pAcl, dwAceIndex, pAce)


@Advapi32Proxy()
def GetStringConditionFromBinary(BinaryAceCondition, BinaryAceConditionSize=None, Reserved1=0, StringAceCondition=NeededParameter):
    if BinaryAceConditionSize is None:
        BinaryAceConditionSize = len(BinaryAceCondition)
    return GetStringConditionFromBinary.ctypes_function(BinaryAceCondition, BinaryAceConditionSize, Reserved1, StringAceCondition)

# Registry

@Advapi32Proxy(error_check=result_is_error_code)
def RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult):
    return RegOpenKeyExA.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)

@Advapi32Proxy(error_check=result_is_error_code)
def RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult):
    return RegOpenKeyExW.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)

@Advapi32Proxy(error_check=result_is_error_code)
def RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
    return RegCreateKeyExA.ctypes_function(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition)

@Advapi32Proxy(error_check=result_is_error_code)
def RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
    return RegCreateKeyExW.ctypes_function(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition)

@Advapi32Proxy(error_check=result_is_error_code)
def RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
    return RegGetValueA.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegGetValueW(hkey, lpSubKey=None, lpValue=NeededParameter, dwFlags=0, pdwType=None, pvData=None, pcbData=None):
    return RegGetValueW.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
    return RegQueryValueExA.ctypes_function(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
    return RegQueryValueExW.ctypes_function(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegCloseKey(hKey):
    return RegCloseKey.ctypes_function(hKey)

@Advapi32Proxy(error_check=result_is_error_code)
def RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData):
    return RegSetValueExW.ctypes_function(hKey, lpValueName, Reserved, dwType, lpData, cbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData):
    return RegSetValueExA.ctypes_function(hKey, lpValueName, Reserved, dwType, lpData, cbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegSetKeyValueA(hKey, lpSubKey, lpValueName, dwType, lpData, cbData):
    return RegSetKeyValueA.ctypes_function(hKey, lpSubKey, lpValueName, dwType, lpData, cbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegSetKeyValueW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData):
    return RegSetKeyValueW.ctypes_function(hKey, lpSubKey, lpValueName, dwType, lpData, cbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime):
    return RegEnumKeyExA.ctypes_function(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime)

@Advapi32Proxy(error_check=result_is_error_code)
def RegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime):
    return RegEnumKeyExW.ctypes_function(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime)

@Advapi32Proxy(error_check=result_is_error_code)
def RegGetKeySecurity(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor):
    return RegGetKeySecurity.ctypes_function(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor)

@Advapi32Proxy(error_check=result_is_error_code)
def RegQueryInfoKeyA(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime):
    return RegQueryInfoKeyA.ctypes_function(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime)

@Advapi32Proxy(error_check=result_is_error_code)
def RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime):
    return RegQueryInfoKeyW.ctypes_function(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime)

@Advapi32Proxy(error_check=result_is_error_code)
def RegDeleteKeyValueW(hKey, lpSubKey, lpValueName):
    return RegDeleteKeyValueW.ctypes_function(hKey, lpSubKey, lpValueName)

@Advapi32Proxy(error_check=result_is_error_code)
def RegDeleteKeyValueA(hKey, lpSubKey, lpValueName):
    return RegDeleteKeyValueA.ctypes_function(hKey, lpSubKey, lpValueName)

@Advapi32Proxy(error_check=result_is_error_code)
def RegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved):
    return RegDeleteKeyExA.ctypes_function(hKey, lpSubKey, samDesired, Reserved)

@Advapi32Proxy(error_check=result_is_error_code)
def RegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved):
    return RegDeleteKeyExW.ctypes_function(hKey, lpSubKey, samDesired, Reserved)

@Advapi32Proxy(error_check=result_is_error_code)
def RegDeleteValueA(hKey, lpValueName):
    return RegDeleteValueA.ctypes_function(hKey, lpValueName)

@Advapi32Proxy(error_check=result_is_error_code)
def RegDeleteValueW(hKey, lpValueName):
    return RegDeleteValueW.ctypes_function(hKey, lpValueName)

@Advapi32Proxy(error_check=result_is_error_code)
def RegDeleteTreeA(hKey, lpSubKey):
    return RegDeleteTreeA.ctypes_function(hKey, lpSubKey)

@Advapi32Proxy(error_check=result_is_error_code)
def RegDeleteTreeW(hKey, lpSubKey):
    return RegDeleteTreeW.ctypes_function(hKey, lpSubKey)

@Advapi32Proxy(error_check=result_is_error_code)
def RegEnumValueA(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData):
    return RegEnumValueA.ctypes_function(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData):
    return RegEnumValueW.ctypes_function(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData)

@Advapi32Proxy(error_check=result_is_error_code)
def RegSaveKeyA(hKey, lpFile, lpSecurityAttributes):
    return RegSaveKeyA.ctypes_function(hKey, lpFile, lpSecurityAttributes)

@Advapi32Proxy(error_check=result_is_error_code)
def RegSaveKeyW(hKey, lpFile, lpSecurityAttributes):
    return RegSaveKeyW.ctypes_function(hKey, lpFile, lpSecurityAttributes)

@Advapi32Proxy(error_check=result_is_error_code)
def RegSaveKeyExA(hKey, lpFile, lpSecurityAttributes, Flags):
    return RegSaveKeyExA.ctypes_function(hKey, lpFile, lpSecurityAttributes, Flags)

@Advapi32Proxy(error_check=result_is_error_code)
def RegSaveKeyExW(hKey, lpFile, lpSecurityAttributes, Flags):
    return RegSaveKeyExW.ctypes_function(hKey, lpFile, lpSecurityAttributes, Flags)

@Advapi32Proxy(error_check=result_is_error_code)
def RegLoadKeyA(hKey, lpSubKey, lpFile):
    return RegLoadKeyA.ctypes_function(hKey, lpSubKey, lpFile)

@Advapi32Proxy(error_check=result_is_error_code)
def RegLoadKeyW(hKey, lpSubKey, lpFile):
    return RegLoadKeyW.ctypes_function(hKey, lpSubKey, lpFile)

@Advapi32Proxy(error_check=result_is_error_code)
def RegUnLoadKeyA(hKey, lpSubKey):
    return RegUnLoadKeyA.ctypes_function(hKey, lpSubKey)

@Advapi32Proxy(error_check=result_is_error_code)
def RegUnLoadKeyW(hKey, lpSubKey):
    return RegUnLoadKeyW.ctypes_function(hKey, lpSubKey)

# Service

@Advapi32Proxy()
def OpenSCManagerA(lpMachineName=None, lpDatabaseName=None, dwDesiredAccess=gdef.SC_MANAGER_ALL_ACCESS):
    return OpenSCManagerA.ctypes_function(lpMachineName, lpDatabaseName, dwDesiredAccess)

@Advapi32Proxy()
def OpenSCManagerW(lpMachineName=None, lpDatabaseName=None, dwDesiredAccess=gdef.SC_MANAGER_ALL_ACCESS):
    return OpenSCManagerW.ctypes_function(lpMachineName, lpDatabaseName, dwDesiredAccess)

@Advapi32Proxy()
def EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
    return EnumServicesStatusExA.ctypes_function(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)

@Advapi32Proxy()
def EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
    return EnumServicesStatusExW.ctypes_function(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)

@Advapi32Proxy()
def StartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors):
    return StartServiceA.ctypes_function(hService, dwNumServiceArgs, lpServiceArgVectors)

@Advapi32Proxy()
def StartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors):
    return StartServiceW.ctypes_function(hService, dwNumServiceArgs, lpServiceArgVectors)

@Advapi32Proxy()
def OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess):
    return OpenServiceA.ctypes_function(hSCManager, lpServiceName, dwDesiredAccess)

@Advapi32Proxy()
def OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess):
    return OpenServiceW.ctypes_function(hSCManager, lpServiceName, dwDesiredAccess)

@Advapi32Proxy()
def ControlService(hService, dwControl, lpServiceStatus):
   return ControlService.ctypes_function(hService, dwControl, lpServiceStatus)

@Advapi32Proxy()
def CloseServiceHandle(hSCObject):
    return CloseServiceHandle.ctypes_function(hSCObject)

@Advapi32Proxy()
def QueryServiceStatus(hService, lpServiceStatus):
    return QueryServiceStatus.ctypes_function(hService, lpServiceStatus)

@Advapi32Proxy()
def QueryServiceStatusEx(hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded):
    return QueryServiceStatusEx.ctypes_function(hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)

@Advapi32Proxy()
def DeleteService(hService):
    return DeleteService.ctypes_function(hService)

@Advapi32Proxy()
def GetServiceDisplayNameA(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer):
    return GetServiceDisplayNameA.ctypes_function(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer)

@Advapi32Proxy()
def GetServiceDisplayNameW(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer):
    return GetServiceDisplayNameW.ctypes_function(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer)

# Event log

@Advapi32Proxy()
def OpenEventLogA(lpUNCServerName=None, lpSourceName=NeededParameter):
    return OpenEventLogA.ctypes_function(lpUNCServerName, lpSourceName)

@Advapi32Proxy()
def OpenEventLogW(lpUNCServerName=None, lpSourceName=NeededParameter):
    return OpenEventLogW.ctypes_function(lpUNCServerName, lpSourceName)

@Advapi32Proxy()
def OpenBackupEventLogA(lpUNCServerName=None, lpSourceName=NeededParameter):
    return OpenBackupEventLogA.ctypes_function(lpUNCServerName, lpSourceName)

@Advapi32Proxy()
def OpenBackupEventLogW(lpUNCServerName=None, lpSourceName=NeededParameter):
    return OpenBackupEventLogW.ctypes_function(lpUNCServerName, lpSourceName)


@Advapi32Proxy()
def ReadEventLogA(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded):
    return ReadEventLogA.ctypes_function(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded)

@Advapi32Proxy()
def ReadEventLogW(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded):
    return ReadEventLogW.ctypes_function(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded)

@Advapi32Proxy()
def GetEventLogInformation(hEventLog, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded):
    return GetEventLogInformation.ctypes_function(hEventLog, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)

@Advapi32Proxy()
def GetNumberOfEventLogRecords(hEventLog, NumberOfRecords):
    return GetNumberOfEventLogRecords.ctypes_function(hEventLog, NumberOfRecords)

@Advapi32Proxy()
def CloseEventLog(hEventLog):
    return CloseEventLog.ctypes_function(hEventLog)


# Crypto
## Crypto key

@Advapi32Proxy()
def CryptGenKey(hProv, Algid, dwFlags, phKey):
    return CryptGenKey.ctypes_function(hProv, Algid, dwFlags, phKey)


@Advapi32Proxy()
def CryptDestroyKey(hKey):
    return CryptDestroyKey.ctypes_function(hKey)

@Advapi32Proxy()
def CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen):
    return CryptExportKey.ctypes_function(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen)

@Advapi32Proxy()
def CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey):
    return CryptImportKey.ctypes_function(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey)

## crypt context

@Advapi32Proxy()
def CryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags):
    return CryptAcquireContextA.ctypes_function(phProv, pszContainer, pszProvider, dwProvType, dwFlags)


@Advapi32Proxy()
def CryptAcquireContextW(phProv, pszContainer, pszProvider, dwProvType, dwFlags):
    return CryptAcquireContextW.ctypes_function(phProv, pszContainer, pszProvider, dwProvType, dwFlags)


@Advapi32Proxy()
def CryptReleaseContext(hProv, dwFlags):
    return CryptReleaseContext.ctypes_function(hProv, dwFlags)

## Encrypt / Decrypt

@Advapi32Proxy()
def CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen):
    return CryptEncrypt.ctypes_function(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)

@Advapi32Proxy()
def CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen):
    return CryptDecrypt.ctypes_function(hKey, hHash, Final, dwFlags, pbData, pdwDataLen)

## Crypt Key

@Advapi32Proxy()
def CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey):
    return CryptDeriveKey.ctypes_function(hProv, Algid, hBaseData, dwFlags, phKey)

## Crypt hash

@Advapi32Proxy()
def CryptCreateHash(hProv, Algid, hKey=None, dwFlags=0, phHash=NeededParameter):
    return CryptCreateHash.ctypes_function(hProv, Algid, hKey, dwFlags, phHash)

@Advapi32Proxy()
def CryptHashData(hHash, pbData, dwDataLen=None, dwFlags=0):
    if isinstance(pbData, windows.pycompat.anybuff):
        pbData = (gdef.BYTE * len(pbData))(*bytearray(pbData))
    if dwDataLen is None:
        dwDataLen = len(pbData)
    return CryptHashData.ctypes_function(hHash, pbData, dwDataLen, dwFlags)

@Advapi32Proxy()
def CryptGetHashParam(hHash, dwParam, pbData, pdwDataLen=None, dwFlags=0):
    if pdwDataLen is None:
        pdwDataLen = ctypes.sizeof(pbData)
    return CryptGetHashParam.ctypes_function(hHash, dwParam, pbData, pdwDataLen, dwFlags)

@Advapi32Proxy()
def CryptVerifySignatureA(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags):
    return CryptVerifySignatureA.ctypes_function(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags)

@Advapi32Proxy()
def CryptVerifySignatureW(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags):
    return CryptVerifySignatureW.ctypes_function(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags)

@Advapi32Proxy()
def CryptSignHashA(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen):
    return CryptSignHashA.ctypes_function(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen)

@Advapi32Proxy()
def CryptSignHashW(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen):
    return CryptSignHashW.ctypes_function(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen)

@Advapi32Proxy()
def CryptDestroyHash(hHash):
    return CryptDestroyHash.ctypes_function(hHash)


## Event Tracing
@Advapi32Proxy(error_check=succeed_on_zero)
def EnumerateTraceGuidsEx(TraceQueryInfoClass, InBuffer, InBufferSize, OutBuffer, OutBufferSize, ReturnLength):
    if isinstance(InBuffer, gdef.GUID):
        # GUID is not convertible to a pointer directly
        # But we want to use it as an array for this function
        # Test/Assert on InBufferSize?
        InBuffer = ctypes.cast(ctypes.pointer(InBuffer), gdef.PVOID) # Caller keep a ref
    return EnumerateTraceGuidsEx.ctypes_function(TraceQueryInfoClass, InBuffer, InBufferSize, OutBuffer, OutBufferSize, ReturnLength)

@Advapi32Proxy(error_check=result_is_error_code)
def QueryAllTracesA(PropertyArray, PropertyArrayCount, SessionCount):
    return QueryAllTracesA.ctypes_function(PropertyArray, PropertyArrayCount, SessionCount)


@Advapi32Proxy(error_check=result_is_error_code)
def QueryAllTracesW(PropertyArray, PropertyArrayCount, SessionCount):
    return QueryAllTracesW.ctypes_function(PropertyArray, PropertyArrayCount, SessionCount)


@Advapi32Proxy(error_check=result_is_handle)
def OpenTraceA(Logfile):
    return OpenTraceA.ctypes_function(Logfile)

@Advapi32Proxy(error_check=result_is_handle)
def OpenTraceW(Logfile):
    return OpenTraceW.ctypes_function(Logfile)


@Advapi32Proxy(error_check=result_is_error_code)
def StartTraceA(TraceHandle, InstanceName, Properties):
    return StartTraceA.ctypes_function(TraceHandle, InstanceName, Properties)

@Advapi32Proxy(error_check=result_is_error_code)
def StartTraceW(TraceHandle, InstanceName, Properties):
    return StartTraceW.ctypes_function(TraceHandle, InstanceName, Properties)

@Advapi32Proxy(error_check=result_is_error_code)
def StopTraceA(TraceHandle, InstanceName, Properties):
    return StopTraceA.ctypes_function(TraceHandle, InstanceName, Properties)

@Advapi32Proxy(error_check=result_is_error_code)
def StopTraceW(TraceHandle, InstanceName, Properties):
    return StopTraceW.ctypes_function(TraceHandle, InstanceName, Properties)

@Advapi32Proxy(error_check=result_is_error_code)
def ControlTraceA(TraceHandle, InstanceName, Properties, ControlCode):
    return ControlTraceA.ctypes_function(TraceHandle, InstanceName, Properties, ControlCode)

@Advapi32Proxy(error_check=result_is_error_code)
def ControlTraceW(TraceHandle, InstanceName, Properties, ControlCode):
    return ControlTraceW.ctypes_function(TraceHandle, InstanceName, Properties, ControlCode)

@Advapi32Proxy(error_check=result_is_error_code)
def ProcessTrace(HandleArray, HandleCount, StartTime, EndTime):
   return ProcessTrace.ctypes_function(HandleArray, HandleCount, StartTime, EndTime)

@Advapi32Proxy(error_check=result_is_error_code)
def EnableTrace(Enable, EnableFlag, EnableLevel, ControlGuid, SessionHandle):
    return EnableTrace.ctypes_function(Enable, EnableFlag, EnableLevel, ControlGuid, SessionHandle)

@Advapi32Proxy(error_check=result_is_error_code)
def EnableTraceEx(ProviderId, SourceId, TraceHandle, IsEnabled, Level, MatchAnyKeyword, MatchAllKeyword, EnableProperty, EnableFilterDesc):
    return EnableTraceEx.ctypes_function(ProviderId, SourceId, TraceHandle, IsEnabled, Level, MatchAnyKeyword, MatchAllKeyword, EnableProperty, EnableFilterDesc)

@Advapi32Proxy(error_check=result_is_error_code)
def EnableTraceEx2(TraceHandle, ProviderId, ControlCode, Level, MatchAnyKeyword, MatchAllKeyword, Timeout, EnableParameters):
    return EnableTraceEx2.ctypes_function(TraceHandle, ProviderId, ControlCode, Level, MatchAnyKeyword, MatchAllKeyword, Timeout, EnableParameters)

@Advapi32Proxy(error_check=result_is_error_code)
def TraceQueryInformation(SessionHandle, InformationClass, TraceInformation, InformationLength, ReturnLength):
    return TraceQueryInformation.ctypes_function(SessionHandle, InformationClass, TraceInformation, InformationLength, ReturnLength)

@Advapi32Proxy(error_check=result_is_error_code)
def TraceSetInformation(SessionHandle, InformationClass, TraceInformation, InformationLength):
    return TraceSetInformation.ctypes_function(SessionHandle, InformationClass, TraceInformation, InformationLength)

@Advapi32Proxy(error_check=result_is_error_code)
def RegisterTraceGuidsW(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle):
    return RegisterTraceGuidsW.ctypes_function(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle)

@Advapi32Proxy(error_check=result_is_error_code)
def RegisterTraceGuidsA(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle):
    return RegisterTraceGuidsA.ctypes_function(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle)

@Advapi32Proxy(error_check=result_is_error_code)
def TraceEvent(SessionHandle, EventTrace):
    return TraceEvent.ctypes_function(SessionHandle, EventTrace)

@Advapi32Proxy(error_check=result_is_handle)
def GetTraceLoggerHandle(Buffer):
    return GetTraceLoggerHandle.ctypes_function(Buffer)


# Lsa APIs
@Advapi32Proxy(error_check=result_is_ntstatus)
def LsaOpenPolicy(SystemName=None, ObjectAttributes=None, DesiredAccess=NeededParameter, PolicyHandle=NeededParameter):
    if ObjectAttributes is None:
        ObjectAttributes = gdef.LSA_OBJECT_ATTRIBUTES()
    return LsaOpenPolicy.ctypes_function(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle)

@Advapi32Proxy(error_check=result_is_ntstatus)
def LsaQueryInformationPolicy(PolicyHandle, InformationClass, Buffer):
    return LsaQueryInformationPolicy.ctypes_function(PolicyHandle, InformationClass, Buffer)

@Advapi32Proxy(error_check=result_is_ntstatus)
def LsaClose(ObjectHandle):
    return LsaClose.ctypes_function(ObjectHandle)

@Advapi32Proxy(error_check=result_is_ntstatus)
def LsaNtStatusToWinError(Status):
    return LsaNtStatusToWinError.ctypes_function(Status)

@Advapi32Proxy(error_check=result_is_ntstatus)
def LsaLookupNames(PolicyHandle, Count, Names, ReferencedDomains, Sids):
    return LsaLookupNames.ctypes_function(PolicyHandle, Count, Names, ReferencedDomains, Sids)

@Advapi32Proxy(error_check=result_is_ntstatus)
def LsaLookupNames2(PolicyHandle, Flags, Count, Names, ReferencedDomains, Sids):
    return LsaLookupNames2.ctypes_function(PolicyHandle, Flags, Count, Names, ReferencedDomains, Sids)

@Advapi32Proxy(error_check=result_is_ntstatus)
def LsaLookupSids(PolicyHandle, Count, Sids, ReferencedDomains, Names):
    return LsaLookupSids.ctypes_function(PolicyHandle, Count, Sids, ReferencedDomains, Names)

@Advapi32Proxy(error_check=result_is_ntstatus)
def LsaLookupSids2(PolicyHandle, LookupOptions, Count, Sids, ReferencedDomains, Names):
    return LsaLookupSids2.ctypes_function(PolicyHandle, LookupOptions, Count, Sids, ReferencedDomains, Names)

