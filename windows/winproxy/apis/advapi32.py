import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero, succeed_on_zero, result_is_error_code

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

# Sid

@Advapi32Proxy()
def LookupAccountSidA(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
    return LookupAccountSidA.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)


@Advapi32Proxy()
def LookupAccountSidW(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
    return LookupAccountSidW.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)

@Advapi32Proxy()
def CreateWellKnownSid(WellKnownSidType, DomainSid=None, pSid=None, cbSid=NeededParameter):
    return CreateWellKnownSid.ctypes_function(WellKnownSidType, DomainSid, pSid, cbSid)

@Advapi32Proxy()
def GetLengthSid(pSid):
    return GetLengthSid.ctypes_function(pSid)

@Advapi32Proxy()
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

@Advapi32Proxy(error_check=succeed_on_zero)
def GetSecurityInfo(handle, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None):
    return GetSecurityInfo.ctypes_function(handle, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)

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
def GetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, lpbGroupDefaulted):
   return GetSecurityDescriptorGroup.ctypes_function(pSecurityDescriptor, pGroup, lpbGroupDefaulted)

@Advapi32Proxy()
def GetSecurityDescriptorSacl(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted):
   return GetSecurityDescriptorSacl.ctypes_function(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted)

# ACE - ACL

@Advapi32Proxy()
def GetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass):
    return GetAclInformation.ctypes_function(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass)

@Advapi32Proxy()
def GetAce(pAcl, dwAceIndex, pAce):
   return GetAce.ctypes_function(pAcl, dwAceIndex, pAce)

# Registry

@Advapi32Proxy(error_check=succeed_on_zero)
def RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult):
    return RegOpenKeyExA.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)

@Advapi32Proxy(error_check=succeed_on_zero)
def RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult):
    return RegOpenKeyExW.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)

@Advapi32Proxy(error_check=succeed_on_zero)
def RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
    return RegGetValueA.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)

@Advapi32Proxy(error_check=succeed_on_zero)
def RegGetValueW(hkey, lpSubKey=None, lpValue=NeededParameter, dwFlags=0, pdwType=None, pvData=None, pcbData=None):
    return RegGetValueW.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)

@Advapi32Proxy(error_check=succeed_on_zero)
def RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
    return RegQueryValueExA.ctypes_function(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)

@Advapi32Proxy(error_check=succeed_on_zero)
def RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
    return RegQueryValueExA.ctypes_function(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)

@Advapi32Proxy(error_check=succeed_on_zero)
def RegCloseKey(hKey):
    return RegCloseKey.ctypes_function(hKey)

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
def CloseServiceHandle(hSCObject):
    return CloseServiceHandle.ctypes_function(hSCObject)

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

