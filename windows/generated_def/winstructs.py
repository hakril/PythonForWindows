#Generated file


from ctypes import *
from ctypes.wintypes import *
from windef import *
BYTE = c_ubyte
PWSTR = LPWSTR
PCWSTR = LPWSTR
SIZE_T = c_size_t
PSIZE_T = POINTER(SIZE_T)
PVOID = c_void_p
PPS_POST_PROCESS_INIT_ROUTINE = PVOID
NTSTATUS = DWORD
SECURITY_INFORMATION = DWORD
PSECURITY_INFORMATION = POINTER(SECURITY_INFORMATION)
PULONG = POINTER(ULONG)
PDWORD = POINTER(DWORD)
LPDWORD = POINTER(DWORD)
LPTHREAD_START_ROUTINE = PVOID
WNDENUMPROC = PVOID
PHANDLER_ROUTINE = PVOID
LPBYTE = POINTER(BYTE)
ULONG_PTR = PVOID
DWORD_PTR = ULONG_PTR
KAFFINITY = ULONG_PTR
KPRIORITY = LONG
CHAR = c_char
INT = c_int
UCHAR = c_char
CSHORT = c_short
VARTYPE = c_ushort
PBOOL = POINTER(BOOL)
PSTR = LPSTR
PCSTR = LPSTR
va_list = c_char_p
BSTR = c_wchar_p
OLECHAR = c_wchar
POLECHAR = c_wchar_p
PUCHAR = POINTER(UCHAR)
double = c_double
FARPROC = PVOID
HGLOBAL = PVOID
PSID = PVOID
PVECTORED_EXCEPTION_HANDLER = PVOID
ULONGLONG = c_ulonglong
LONGLONG = c_longlong
ULONG64 = c_ulonglong
UINT64 = ULONG64
LONG64 = c_longlong
LARGE_INTEGER = LONGLONG
PLARGE_INTEGER = POINTER(LARGE_INTEGER)
DWORD64 = ULONG64
SCODE = LONG
CIMTYPE = LONG
NET_IFINDEX = ULONG
IF_INDEX = NET_IFINDEX
IFTYPE = ULONG
PULONG64 = POINTER(ULONG64)
PUINT = POINTER(UINT)
PHANDLE = POINTER(HANDLE)
HKEY = HANDLE
HCATADMIN = HANDLE
HCATINFO = HANDLE
HDC = HANDLE
HBITMAP = HANDLE
SC_HANDLE = HANDLE
HCERTCHAINENGINE = HANDLE
LPHANDLE = POINTER(HANDLE)
ALPC_HANDLE = HANDLE
PALPC_HANDLE = POINTER(ALPC_HANDLE)
PHKEY = POINTER(HKEY)
ACCESS_MASK = DWORD
REGSAM = ACCESS_MASK
SECURITY_CONTEXT_TRACKING_MODE = BOOLEAN
HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = PULONG
HCRYPTPROV_LEGACY = PULONG
HCRYPTKEY = PULONG
HCRYPTPROV = PULONG
HCRYPTHASH = PULONG
ALG_ID = UINT
DISPID = LONG
MEMBERID = DISPID
PSECURITY_DESCRIPTOR = PVOID
LPPROC_THREAD_ATTRIBUTE_LIST = PVOID
LPUNKNOWN = POINTER(PVOID)
SPC_UUID = BYTE * 16
PWINDBG_EXTENSION_APIS32 = PVOID
PWINDBG_EXTENSION_APIS64 = PVOID
LPCONTEXT = PVOID
HCERTSTORE = PVOID
HCRYPTMSG = PVOID
PALPC_PORT_ATTRIBUTES = PVOID
VOID = DWORD
class EnumValue(Flag):
    def __new__(cls, enum_name, name, value):
        return super(EnumValue, cls).__new__(cls, name, value)

    def __init__(self, enum_name, name, value):
        self.enum_name = enum_name
        self.name = name

    def __repr__(self):
        return "{0}.{1}({2})".format(self.enum_name, self.name, hex(self))

    # Fix pickling with protocol 2
    def __getnewargs__(self, *args):
        return self.enum_name, self.name, int(self)


class EnumType(DWORD):
    values = ()
    mapper = {}

    @property
    def value(self):
        raw_value = super(EnumType, self).value
        return self.mapper.get(raw_value, raw_value)

    def __repr__(self):
        raw_value = super(EnumType, self).value
        if raw_value in self.values:
            value = self.value
            return "<{0} {1}({2})>".format(type(self).__name__, value.name, hex(raw_value))
        return "<{0}({1})>".format(type(self).__name__, hex(self.value))


SystemBasicInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBasicInformation", 0x0)
SystemProcessorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorInformation", 0x1)
SystemPerformanceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPerformanceInformation", 0x2)
SystemTimeOfDayInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemTimeOfDayInformation", 0x3)
SystemPathInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPathInformation", 0x4)
SystemProcessInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessInformation", 0x5)
SystemCallCountInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCallCountInformation", 0x6)
SystemDeviceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDeviceInformation", 0x7)
SystemProcessorPerformanceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorPerformanceInformation", 0x8)
SystemFlagsInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFlagsInformation", 0x9)
SystemCallTimeInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCallTimeInformation", 0xa)
SystemModuleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemModuleInformation", 0xb)
SystemLocksInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLocksInformation", 0xc)
SystemStackTraceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemStackTraceInformation", 0xd)
SystemPagedPoolInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPagedPoolInformation", 0xe)
SystemNonPagedPoolInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemNonPagedPoolInformation", 0xf)
SystemHandleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemHandleInformation", 0x10)
SystemObjectInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemObjectInformation", 0x11)
SystemPageFileInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPageFileInformation", 0x12)
SystemVdmInstemulInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVdmInstemulInformation", 0x13)
SystemVdmBopInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVdmBopInformation", 0x14)
SystemFileCacheInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFileCacheInformation", 0x15)
SystemPoolTagInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPoolTagInformation", 0x16)
SystemInterruptInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemInterruptInformation", 0x17)
SystemDpcBehaviorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemDpcBehaviorInformation", 0x18)
SystemFullMemoryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFullMemoryInformation", 0x19)
SystemLoadGdiDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLoadGdiDriverInformation", 0x1a)
SystemUnloadGdiDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemUnloadGdiDriverInformation", 0x1b)
SystemTimeAdjustmentInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemTimeAdjustmentInformation", 0x1c)
SystemSummaryMemoryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSummaryMemoryInformation", 0x1d)
SystemMirrorMemoryInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemMirrorMemoryInformation", 0x1e)
SystemPerformanceTraceInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPerformanceTraceInformation", 0x1f)
SystemObsolete0 = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemObsolete0", 0x20)
SystemExceptionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemExceptionInformation", 0x21)
SystemCrashDumpStateInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCrashDumpStateInformation", 0x22)
SystemKernelDebuggerInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemKernelDebuggerInformation", 0x23)
SystemContextSwitchInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemContextSwitchInformation", 0x24)
SystemRegistryQuotaInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRegistryQuotaInformation", 0x25)
SystemExtendServiceTableInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemExtendServiceTableInformation", 0x26)
SystemPrioritySeperation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPrioritySeperation", 0x27)
SystemVerifierAddDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierAddDriverInformation", 0x28)
SystemVerifierRemoveDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierRemoveDriverInformation", 0x29)
SystemProcessorIdleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorIdleInformation", 0x2a)
SystemLegacyDriverInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLegacyDriverInformation", 0x2b)
SystemCurrentTimeZoneInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemCurrentTimeZoneInformation", 0x2c)
SystemLookasideInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLookasideInformation", 0x2d)
SystemTimeSlipNotification = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemTimeSlipNotification", 0x2e)
SystemSessionCreate = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionCreate", 0x2f)
SystemSessionDetach = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionDetach", 0x30)
SystemSessionInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionInformation", 0x31)
SystemRangeStartInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRangeStartInformation", 0x32)
SystemVerifierInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierInformation", 0x33)
SystemVerifierThunkExtend = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierThunkExtend", 0x34)
SystemSessionProcessInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionProcessInformation", 0x35)
SystemLoadGdiDriverInSystemSpace = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLoadGdiDriverInSystemSpace", 0x36)
SystemNumaProcessorMap = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemNumaProcessorMap", 0x37)
SystemPrefetcherInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemPrefetcherInformation", 0x38)
SystemExtendedProcessInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemExtendedProcessInformation", 0x39)
SystemRecommendedSharedDataAlignment = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRecommendedSharedDataAlignment", 0x3a)
SystemComPlusPackage = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemComPlusPackage", 0x3b)
SystemNumaAvailableMemory = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemNumaAvailableMemory", 0x3c)
SystemProcessorPowerInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemProcessorPowerInformation", 0x3d)
SystemEmulationBasicInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemEmulationBasicInformation", 0x3e)
SystemEmulationProcessorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemEmulationProcessorInformation", 0x3f)
SystemExtendedHandleInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemExtendedHandleInformation", 0x40)
SystemLostDelayedWriteInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLostDelayedWriteInformation", 0x41)
SystemBigPoolInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemBigPoolInformation", 0x42)
SystemSessionPoolTagInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionPoolTagInformation", 0x43)
SystemSessionMappedViewInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSessionMappedViewInformation", 0x44)
SystemHotpatchInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemHotpatchInformation", 0x45)
SystemObjectSecurityMode = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemObjectSecurityMode", 0x46)
SystemWatchdogTimerHandler = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWatchdogTimerHandler", 0x47)
SystemWatchdogTimerInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWatchdogTimerInformation", 0x48)
SystemLogicalProcessorInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemLogicalProcessorInformation", 0x49)
SystemWow64SharedInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemWow64SharedInformation", 0x4a)
SystemRegisterFirmwareTableInformationHandler = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemRegisterFirmwareTableInformationHandler", 0x4b)
SystemFirmwareTableInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFirmwareTableInformation", 0x4c)
SystemModuleInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemModuleInformationEx", 0x4d)
SystemVerifierTriageInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemVerifierTriageInformation", 0x4e)
SystemSuperfetchInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemSuperfetchInformation", 0x4f)
SystemMemoryListInformation = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemMemoryListInformation", 0x50)
SystemFileCacheInformationEx = EnumValue("_SYSTEM_INFORMATION_CLASS", "SystemFileCacheInformationEx", 0x51)
MaxSystemInfoClass = EnumValue("_SYSTEM_INFORMATION_CLASS", "MaxSystemInfoClass", 0x52)
class _SYSTEM_INFORMATION_CLASS(EnumType):
    values = [SystemBasicInformation, SystemProcessorInformation, SystemPerformanceInformation, SystemTimeOfDayInformation, SystemPathInformation, SystemProcessInformation, SystemCallCountInformation, SystemDeviceInformation, SystemProcessorPerformanceInformation, SystemFlagsInformation, SystemCallTimeInformation, SystemModuleInformation, SystemLocksInformation, SystemStackTraceInformation, SystemPagedPoolInformation, SystemNonPagedPoolInformation, SystemHandleInformation, SystemObjectInformation, SystemPageFileInformation, SystemVdmInstemulInformation, SystemVdmBopInformation, SystemFileCacheInformation, SystemPoolTagInformation, SystemInterruptInformation, SystemDpcBehaviorInformation, SystemFullMemoryInformation, SystemLoadGdiDriverInformation, SystemUnloadGdiDriverInformation, SystemTimeAdjustmentInformation, SystemSummaryMemoryInformation, SystemMirrorMemoryInformation, SystemPerformanceTraceInformation, SystemObsolete0, SystemExceptionInformation, SystemCrashDumpStateInformation, SystemKernelDebuggerInformation, SystemContextSwitchInformation, SystemRegistryQuotaInformation, SystemExtendServiceTableInformation, SystemPrioritySeperation, SystemVerifierAddDriverInformation, SystemVerifierRemoveDriverInformation, SystemProcessorIdleInformation, SystemLegacyDriverInformation, SystemCurrentTimeZoneInformation, SystemLookasideInformation, SystemTimeSlipNotification, SystemSessionCreate, SystemSessionDetach, SystemSessionInformation, SystemRangeStartInformation, SystemVerifierInformation, SystemVerifierThunkExtend, SystemSessionProcessInformation, SystemLoadGdiDriverInSystemSpace, SystemNumaProcessorMap, SystemPrefetcherInformation, SystemExtendedProcessInformation, SystemRecommendedSharedDataAlignment, SystemComPlusPackage, SystemNumaAvailableMemory, SystemProcessorPowerInformation, SystemEmulationBasicInformation, SystemEmulationProcessorInformation, SystemExtendedHandleInformation, SystemLostDelayedWriteInformation, SystemBigPoolInformation, SystemSessionPoolTagInformation, SystemSessionMappedViewInformation, SystemHotpatchInformation, SystemObjectSecurityMode, SystemWatchdogTimerHandler, SystemWatchdogTimerInformation, SystemLogicalProcessorInformation, SystemWow64SharedInformation, SystemRegisterFirmwareTableInformationHandler, SystemFirmwareTableInformation, SystemModuleInformationEx, SystemVerifierTriageInformation, SystemSuperfetchInformation, SystemMemoryListInformation, SystemFileCacheInformationEx, MaxSystemInfoClass]
    mapper = {x:x for x in values}
SYSTEM_INFORMATION_CLASS = _SYSTEM_INFORMATION_CLASS


WinNullSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNullSid", 0x0)
WinWorldSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinWorldSid", 0x1)
WinLocalSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLocalSid", 0x2)
WinCreatorOwnerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorOwnerSid", 0x3)
WinCreatorGroupSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorGroupSid", 0x4)
WinCreatorOwnerServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorOwnerServerSid", 0x5)
WinCreatorGroupServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorGroupServerSid", 0x6)
WinNtAuthoritySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNtAuthoritySid", 0x7)
WinDialupSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinDialupSid", 0x8)
WinNetworkSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNetworkSid", 0x9)
WinBatchSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBatchSid", 0xa)
WinInteractiveSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinInteractiveSid", 0xb)
WinServiceSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinServiceSid", 0xc)
WinAnonymousSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAnonymousSid", 0xd)
WinProxySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinProxySid", 0xe)
WinEnterpriseControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinEnterpriseControllersSid", 0xf)
WinSelfSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinSelfSid", 0x10)
WinAuthenticatedUserSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAuthenticatedUserSid", 0x11)
WinRestrictedCodeSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinRestrictedCodeSid", 0x12)
WinTerminalServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinTerminalServerSid", 0x13)
WinRemoteLogonIdSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinRemoteLogonIdSid", 0x14)
WinLogonIdsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLogonIdsSid", 0x15)
WinLocalSystemSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLocalSystemSid", 0x16)
WinLocalServiceSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLocalServiceSid", 0x17)
WinNetworkServiceSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNetworkServiceSid", 0x18)
WinBuiltinDomainSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinDomainSid", 0x19)
WinBuiltinAdministratorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinAdministratorsSid", 0x1a)
WinBuiltinUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinUsersSid", 0x1b)
WinBuiltinGuestsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinGuestsSid", 0x1c)
WinBuiltinPowerUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPowerUsersSid", 0x1d)
WinBuiltinAccountOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinAccountOperatorsSid", 0x1e)
WinBuiltinSystemOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinSystemOperatorsSid", 0x1f)
WinBuiltinPrintOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPrintOperatorsSid", 0x20)
WinBuiltinBackupOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinBackupOperatorsSid", 0x21)
WinBuiltinReplicatorSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinReplicatorSid", 0x22)
WinBuiltinPreWindows2000CompatibleAccessSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPreWindows2000CompatibleAccessSid", 0x23)
WinBuiltinRemoteDesktopUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinRemoteDesktopUsersSid", 0x24)
WinBuiltinNetworkConfigurationOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinNetworkConfigurationOperatorsSid", 0x25)
WinAccountAdministratorSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountAdministratorSid", 0x26)
WinAccountGuestSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountGuestSid", 0x27)
WinAccountKrbtgtSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountKrbtgtSid", 0x28)
WinAccountDomainAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountDomainAdminsSid", 0x29)
WinAccountDomainUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountDomainUsersSid", 0x2a)
WinAccountDomainGuestsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountDomainGuestsSid", 0x2b)
WinAccountComputersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountComputersSid", 0x2c)
WinAccountControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountControllersSid", 0x2d)
WinAccountCertAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountCertAdminsSid", 0x2e)
WinAccountSchemaAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountSchemaAdminsSid", 0x2f)
WinAccountEnterpriseAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountEnterpriseAdminsSid", 0x30)
WinAccountPolicyAdminsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountPolicyAdminsSid", 0x31)
WinAccountRasAndIasServersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountRasAndIasServersSid", 0x32)
WinNTLMAuthenticationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNTLMAuthenticationSid", 0x33)
WinDigestAuthenticationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinDigestAuthenticationSid", 0x34)
WinSChannelAuthenticationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinSChannelAuthenticationSid", 0x35)
WinThisOrganizationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinThisOrganizationSid", 0x36)
WinOtherOrganizationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinOtherOrganizationSid", 0x37)
WinBuiltinIncomingForestTrustBuildersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinIncomingForestTrustBuildersSid", 0x38)
WinBuiltinPerfMonitoringUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPerfMonitoringUsersSid", 0x39)
WinBuiltinPerfLoggingUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinPerfLoggingUsersSid", 0x3a)
WinBuiltinAuthorizationAccessSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinAuthorizationAccessSid", 0x3b)
WinBuiltinTerminalServerLicenseServersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinTerminalServerLicenseServersSid", 0x3c)
WinBuiltinDCOMUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinDCOMUsersSid", 0x3d)
WinBuiltinIUsersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinIUsersSid", 0x3e)
WinIUserSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinIUserSid", 0x3f)
WinBuiltinCryptoOperatorsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinCryptoOperatorsSid", 0x40)
WinUntrustedLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinUntrustedLabelSid", 0x41)
WinLowLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLowLabelSid", 0x42)
WinMediumLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinMediumLabelSid", 0x43)
WinHighLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinHighLabelSid", 0x44)
WinSystemLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinSystemLabelSid", 0x45)
WinWriteRestrictedCodeSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinWriteRestrictedCodeSid", 0x46)
WinCreatorOwnerRightsSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCreatorOwnerRightsSid", 0x47)
WinCacheablePrincipalsGroupSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCacheablePrincipalsGroupSid", 0x48)
WinNonCacheablePrincipalsGroupSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNonCacheablePrincipalsGroupSid", 0x49)
WinEnterpriseReadonlyControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinEnterpriseReadonlyControllersSid", 0x4a)
WinAccountReadonlyControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinAccountReadonlyControllersSid", 0x4b)
WinBuiltinEventLogReadersGroup = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinEventLogReadersGroup", 0x4c)
WinNewEnterpriseReadonlyControllersSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinNewEnterpriseReadonlyControllersSid", 0x4d)
WinBuiltinCertSvcDComAccessGroup = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinCertSvcDComAccessGroup", 0x4e)
WinMediumPlusLabelSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinMediumPlusLabelSid", 0x4f)
WinLocalLogonSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinLocalLogonSid", 0x50)
WinConsoleLogonSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinConsoleLogonSid", 0x51)
WinThisOrganizationCertificateSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinThisOrganizationCertificateSid", 0x52)
WinApplicationPackageAuthoritySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinApplicationPackageAuthoritySid", 0x53)
WinBuiltinAnyPackageSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinBuiltinAnyPackageSid", 0x54)
WinCapabilityInternetClientSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityInternetClientSid", 0x55)
WinCapabilityInternetClientServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityInternetClientServerSid", 0x56)
WinCapabilityPrivateNetworkClientServerSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityPrivateNetworkClientServerSid", 0x57)
WinCapabilityPicturesLibrarySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityPicturesLibrarySid", 0x58)
WinCapabilityVideosLibrarySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityVideosLibrarySid", 0x59)
WinCapabilityMusicLibrarySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityMusicLibrarySid", 0x5a)
WinCapabilityDocumentsLibrarySid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityDocumentsLibrarySid", 0x5b)
WinCapabilitySharedUserCertificatesSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilitySharedUserCertificatesSid", 0x5c)
WinCapabilityEnterpriseAuthenticationSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityEnterpriseAuthenticationSid", 0x5d)
WinCapabilityRemovableStorageSid = EnumValue("_WELL_KNOWN_SID_TYPE", "WinCapabilityRemovableStorageSid", 0x5e)
class _WELL_KNOWN_SID_TYPE(EnumType):
    values = [WinNullSid, WinWorldSid, WinLocalSid, WinCreatorOwnerSid, WinCreatorGroupSid, WinCreatorOwnerServerSid, WinCreatorGroupServerSid, WinNtAuthoritySid, WinDialupSid, WinNetworkSid, WinBatchSid, WinInteractiveSid, WinServiceSid, WinAnonymousSid, WinProxySid, WinEnterpriseControllersSid, WinSelfSid, WinAuthenticatedUserSid, WinRestrictedCodeSid, WinTerminalServerSid, WinRemoteLogonIdSid, WinLogonIdsSid, WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid, WinBuiltinDomainSid, WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinBuiltinGuestsSid, WinBuiltinPowerUsersSid, WinBuiltinAccountOperatorsSid, WinBuiltinSystemOperatorsSid, WinBuiltinPrintOperatorsSid, WinBuiltinBackupOperatorsSid, WinBuiltinReplicatorSid, WinBuiltinPreWindows2000CompatibleAccessSid, WinBuiltinRemoteDesktopUsersSid, WinBuiltinNetworkConfigurationOperatorsSid, WinAccountAdministratorSid, WinAccountGuestSid, WinAccountKrbtgtSid, WinAccountDomainAdminsSid, WinAccountDomainUsersSid, WinAccountDomainGuestsSid, WinAccountComputersSid, WinAccountControllersSid, WinAccountCertAdminsSid, WinAccountSchemaAdminsSid, WinAccountEnterpriseAdminsSid, WinAccountPolicyAdminsSid, WinAccountRasAndIasServersSid, WinNTLMAuthenticationSid, WinDigestAuthenticationSid, WinSChannelAuthenticationSid, WinThisOrganizationSid, WinOtherOrganizationSid, WinBuiltinIncomingForestTrustBuildersSid, WinBuiltinPerfMonitoringUsersSid, WinBuiltinPerfLoggingUsersSid, WinBuiltinAuthorizationAccessSid, WinBuiltinTerminalServerLicenseServersSid, WinBuiltinDCOMUsersSid, WinBuiltinIUsersSid, WinIUserSid, WinBuiltinCryptoOperatorsSid, WinUntrustedLabelSid, WinLowLabelSid, WinMediumLabelSid, WinHighLabelSid, WinSystemLabelSid, WinWriteRestrictedCodeSid, WinCreatorOwnerRightsSid, WinCacheablePrincipalsGroupSid, WinNonCacheablePrincipalsGroupSid, WinEnterpriseReadonlyControllersSid, WinAccountReadonlyControllersSid, WinBuiltinEventLogReadersGroup, WinNewEnterpriseReadonlyControllersSid, WinBuiltinCertSvcDComAccessGroup, WinMediumPlusLabelSid, WinLocalLogonSid, WinConsoleLogonSid, WinThisOrganizationCertificateSid, WinApplicationPackageAuthoritySid, WinBuiltinAnyPackageSid, WinCapabilityInternetClientSid, WinCapabilityInternetClientServerSid, WinCapabilityPrivateNetworkClientServerSid, WinCapabilityPicturesLibrarySid, WinCapabilityVideosLibrarySid, WinCapabilityMusicLibrarySid, WinCapabilityDocumentsLibrarySid, WinCapabilitySharedUserCertificatesSid, WinCapabilityEnterpriseAuthenticationSid, WinCapabilityRemovableStorageSid]
    mapper = {x:x for x in values}
WELL_KNOWN_SID_TYPE = _WELL_KNOWN_SID_TYPE


ViewShare = EnumValue("_SECTION_INHERIT", "ViewShare", 0x1)
ViewUnmap = EnumValue("_SECTION_INHERIT", "ViewUnmap", 0x2)
class _SECTION_INHERIT(EnumType):
    values = [ViewShare, ViewUnmap]
    mapper = {x:x for x in values}
SECTION_INHERIT = _SECTION_INHERIT


MemoryBasicInformation = EnumValue("_MEMORY_INFORMATION_CLASS", "MemoryBasicInformation", 0x0)
MemoryWorkingSetList = EnumValue("_MEMORY_INFORMATION_CLASS", "MemoryWorkingSetList", 0x1)
MemorySectionName = EnumValue("_MEMORY_INFORMATION_CLASS", "MemorySectionName", 0x2)
MemoryBasicVlmInformation = EnumValue("_MEMORY_INFORMATION_CLASS", "MemoryBasicVlmInformation", 0x3)
MemoryWorkingSetListEx = EnumValue("_MEMORY_INFORMATION_CLASS", "MemoryWorkingSetListEx", 0x4)
class _MEMORY_INFORMATION_CLASS(EnumType):
    values = [MemoryBasicInformation, MemoryWorkingSetList, MemorySectionName, MemoryBasicVlmInformation, MemoryWorkingSetListEx]
    mapper = {x:x for x in values}
MEMORY_INFORMATION_CLASS = _MEMORY_INFORMATION_CLASS


ThreadBasicInformation = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadBasicInformation", 0x0)
ThreadTimes = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadTimes", 0x1)
ThreadPriority = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadPriority", 0x2)
ThreadBasePriority = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadBasePriority", 0x3)
ThreadAffinityMask = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadAffinityMask", 0x4)
ThreadImpersonationToken = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadImpersonationToken", 0x5)
ThreadDescriptorTableEntry = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadDescriptorTableEntry", 0x6)
ThreadEnableAlignmentFaultFixup = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadEnableAlignmentFaultFixup", 0x7)
ThreadEventPair = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadEventPair", 0x8)
ThreadQuerySetWin32StartAddress = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadQuerySetWin32StartAddress", 0x9)
ThreadZeroTlsCell = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadZeroTlsCell", 0xa)
ThreadPerformanceCount = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadPerformanceCount", 0xb)
ThreadAmILastThread = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadAmILastThread", 0xc)
ThreadIdealProcessor = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadIdealProcessor", 0xd)
ThreadPriorityBoost = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadPriorityBoost", 0xe)
ThreadSetTlsArrayAddress = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadSetTlsArrayAddress", 0xf)
ThreadIsIoPending = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadIsIoPending", 0x10)
ThreadHideFromDebugger = EnumValue("_THREAD_INFORMATION_CLASS", "ThreadHideFromDebugger", 0x11)
class _THREAD_INFORMATION_CLASS(EnumType):
    values = [ThreadBasicInformation, ThreadTimes, ThreadPriority, ThreadBasePriority, ThreadAffinityMask, ThreadImpersonationToken, ThreadDescriptorTableEntry, ThreadEnableAlignmentFaultFixup, ThreadEventPair, ThreadQuerySetWin32StartAddress, ThreadZeroTlsCell, ThreadPerformanceCount, ThreadAmILastThread, ThreadIdealProcessor, ThreadPriorityBoost, ThreadSetTlsArrayAddress, ThreadIsIoPending, ThreadHideFromDebugger]
    mapper = {x:x for x in values}
THREAD_INFORMATION_CLASS = _THREAD_INFORMATION_CLASS
PTHREAD_INFORMATION_CLASS = POINTER(_THREAD_INFORMATION_CLASS)


TCP_TABLE_BASIC_LISTENER = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_BASIC_LISTENER", 0x0)
TCP_TABLE_BASIC_CONNECTIONS = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_BASIC_CONNECTIONS", 0x1)
TCP_TABLE_BASIC_ALL = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_BASIC_ALL", 0x2)
TCP_TABLE_OWNER_PID_LISTENER = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_PID_LISTENER", 0x3)
TCP_TABLE_OWNER_PID_CONNECTIONS = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_PID_CONNECTIONS", 0x4)
TCP_TABLE_OWNER_PID_ALL = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_PID_ALL", 0x5)
TCP_TABLE_OWNER_MODULE_LISTENER = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_MODULE_LISTENER", 0x6)
TCP_TABLE_OWNER_MODULE_CONNECTIONS = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_MODULE_CONNECTIONS", 0x7)
TCP_TABLE_OWNER_MODULE_ALL = EnumValue("_TCP_TABLE_CLASS", "TCP_TABLE_OWNER_MODULE_ALL", 0x8)
class _TCP_TABLE_CLASS(EnumType):
    values = [TCP_TABLE_BASIC_LISTENER, TCP_TABLE_BASIC_CONNECTIONS, TCP_TABLE_BASIC_ALL, TCP_TABLE_OWNER_PID_LISTENER, TCP_TABLE_OWNER_PID_CONNECTIONS, TCP_TABLE_OWNER_PID_ALL, TCP_TABLE_OWNER_MODULE_LISTENER, TCP_TABLE_OWNER_MODULE_CONNECTIONS, TCP_TABLE_OWNER_MODULE_ALL]
    mapper = {x:x for x in values}
TCP_TABLE_CLASS = _TCP_TABLE_CLASS


VT_EMPTY = EnumValue("_VARENUM", "VT_EMPTY", 0x0)
VT_NULL = EnumValue("_VARENUM", "VT_NULL", 0x1)
VT_I2 = EnumValue("_VARENUM", "VT_I2", 0x2)
VT_I4 = EnumValue("_VARENUM", "VT_I4", 0x3)
VT_R4 = EnumValue("_VARENUM", "VT_R4", 0x4)
VT_R8 = EnumValue("_VARENUM", "VT_R8", 0x5)
VT_CY = EnumValue("_VARENUM", "VT_CY", 0x6)
VT_DATE = EnumValue("_VARENUM", "VT_DATE", 0x7)
VT_BSTR = EnumValue("_VARENUM", "VT_BSTR", 0x8)
VT_DISPATCH = EnumValue("_VARENUM", "VT_DISPATCH", 0x9)
VT_ERROR = EnumValue("_VARENUM", "VT_ERROR", 0xa)
VT_BOOL = EnumValue("_VARENUM", "VT_BOOL", 0xb)
VT_VARIANT = EnumValue("_VARENUM", "VT_VARIANT", 0xc)
VT_UNKNOWN = EnumValue("_VARENUM", "VT_UNKNOWN", 0xd)
VT_DECIMAL = EnumValue("_VARENUM", "VT_DECIMAL", 0xe)
VT_I1 = EnumValue("_VARENUM", "VT_I1", 0x10)
VT_UI1 = EnumValue("_VARENUM", "VT_UI1", 0x11)
VT_UI2 = EnumValue("_VARENUM", "VT_UI2", 0x12)
VT_UI4 = EnumValue("_VARENUM", "VT_UI4", 0x13)
VT_I8 = EnumValue("_VARENUM", "VT_I8", 0x14)
VT_UI8 = EnumValue("_VARENUM", "VT_UI8", 0x15)
VT_INT = EnumValue("_VARENUM", "VT_INT", 0x16)
VT_UINT = EnumValue("_VARENUM", "VT_UINT", 0x17)
VT_VOID = EnumValue("_VARENUM", "VT_VOID", 0x18)
VT_HRESULT = EnumValue("_VARENUM", "VT_HRESULT", 0x19)
VT_PTR = EnumValue("_VARENUM", "VT_PTR", 0x1a)
VT_SAFEARRAY = EnumValue("_VARENUM", "VT_SAFEARRAY", 0x1b)
VT_CARRAY = EnumValue("_VARENUM", "VT_CARRAY", 0x1c)
VT_USERDEFINED = EnumValue("_VARENUM", "VT_USERDEFINED", 0x1d)
VT_LPSTR = EnumValue("_VARENUM", "VT_LPSTR", 0x1e)
VT_LPWSTR = EnumValue("_VARENUM", "VT_LPWSTR", 0x1f)
VT_RECORD = EnumValue("_VARENUM", "VT_RECORD", 0x24)
VT_INT_PTR = EnumValue("_VARENUM", "VT_INT_PTR", 0x25)
VT_UINT_PTR = EnumValue("_VARENUM", "VT_UINT_PTR", 0x26)
VT_FILETIME = EnumValue("_VARENUM", "VT_FILETIME", 0x40)
VT_BLOB = EnumValue("_VARENUM", "VT_BLOB", 0x41)
VT_STREAM = EnumValue("_VARENUM", "VT_STREAM", 0x42)
VT_STORAGE = EnumValue("_VARENUM", "VT_STORAGE", 0x43)
VT_STREAMED_OBJECT = EnumValue("_VARENUM", "VT_STREAMED_OBJECT", 0x44)
VT_STORED_OBJECT = EnumValue("_VARENUM", "VT_STORED_OBJECT", 0x45)
VT_BLOB_OBJECT = EnumValue("_VARENUM", "VT_BLOB_OBJECT", 0x46)
VT_CF = EnumValue("_VARENUM", "VT_CF", 0x47)
VT_CLSID = EnumValue("_VARENUM", "VT_CLSID", 0x48)
VT_VERSIONED_STREAM = EnumValue("_VARENUM", "VT_VERSIONED_STREAM", 0x49)
VT_BSTR_BLOB = EnumValue("_VARENUM", "VT_BSTR_BLOB", 0xfff)
VT_VECTOR = EnumValue("_VARENUM", "VT_VECTOR", 0x1000)
VT_ARRAY = EnumValue("_VARENUM", "VT_ARRAY", 0x2000)
VT_BYREF = EnumValue("_VARENUM", "VT_BYREF", 0x4000)
VT_RESERVED = EnumValue("_VARENUM", "VT_RESERVED", 0x8000)
VT_ILLEGAL = EnumValue("_VARENUM", "VT_ILLEGAL", 0xffff)
VT_ILLEGALMASKED = EnumValue("_VARENUM", "VT_ILLEGALMASKED", 0xfff)
VT_TYPEMASK = EnumValue("_VARENUM", "VT_TYPEMASK", 0xfff)
class _VARENUM(EnumType):
    values = [VT_EMPTY, VT_NULL, VT_I2, VT_I4, VT_R4, VT_R8, VT_CY, VT_DATE, VT_BSTR, VT_DISPATCH, VT_ERROR, VT_BOOL, VT_VARIANT, VT_UNKNOWN, VT_DECIMAL, VT_I1, VT_UI1, VT_UI2, VT_UI4, VT_I8, VT_UI8, VT_INT, VT_UINT, VT_VOID, VT_HRESULT, VT_PTR, VT_SAFEARRAY, VT_CARRAY, VT_USERDEFINED, VT_LPSTR, VT_LPWSTR, VT_RECORD, VT_INT_PTR, VT_UINT_PTR, VT_FILETIME, VT_BLOB, VT_STREAM, VT_STORAGE, VT_STREAMED_OBJECT, VT_STORED_OBJECT, VT_BLOB_OBJECT, VT_CF, VT_CLSID, VT_VERSIONED_STREAM, VT_BSTR_BLOB, VT_VECTOR, VT_ARRAY, VT_BYREF, VT_RESERVED, VT_ILLEGAL, VT_ILLEGALMASKED, VT_TYPEMASK]
    mapper = {x:x for x in values}
VARENUM = _VARENUM


UDP_TABLE_BASIC = EnumValue("_UDP_TABLE_CLASS", "UDP_TABLE_BASIC", 0x0)
UDP_TABLE_OWNER_PID = EnumValue("_UDP_TABLE_CLASS", "UDP_TABLE_OWNER_PID", 0x1)
UDP_TABLE_OWNER_MODULE = EnumValue("_UDP_TABLE_CLASS", "UDP_TABLE_OWNER_MODULE", 0x2)
class _UDP_TABLE_CLASS(EnumType):
    values = [UDP_TABLE_BASIC, UDP_TABLE_OWNER_PID, UDP_TABLE_OWNER_MODULE]
    mapper = {x:x for x in values}
UDP_TABLE_CLASS = _UDP_TABLE_CLASS


NET_FW_RULE_DIR_IN = EnumValue("NET_FW_RULE_DIRECTION_", "NET_FW_RULE_DIR_IN", 0x1)
NET_FW_RULE_DIR_OUT = EnumValue("NET_FW_RULE_DIRECTION_", "NET_FW_RULE_DIR_OUT", 0x2)
NET_FW_RULE_DIR_MAX = EnumValue("NET_FW_RULE_DIRECTION_", "NET_FW_RULE_DIR_MAX", 0x3)
class NET_FW_RULE_DIRECTION_(EnumType):
    values = [NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIR_MAX]
    mapper = {x:x for x in values}
NET_FW_RULE_DIRECTION = NET_FW_RULE_DIRECTION_


NET_FW_PROFILE2_DOMAIN = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_DOMAIN", 0x1)
NET_FW_PROFILE2_PRIVATE = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_PRIVATE", 0x2)
NET_FW_PROFILE2_PUBLIC = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_PUBLIC", 0x4)
NET_FW_PROFILE2_ALL = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_ALL", 0x7fffffff)
class NET_FW_PROFILE_TYPE2_(EnumType):
    values = [NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE2_ALL]
    mapper = {x:x for x in values}
NET_FW_PROFILE_TYPE2 = NET_FW_PROFILE_TYPE2_


MIB_TCP_STATE_CLOSED = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_CLOSED", 0x1)
MIB_TCP_STATE_LISTEN = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_LISTEN", 0x2)
MIB_TCP_STATE_SYN_SENT = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_SYN_SENT", 0x3)
MIB_TCP_STATE_SYN_RCVD = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_SYN_RCVD", 0x4)
MIB_TCP_STATE_ESTAB = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_ESTAB", 0x5)
MIB_TCP_STATE_FIN_WAIT1 = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_FIN_WAIT1", 0x6)
MIB_TCP_STATE_FIN_WAIT2 = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_FIN_WAIT2", 0x7)
MIB_TCP_STATE_CLOSE_WAIT = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_CLOSE_WAIT", 0x8)
MIB_TCP_STATE_CLOSING = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_CLOSING", 0x9)
MIB_TCP_STATE_LAST_ACK = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_LAST_ACK", 0xa)
MIB_TCP_STATE_TIME_WAIT = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_TIME_WAIT", 0xb)
MIB_TCP_STATE_DELETE_TCB = EnumValue("_MIB_TCP_STATE", "MIB_TCP_STATE_DELETE_TCB", 0xc)
class _MIB_TCP_STATE(EnumType):
    values = [MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1, MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_TIME_WAIT, MIB_TCP_STATE_DELETE_TCB]
    mapper = {x:x for x in values}
MIB_TCP_STATE = _MIB_TCP_STATE


NET_FW_IP_PROTOCOL_TCP = EnumValue("NET_FW_IP_PROTOCOL_", "NET_FW_IP_PROTOCOL_TCP", 0x6)
NET_FW_IP_PROTOCOL_UDP = EnumValue("NET_FW_IP_PROTOCOL_", "NET_FW_IP_PROTOCOL_UDP", 0x11)
NET_FW_IP_PROTOCOL_ANY = EnumValue("NET_FW_IP_PROTOCOL_", "NET_FW_IP_PROTOCOL_ANY", 0x100)
class NET_FW_IP_PROTOCOL_(EnumType):
    values = [NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_IP_PROTOCOL_ANY]
    mapper = {x:x for x in values}
NET_FW_IP_PROTOCOL = NET_FW_IP_PROTOCOL_


TokenInvalid = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenInvalid", 0x0)
TokenUser = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenUser", 0x1)
TokenGroups = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenGroups", 0x2)
TokenPrivileges = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenPrivileges", 0x3)
TokenOwner = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenOwner", 0x4)
TokenPrimaryGroup = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenPrimaryGroup", 0x5)
TokenDefaultDacl = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenDefaultDacl", 0x6)
TokenSource = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSource", 0x7)
TokenType = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenType", 0x8)
TokenImpersonationLevel = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenImpersonationLevel", 0x9)
TokenStatistics = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenStatistics", 0xa)
TokenRestrictedSids = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenRestrictedSids", 0xb)
TokenSessionId = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSessionId", 0xc)
TokenGroupsAndPrivileges = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenGroupsAndPrivileges", 0xd)
TokenSessionReference = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSessionReference", 0xe)
TokenSandBoxInert = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSandBoxInert", 0xf)
TokenAuditPolicy = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenAuditPolicy", 0x10)
TokenOrigin = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenOrigin", 0x11)
TokenElevationType = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenElevationType", 0x12)
TokenLinkedToken = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenLinkedToken", 0x13)
TokenElevation = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenElevation", 0x14)
TokenHasRestrictions = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenHasRestrictions", 0x15)
TokenAccessInformation = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenAccessInformation", 0x16)
TokenVirtualizationAllowed = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenVirtualizationAllowed", 0x17)
TokenVirtualizationEnabled = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenVirtualizationEnabled", 0x18)
TokenIntegrityLevel = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenIntegrityLevel", 0x19)
TokenUIAccess = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenUIAccess", 0x1a)
TokenMandatoryPolicy = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenMandatoryPolicy", 0x1b)
TokenLogonSid = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenLogonSid", 0x1c)
TokenIsAppContainer = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenIsAppContainer", 0x1d)
TokenCapabilities = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenCapabilities", 0x1e)
TokenAppContainerSid = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenAppContainerSid", 0x1f)
TokenAppContainerNumber = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenAppContainerNumber", 0x20)
TokenUserClaimAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenUserClaimAttributes", 0x21)
TokenDeviceClaimAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenDeviceClaimAttributes", 0x22)
TokenRestrictedUserClaimAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenRestrictedUserClaimAttributes", 0x23)
TokenRestrictedDeviceClaimAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenRestrictedDeviceClaimAttributes", 0x24)
TokenDeviceGroups = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenDeviceGroups", 0x25)
TokenRestrictedDeviceGroups = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenRestrictedDeviceGroups", 0x26)
TokenSecurityAttributes = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenSecurityAttributes", 0x27)
TokenIsRestricted = EnumValue("_TOKEN_INFORMATION_CLASS", "TokenIsRestricted", 0x28)
MaxTokenInfoClass = EnumValue("_TOKEN_INFORMATION_CLASS", "MaxTokenInfoClass", 0x29)
class _TOKEN_INFORMATION_CLASS(EnumType):
    values = [TokenInvalid, TokenUser, TokenGroups, TokenPrivileges, TokenOwner, TokenPrimaryGroup, TokenDefaultDacl, TokenSource, TokenType, TokenImpersonationLevel, TokenStatistics, TokenRestrictedSids, TokenSessionId, TokenGroupsAndPrivileges, TokenSessionReference, TokenSandBoxInert, TokenAuditPolicy, TokenOrigin, TokenElevationType, TokenLinkedToken, TokenElevation, TokenHasRestrictions, TokenAccessInformation, TokenVirtualizationAllowed, TokenVirtualizationEnabled, TokenIntegrityLevel, TokenUIAccess, TokenMandatoryPolicy, TokenLogonSid, TokenIsAppContainer, TokenCapabilities, TokenAppContainerSid, TokenAppContainerNumber, TokenUserClaimAttributes, TokenDeviceClaimAttributes, TokenRestrictedUserClaimAttributes, TokenRestrictedDeviceClaimAttributes, TokenDeviceGroups, TokenRestrictedDeviceGroups, TokenSecurityAttributes, TokenIsRestricted, MaxTokenInfoClass]
    mapper = {x:x for x in values}
TOKEN_INFORMATION_CLASS = _TOKEN_INFORMATION_CLASS
PTOKEN_INFORMATION_CLASS = POINTER(_TOKEN_INFORMATION_CLASS)


SecurityAnonymous = EnumValue("_SECURITY_IMPERSONATION_LEVEL", "SecurityAnonymous", 0x0)
SecurityIdentification = EnumValue("_SECURITY_IMPERSONATION_LEVEL", "SecurityIdentification", 0x1)
SecurityImpersonation = EnumValue("_SECURITY_IMPERSONATION_LEVEL", "SecurityImpersonation", 0x2)
SecurityDelegation = EnumValue("_SECURITY_IMPERSONATION_LEVEL", "SecurityDelegation", 0x3)
class _SECURITY_IMPERSONATION_LEVEL(EnumType):
    values = [SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation]
    mapper = {x:x for x in values}
SECURITY_IMPERSONATION_LEVEL = _SECURITY_IMPERSONATION_LEVEL
PSECURITY_IMPERSONATION_LEVEL = POINTER(_SECURITY_IMPERSONATION_LEVEL)


SC_ENUM_PROCESS_INFO = EnumValue("_SC_ENUM_TYPE", "SC_ENUM_PROCESS_INFO", 0x0)
class _SC_ENUM_TYPE(EnumType):
    values = [SC_ENUM_PROCESS_INFO]
    mapper = {x:x for x in values}
SC_ENUM_TYPE = _SC_ENUM_TYPE


SC_STATUS_PROCESS_INFO = EnumValue("_SC_STATUS_TYPE", "SC_STATUS_PROCESS_INFO", 0x0)
class _SC_STATUS_TYPE(EnumType):
    values = [SC_STATUS_PROCESS_INFO]
    mapper = {x:x for x in values}
SC_STATUS_TYPE = _SC_STATUS_TYPE


ObjectBasicInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectBasicInformation", 0x0)
ObjectNameInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectNameInformation", 0x1)
ObjectTypeInformation = EnumValue("_OBJECT_INFORMATION_CLASS", "ObjectTypeInformation", 0x2)
class _OBJECT_INFORMATION_CLASS(EnumType):
    values = [ObjectBasicInformation, ObjectNameInformation, ObjectTypeInformation]
    mapper = {x:x for x in values}
OBJECT_INFORMATION_CLASS = _OBJECT_INFORMATION_CLASS


SidTypeUser = EnumValue("_SID_NAME_USE", "SidTypeUser", 0x1)
SidTypeGroup = EnumValue("_SID_NAME_USE", "SidTypeGroup", 0x2)
SidTypeDomain = EnumValue("_SID_NAME_USE", "SidTypeDomain", 0x3)
SidTypeAlias = EnumValue("_SID_NAME_USE", "SidTypeAlias", 0x4)
SidTypeWellKnownGroup = EnumValue("_SID_NAME_USE", "SidTypeWellKnownGroup", 0x5)
SidTypeDeletedAccount = EnumValue("_SID_NAME_USE", "SidTypeDeletedAccount", 0x6)
SidTypeInvalid = EnumValue("_SID_NAME_USE", "SidTypeInvalid", 0x7)
SidTypeUnknown = EnumValue("_SID_NAME_USE", "SidTypeUnknown", 0x8)
SidTypeComputer = EnumValue("_SID_NAME_USE", "SidTypeComputer", 0x9)
SidTypeLabel = EnumValue("_SID_NAME_USE", "SidTypeLabel", 0xa)
class _SID_NAME_USE(EnumType):
    values = [SidTypeUser, SidTypeGroup, SidTypeDomain, SidTypeAlias, SidTypeWellKnownGroup, SidTypeDeletedAccount, SidTypeInvalid, SidTypeUnknown, SidTypeComputer, SidTypeLabel]
    mapper = {x:x for x in values}
SID_NAME_USE = _SID_NAME_USE
PSID_NAME_USE = POINTER(_SID_NAME_USE)


NET_FW_PROFILE2_DOMAIN = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_DOMAIN", 0x1)
NET_FW_PROFILE2_PRIVATE = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_PRIVATE", 0x2)
NET_FW_PROFILE2_PUBLIC = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_PUBLIC", 0x4)
NET_FW_PROFILE2_ALL = EnumValue("NET_FW_PROFILE_TYPE2_", "NET_FW_PROFILE2_ALL", 0x7fffffff)
class NET_FW_PROFILE_TYPE2_(EnumType):
    values = [NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE2_ALL]
    mapper = {x:x for x in values}
NET_FW_PROFILE_TYPE2 = NET_FW_PROFILE_TYPE2_


NET_FW_ACTION_BLOCK = EnumValue("NET_FW_ACTION_", "NET_FW_ACTION_BLOCK", 0x0)
NET_FW_ACTION_ALLOW = EnumValue("NET_FW_ACTION_", "NET_FW_ACTION_ALLOW", 0x1)
NET_FW_ACTION_MAX = EnumValue("NET_FW_ACTION_", "NET_FW_ACTION_MAX", 0x2)
class NET_FW_ACTION_(EnumType):
    values = [NET_FW_ACTION_BLOCK, NET_FW_ACTION_ALLOW, NET_FW_ACTION_MAX]
    mapper = {x:x for x in values}
NET_FW_ACTION = NET_FW_ACTION_


NET_FW_MODIFY_STATE_OK = EnumValue("NET_FW_MODIFY_STATE_", "NET_FW_MODIFY_STATE_OK", 0x0)
NET_FW_MODIFY_STATE_GP_OVERRIDE = EnumValue("NET_FW_MODIFY_STATE_", "NET_FW_MODIFY_STATE_GP_OVERRIDE", 0x1)
NET_FW_MODIFY_STATE_INBOUND_BLOCKED = EnumValue("NET_FW_MODIFY_STATE_", "NET_FW_MODIFY_STATE_INBOUND_BLOCKED", 0x2)
class NET_FW_MODIFY_STATE_(EnumType):
    values = [NET_FW_MODIFY_STATE_OK, NET_FW_MODIFY_STATE_GP_OVERRIDE, NET_FW_MODIFY_STATE_INBOUND_BLOCKED]
    mapper = {x:x for x in values}
NET_FW_MODIFY_STATE = NET_FW_MODIFY_STATE_


NET_FW_RULE_DIR_IN = EnumValue("NET_FW_RULE_DIRECTION_", "NET_FW_RULE_DIR_IN", 0x1)
NET_FW_RULE_DIR_OUT = EnumValue("NET_FW_RULE_DIRECTION_", "NET_FW_RULE_DIR_OUT", 0x2)
NET_FW_RULE_DIR_MAX = EnumValue("NET_FW_RULE_DIRECTION_", "NET_FW_RULE_DIR_MAX", 0x3)
class NET_FW_RULE_DIRECTION_(EnumType):
    values = [NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIR_MAX]
    mapper = {x:x for x in values}
NET_FW_RULE_DIRECTION = NET_FW_RULE_DIRECTION_


WBEM_NO_ERROR = EnumValue("tag_WBEMSTATUS", "WBEM_NO_ERROR", 0x0)
WBEM_S_NO_ERROR = EnumValue("tag_WBEMSTATUS", "WBEM_S_NO_ERROR", 0x0)
WBEM_S_SAME = EnumValue("tag_WBEMSTATUS", "WBEM_S_SAME", 0x0)
WBEM_S_FALSE = EnumValue("tag_WBEMSTATUS", "WBEM_S_FALSE", 0x1)
WBEM_S_ALREADY_EXISTS = EnumValue("tag_WBEMSTATUS", "WBEM_S_ALREADY_EXISTS", 0x40001)
WBEM_S_RESET_TO_DEFAULT = EnumValue("tag_WBEMSTATUS", "WBEM_S_RESET_TO_DEFAULT", 0x40002)
WBEM_S_DIFFERENT = EnumValue("tag_WBEMSTATUS", "WBEM_S_DIFFERENT", 0x40003)
WBEM_S_TIMEDOUT = EnumValue("tag_WBEMSTATUS", "WBEM_S_TIMEDOUT", 0x40004)
WBEM_S_NO_MORE_DATA = EnumValue("tag_WBEMSTATUS", "WBEM_S_NO_MORE_DATA", 0x40005)
WBEM_S_OPERATION_CANCELLED = EnumValue("tag_WBEMSTATUS", "WBEM_S_OPERATION_CANCELLED", 0x40006)
WBEM_S_PENDING = EnumValue("tag_WBEMSTATUS", "WBEM_S_PENDING", 0x40007)
WBEM_S_DUPLICATE_OBJECTS = EnumValue("tag_WBEMSTATUS", "WBEM_S_DUPLICATE_OBJECTS", 0x40008)
WBEM_S_ACCESS_DENIED = EnumValue("tag_WBEMSTATUS", "WBEM_S_ACCESS_DENIED", 0x40009)
WBEM_S_PARTIAL_RESULTS = EnumValue("tag_WBEMSTATUS", "WBEM_S_PARTIAL_RESULTS", 0x40010)
WBEM_S_SOURCE_NOT_AVAILABLE = EnumValue("tag_WBEMSTATUS", "WBEM_S_SOURCE_NOT_AVAILABLE", 0x40017)
WBEM_E_FAILED = EnumValue("tag_WBEMSTATUS", "WBEM_E_FAILED", 0x80041001L)
WBEM_E_NOT_FOUND = EnumValue("tag_WBEMSTATUS", "WBEM_E_NOT_FOUND", 0x80041002L)
WBEM_E_ACCESS_DENIED = EnumValue("tag_WBEMSTATUS", "WBEM_E_ACCESS_DENIED", 0x80041003L)
WBEM_E_PROVIDER_FAILURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_FAILURE", 0x80041004L)
WBEM_E_TYPE_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEM_E_TYPE_MISMATCH", 0x80041005L)
WBEM_E_OUT_OF_MEMORY = EnumValue("tag_WBEMSTATUS", "WBEM_E_OUT_OF_MEMORY", 0x80041006L)
WBEM_E_INVALID_CONTEXT = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_CONTEXT", 0x80041007L)
WBEM_E_INVALID_PARAMETER = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PARAMETER", 0x80041008L)
WBEM_E_NOT_AVAILABLE = EnumValue("tag_WBEMSTATUS", "WBEM_E_NOT_AVAILABLE", 0x80041009L)
WBEM_E_CRITICAL_ERROR = EnumValue("tag_WBEMSTATUS", "WBEM_E_CRITICAL_ERROR", 0x8004100aL)
WBEM_E_INVALID_STREAM = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_STREAM", 0x8004100bL)
WBEM_E_NOT_SUPPORTED = EnumValue("tag_WBEMSTATUS", "WBEM_E_NOT_SUPPORTED", 0x8004100cL)
WBEM_E_INVALID_SUPERCLASS = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_SUPERCLASS", 0x8004100dL)
WBEM_E_INVALID_NAMESPACE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_NAMESPACE", 0x8004100eL)
WBEM_E_INVALID_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_OBJECT", 0x8004100fL)
WBEM_E_INVALID_CLASS = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_CLASS", 0x80041010L)
WBEM_E_PROVIDER_NOT_FOUND = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_NOT_FOUND", 0x80041011L)
WBEM_E_INVALID_PROVIDER_REGISTRATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PROVIDER_REGISTRATION", 0x80041012L)
WBEM_E_PROVIDER_LOAD_FAILURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_LOAD_FAILURE", 0x80041013L)
WBEM_E_INITIALIZATION_FAILURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INITIALIZATION_FAILURE", 0x80041014L)
WBEM_E_TRANSPORT_FAILURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_TRANSPORT_FAILURE", 0x80041015L)
WBEM_E_INVALID_OPERATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_OPERATION", 0x80041016L)
WBEM_E_INVALID_QUERY = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_QUERY", 0x80041017L)
WBEM_E_INVALID_QUERY_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_QUERY_TYPE", 0x80041018L)
WBEM_E_ALREADY_EXISTS = EnumValue("tag_WBEMSTATUS", "WBEM_E_ALREADY_EXISTS", 0x80041019L)
WBEM_E_OVERRIDE_NOT_ALLOWED = EnumValue("tag_WBEMSTATUS", "WBEM_E_OVERRIDE_NOT_ALLOWED", 0x8004101aL)
WBEM_E_PROPAGATED_QUALIFIER = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPAGATED_QUALIFIER", 0x8004101bL)
WBEM_E_PROPAGATED_PROPERTY = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPAGATED_PROPERTY", 0x8004101cL)
WBEM_E_UNEXPECTED = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNEXPECTED", 0x8004101dL)
WBEM_E_ILLEGAL_OPERATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_ILLEGAL_OPERATION", 0x8004101eL)
WBEM_E_CANNOT_BE_KEY = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_BE_KEY", 0x8004101fL)
WBEM_E_INCOMPLETE_CLASS = EnumValue("tag_WBEMSTATUS", "WBEM_E_INCOMPLETE_CLASS", 0x80041020L)
WBEM_E_INVALID_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_SYNTAX", 0x80041021L)
WBEM_E_NONDECORATED_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_NONDECORATED_OBJECT", 0x80041022L)
WBEM_E_READ_ONLY = EnumValue("tag_WBEMSTATUS", "WBEM_E_READ_ONLY", 0x80041023L)
WBEM_E_PROVIDER_NOT_CAPABLE = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_NOT_CAPABLE", 0x80041024L)
WBEM_E_CLASS_HAS_CHILDREN = EnumValue("tag_WBEMSTATUS", "WBEM_E_CLASS_HAS_CHILDREN", 0x80041025L)
WBEM_E_CLASS_HAS_INSTANCES = EnumValue("tag_WBEMSTATUS", "WBEM_E_CLASS_HAS_INSTANCES", 0x80041026L)
WBEM_E_QUERY_NOT_IMPLEMENTED = EnumValue("tag_WBEMSTATUS", "WBEM_E_QUERY_NOT_IMPLEMENTED", 0x80041027L)
WBEM_E_ILLEGAL_NULL = EnumValue("tag_WBEMSTATUS", "WBEM_E_ILLEGAL_NULL", 0x80041028L)
WBEM_E_INVALID_QUALIFIER_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_QUALIFIER_TYPE", 0x80041029L)
WBEM_E_INVALID_PROPERTY_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PROPERTY_TYPE", 0x8004102aL)
WBEM_E_VALUE_OUT_OF_RANGE = EnumValue("tag_WBEMSTATUS", "WBEM_E_VALUE_OUT_OF_RANGE", 0x8004102bL)
WBEM_E_CANNOT_BE_SINGLETON = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_BE_SINGLETON", 0x8004102cL)
WBEM_E_INVALID_CIM_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_CIM_TYPE", 0x8004102dL)
WBEM_E_INVALID_METHOD = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_METHOD", 0x8004102eL)
WBEM_E_INVALID_METHOD_PARAMETERS = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_METHOD_PARAMETERS", 0x8004102fL)
WBEM_E_SYSTEM_PROPERTY = EnumValue("tag_WBEMSTATUS", "WBEM_E_SYSTEM_PROPERTY", 0x80041030L)
WBEM_E_INVALID_PROPERTY = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PROPERTY", 0x80041031L)
WBEM_E_CALL_CANCELLED = EnumValue("tag_WBEMSTATUS", "WBEM_E_CALL_CANCELLED", 0x80041032L)
WBEM_E_SHUTTING_DOWN = EnumValue("tag_WBEMSTATUS", "WBEM_E_SHUTTING_DOWN", 0x80041033L)
WBEM_E_PROPAGATED_METHOD = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPAGATED_METHOD", 0x80041034L)
WBEM_E_UNSUPPORTED_PARAMETER = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNSUPPORTED_PARAMETER", 0x80041035L)
WBEM_E_MISSING_PARAMETER_ID = EnumValue("tag_WBEMSTATUS", "WBEM_E_MISSING_PARAMETER_ID", 0x80041036L)
WBEM_E_INVALID_PARAMETER_ID = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_PARAMETER_ID", 0x80041037L)
WBEM_E_NONCONSECUTIVE_PARAMETER_IDS = EnumValue("tag_WBEMSTATUS", "WBEM_E_NONCONSECUTIVE_PARAMETER_IDS", 0x80041038L)
WBEM_E_PARAMETER_ID_ON_RETVAL = EnumValue("tag_WBEMSTATUS", "WBEM_E_PARAMETER_ID_ON_RETVAL", 0x80041039L)
WBEM_E_INVALID_OBJECT_PATH = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_OBJECT_PATH", 0x8004103aL)
WBEM_E_OUT_OF_DISK_SPACE = EnumValue("tag_WBEMSTATUS", "WBEM_E_OUT_OF_DISK_SPACE", 0x8004103bL)
WBEM_E_BUFFER_TOO_SMALL = EnumValue("tag_WBEMSTATUS", "WBEM_E_BUFFER_TOO_SMALL", 0x8004103cL)
WBEM_E_UNSUPPORTED_PUT_EXTENSION = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNSUPPORTED_PUT_EXTENSION", 0x8004103dL)
WBEM_E_UNKNOWN_OBJECT_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNKNOWN_OBJECT_TYPE", 0x8004103eL)
WBEM_E_UNKNOWN_PACKET_TYPE = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNKNOWN_PACKET_TYPE", 0x8004103fL)
WBEM_E_MARSHAL_VERSION_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEM_E_MARSHAL_VERSION_MISMATCH", 0x80041040L)
WBEM_E_MARSHAL_INVALID_SIGNATURE = EnumValue("tag_WBEMSTATUS", "WBEM_E_MARSHAL_INVALID_SIGNATURE", 0x80041041L)
WBEM_E_INVALID_QUALIFIER = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_QUALIFIER", 0x80041042L)
WBEM_E_INVALID_DUPLICATE_PARAMETER = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_DUPLICATE_PARAMETER", 0x80041043L)
WBEM_E_TOO_MUCH_DATA = EnumValue("tag_WBEMSTATUS", "WBEM_E_TOO_MUCH_DATA", 0x80041044L)
WBEM_E_SERVER_TOO_BUSY = EnumValue("tag_WBEMSTATUS", "WBEM_E_SERVER_TOO_BUSY", 0x80041045L)
WBEM_E_INVALID_FLAVOR = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_FLAVOR", 0x80041046L)
WBEM_E_CIRCULAR_REFERENCE = EnumValue("tag_WBEMSTATUS", "WBEM_E_CIRCULAR_REFERENCE", 0x80041047L)
WBEM_E_UNSUPPORTED_CLASS_UPDATE = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNSUPPORTED_CLASS_UPDATE", 0x80041048L)
WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE", 0x80041049L)
WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE", 0x80041050L)
WBEM_E_TOO_MANY_PROPERTIES = EnumValue("tag_WBEMSTATUS", "WBEM_E_TOO_MANY_PROPERTIES", 0x80041051L)
WBEM_E_UPDATE_TYPE_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEM_E_UPDATE_TYPE_MISMATCH", 0x80041052L)
WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED = EnumValue("tag_WBEMSTATUS", "WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED", 0x80041053L)
WBEM_E_UPDATE_PROPAGATED_METHOD = EnumValue("tag_WBEMSTATUS", "WBEM_E_UPDATE_PROPAGATED_METHOD", 0x80041054L)
WBEM_E_METHOD_NOT_IMPLEMENTED = EnumValue("tag_WBEMSTATUS", "WBEM_E_METHOD_NOT_IMPLEMENTED", 0x80041055L)
WBEM_E_METHOD_DISABLED = EnumValue("tag_WBEMSTATUS", "WBEM_E_METHOD_DISABLED", 0x80041056L)
WBEM_E_REFRESHER_BUSY = EnumValue("tag_WBEMSTATUS", "WBEM_E_REFRESHER_BUSY", 0x80041057L)
WBEM_E_UNPARSABLE_QUERY = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNPARSABLE_QUERY", 0x80041058L)
WBEM_E_NOT_EVENT_CLASS = EnumValue("tag_WBEMSTATUS", "WBEM_E_NOT_EVENT_CLASS", 0x80041059L)
WBEM_E_MISSING_GROUP_WITHIN = EnumValue("tag_WBEMSTATUS", "WBEM_E_MISSING_GROUP_WITHIN", 0x8004105aL)
WBEM_E_MISSING_AGGREGATION_LIST = EnumValue("tag_WBEMSTATUS", "WBEM_E_MISSING_AGGREGATION_LIST", 0x8004105bL)
WBEM_E_PROPERTY_NOT_AN_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPERTY_NOT_AN_OBJECT", 0x8004105cL)
WBEM_E_AGGREGATING_BY_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_AGGREGATING_BY_OBJECT", 0x8004105dL)
WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY", 0x8004105fL)
WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING = EnumValue("tag_WBEMSTATUS", "WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING", 0x80041060L)
WBEM_E_QUEUE_OVERFLOW = EnumValue("tag_WBEMSTATUS", "WBEM_E_QUEUE_OVERFLOW", 0x80041061L)
WBEM_E_PRIVILEGE_NOT_HELD = EnumValue("tag_WBEMSTATUS", "WBEM_E_PRIVILEGE_NOT_HELD", 0x80041062L)
WBEM_E_INVALID_OPERATOR = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_OPERATOR", 0x80041063L)
WBEM_E_LOCAL_CREDENTIALS = EnumValue("tag_WBEMSTATUS", "WBEM_E_LOCAL_CREDENTIALS", 0x80041064L)
WBEM_E_CANNOT_BE_ABSTRACT = EnumValue("tag_WBEMSTATUS", "WBEM_E_CANNOT_BE_ABSTRACT", 0x80041065L)
WBEM_E_AMENDED_OBJECT = EnumValue("tag_WBEMSTATUS", "WBEM_E_AMENDED_OBJECT", 0x80041066L)
WBEM_E_CLIENT_TOO_SLOW = EnumValue("tag_WBEMSTATUS", "WBEM_E_CLIENT_TOO_SLOW", 0x80041067L)
WBEM_E_NULL_SECURITY_DESCRIPTOR = EnumValue("tag_WBEMSTATUS", "WBEM_E_NULL_SECURITY_DESCRIPTOR", 0x80041068L)
WBEM_E_TIMED_OUT = EnumValue("tag_WBEMSTATUS", "WBEM_E_TIMED_OUT", 0x80041069L)
WBEM_E_INVALID_ASSOCIATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_ASSOCIATION", 0x8004106aL)
WBEM_E_AMBIGUOUS_OPERATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_AMBIGUOUS_OPERATION", 0x8004106bL)
WBEM_E_QUOTA_VIOLATION = EnumValue("tag_WBEMSTATUS", "WBEM_E_QUOTA_VIOLATION", 0x8004106cL)
WBEM_E_RESERVED_001 = EnumValue("tag_WBEMSTATUS", "WBEM_E_RESERVED_001", 0x8004106dL)
WBEM_E_RESERVED_002 = EnumValue("tag_WBEMSTATUS", "WBEM_E_RESERVED_002", 0x8004106eL)
WBEM_E_UNSUPPORTED_LOCALE = EnumValue("tag_WBEMSTATUS", "WBEM_E_UNSUPPORTED_LOCALE", 0x8004106fL)
WBEM_E_HANDLE_OUT_OF_DATE = EnumValue("tag_WBEMSTATUS", "WBEM_E_HANDLE_OUT_OF_DATE", 0x80041070L)
WBEM_E_CONNECTION_FAILED = EnumValue("tag_WBEMSTATUS", "WBEM_E_CONNECTION_FAILED", 0x80041071L)
WBEM_E_INVALID_HANDLE_REQUEST = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_HANDLE_REQUEST", 0x80041072L)
WBEM_E_PROPERTY_NAME_TOO_WIDE = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROPERTY_NAME_TOO_WIDE", 0x80041073L)
WBEM_E_CLASS_NAME_TOO_WIDE = EnumValue("tag_WBEMSTATUS", "WBEM_E_CLASS_NAME_TOO_WIDE", 0x80041074L)
WBEM_E_METHOD_NAME_TOO_WIDE = EnumValue("tag_WBEMSTATUS", "WBEM_E_METHOD_NAME_TOO_WIDE", 0x80041075L)
WBEM_E_QUALIFIER_NAME_TOO_WIDE = EnumValue("tag_WBEMSTATUS", "WBEM_E_QUALIFIER_NAME_TOO_WIDE", 0x80041076L)
WBEM_E_RERUN_COMMAND = EnumValue("tag_WBEMSTATUS", "WBEM_E_RERUN_COMMAND", 0x80041077L)
WBEM_E_DATABASE_VER_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEM_E_DATABASE_VER_MISMATCH", 0x80041078L)
WBEM_E_VETO_DELETE = EnumValue("tag_WBEMSTATUS", "WBEM_E_VETO_DELETE", 0x80041079L)
WBEM_E_VETO_PUT = EnumValue("tag_WBEMSTATUS", "WBEM_E_VETO_PUT", 0x8004107aL)
WBEM_E_INVALID_LOCALE = EnumValue("tag_WBEMSTATUS", "WBEM_E_INVALID_LOCALE", 0x80041080L)
WBEM_E_PROVIDER_SUSPENDED = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_SUSPENDED", 0x80041081L)
WBEM_E_SYNCHRONIZATION_REQUIRED = EnumValue("tag_WBEMSTATUS", "WBEM_E_SYNCHRONIZATION_REQUIRED", 0x80041082L)
WBEM_E_NO_SCHEMA = EnumValue("tag_WBEMSTATUS", "WBEM_E_NO_SCHEMA", 0x80041083L)
WBEM_E_PROVIDER_ALREADY_REGISTERED = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_ALREADY_REGISTERED", 0x80041084L)
WBEM_E_PROVIDER_NOT_REGISTERED = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_NOT_REGISTERED", 0x80041085L)
WBEM_E_FATAL_TRANSPORT_ERROR = EnumValue("tag_WBEMSTATUS", "WBEM_E_FATAL_TRANSPORT_ERROR", 0x80041086L)
WBEM_E_ENCRYPTED_CONNECTION_REQUIRED = EnumValue("tag_WBEMSTATUS", "WBEM_E_ENCRYPTED_CONNECTION_REQUIRED", 0x80041087L)
WBEM_E_PROVIDER_TIMED_OUT = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_TIMED_OUT", 0x80041088L)
WBEM_E_NO_KEY = EnumValue("tag_WBEMSTATUS", "WBEM_E_NO_KEY", 0x80041089L)
WBEM_E_PROVIDER_DISABLED = EnumValue("tag_WBEMSTATUS", "WBEM_E_PROVIDER_DISABLED", 0x8004108aL)
WBEMESS_E_REGISTRATION_TOO_BROAD = EnumValue("tag_WBEMSTATUS", "WBEMESS_E_REGISTRATION_TOO_BROAD", 0x80042001L)
WBEMESS_E_REGISTRATION_TOO_PRECISE = EnumValue("tag_WBEMSTATUS", "WBEMESS_E_REGISTRATION_TOO_PRECISE", 0x80042002L)
WBEMESS_E_AUTHZ_NOT_PRIVILEGED = EnumValue("tag_WBEMSTATUS", "WBEMESS_E_AUTHZ_NOT_PRIVILEGED", 0x80042003L)
WBEMMOF_E_EXPECTED_QUALIFIER_NAME = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_QUALIFIER_NAME", 0x80044001L)
WBEMMOF_E_EXPECTED_SEMI = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_SEMI", 0x80044002L)
WBEMMOF_E_EXPECTED_OPEN_BRACE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_OPEN_BRACE", 0x80044003L)
WBEMMOF_E_EXPECTED_CLOSE_BRACE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_CLOSE_BRACE", 0x80044004L)
WBEMMOF_E_EXPECTED_CLOSE_BRACKET = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_CLOSE_BRACKET", 0x80044005L)
WBEMMOF_E_EXPECTED_CLOSE_PAREN = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_CLOSE_PAREN", 0x80044006L)
WBEMMOF_E_ILLEGAL_CONSTANT_VALUE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_ILLEGAL_CONSTANT_VALUE", 0x80044007L)
WBEMMOF_E_EXPECTED_TYPE_IDENTIFIER = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_TYPE_IDENTIFIER", 0x80044008L)
WBEMMOF_E_EXPECTED_OPEN_PAREN = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_OPEN_PAREN", 0x80044009L)
WBEMMOF_E_UNRECOGNIZED_TOKEN = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNRECOGNIZED_TOKEN", 0x8004400aL)
WBEMMOF_E_UNRECOGNIZED_TYPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNRECOGNIZED_TYPE", 0x8004400bL)
WBEMMOF_E_EXPECTED_PROPERTY_NAME = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_PROPERTY_NAME", 0x8004400cL)
WBEMMOF_E_TYPEDEF_NOT_SUPPORTED = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_TYPEDEF_NOT_SUPPORTED", 0x8004400dL)
WBEMMOF_E_UNEXPECTED_ALIAS = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNEXPECTED_ALIAS", 0x8004400eL)
WBEMMOF_E_UNEXPECTED_ARRAY_INIT = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNEXPECTED_ARRAY_INIT", 0x8004400fL)
WBEMMOF_E_INVALID_AMENDMENT_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_AMENDMENT_SYNTAX", 0x80044010L)
WBEMMOF_E_INVALID_DUPLICATE_AMENDMENT = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_DUPLICATE_AMENDMENT", 0x80044011L)
WBEMMOF_E_INVALID_PRAGMA = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_PRAGMA", 0x80044012L)
WBEMMOF_E_INVALID_NAMESPACE_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_NAMESPACE_SYNTAX", 0x80044013L)
WBEMMOF_E_EXPECTED_CLASS_NAME = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_CLASS_NAME", 0x80044014L)
WBEMMOF_E_TYPE_MISMATCH = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_TYPE_MISMATCH", 0x80044015L)
WBEMMOF_E_EXPECTED_ALIAS_NAME = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_ALIAS_NAME", 0x80044016L)
WBEMMOF_E_INVALID_CLASS_DECLARATION = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_CLASS_DECLARATION", 0x80044017L)
WBEMMOF_E_INVALID_INSTANCE_DECLARATION = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_INSTANCE_DECLARATION", 0x80044018L)
WBEMMOF_E_EXPECTED_DOLLAR = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_DOLLAR", 0x80044019L)
WBEMMOF_E_CIMTYPE_QUALIFIER = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_CIMTYPE_QUALIFIER", 0x8004401aL)
WBEMMOF_E_DUPLICATE_PROPERTY = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_DUPLICATE_PROPERTY", 0x8004401bL)
WBEMMOF_E_INVALID_NAMESPACE_SPECIFICATION = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_NAMESPACE_SPECIFICATION", 0x8004401cL)
WBEMMOF_E_OUT_OF_RANGE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_OUT_OF_RANGE", 0x8004401dL)
WBEMMOF_E_INVALID_FILE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_FILE", 0x8004401eL)
WBEMMOF_E_ALIASES_IN_EMBEDDED = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_ALIASES_IN_EMBEDDED", 0x8004401fL)
WBEMMOF_E_NULL_ARRAY_ELEM = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_NULL_ARRAY_ELEM", 0x80044020L)
WBEMMOF_E_DUPLICATE_QUALIFIER = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_DUPLICATE_QUALIFIER", 0x80044021L)
WBEMMOF_E_EXPECTED_FLAVOR_TYPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_FLAVOR_TYPE", 0x80044022L)
WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES", 0x80044023L)
WBEMMOF_E_MULTIPLE_ALIASES = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_MULTIPLE_ALIASES", 0x80044024L)
WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES2 = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES2", 0x80044025L)
WBEMMOF_E_NO_ARRAYS_RETURNED = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_NO_ARRAYS_RETURNED", 0x80044026L)
WBEMMOF_E_MUST_BE_IN_OR_OUT = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_MUST_BE_IN_OR_OUT", 0x80044027L)
WBEMMOF_E_INVALID_FLAGS_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_FLAGS_SYNTAX", 0x80044028L)
WBEMMOF_E_EXPECTED_BRACE_OR_BAD_TYPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_EXPECTED_BRACE_OR_BAD_TYPE", 0x80044029L)
WBEMMOF_E_UNSUPPORTED_CIMV22_QUAL_VALUE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNSUPPORTED_CIMV22_QUAL_VALUE", 0x8004402aL)
WBEMMOF_E_UNSUPPORTED_CIMV22_DATA_TYPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_UNSUPPORTED_CIMV22_DATA_TYPE", 0x8004402bL)
WBEMMOF_E_INVALID_DELETEINSTANCE_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_DELETEINSTANCE_SYNTAX", 0x8004402cL)
WBEMMOF_E_INVALID_QUALIFIER_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_QUALIFIER_SYNTAX", 0x8004402dL)
WBEMMOF_E_QUALIFIER_USED_OUTSIDE_SCOPE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_QUALIFIER_USED_OUTSIDE_SCOPE", 0x8004402eL)
WBEMMOF_E_ERROR_CREATING_TEMP_FILE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_ERROR_CREATING_TEMP_FILE", 0x8004402fL)
WBEMMOF_E_ERROR_INVALID_INCLUDE_FILE = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_ERROR_INVALID_INCLUDE_FILE", 0x80044030L)
WBEMMOF_E_INVALID_DELETECLASS_SYNTAX = EnumValue("tag_WBEMSTATUS", "WBEMMOF_E_INVALID_DELETECLASS_SYNTAX", 0x80044031L)
class tag_WBEMSTATUS(EnumType):
    values = [WBEM_NO_ERROR, WBEM_S_NO_ERROR, WBEM_S_SAME, WBEM_S_FALSE, WBEM_S_ALREADY_EXISTS, WBEM_S_RESET_TO_DEFAULT, WBEM_S_DIFFERENT, WBEM_S_TIMEDOUT, WBEM_S_NO_MORE_DATA, WBEM_S_OPERATION_CANCELLED, WBEM_S_PENDING, WBEM_S_DUPLICATE_OBJECTS, WBEM_S_ACCESS_DENIED, WBEM_S_PARTIAL_RESULTS, WBEM_S_SOURCE_NOT_AVAILABLE, WBEM_E_FAILED, WBEM_E_NOT_FOUND, WBEM_E_ACCESS_DENIED, WBEM_E_PROVIDER_FAILURE, WBEM_E_TYPE_MISMATCH, WBEM_E_OUT_OF_MEMORY, WBEM_E_INVALID_CONTEXT, WBEM_E_INVALID_PARAMETER, WBEM_E_NOT_AVAILABLE, WBEM_E_CRITICAL_ERROR, WBEM_E_INVALID_STREAM, WBEM_E_NOT_SUPPORTED, WBEM_E_INVALID_SUPERCLASS, WBEM_E_INVALID_NAMESPACE, WBEM_E_INVALID_OBJECT, WBEM_E_INVALID_CLASS, WBEM_E_PROVIDER_NOT_FOUND, WBEM_E_INVALID_PROVIDER_REGISTRATION, WBEM_E_PROVIDER_LOAD_FAILURE, WBEM_E_INITIALIZATION_FAILURE, WBEM_E_TRANSPORT_FAILURE, WBEM_E_INVALID_OPERATION, WBEM_E_INVALID_QUERY, WBEM_E_INVALID_QUERY_TYPE, WBEM_E_ALREADY_EXISTS, WBEM_E_OVERRIDE_NOT_ALLOWED, WBEM_E_PROPAGATED_QUALIFIER, WBEM_E_PROPAGATED_PROPERTY, WBEM_E_UNEXPECTED, WBEM_E_ILLEGAL_OPERATION, WBEM_E_CANNOT_BE_KEY, WBEM_E_INCOMPLETE_CLASS, WBEM_E_INVALID_SYNTAX, WBEM_E_NONDECORATED_OBJECT, WBEM_E_READ_ONLY, WBEM_E_PROVIDER_NOT_CAPABLE, WBEM_E_CLASS_HAS_CHILDREN, WBEM_E_CLASS_HAS_INSTANCES, WBEM_E_QUERY_NOT_IMPLEMENTED, WBEM_E_ILLEGAL_NULL, WBEM_E_INVALID_QUALIFIER_TYPE, WBEM_E_INVALID_PROPERTY_TYPE, WBEM_E_VALUE_OUT_OF_RANGE, WBEM_E_CANNOT_BE_SINGLETON, WBEM_E_INVALID_CIM_TYPE, WBEM_E_INVALID_METHOD, WBEM_E_INVALID_METHOD_PARAMETERS, WBEM_E_SYSTEM_PROPERTY, WBEM_E_INVALID_PROPERTY, WBEM_E_CALL_CANCELLED, WBEM_E_SHUTTING_DOWN, WBEM_E_PROPAGATED_METHOD, WBEM_E_UNSUPPORTED_PARAMETER, WBEM_E_MISSING_PARAMETER_ID, WBEM_E_INVALID_PARAMETER_ID, WBEM_E_NONCONSECUTIVE_PARAMETER_IDS, WBEM_E_PARAMETER_ID_ON_RETVAL, WBEM_E_INVALID_OBJECT_PATH, WBEM_E_OUT_OF_DISK_SPACE, WBEM_E_BUFFER_TOO_SMALL, WBEM_E_UNSUPPORTED_PUT_EXTENSION, WBEM_E_UNKNOWN_OBJECT_TYPE, WBEM_E_UNKNOWN_PACKET_TYPE, WBEM_E_MARSHAL_VERSION_MISMATCH, WBEM_E_MARSHAL_INVALID_SIGNATURE, WBEM_E_INVALID_QUALIFIER, WBEM_E_INVALID_DUPLICATE_PARAMETER, WBEM_E_TOO_MUCH_DATA, WBEM_E_SERVER_TOO_BUSY, WBEM_E_INVALID_FLAVOR, WBEM_E_CIRCULAR_REFERENCE, WBEM_E_UNSUPPORTED_CLASS_UPDATE, WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE, WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE, WBEM_E_TOO_MANY_PROPERTIES, WBEM_E_UPDATE_TYPE_MISMATCH, WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED, WBEM_E_UPDATE_PROPAGATED_METHOD, WBEM_E_METHOD_NOT_IMPLEMENTED, WBEM_E_METHOD_DISABLED, WBEM_E_REFRESHER_BUSY, WBEM_E_UNPARSABLE_QUERY, WBEM_E_NOT_EVENT_CLASS, WBEM_E_MISSING_GROUP_WITHIN, WBEM_E_MISSING_AGGREGATION_LIST, WBEM_E_PROPERTY_NOT_AN_OBJECT, WBEM_E_AGGREGATING_BY_OBJECT, WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY, WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING, WBEM_E_QUEUE_OVERFLOW, WBEM_E_PRIVILEGE_NOT_HELD, WBEM_E_INVALID_OPERATOR, WBEM_E_LOCAL_CREDENTIALS, WBEM_E_CANNOT_BE_ABSTRACT, WBEM_E_AMENDED_OBJECT, WBEM_E_CLIENT_TOO_SLOW, WBEM_E_NULL_SECURITY_DESCRIPTOR, WBEM_E_TIMED_OUT, WBEM_E_INVALID_ASSOCIATION, WBEM_E_AMBIGUOUS_OPERATION, WBEM_E_QUOTA_VIOLATION, WBEM_E_RESERVED_001, WBEM_E_RESERVED_002, WBEM_E_UNSUPPORTED_LOCALE, WBEM_E_HANDLE_OUT_OF_DATE, WBEM_E_CONNECTION_FAILED, WBEM_E_INVALID_HANDLE_REQUEST, WBEM_E_PROPERTY_NAME_TOO_WIDE, WBEM_E_CLASS_NAME_TOO_WIDE, WBEM_E_METHOD_NAME_TOO_WIDE, WBEM_E_QUALIFIER_NAME_TOO_WIDE, WBEM_E_RERUN_COMMAND, WBEM_E_DATABASE_VER_MISMATCH, WBEM_E_VETO_DELETE, WBEM_E_VETO_PUT, WBEM_E_INVALID_LOCALE, WBEM_E_PROVIDER_SUSPENDED, WBEM_E_SYNCHRONIZATION_REQUIRED, WBEM_E_NO_SCHEMA, WBEM_E_PROVIDER_ALREADY_REGISTERED, WBEM_E_PROVIDER_NOT_REGISTERED, WBEM_E_FATAL_TRANSPORT_ERROR, WBEM_E_ENCRYPTED_CONNECTION_REQUIRED, WBEM_E_PROVIDER_TIMED_OUT, WBEM_E_NO_KEY, WBEM_E_PROVIDER_DISABLED, WBEMESS_E_REGISTRATION_TOO_BROAD, WBEMESS_E_REGISTRATION_TOO_PRECISE, WBEMESS_E_AUTHZ_NOT_PRIVILEGED, WBEMMOF_E_EXPECTED_QUALIFIER_NAME, WBEMMOF_E_EXPECTED_SEMI, WBEMMOF_E_EXPECTED_OPEN_BRACE, WBEMMOF_E_EXPECTED_CLOSE_BRACE, WBEMMOF_E_EXPECTED_CLOSE_BRACKET, WBEMMOF_E_EXPECTED_CLOSE_PAREN, WBEMMOF_E_ILLEGAL_CONSTANT_VALUE, WBEMMOF_E_EXPECTED_TYPE_IDENTIFIER, WBEMMOF_E_EXPECTED_OPEN_PAREN, WBEMMOF_E_UNRECOGNIZED_TOKEN, WBEMMOF_E_UNRECOGNIZED_TYPE, WBEMMOF_E_EXPECTED_PROPERTY_NAME, WBEMMOF_E_TYPEDEF_NOT_SUPPORTED, WBEMMOF_E_UNEXPECTED_ALIAS, WBEMMOF_E_UNEXPECTED_ARRAY_INIT, WBEMMOF_E_INVALID_AMENDMENT_SYNTAX, WBEMMOF_E_INVALID_DUPLICATE_AMENDMENT, WBEMMOF_E_INVALID_PRAGMA, WBEMMOF_E_INVALID_NAMESPACE_SYNTAX, WBEMMOF_E_EXPECTED_CLASS_NAME, WBEMMOF_E_TYPE_MISMATCH, WBEMMOF_E_EXPECTED_ALIAS_NAME, WBEMMOF_E_INVALID_CLASS_DECLARATION, WBEMMOF_E_INVALID_INSTANCE_DECLARATION, WBEMMOF_E_EXPECTED_DOLLAR, WBEMMOF_E_CIMTYPE_QUALIFIER, WBEMMOF_E_DUPLICATE_PROPERTY, WBEMMOF_E_INVALID_NAMESPACE_SPECIFICATION, WBEMMOF_E_OUT_OF_RANGE, WBEMMOF_E_INVALID_FILE, WBEMMOF_E_ALIASES_IN_EMBEDDED, WBEMMOF_E_NULL_ARRAY_ELEM, WBEMMOF_E_DUPLICATE_QUALIFIER, WBEMMOF_E_EXPECTED_FLAVOR_TYPE, WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES, WBEMMOF_E_MULTIPLE_ALIASES, WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES2, WBEMMOF_E_NO_ARRAYS_RETURNED, WBEMMOF_E_MUST_BE_IN_OR_OUT, WBEMMOF_E_INVALID_FLAGS_SYNTAX, WBEMMOF_E_EXPECTED_BRACE_OR_BAD_TYPE, WBEMMOF_E_UNSUPPORTED_CIMV22_QUAL_VALUE, WBEMMOF_E_UNSUPPORTED_CIMV22_DATA_TYPE, WBEMMOF_E_INVALID_DELETEINSTANCE_SYNTAX, WBEMMOF_E_INVALID_QUALIFIER_SYNTAX, WBEMMOF_E_QUALIFIER_USED_OUTSIDE_SCOPE, WBEMMOF_E_ERROR_CREATING_TEMP_FILE, WBEMMOF_E_ERROR_INVALID_INCLUDE_FILE, WBEMMOF_E_INVALID_DELETECLASS_SYNTAX]
    mapper = {x:x for x in values}
WBEMSTATUS = tag_WBEMSTATUS


CLSCTX_INPROC_SERVER = EnumValue("tagCLSCTX", "CLSCTX_INPROC_SERVER", 0x1)
CLSCTX_INPROC_HANDLER = EnumValue("tagCLSCTX", "CLSCTX_INPROC_HANDLER", 0x2)
CLSCTX_LOCAL_SERVER = EnumValue("tagCLSCTX", "CLSCTX_LOCAL_SERVER", 0x4)
CLSCTX_INPROC_SERVER16 = EnumValue("tagCLSCTX", "CLSCTX_INPROC_SERVER16", 0x8)
CLSCTX_REMOTE_SERVER = EnumValue("tagCLSCTX", "CLSCTX_REMOTE_SERVER", 0x10)
CLSCTX_INPROC_HANDLER16 = EnumValue("tagCLSCTX", "CLSCTX_INPROC_HANDLER16", 0x20)
CLSCTX_RESERVED1 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED1", 0x40)
CLSCTX_RESERVED2 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED2", 0x80)
CLSCTX_RESERVED3 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED3", 0x100)
CLSCTX_RESERVED4 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED4", 0x200)
CLSCTX_NO_CODE_DOWNLOAD = EnumValue("tagCLSCTX", "CLSCTX_NO_CODE_DOWNLOAD", 0x400)
CLSCTX_RESERVED5 = EnumValue("tagCLSCTX", "CLSCTX_RESERVED5", 0x800)
CLSCTX_NO_CUSTOM_MARSHAL = EnumValue("tagCLSCTX", "CLSCTX_NO_CUSTOM_MARSHAL", 0x1000)
CLSCTX_ENABLE_CODE_DOWNLOAD = EnumValue("tagCLSCTX", "CLSCTX_ENABLE_CODE_DOWNLOAD", 0x2000)
CLSCTX_NO_FAILURE_LOG = EnumValue("tagCLSCTX", "CLSCTX_NO_FAILURE_LOG", 0x4000)
CLSCTX_DISABLE_AAA = EnumValue("tagCLSCTX", "CLSCTX_DISABLE_AAA", 0x8000)
CLSCTX_ENABLE_AAA = EnumValue("tagCLSCTX", "CLSCTX_ENABLE_AAA", 0x10000)
CLSCTX_FROM_DEFAULT_CONTEXT = EnumValue("tagCLSCTX", "CLSCTX_FROM_DEFAULT_CONTEXT", 0x20000)
CLSCTX_ACTIVATE_32_BIT_SERVER = EnumValue("tagCLSCTX", "CLSCTX_ACTIVATE_32_BIT_SERVER", 0x40000)
CLSCTX_ACTIVATE_64_BIT_SERVER = EnumValue("tagCLSCTX", "CLSCTX_ACTIVATE_64_BIT_SERVER", 0x80000)
CLSCTX_ENABLE_CLOAKING = EnumValue("tagCLSCTX", "CLSCTX_ENABLE_CLOAKING", 0x100000)
CLSCTX_APPCONTAINER = EnumValue("tagCLSCTX", "CLSCTX_APPCONTAINER", 0x400000)
CLSCTX_ACTIVATE_AAA_AS_IU = EnumValue("tagCLSCTX", "CLSCTX_ACTIVATE_AAA_AS_IU", 0x800000)
CLSCTX_PS_DLL = EnumValue("tagCLSCTX", "CLSCTX_PS_DLL", 0x80000000L)
class tagCLSCTX(EnumType):
    values = [CLSCTX_INPROC_SERVER, CLSCTX_INPROC_HANDLER, CLSCTX_LOCAL_SERVER, CLSCTX_INPROC_SERVER16, CLSCTX_REMOTE_SERVER, CLSCTX_INPROC_HANDLER16, CLSCTX_RESERVED1, CLSCTX_RESERVED2, CLSCTX_RESERVED3, CLSCTX_RESERVED4, CLSCTX_NO_CODE_DOWNLOAD, CLSCTX_RESERVED5, CLSCTX_NO_CUSTOM_MARSHAL, CLSCTX_ENABLE_CODE_DOWNLOAD, CLSCTX_NO_FAILURE_LOG, CLSCTX_DISABLE_AAA, CLSCTX_ENABLE_AAA, CLSCTX_FROM_DEFAULT_CONTEXT, CLSCTX_ACTIVATE_32_BIT_SERVER, CLSCTX_ACTIVATE_64_BIT_SERVER, CLSCTX_ENABLE_CLOAKING, CLSCTX_APPCONTAINER, CLSCTX_ACTIVATE_AAA_AS_IU, CLSCTX_PS_DLL]
    mapper = {x:x for x in values}
CLSCTX = tagCLSCTX


SE_UNKNOWN_OBJECT_TYPE = EnumValue("_SE_OBJECT_TYPE", "SE_UNKNOWN_OBJECT_TYPE", 0x0)
SE_FILE_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_FILE_OBJECT", 0x1)
SE_SERVICE = EnumValue("_SE_OBJECT_TYPE", "SE_SERVICE", 0x2)
SE_PRINTER = EnumValue("_SE_OBJECT_TYPE", "SE_PRINTER", 0x3)
SE_REGISTRY_KEY = EnumValue("_SE_OBJECT_TYPE", "SE_REGISTRY_KEY", 0x4)
SE_LMSHARE = EnumValue("_SE_OBJECT_TYPE", "SE_LMSHARE", 0x5)
SE_KERNEL_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_KERNEL_OBJECT", 0x6)
SE_WINDOW_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_WINDOW_OBJECT", 0x7)
SE_DS_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_DS_OBJECT", 0x8)
SE_DS_OBJECT_ALL = EnumValue("_SE_OBJECT_TYPE", "SE_DS_OBJECT_ALL", 0x9)
SE_PROVIDER_DEFINED_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_PROVIDER_DEFINED_OBJECT", 0xa)
SE_WMIGUID_OBJECT = EnumValue("_SE_OBJECT_TYPE", "SE_WMIGUID_OBJECT", 0xb)
SE_REGISTRY_WOW64_32KEY = EnumValue("_SE_OBJECT_TYPE", "SE_REGISTRY_WOW64_32KEY", 0xc)
class _SE_OBJECT_TYPE(EnumType):
    values = [SE_UNKNOWN_OBJECT_TYPE, SE_FILE_OBJECT, SE_SERVICE, SE_PRINTER, SE_REGISTRY_KEY, SE_LMSHARE, SE_KERNEL_OBJECT, SE_WINDOW_OBJECT, SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_PROVIDER_DEFINED_OBJECT, SE_WMIGUID_OBJECT, SE_REGISTRY_WOW64_32KEY]
    mapper = {x:x for x in values}
SE_OBJECT_TYPE = _SE_OBJECT_TYPE


IF_OPER_STATUS_NON_OPERATIONAL = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_NON_OPERATIONAL", 0x0)
IF_OPER_STATUS_UNREACHABLE = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_UNREACHABLE", 0x1)
IF_OPER_STATUS_DISCONNECTED = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_DISCONNECTED", 0x2)
IF_OPER_STATUS_CONNECTING = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_CONNECTING", 0x3)
IF_OPER_STATUS_CONNECTED = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_CONNECTED", 0x4)
IF_OPER_STATUS_OPERATIONAL = EnumValue("_INTERNAL_IF_OPER_STATUS", "IF_OPER_STATUS_OPERATIONAL", 0x5)
class _INTERNAL_IF_OPER_STATUS(EnumType):
    values = [IF_OPER_STATUS_NON_OPERATIONAL, IF_OPER_STATUS_UNREACHABLE, IF_OPER_STATUS_DISCONNECTED, IF_OPER_STATUS_CONNECTING, IF_OPER_STATUS_CONNECTED, IF_OPER_STATUS_OPERATIONAL]
    mapper = {x:x for x in values}
INTERNAL_IF_OPER_STATUS = _INTERNAL_IF_OPER_STATUS


TI_GET_SYMTAG = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_SYMTAG", 0x0)
TI_GET_SYMNAME = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_SYMNAME", 0x1)
TI_GET_LENGTH = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_LENGTH", 0x2)
TI_GET_TYPE = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_TYPE", 0x3)
TI_GET_TYPEID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_TYPEID", 0x4)
TI_GET_BASETYPE = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_BASETYPE", 0x5)
TI_GET_ARRAYINDEXTYPEID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_ARRAYINDEXTYPEID", 0x6)
TI_FINDCHILDREN = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_FINDCHILDREN", 0x7)
TI_GET_DATAKIND = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_DATAKIND", 0x8)
TI_GET_ADDRESSOFFSET = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_ADDRESSOFFSET", 0x9)
TI_GET_OFFSET = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_OFFSET", 0xa)
TI_GET_VALUE = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VALUE", 0xb)
TI_GET_COUNT = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_COUNT", 0xc)
TI_GET_CHILDRENCOUNT = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_CHILDRENCOUNT", 0xd)
TI_GET_BITPOSITION = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_BITPOSITION", 0xe)
TI_GET_VIRTUALBASECLASS = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALBASECLASS", 0xf)
TI_GET_VIRTUALTABLESHAPEID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALTABLESHAPEID", 0x10)
TI_GET_VIRTUALBASEPOINTEROFFSET = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALBASEPOINTEROFFSET", 0x11)
TI_GET_CLASSPARENTID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_CLASSPARENTID", 0x12)
TI_GET_NESTED = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_NESTED", 0x13)
TI_GET_SYMINDEX = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_SYMINDEX", 0x14)
TI_GET_LEXICALPARENT = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_LEXICALPARENT", 0x15)
TI_GET_ADDRESS = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_ADDRESS", 0x16)
TI_GET_THISADJUST = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_THISADJUST", 0x17)
TI_GET_UDTKIND = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_UDTKIND", 0x18)
TI_IS_EQUIV_TO = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_IS_EQUIV_TO", 0x19)
TI_GET_CALLING_CONVENTION = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_CALLING_CONVENTION", 0x1a)
TI_IS_CLOSE_EQUIV_TO = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_IS_CLOSE_EQUIV_TO", 0x1b)
TI_GTIEX_REQS_VALID = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GTIEX_REQS_VALID", 0x1c)
TI_GET_VIRTUALBASEOFFSET = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALBASEOFFSET", 0x1d)
TI_GET_VIRTUALBASEDISPINDEX = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_VIRTUALBASEDISPINDEX", 0x1e)
TI_GET_IS_REFERENCE = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_IS_REFERENCE", 0x1f)
TI_GET_INDIRECTVIRTUALBASECLASS = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "TI_GET_INDIRECTVIRTUALBASECLASS", 0x20)
IMAGEHLP_SYMBOL_TYPE_INFO_MAX = EnumValue("_IMAGEHLP_SYMBOL_TYPE_INFO", "IMAGEHLP_SYMBOL_TYPE_INFO_MAX", 0x21)
class _IMAGEHLP_SYMBOL_TYPE_INFO(EnumType):
    values = [TI_GET_SYMTAG, TI_GET_SYMNAME, TI_GET_LENGTH, TI_GET_TYPE, TI_GET_TYPEID, TI_GET_BASETYPE, TI_GET_ARRAYINDEXTYPEID, TI_FINDCHILDREN, TI_GET_DATAKIND, TI_GET_ADDRESSOFFSET, TI_GET_OFFSET, TI_GET_VALUE, TI_GET_COUNT, TI_GET_CHILDRENCOUNT, TI_GET_BITPOSITION, TI_GET_VIRTUALBASECLASS, TI_GET_VIRTUALTABLESHAPEID, TI_GET_VIRTUALBASEPOINTEROFFSET, TI_GET_CLASSPARENTID, TI_GET_NESTED, TI_GET_SYMINDEX, TI_GET_LEXICALPARENT, TI_GET_ADDRESS, TI_GET_THISADJUST, TI_GET_UDTKIND, TI_IS_EQUIV_TO, TI_GET_CALLING_CONVENTION, TI_IS_CLOSE_EQUIV_TO, TI_GTIEX_REQS_VALID, TI_GET_VIRTUALBASEOFFSET, TI_GET_VIRTUALBASEDISPINDEX, TI_GET_IS_REFERENCE, TI_GET_INDIRECTVIRTUALBASECLASS, IMAGEHLP_SYMBOL_TYPE_INFO_MAX]
    mapper = {x:x for x in values}
IMAGEHLP_SYMBOL_TYPE_INFO = _IMAGEHLP_SYMBOL_TYPE_INFO


ProcessBasicInformation = EnumValue("_PROCESSINFOCLASS", "ProcessBasicInformation", 0x0)
ProcessWow64Information = EnumValue("_PROCESSINFOCLASS", "ProcessWow64Information", 0x1a)
class _PROCESSINFOCLASS(EnumType):
    values = [ProcessBasicInformation, ProcessWow64Information]
    mapper = {x:x for x in values}
PROCESSINFOCLASS = _PROCESSINFOCLASS


COINIT_APARTMENTTHREADED = EnumValue("tagCOINIT", "COINIT_APARTMENTTHREADED", 0x2)
COINIT_MULTITHREADED = EnumValue("tagCOINIT", "COINIT_MULTITHREADED", 0x0)
COINIT_DISABLE_OLE1DDE = EnumValue("tagCOINIT", "COINIT_DISABLE_OLE1DDE", 0x4)
COINIT_SPEED_OVER_MEMORY = EnumValue("tagCOINIT", "COINIT_SPEED_OVER_MEMORY", 0x8)
class tagCOINIT(EnumType):
    values = [COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED, COINIT_DISABLE_OLE1DDE, COINIT_SPEED_OVER_MEMORY]
    mapper = {x:x for x in values}
COINIT = tagCOINIT


TKIND_ENUM = EnumValue("tagTYPEKIND", "TKIND_ENUM", 0x0)
TKIND_RECORD = EnumValue("tagTYPEKIND", "TKIND_RECORD", 0x1)
TKIND_MODULE = EnumValue("tagTYPEKIND", "TKIND_MODULE", 0x2)
TKIND_INTERFACE = EnumValue("tagTYPEKIND", "TKIND_INTERFACE", 0x3)
TKIND_DISPATCH = EnumValue("tagTYPEKIND", "TKIND_DISPATCH", 0x4)
TKIND_COCLASS = EnumValue("tagTYPEKIND", "TKIND_COCLASS", 0x5)
TKIND_ALIAS = EnumValue("tagTYPEKIND", "TKIND_ALIAS", 0x6)
TKIND_UNION = EnumValue("tagTYPEKIND", "TKIND_UNION", 0x7)
TKIND_MAX = EnumValue("tagTYPEKIND", "TKIND_MAX", 0x8)
class tagTYPEKIND(EnumType):
    values = [TKIND_ENUM, TKIND_RECORD, TKIND_MODULE, TKIND_INTERFACE, TKIND_DISPATCH, TKIND_COCLASS, TKIND_ALIAS, TKIND_UNION, TKIND_MAX]
    mapper = {x:x for x in values}
TYPEKIND = tagTYPEKIND


BG_JOB_STATE_QUEUED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_QUEUED", 0x0)
BG_JOB_STATE_CONNECTING = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_CONNECTING", 0x1)
BG_JOB_STATE_TRANSFERRING = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_TRANSFERRING", 0x2)
BG_JOB_STATE_SUSPENDED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_SUSPENDED", 0x3)
BG_JOB_STATE_ERROR = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_ERROR", 0x4)
BG_JOB_STATE_TRANSIENT_ERROR = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_TRANSIENT_ERROR", 0x5)
BG_JOB_STATE_TRANSFERRED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_TRANSFERRED", 0x6)
BG_JOB_STATE_ACKNOWLEDGED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_ACKNOWLEDGED", 0x7)
BG_JOB_STATE_CANCELLED = EnumValue("_BG_JOB_STATE", "BG_JOB_STATE_CANCELLED", 0x8)
class _BG_JOB_STATE(EnumType):
    values = [BG_JOB_STATE_QUEUED, BG_JOB_STATE_CONNECTING, BG_JOB_STATE_TRANSFERRING, BG_JOB_STATE_SUSPENDED, BG_JOB_STATE_ERROR, BG_JOB_STATE_TRANSIENT_ERROR, BG_JOB_STATE_TRANSFERRED, BG_JOB_STATE_ACKNOWLEDGED, BG_JOB_STATE_CANCELLED]
    mapper = {x:x for x in values}
BG_JOB_STATE = _BG_JOB_STATE


BG_JOB_PROXY_USAGE_PRECONFIG = EnumValue("_BG_JOB_PROXY_USAGE", "BG_JOB_PROXY_USAGE_PRECONFIG", 0x0)
BG_JOB_PROXY_USAGE_NO_PROXY = EnumValue("_BG_JOB_PROXY_USAGE", "BG_JOB_PROXY_USAGE_NO_PROXY", 0x1)
BG_JOB_PROXY_USAGE_OVERRIDE = EnumValue("_BG_JOB_PROXY_USAGE", "BG_JOB_PROXY_USAGE_OVERRIDE", 0x2)
BG_JOB_PROXY_USAGE_AUTODETECT = EnumValue("_BG_JOB_PROXY_USAGE", "BG_JOB_PROXY_USAGE_AUTODETECT", 0x3)
class _BG_JOB_PROXY_USAGE(EnumType):
    values = [BG_JOB_PROXY_USAGE_PRECONFIG, BG_JOB_PROXY_USAGE_NO_PROXY, BG_JOB_PROXY_USAGE_OVERRIDE, BG_JOB_PROXY_USAGE_AUTODETECT]
    mapper = {x:x for x in values}
BG_JOB_PROXY_USAGE = _BG_JOB_PROXY_USAGE


BG_JOB_PRIORITY_FOREGROUND = EnumValue("_BG_JOB_PRIORITY", "BG_JOB_PRIORITY_FOREGROUND", 0x0)
BG_JOB_PRIORITY_HIGH = EnumValue("_BG_JOB_PRIORITY", "BG_JOB_PRIORITY_HIGH", 0x1)
BG_JOB_PRIORITY_NORMAL = EnumValue("_BG_JOB_PRIORITY", "BG_JOB_PRIORITY_NORMAL", 0x2)
BG_JOB_PRIORITY_LOW = EnumValue("_BG_JOB_PRIORITY", "BG_JOB_PRIORITY_LOW", 0x3)
class _BG_JOB_PRIORITY(EnumType):
    values = [BG_JOB_PRIORITY_FOREGROUND, BG_JOB_PRIORITY_HIGH, BG_JOB_PRIORITY_NORMAL, BG_JOB_PRIORITY_LOW]
    mapper = {x:x for x in values}
BG_JOB_PRIORITY = _BG_JOB_PRIORITY


BG_ERROR_CONTEXT_NONE = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_NONE", 0x0)
BG_ERROR_CONTEXT_UNKNOWN = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_UNKNOWN", 0x1)
BG_ERROR_CONTEXT_GENERAL_QUEUE_MANAGER = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_GENERAL_QUEUE_MANAGER", 0x2)
BG_ERROR_CONTEXT_QUEUE_MANAGER_NOTIFICATION = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_QUEUE_MANAGER_NOTIFICATION", 0x3)
BG_ERROR_CONTEXT_LOCAL_FILE = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_LOCAL_FILE", 0x4)
BG_ERROR_CONTEXT_REMOTE_FILE = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_REMOTE_FILE", 0x5)
BG_ERROR_CONTEXT_GENERAL_TRANSPORT = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_GENERAL_TRANSPORT", 0x6)
BG_ERROR_CONTEXT_REMOTE_APPLICATION = EnumValue("_BG_ERROR_CONTEXT", "BG_ERROR_CONTEXT_REMOTE_APPLICATION", 0x7)
class _BG_ERROR_CONTEXT(EnumType):
    values = [BG_ERROR_CONTEXT_NONE, BG_ERROR_CONTEXT_UNKNOWN, BG_ERROR_CONTEXT_GENERAL_QUEUE_MANAGER, BG_ERROR_CONTEXT_QUEUE_MANAGER_NOTIFICATION, BG_ERROR_CONTEXT_LOCAL_FILE, BG_ERROR_CONTEXT_REMOTE_FILE, BG_ERROR_CONTEXT_GENERAL_TRANSPORT, BG_ERROR_CONTEXT_REMOTE_APPLICATION]
    mapper = {x:x for x in values}
BG_ERROR_CONTEXT = _BG_ERROR_CONTEXT


BG_JOB_TYPE_DOWNLOAD = EnumValue("_BG_JOB_TYPE", "BG_JOB_TYPE_DOWNLOAD", 0x0)
BG_JOB_TYPE_UPLOAD = EnumValue("_BG_JOB_TYPE", "BG_JOB_TYPE_UPLOAD", 0x1)
BG_JOB_TYPE_UPLOAD_REPLY = EnumValue("_BG_JOB_TYPE", "BG_JOB_TYPE_UPLOAD_REPLY", 0x2)
class _BG_JOB_TYPE(EnumType):
    values = [BG_JOB_TYPE_DOWNLOAD, BG_JOB_TYPE_UPLOAD, BG_JOB_TYPE_UPLOAD_REPLY]
    mapper = {x:x for x in values}
BG_JOB_TYPE = _BG_JOB_TYPE


AlpcBasicInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcBasicInformation", 0x0)
AlpcPortInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcPortInformation", 0x1)
AlpcAssociateCompletionPortInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcAssociateCompletionPortInformation", 0x2)
AlpcConnectedSIDInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcConnectedSIDInformation", 0x3)
AlpcServerInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcServerInformation", 0x4)
AlpcMessageZoneInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcMessageZoneInformation", 0x5)
AlpcRegisterCompletionListInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcRegisterCompletionListInformation", 0x6)
AlpcUnregisterCompletionListInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcUnregisterCompletionListInformation", 0x7)
AlpcAdjustCompletionListConcurrencyCountInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcAdjustCompletionListConcurrencyCountInformation", 0x8)
AlpcRegisterCallbackInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcRegisterCallbackInformation", 0x9)
AlpcCompletionListRundownInformation = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcCompletionListRundownInformation", 0xa)
AlpcWaitForPortReferences = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "AlpcWaitForPortReferences", 0xb)
MaxAlpcPortInfoClass = EnumValue("_ALPC_PORT_INFORMATION_CLASS", "MaxAlpcPortInfoClass", 0xc)
class _ALPC_PORT_INFORMATION_CLASS(EnumType):
    values = [AlpcBasicInformation, AlpcPortInformation, AlpcAssociateCompletionPortInformation, AlpcConnectedSIDInformation, AlpcServerInformation, AlpcMessageZoneInformation, AlpcRegisterCompletionListInformation, AlpcUnregisterCompletionListInformation, AlpcAdjustCompletionListConcurrencyCountInformation, AlpcRegisterCallbackInformation, AlpcCompletionListRundownInformation, AlpcWaitForPortReferences, MaxAlpcPortInfoClass]
    mapper = {x:x for x in values}
ALPC_PORT_INFORMATION_CLASS = _ALPC_PORT_INFORMATION_CLASS


# Self referencing struct tricks
class _LIST_ENTRY(Structure): pass
PLIST_ENTRY = POINTER(_LIST_ENTRY)
LIST_ENTRY = _LIST_ENTRY
PRLIST_ENTRY = POINTER(_LIST_ENTRY)
_LIST_ENTRY._fields_ = [
    ("Flink", POINTER(_LIST_ENTRY)),
    ("Blink", POINTER(_LIST_ENTRY)),
]

class _PEB_LDR_DATA(Structure):
    _fields_ = [
        ("Reserved1", BYTE * 8),
        ("Reserved2", PVOID * 3),
        ("InMemoryOrderModuleList", LIST_ENTRY),
    ]
PPEB_LDR_DATA = POINTER(_PEB_LDR_DATA)
PEB_LDR_DATA = _PEB_LDR_DATA

class _LSA_UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", PWSTR),
    ]
PUNICODE_STRING = POINTER(_LSA_UNICODE_STRING)
UNICODE_STRING = _LSA_UNICODE_STRING
LSA_UNICODE_STRING = _LSA_UNICODE_STRING
PLSA_UNICODE_STRING = POINTER(_LSA_UNICODE_STRING)

class _RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [
        ("Reserved1", BYTE * 16),
        ("Reserved2", PVOID * 10),
        ("ImagePathName", UNICODE_STRING),
        ("CommandLine", UNICODE_STRING),
    ]
PRTL_USER_PROCESS_PARAMETERS = POINTER(_RTL_USER_PROCESS_PARAMETERS)
RTL_USER_PROCESS_PARAMETERS = _RTL_USER_PROCESS_PARAMETERS

class _PEB(Structure):
    _fields_ = [
        ("Reserved1", BYTE * 2),
        ("BeingDebugged", BYTE),
        ("Reserved2", BYTE * 1),
        ("Mutant", PVOID),
        ("ImageBaseAddress", PVOID),
        ("Ldr", PPEB_LDR_DATA),
        ("ProcessParameters", PRTL_USER_PROCESS_PARAMETERS),
        ("Reserved4", BYTE * 104),
        ("Reserved5", PVOID * 52),
        ("PostProcessInitRoutine", PPS_POST_PROCESS_INIT_ROUTINE),
        ("Reserved6", BYTE * 128),
        ("Reserved7", PVOID * 1),
        ("SessionId", ULONG),
    ]
PPEB = POINTER(_PEB)
PEB = _PEB

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL),
    ]
SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
PSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)

class _SYSTEM_VERIFIER_INFORMATION(Structure):
    _fields_ = [
        ("NextEntryOffset", ULONG),
        ("Level", ULONG),
        ("DriverName", UNICODE_STRING),
        ("RaiseIrqls", ULONG),
        ("AcquireSpinLocks", ULONG),
        ("SynchronizeExecutions", ULONG),
        ("AllocationsAttempted", ULONG),
        ("AllocationsSucceeded", ULONG),
        ("AllocationsSucceededSpecialPool", ULONG),
        ("AllocationsWithNoTag", ULONG),
        ("TrimRequests", ULONG),
        ("Trims", ULONG),
        ("AllocationsFailed", ULONG),
        ("AllocationsFailedDeliberately", ULONG),
        ("Loads", ULONG),
        ("Unloads", ULONG),
        ("UnTrackedPool", ULONG),
        ("CurrentPagedPoolAllocations", ULONG),
        ("CurrentNonPagedPoolAllocations", ULONG),
        ("PeakPagedPoolAllocations", ULONG),
        ("PeakNonPagedPoolAllocations", ULONG),
        ("PagedPoolUsageInBytes", SIZE_T),
        ("NonPagedPoolUsageInBytes", SIZE_T),
        ("PeakPagedPoolUsageInBytes", SIZE_T),
        ("PeakNonPagedPoolUsageInBytes", SIZE_T),
    ]
PSYSTEM_VERIFIER_INFORMATION = POINTER(_SYSTEM_VERIFIER_INFORMATION)
SYSTEM_VERIFIER_INFORMATION = _SYSTEM_VERIFIER_INFORMATION

class _CLIENT_ID(Structure):
    _fields_ = [
        ("UniqueProcess", HANDLE),
        ("UniqueThread", HANDLE),
    ]
CLIENT_ID = _CLIENT_ID

class _CLIENT_ID64(Structure):
    _fields_ = [
        ("UniqueProcess", ULONG64),
        ("UniqueThread", ULONG64),
    ]
CLIENT_ID64 = _CLIENT_ID64

class _CLIENT_ID32(Structure):
    _fields_ = [
        ("UniqueProcess", ULONG),
        ("UniqueThread", ULONG),
    ]
CLIENT_ID32 = _CLIENT_ID32

class _LDR_DATA_TABLE_ENTRY(Structure):
    _fields_ = [
        ("Reserved1", PVOID * 2),
        ("InMemoryOrderLinks", LIST_ENTRY),
        ("Reserved2", PVOID * 2),
        ("DllBase", PVOID),
        ("EntryPoint", PVOID),
        ("SizeOfImage", PVOID),
        ("FullDllName", UNICODE_STRING),
        ("BaseDllName", UNICODE_STRING),
        ("Reserved5", PVOID * 3),
        ("CheckSum", ULONG),
        ("TimeDateStamp", ULONG),
    ]
PLDR_DATA_TABLE_ENTRY = POINTER(_LDR_DATA_TABLE_ENTRY)
LDR_DATA_TABLE_ENTRY = _LDR_DATA_TABLE_ENTRY

class _IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ("Machine", WORD),
        ("NumberOfSections", WORD),
        ("TimeDateStamp", DWORD),
        ("PointerToSymbolTable", DWORD),
        ("NumberOfSymbols", DWORD),
        ("SizeOfOptionalHeader", WORD),
        ("Characteristics", WORD),
    ]
IMAGE_FILE_HEADER = _IMAGE_FILE_HEADER
PIMAGE_FILE_HEADER = POINTER(_IMAGE_FILE_HEADER)

class _IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ("VirtualAddress", DWORD),
        ("Size", DWORD),
    ]
IMAGE_DATA_DIRECTORY = _IMAGE_DATA_DIRECTORY
PIMAGE_DATA_DIRECTORY = POINTER(_IMAGE_DATA_DIRECTORY)

class _IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ("Name", BYTE * IMAGE_SIZEOF_SHORT_NAME),
        ("VirtualSize", DWORD),
        ("VirtualAddress", DWORD),
        ("SizeOfRawData", DWORD),
        ("PointerToRawData", DWORD),
        ("PointerToRelocations", DWORD),
        ("PointerToLinenumbers", DWORD),
        ("NumberOfRelocations", WORD),
        ("NumberOfLinenumbers", WORD),
        ("Characteristics", DWORD),
    ]
PIMAGE_SECTION_HEADER = POINTER(_IMAGE_SECTION_HEADER)
IMAGE_SECTION_HEADER = _IMAGE_SECTION_HEADER

class _IMAGE_OPTIONAL_HEADER64(Structure):
    _fields_ = [
        ("Magic", WORD),
        ("MajorLinkerVersion", BYTE),
        ("MinorLinkerVersion", BYTE),
        ("SizeOfCode", DWORD),
        ("SizeOfInitializedData", DWORD),
        ("SizeOfUninitializedData", DWORD),
        ("AddressOfEntryPoint", DWORD),
        ("BaseOfCode", DWORD),
        ("ImageBase", ULONGLONG),
        ("SectionAlignment", DWORD),
        ("FileAlignment", DWORD),
        ("MajorOperatingSystemVersion", WORD),
        ("MinorOperatingSystemVersion", WORD),
        ("MajorImageVersion", WORD),
        ("MinorImageVersion", WORD),
        ("MajorSubsystemVersion", WORD),
        ("MinorSubsystemVersion", WORD),
        ("Win32VersionValue", DWORD),
        ("SizeOfImage", DWORD),
        ("SizeOfHeaders", DWORD),
        ("CheckSum", DWORD),
        ("Subsystem", WORD),
        ("DllCharacteristics", WORD),
        ("SizeOfStackReserve", ULONGLONG),
        ("SizeOfStackCommit", ULONGLONG),
        ("SizeOfHeapReserve", ULONGLONG),
        ("SizeOfHeapCommit", ULONGLONG),
        ("LoaderFlags", DWORD),
        ("NumberOfRvaAndSizes", DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]
PIMAGE_OPTIONAL_HEADER64 = POINTER(_IMAGE_OPTIONAL_HEADER64)
IMAGE_OPTIONAL_HEADER64 = _IMAGE_OPTIONAL_HEADER64

class _IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [
        ("Magic", WORD),
        ("MajorLinkerVersion", BYTE),
        ("MinorLinkerVersion", BYTE),
        ("SizeOfCode", DWORD),
        ("SizeOfInitializedData", DWORD),
        ("SizeOfUninitializedData", DWORD),
        ("AddressOfEntryPoint", DWORD),
        ("BaseOfCode", DWORD),
        ("BaseOfData", DWORD),
        ("ImageBase", DWORD),
        ("SectionAlignment", DWORD),
        ("FileAlignment", DWORD),
        ("MajorOperatingSystemVersion", WORD),
        ("MinorOperatingSystemVersion", WORD),
        ("MajorImageVersion", WORD),
        ("MinorImageVersion", WORD),
        ("MajorSubsystemVersion", WORD),
        ("MinorSubsystemVersion", WORD),
        ("Win32VersionValue", DWORD),
        ("SizeOfImage", DWORD),
        ("SizeOfHeaders", DWORD),
        ("CheckSum", DWORD),
        ("Subsystem", WORD),
        ("DllCharacteristics", WORD),
        ("SizeOfStackReserve", DWORD),
        ("SizeOfStackCommit", DWORD),
        ("SizeOfHeapReserve", DWORD),
        ("SizeOfHeapCommit", DWORD),
        ("LoaderFlags", DWORD),
        ("NumberOfRvaAndSizes", DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]
PIMAGE_OPTIONAL_HEADER32 = POINTER(_IMAGE_OPTIONAL_HEADER)
IMAGE_OPTIONAL_HEADER32 = _IMAGE_OPTIONAL_HEADER

class _IMAGE_NT_HEADERS64(Structure):
    _fields_ = [
        ("Signature", DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER64),
    ]
PIMAGE_NT_HEADERS64 = POINTER(_IMAGE_NT_HEADERS64)
IMAGE_NT_HEADERS64 = _IMAGE_NT_HEADERS64

class _IMAGE_NT_HEADERS(Structure):
    _fields_ = [
        ("Signature", DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER32),
    ]
IMAGE_NT_HEADERS32 = _IMAGE_NT_HEADERS
PIMAGE_NT_HEADERS32 = POINTER(_IMAGE_NT_HEADERS)

class _IMAGE_IMPORT_DESCRIPTOR(Structure):
    _fields_ = [
        ("OriginalFirstThunk", DWORD),
        ("TimeDateStamp", DWORD),
        ("ForwarderChain", DWORD),
        ("Name", DWORD),
        ("FirstThunk", DWORD),
    ]
IMAGE_IMPORT_DESCRIPTOR = _IMAGE_IMPORT_DESCRIPTOR
PIMAGE_IMPORT_DESCRIPTOR = POINTER(_IMAGE_IMPORT_DESCRIPTOR)

class _IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [
        ("Hint", WORD),
        ("Name", BYTE * 1),
    ]
PIMAGE_IMPORT_BY_NAME = POINTER(_IMAGE_IMPORT_BY_NAME)
IMAGE_IMPORT_BY_NAME = _IMAGE_IMPORT_BY_NAME

class _IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [
        ("Characteristics", DWORD),
        ("TimeDateStamp", DWORD),
        ("MajorVersion", WORD),
        ("MinorVersion", WORD),
        ("Name", DWORD),
        ("Base", DWORD),
        ("NumberOfFunctions", DWORD),
        ("NumberOfNames", DWORD),
        ("AddressOfFunctions", DWORD),
        ("AddressOfNames", DWORD),
        ("AddressOfNameOrdinals", DWORD),
    ]
IMAGE_EXPORT_DIRECTORY = _IMAGE_EXPORT_DIRECTORY
PIMAGE_EXPORT_DIRECTORY = POINTER(_IMAGE_EXPORT_DIRECTORY)

class _MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]
PMEMORY_BASIC_INFORMATION = POINTER(_MEMORY_BASIC_INFORMATION)
MEMORY_BASIC_INFORMATION = _MEMORY_BASIC_INFORMATION

class _THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus", NTSTATUS),
        ("TebBaseAddress", PVOID),
        ("ClientId", CLIENT_ID),
        ("AffinityMask", KAFFINITY),
        ("Priority", KPRIORITY),
        ("BasePriority", KPRIORITY),
    ]
THREAD_BASIC_INFORMATION = _THREAD_BASIC_INFORMATION
PTHREAD_BASIC_INFORMATION = POINTER(_THREAD_BASIC_INFORMATION)

class _MEMORY_BASIC_INFORMATION32(Structure):
    _fields_ = [
        ("BaseAddress", DWORD),
        ("AllocationBase", DWORD),
        ("AllocationProtect", DWORD),
        ("RegionSize", DWORD),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]
MEMORY_BASIC_INFORMATION32 = _MEMORY_BASIC_INFORMATION32
PMEMORY_BASIC_INFORMATION32 = POINTER(_MEMORY_BASIC_INFORMATION32)

class _MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [
        ("BaseAddress", ULONGLONG),
        ("AllocationBase", ULONGLONG),
        ("AllocationProtect", DWORD),
        ("__alignment1", DWORD),
        ("RegionSize", ULONGLONG),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
        ("__alignment2", DWORD),
    ]
PMEMORY_BASIC_INFORMATION64 = POINTER(_MEMORY_BASIC_INFORMATION64)
MEMORY_BASIC_INFORMATION64 = _MEMORY_BASIC_INFORMATION64

class _PSAPI_WORKING_SET_BLOCK(Union):
    _fields_ = [
        ("Flags", PVOID),
    ]
PSAPI_WORKING_SET_BLOCK = _PSAPI_WORKING_SET_BLOCK
PPSAPI_WORKING_SET_BLOCK = POINTER(_PSAPI_WORKING_SET_BLOCK)

class _PSAPI_WORKING_SET_BLOCK32(Union):
    _fields_ = [
        ("Flags", DWORD),
    ]
PSAPI_WORKING_SET_BLOCK32 = _PSAPI_WORKING_SET_BLOCK32
PPSAPI_WORKING_SET_BLOCK32 = POINTER(_PSAPI_WORKING_SET_BLOCK32)

class _PSAPI_WORKING_SET_BLOCK64(Union):
    _fields_ = [
        ("Flags", ULONG64),
    ]
PSAPI_WORKING_SET_BLOCK64 = _PSAPI_WORKING_SET_BLOCK64
PPSAPI_WORKING_SET_BLOCK64 = POINTER(_PSAPI_WORKING_SET_BLOCK64)

class _PSAPI_WORKING_SET_INFORMATION(Structure):
    _fields_ = [
        ("NumberOfEntries", PVOID),
        ("WorkingSetInfo", PSAPI_WORKING_SET_BLOCK * 1),
    ]
PPSAPI_WORKING_SET_INFORMATION = POINTER(_PSAPI_WORKING_SET_INFORMATION)
PSAPI_WORKING_SET_INFORMATION = _PSAPI_WORKING_SET_INFORMATION

class _PSAPI_WORKING_SET_INFORMATION32(Structure):
    _fields_ = [
        ("NumberOfEntries", DWORD),
        ("WorkingSetInfo", PSAPI_WORKING_SET_BLOCK32 * 1),
    ]
PPSAPI_WORKING_SET_INFORMATION32 = POINTER(_PSAPI_WORKING_SET_INFORMATION32)
PSAPI_WORKING_SET_INFORMATION32 = _PSAPI_WORKING_SET_INFORMATION32

class _PSAPI_WORKING_SET_INFORMATION64(Structure):
    _fields_ = [
        ("NumberOfEntries", ULONG64),
        ("WorkingSetInfo", PSAPI_WORKING_SET_BLOCK64 * 1),
    ]
PSAPI_WORKING_SET_INFORMATION64 = _PSAPI_WORKING_SET_INFORMATION64
PPSAPI_WORKING_SET_INFORMATION64 = POINTER(_PSAPI_WORKING_SET_INFORMATION64)

class _PSAPI_WORKING_SET_EX_BLOCK(Union):
    _fields_ = [
        ("Flags", PVOID),
    ]
PSAPI_WORKING_SET_EX_BLOCK = _PSAPI_WORKING_SET_EX_BLOCK
PPSAPI_WORKING_SET_EX_BLOCK = POINTER(_PSAPI_WORKING_SET_EX_BLOCK)

class _PSAPI_WORKING_SET_EX_BLOCK32(Union):
    _fields_ = [
        ("Flags", DWORD),
    ]
PPSAPI_WORKING_SET_EX_BLOCK32 = POINTER(_PSAPI_WORKING_SET_EX_BLOCK32)
PSAPI_WORKING_SET_EX_BLOCK32 = _PSAPI_WORKING_SET_EX_BLOCK32

class _PSAPI_WORKING_SET_EX_BLOCK64(Union):
    _fields_ = [
        ("Flags", ULONG64),
    ]
PSAPI_WORKING_SET_EX_BLOCK64 = _PSAPI_WORKING_SET_EX_BLOCK64
PPSAPI_WORKING_SET_EX_BLOCK64 = POINTER(_PSAPI_WORKING_SET_EX_BLOCK64)

class _PSAPI_WORKING_SET_EX_INFORMATION(Structure):
    _fields_ = [
        ("VirtualAddress", PVOID),
        ("VirtualAttributes", PSAPI_WORKING_SET_EX_BLOCK),
    ]
PPSAPI_WORKING_SET_EX_INFORMATION = POINTER(_PSAPI_WORKING_SET_EX_INFORMATION)
PSAPI_WORKING_SET_EX_INFORMATION = _PSAPI_WORKING_SET_EX_INFORMATION

class _PSAPI_WORKING_SET_EX_INFORMATION32(Structure):
    _fields_ = [
        ("VirtualAddress", DWORD),
        ("VirtualAttributes", PSAPI_WORKING_SET_EX_BLOCK32),
    ]
PSAPI_WORKING_SET_EX_INFORMATION32 = _PSAPI_WORKING_SET_EX_INFORMATION32
PPSAPI_WORKING_SET_EX_INFORMATION32 = POINTER(_PSAPI_WORKING_SET_EX_INFORMATION32)

class _PSAPI_WORKING_SET_EX_INFORMATION64(Structure):
    _fields_ = [
        ("VirtualAddress", ULONG64),
        ("VirtualAttributes", PSAPI_WORKING_SET_EX_BLOCK64),
    ]
PPSAPI_WORKING_SET_EX_INFORMATION64 = POINTER(_PSAPI_WORKING_SET_EX_INFORMATION64)
PSAPI_WORKING_SET_EX_INFORMATION64 = _PSAPI_WORKING_SET_EX_INFORMATION64

class _STARTUPINFOA(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPSTR),
        ("lpDesktop", LPSTR),
        ("lpTitle", LPSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]
LPSTARTUPINFOA = POINTER(_STARTUPINFOA)
STARTUPINFOA = _STARTUPINFOA

class _STARTUPINFOW(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPWSTR),
        ("lpDesktop", LPWSTR),
        ("lpTitle", LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]
STARTUPINFOW = _STARTUPINFOW
LPSTARTUPINFOW = POINTER(_STARTUPINFOW)

class _STARTUPINFOEXA(Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOA),
        ("lpAttributeList", LPPROC_THREAD_ATTRIBUTE_LIST),
    ]
LPSTARTUPINFOEXA = POINTER(_STARTUPINFOEXA)
STARTUPINFOEXA = _STARTUPINFOEXA

class _STARTUPINFOEXW(Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", LPPROC_THREAD_ATTRIBUTE_LIST),
    ]
STARTUPINFOEXW = _STARTUPINFOEXW
LPSTARTUPINFOEXW = POINTER(_STARTUPINFOEXW)

class _PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]
LPPROCESS_INFORMATION = POINTER(_PROCESS_INFORMATION)
PROCESS_INFORMATION = _PROCESS_INFORMATION
PPROCESS_INFORMATION = POINTER(_PROCESS_INFORMATION)

class _FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
    ]
FLOATING_SAVE_AREA = _FLOATING_SAVE_AREA

class _CONTEXT32(Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
    ]
PCONTEXT32 = POINTER(_CONTEXT32)
CONTEXT32 = _CONTEXT32
LPCONTEXT32 = POINTER(_CONTEXT32)

class _WOW64_FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * WOW64_SIZE_OF_80387_REGISTERS),
        ("Cr0NpxState", DWORD),
    ]
WOW64_FLOATING_SAVE_AREA = _WOW64_FLOATING_SAVE_AREA

class _WOW64_CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * WOW64_MAXIMUM_SUPPORTED_EXTENSION),
    ]
PWOW64_CONTEXT = POINTER(_WOW64_CONTEXT)
WOW64_CONTEXT = _WOW64_CONTEXT

class _M128A(Structure):
    _fields_ = [
        ("Low", ULONGLONG),
        ("High", LONGLONG),
    ]
M128A = _M128A
PM128A = POINTER(_M128A)

class _XSAVE_FORMAT_64(Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", BYTE * 96),
    ]
XSAVE_FORMAT_64 = _XSAVE_FORMAT_64
PXSAVE_FORMAT_64 = POINTER(_XSAVE_FORMAT_64)

class _XSAVE_FORMAT_32(Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 8),
        ("Reserved4", BYTE * 192),
        ("StackControl", DWORD * 7),
        ("Cr0NpxState", DWORD),
    ]
XSAVE_FORMAT_32 = _XSAVE_FORMAT_32
PXSAVE_FORMAT_32 = POINTER(_XSAVE_FORMAT_32)

class _TMP_DUMMYSTRUCTNAME(Structure):
    _fields_ = [
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
    ]
TMP_DUMMYSTRUCTNAME = _TMP_DUMMYSTRUCTNAME

class _TMP_CONTEXT64_SUBUNION(Union):
    _fields_ = [
        ("FltSave", XSAVE_FORMAT_64),
        ("DUMMYSTRUCTNAME", TMP_DUMMYSTRUCTNAME),
    ]
TMP_CONTEXT64_SUBUNION = _TMP_CONTEXT64_SUBUNION

class _CONTEXT64(Structure):
    _fields_ = [
        ("P1Home", DWORD64),
        ("P2Home", DWORD64),
        ("P3Home", DWORD64),
        ("P4Home", DWORD64),
        ("P5Home", DWORD64),
        ("P6Home", DWORD64),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegFs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("EFlags", DWORD),
        ("Dr0", DWORD64),
        ("Dr1", DWORD64),
        ("Dr2", DWORD64),
        ("Dr3", DWORD64),
        ("Dr6", DWORD64),
        ("Dr7", DWORD64),
        ("Rax", DWORD64),
        ("Rcx", DWORD64),
        ("Rdx", DWORD64),
        ("Rbx", DWORD64),
        ("Rsp", DWORD64),
        ("Rbp", DWORD64),
        ("Rsi", DWORD64),
        ("Rdi", DWORD64),
        ("R8", DWORD64),
        ("R9", DWORD64),
        ("R10", DWORD64),
        ("R11", DWORD64),
        ("R12", DWORD64),
        ("R13", DWORD64),
        ("R14", DWORD64),
        ("R15", DWORD64),
        ("Rip", DWORD64),
        ("DUMMYUNIONNAME", TMP_CONTEXT64_SUBUNION),
        ("VectorRegister", M128A * 26),
        ("VectorControl", DWORD64),
        ("DebugControl", DWORD64),
        ("LastBranchToRip", DWORD64),
        ("LastBranchFromRip", DWORD64),
        ("LastExceptionToRip", DWORD64),
        ("LastExceptionFromRip", DWORD64),
    ]
PCONTEXT64 = POINTER(_CONTEXT64)
CONTEXT64 = _CONTEXT64
LPCONTEXT64 = POINTER(_CONTEXT64)

class tagPROCESSENTRY32W(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", WCHAR * MAX_PATH),
    ]
PPROCESSENTRY32W = POINTER(tagPROCESSENTRY32W)
LPPROCESSENTRY32W = POINTER(tagPROCESSENTRY32W)
PROCESSENTRY32W = tagPROCESSENTRY32W

class tagPROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", CHAR * MAX_PATH),
    ]
PROCESSENTRY32 = tagPROCESSENTRY32
PPROCESSENTRY32 = POINTER(tagPROCESSENTRY32)
LPPROCESSENTRY32 = POINTER(tagPROCESSENTRY32)

class tagTHREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", LONG),
        ("tpDeltaPri", LONG),
        ("dwFlags", DWORD),
    ]
PTHREADENTRY32 = POINTER(tagTHREADENTRY32)
THREADENTRY32 = tagTHREADENTRY32
LPTHREADENTRY32 = POINTER(tagTHREADENTRY32)

class _LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]
LUID = _LUID
PLUID = POINTER(_LUID)

class _LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]
LUID_AND_ATTRIBUTES = _LUID_AND_ATTRIBUTES
PLUID_AND_ATTRIBUTES = POINTER(_LUID_AND_ATTRIBUTES)

class _TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * ANYSIZE_ARRAY),
    ]
TOKEN_PRIVILEGES = _TOKEN_PRIVILEGES
PTOKEN_PRIVILEGES = POINTER(_TOKEN_PRIVILEGES)

class _TOKEN_ELEVATION(Structure):
    _fields_ = [
        ("TokenIsElevated", DWORD),
    ]
TOKEN_ELEVATION = _TOKEN_ELEVATION
PTOKEN_ELEVATION = POINTER(_TOKEN_ELEVATION)

class _SID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Sid", PSID),
        ("Attributes", DWORD),
    ]
SID_AND_ATTRIBUTES = _SID_AND_ATTRIBUTES
PSID_AND_ATTRIBUTES = POINTER(_SID_AND_ATTRIBUTES)

class _TOKEN_MANDATORY_LABEL(Structure):
    _fields_ = [
        ("Label", SID_AND_ATTRIBUTES),
    ]
TOKEN_MANDATORY_LABEL = _TOKEN_MANDATORY_LABEL
PTOKEN_MANDATORY_LABEL = POINTER(_TOKEN_MANDATORY_LABEL)

class _TOKEN_USER(Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES),
    ]
PTOKEN_USER = POINTER(_TOKEN_USER)
TOKEN_USER = _TOKEN_USER

class _OSVERSIONINFOA(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", CHAR * 128),
    ]
POSVERSIONINFOA = POINTER(_OSVERSIONINFOA)
OSVERSIONINFOA = _OSVERSIONINFOA
LPOSVERSIONINFOA = POINTER(_OSVERSIONINFOA)

class _OSVERSIONINFOW(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", WCHAR * 128),
    ]
RTL_OSVERSIONINFOW = _OSVERSIONINFOW
PRTL_OSVERSIONINFOW = POINTER(_OSVERSIONINFOW)
LPOSVERSIONINFOW = POINTER(_OSVERSIONINFOW)
POSVERSIONINFOW = POINTER(_OSVERSIONINFOW)
OSVERSIONINFOW = _OSVERSIONINFOW

class _OSVERSIONINFOEXA(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", CHAR * 128),
        ("wServicePackMajor", WORD),
        ("wServicePackMinor", WORD),
        ("wSuiteMask", WORD),
        ("wProductType", BYTE),
        ("wReserved", BYTE),
    ]
OSVERSIONINFOEXA = _OSVERSIONINFOEXA
POSVERSIONINFOEXA = POINTER(_OSVERSIONINFOEXA)
LPOSVERSIONINFOEXA = POINTER(_OSVERSIONINFOEXA)

class _OSVERSIONINFOEXW(Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", WCHAR * 128),
        ("wServicePackMajor", WORD),
        ("wServicePackMinor", WORD),
        ("wSuiteMask", WORD),
        ("wProductType", BYTE),
        ("wReserved", BYTE),
    ]
PRTL_OSVERSIONINFOEXW = POINTER(_OSVERSIONINFOEXW)
LPOSVERSIONINFOEXW = POINTER(_OSVERSIONINFOEXW)
OSVERSIONINFOEXW = _OSVERSIONINFOEXW
POSVERSIONINFOEXW = POINTER(_OSVERSIONINFOEXW)
RTL_OSVERSIONINFOEXW = _OSVERSIONINFOEXW

class _OVERLAPPED(Structure):
    _fields_ = [
        ("Internal", ULONG_PTR),
        ("InternalHigh", ULONG_PTR),
        ("Pointer", PVOID),
        ("hEvent", HANDLE),
    ]
LPOVERLAPPED = POINTER(_OVERLAPPED)
OVERLAPPED = _OVERLAPPED

class _MIB_IPADDRROW_XP(Structure):
    _fields_ = [
        ("dwAddr", DWORD),
        ("dwIndex", IF_INDEX),
        ("dwMask", DWORD),
        ("dwBCastAddr", DWORD),
        ("dwReasmSize", DWORD),
        ("unused1", USHORT),
        ("wType", USHORT),
    ]
MIB_IPADDRROW = _MIB_IPADDRROW_XP
PMIB_IPADDRROW_XP = POINTER(_MIB_IPADDRROW_XP)
MIB_IPADDRROW_XP = _MIB_IPADDRROW_XP

class _MIB_IPADDRTABLE(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_IPADDRROW * ANY_SIZE),
    ]
PMIB_IPADDRTABLE = POINTER(_MIB_IPADDRTABLE)
MIB_IPADDRTABLE = _MIB_IPADDRTABLE

class _MIB_IFROW(Structure):
    _fields_ = [
        ("wszName", WCHAR * MAX_INTERFACE_NAME_LEN),
        ("dwIndex", IF_INDEX),
        ("dwType", IFTYPE),
        ("dwMtu", DWORD),
        ("dwSpeed", DWORD),
        ("dwPhysAddrLen", DWORD),
        ("bPhysAddr", BYTE * MAXLEN_PHYSADDR),
        ("dwAdminStatus", DWORD),
        ("dwOperStatus", INTERNAL_IF_OPER_STATUS),
        ("dwLastChange", DWORD),
        ("dwInOctets", DWORD),
        ("dwInUcastPkts", DWORD),
        ("dwInNUcastPkts", DWORD),
        ("dwInDiscards", DWORD),
        ("dwInErrors", DWORD),
        ("dwInUnknownProtos", DWORD),
        ("dwOutOctets", DWORD),
        ("dwOutUcastPkts", DWORD),
        ("dwOutNUcastPkts", DWORD),
        ("dwOutDiscards", DWORD),
        ("dwOutErrors", DWORD),
        ("dwOutQLen", DWORD),
        ("dwDescrLen", DWORD),
        ("bDescr", UCHAR * MAXLEN_IFDESCR),
    ]
PMIB_IFROW = POINTER(_MIB_IFROW)
MIB_IFROW = _MIB_IFROW

class _MIB_IFTABLE(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_IFROW * ANY_SIZE),
    ]
PMIB_IFTABLE = POINTER(_MIB_IFTABLE)
MIB_IFTABLE = _MIB_IFTABLE

class _MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwState", DWORD),
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_TCPROW_OWNER_PID = _MIB_TCPROW_OWNER_PID
PMIB_TCPROW_OWNER_PID = POINTER(_MIB_TCPROW_OWNER_PID)

class _MIB_TCPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCPROW_OWNER_PID * ANY_SIZE),
    ]
MIB_TCPTABLE_OWNER_PID = _MIB_TCPTABLE_OWNER_PID
PMIB_TCPTABLE_OWNER_PID = POINTER(_MIB_TCPTABLE_OWNER_PID)

class _MIB_UDPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_UDPROW_OWNER_PID = _MIB_UDPROW_OWNER_PID
PMIB_UDPROW_OWNER_PID = POINTER(_MIB_UDPROW_OWNER_PID)

class _MIB_UDPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_UDPROW_OWNER_PID * ANY_SIZE),
    ]
MIB_UDPTABLE_OWNER_PID = _MIB_UDPTABLE_OWNER_PID
PMIB_UDPTABLE_OWNER_PID = POINTER(_MIB_UDPTABLE_OWNER_PID)

class _MIB_UDP6ROW_OWNER_PID(Structure):
    _fields_ = [
        ("ucLocalAddr", UCHAR * 16),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_UDP6ROW_OWNER_PID = _MIB_UDP6ROW_OWNER_PID
PMIB_UDP6ROW_OWNER_PID = POINTER(_MIB_UDP6ROW_OWNER_PID)

class _MIB_UDP6TABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_UDP6ROW_OWNER_PID * ANY_SIZE),
    ]
PMIB_UDP6TABLE_OWNER_PID = POINTER(_MIB_UDP6TABLE_OWNER_PID)
MIB_UDP6TABLE_OWNER_PID = _MIB_UDP6TABLE_OWNER_PID

class _MIB_TCP6ROW_OWNER_PID(Structure):
    _fields_ = [
        ("ucLocalAddr", UCHAR * 16),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("ucRemoteAddr", UCHAR * 16),
        ("dwRemoteScopeId", DWORD),
        ("dwRemotePort", DWORD),
        ("dwState", DWORD),
        ("dwOwningPid", DWORD),
    ]
MIB_TCP6ROW_OWNER_PID = _MIB_TCP6ROW_OWNER_PID
PMIB_TCP6ROW_OWNER_PID = POINTER(_MIB_TCP6ROW_OWNER_PID)

class _MIB_TCP6TABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCP6ROW_OWNER_PID * ANY_SIZE),
    ]
MIB_TCP6TABLE_OWNER_PID = _MIB_TCP6TABLE_OWNER_PID
PMIB_TCP6TABLE_OWNER_PID = POINTER(_MIB_TCP6TABLE_OWNER_PID)

class _MIB_TCPROW(Structure):
    _fields_ = [
        ("dwState", DWORD),
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
    ]
MIB_TCPROW = _MIB_TCPROW
PMIB_TCPROW = POINTER(_MIB_TCPROW)

class _IP_ADAPTER_INDEX_MAP(Structure):
    _fields_ = [
        ("Index", ULONG),
        ("Name", WCHAR * MAX_ADAPTER_NAME),
    ]
PIP_ADAPTER_INDEX_MAP = POINTER(_IP_ADAPTER_INDEX_MAP)
IP_ADAPTER_INDEX_MAP = _IP_ADAPTER_INDEX_MAP

class _IP_INTERFACE_INFO(Structure):
    _fields_ = [
        ("NumAdapters", LONG),
        ("Adapter", IP_ADAPTER_INDEX_MAP * 1),
    ]
PIP_INTERFACE_INFO = POINTER(_IP_INTERFACE_INFO)
IP_INTERFACE_INFO = _IP_INTERFACE_INFO

# Self referencing struct tricks
class _EXCEPTION_RECORD(Structure): pass
PEXCEPTION_RECORD = POINTER(_EXCEPTION_RECORD)
EXCEPTION_RECORD = _EXCEPTION_RECORD
_EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", POINTER(_EXCEPTION_RECORD)),
    ("ExceptionAddress", PVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", ULONG_PTR * EXCEPTION_MAXIMUM_PARAMETERS),
]

class _EXCEPTION_RECORD32(Structure):
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", DWORD),
        ("ExceptionAddress", DWORD),
        ("NumberParameters", DWORD),
        ("ExceptionInformation", DWORD * EXCEPTION_MAXIMUM_PARAMETERS),
    ]
EXCEPTION_RECORD32 = _EXCEPTION_RECORD32
PEXCEPTION_RECORD32 = POINTER(_EXCEPTION_RECORD32)

class _EXCEPTION_RECORD64(Structure):
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", DWORD64),
        ("ExceptionAddress", DWORD64),
        ("NumberParameters", DWORD),
        ("__unusedAlignment", DWORD),
        ("ExceptionInformation", DWORD64 * EXCEPTION_MAXIMUM_PARAMETERS),
    ]
PEXCEPTION_RECORD64 = POINTER(_EXCEPTION_RECORD64)
EXCEPTION_RECORD64 = _EXCEPTION_RECORD64

class _EXCEPTION_POINTERS64(Structure):
    _fields_ = [
        ("ExceptionRecord", PEXCEPTION_RECORD),
        ("ContextRecord", PCONTEXT64),
    ]
EXCEPTION_POINTERS64 = _EXCEPTION_POINTERS64
PEXCEPTION_POINTERS64 = POINTER(_EXCEPTION_POINTERS64)

class _EXCEPTION_POINTERS32(Structure):
    _fields_ = [
        ("ExceptionRecord", PEXCEPTION_RECORD),
        ("ContextRecord", PCONTEXT32),
    ]
PEXCEPTION_POINTERS32 = POINTER(_EXCEPTION_POINTERS32)
EXCEPTION_POINTERS32 = _EXCEPTION_POINTERS32

class _DEBUG_PROCESSOR_IDENTIFICATION_ALPHA(Structure):
    _fields_ = [
        ("Type", ULONG),
        ("Revision", ULONG),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_ALPHA = _DEBUG_PROCESSOR_IDENTIFICATION_ALPHA
PDEBUG_PROCESSOR_IDENTIFICATION_ALPHA = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_ALPHA)

class _DEBUG_PROCESSOR_IDENTIFICATION_AMD64(Structure):
    _fields_ = [
        ("Family", ULONG),
        ("Model", ULONG),
        ("Stepping", ULONG),
        ("VendorString", CHAR * 16),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_AMD64 = _DEBUG_PROCESSOR_IDENTIFICATION_AMD64
PDEBUG_PROCESSOR_IDENTIFICATION_AMD64 = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_AMD64)

class _DEBUG_PROCESSOR_IDENTIFICATION_IA64(Structure):
    _fields_ = [
        ("Model", ULONG),
        ("Revision", ULONG),
        ("Family", ULONG),
        ("ArchRev", ULONG),
        ("VendorString", CHAR * 16),
    ]
PDEBUG_PROCESSOR_IDENTIFICATION_IA64 = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_IA64)
DEBUG_PROCESSOR_IDENTIFICATION_IA64 = _DEBUG_PROCESSOR_IDENTIFICATION_IA64

class _DEBUG_PROCESSOR_IDENTIFICATION_X86(Structure):
    _fields_ = [
        ("Family", ULONG),
        ("Model", ULONG),
        ("Stepping", ULONG),
        ("VendorString", CHAR * 16),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_X86 = _DEBUG_PROCESSOR_IDENTIFICATION_X86
PDEBUG_PROCESSOR_IDENTIFICATION_X86 = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_X86)

class _DEBUG_PROCESSOR_IDENTIFICATION_ARM(Structure):
    _fields_ = [
        ("Type", ULONG),
        ("Revision", ULONG),
    ]
DEBUG_PROCESSOR_IDENTIFICATION_ARM = _DEBUG_PROCESSOR_IDENTIFICATION_ARM
PDEBUG_PROCESSOR_IDENTIFICATION_ARM = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_ARM)

class _DEBUG_PROCESSOR_IDENTIFICATION_ALL(Union):
    _fields_ = [
        ("Alpha", DEBUG_PROCESSOR_IDENTIFICATION_ALPHA),
        ("Amd64", DEBUG_PROCESSOR_IDENTIFICATION_AMD64),
        ("Ia64", DEBUG_PROCESSOR_IDENTIFICATION_IA64),
        ("X86", DEBUG_PROCESSOR_IDENTIFICATION_X86),
        ("Arm", DEBUG_PROCESSOR_IDENTIFICATION_ARM),
    ]
PDEBUG_PROCESSOR_IDENTIFICATION_ALL = POINTER(_DEBUG_PROCESSOR_IDENTIFICATION_ALL)
DEBUG_PROCESSOR_IDENTIFICATION_ALL = _DEBUG_PROCESSOR_IDENTIFICATION_ALL

class _SYMBOL_INFO(Structure):
    _fields_ = [
        ("SizeOfStruct", ULONG),
        ("TypeIndex", ULONG),
        ("Reserved", ULONG64 * 2),
        ("Index", ULONG),
        ("Size", ULONG),
        ("ModBase", ULONG64),
        ("Flags", ULONG),
        ("Value", ULONG64),
        ("Address", ULONG64),
        ("Register", ULONG),
        ("Scope", ULONG),
        ("Tag", ULONG),
        ("NameLen", ULONG),
        ("MaxNameLen", ULONG),
        ("Name", CHAR * 1),
    ]
SYMBOL_INFO = _SYMBOL_INFO
PSYMBOL_INFO = POINTER(_SYMBOL_INFO)

class _MODLOAD_DATA(Structure):
    _fields_ = [
        ("ssize", DWORD),
        ("ssig", DWORD),
        ("data", PVOID),
        ("size", DWORD),
        ("flags", DWORD),
    ]
PMODLOAD_DATA = POINTER(_MODLOAD_DATA)
MODLOAD_DATA = _MODLOAD_DATA

class _SYSTEM_MODULE32(Structure):
    _fields_ = [
        ("Reserved", ULONG * 2),
        ("Base", ULONG),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Index", USHORT),
        ("Unknown", USHORT),
        ("LoadCount", USHORT),
        ("ModuleNameOffset", USHORT),
        ("ImageName", CHAR * 256),
    ]
SYSTEM_MODULE32 = _SYSTEM_MODULE32
PSYSTEM_MODULE32 = POINTER(_SYSTEM_MODULE32)

class _SYSTEM_MODULE64(Structure):
    _fields_ = [
        ("Reserved", ULONG * 4),
        ("Base", ULONG64),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("Index", USHORT),
        ("Unknown", USHORT),
        ("LoadCount", USHORT),
        ("ModuleNameOffset", USHORT),
        ("ImageName", CHAR * 256),
    ]
SYSTEM_MODULE64 = _SYSTEM_MODULE64
PSYSTEM_MODULE64 = POINTER(_SYSTEM_MODULE64)

class _SYSTEM_MODULE_INFORMATION32(Structure):
    _fields_ = [
        ("ModulesCount", ULONG),
        ("Modules", SYSTEM_MODULE32 * 0),
    ]
PSYSTEM_MODULE_INFORMATION32 = POINTER(_SYSTEM_MODULE_INFORMATION32)
SYSTEM_MODULE_INFORMATION32 = _SYSTEM_MODULE_INFORMATION32

class _SYSTEM_MODULE_INFORMATION64(Structure):
    _fields_ = [
        ("ModulesCount", ULONG),
        ("Modules", SYSTEM_MODULE64 * 0),
    ]
PSYSTEM_MODULE_INFORMATION64 = POINTER(_SYSTEM_MODULE_INFORMATION64)
SYSTEM_MODULE_INFORMATION64 = _SYSTEM_MODULE_INFORMATION64

class tagSAFEARRAYBOUND(Structure):
    _fields_ = [
        ("cElements", ULONG),
        ("lLbound", LONG),
    ]
SAFEARRAYBOUND = tagSAFEARRAYBOUND
LPSAFEARRAYBOUND = POINTER(tagSAFEARRAYBOUND)

class tagSAFEARRAY(Structure):
    _fields_ = [
        ("cDims", USHORT),
        ("fFeatures", USHORT),
        ("cbElements", ULONG),
        ("cLocks", ULONG),
        ("pvData", PVOID),
        ("rgsabound", SAFEARRAYBOUND * 1),
    ]
SAFEARRAY = tagSAFEARRAY

class _DEBUG_BREAKPOINT_PARAMETERS(Structure):
    _fields_ = [
        ("Offset", ULONG64),
        ("Id", ULONG),
        ("BreakType", ULONG),
        ("ProcType", ULONG),
        ("Flags", ULONG),
        ("DataSize", ULONG),
        ("DataAccessType", ULONG),
        ("PassCount", ULONG),
        ("CurrentPassCount", ULONG),
        ("MatchThread", ULONG),
        ("CommandSize", ULONG),
        ("OffsetExpressionSize", ULONG),
    ]
PDEBUG_BREAKPOINT_PARAMETERS = POINTER(_DEBUG_BREAKPOINT_PARAMETERS)
DEBUG_BREAKPOINT_PARAMETERS = _DEBUG_BREAKPOINT_PARAMETERS

class _DEBUG_REGISTER_DESCRIPTION(Structure):
    _fields_ = [
        ("Type", ULONG),
        ("Flags", ULONG),
        ("SubregMaster", ULONG),
        ("SubregLength", ULONG),
        ("SubregMask", ULONG64),
        ("SubregShift", ULONG),
        ("Reserved0", ULONG),
    ]
DEBUG_REGISTER_DESCRIPTION = _DEBUG_REGISTER_DESCRIPTION
PDEBUG_REGISTER_DESCRIPTION = POINTER(_DEBUG_REGISTER_DESCRIPTION)

class _DEBUG_STACK_FRAME(Structure):
    _fields_ = [
        ("InstructionOffset", ULONG64),
        ("ReturnOffset", ULONG64),
        ("FrameOffset", ULONG64),
        ("StackOffset", ULONG64),
        ("FuncTableEntry", ULONG64),
        ("Params", ULONG64 * 4),
        ("Reserved", ULONG64 * 6),
        ("Virtual", BOOL),
        ("FrameNumber", ULONG),
    ]
PDEBUG_STACK_FRAME = POINTER(_DEBUG_STACK_FRAME)
DEBUG_STACK_FRAME = _DEBUG_STACK_FRAME

class _DEBUG_LAST_EVENT_INFO_BREAKPOINT(Structure):
    _fields_ = [
        ("Id", ULONG),
    ]
DEBUG_LAST_EVENT_INFO_BREAKPOINT = _DEBUG_LAST_EVENT_INFO_BREAKPOINT
PDEBUG_LAST_EVENT_INFO_BREAKPOINT = POINTER(_DEBUG_LAST_EVENT_INFO_BREAKPOINT)

class _DEBUG_LAST_EVENT_INFO_EXCEPTION(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD64),
        ("FirstChance", ULONG),
    ]
DEBUG_LAST_EVENT_INFO_EXCEPTION = _DEBUG_LAST_EVENT_INFO_EXCEPTION
PDEBUG_LAST_EVENT_INFO_EXCEPTION = POINTER(_DEBUG_LAST_EVENT_INFO_EXCEPTION)

class _DEBUG_LAST_EVENT_INFO_EXIT_THREAD(Structure):
    _fields_ = [
        ("ExitCode", ULONG),
    ]
PDEBUG_LAST_EVENT_INFO_EXIT_THREAD = POINTER(_DEBUG_LAST_EVENT_INFO_EXIT_THREAD)
DEBUG_LAST_EVENT_INFO_EXIT_THREAD = _DEBUG_LAST_EVENT_INFO_EXIT_THREAD

class _DEBUG_LAST_EVENT_INFO_EXIT_PROCESS(Structure):
    _fields_ = [
        ("ExitCode", ULONG),
    ]
PDEBUG_LAST_EVENT_INFO_EXIT_PROCESS = POINTER(_DEBUG_LAST_EVENT_INFO_EXIT_PROCESS)
DEBUG_LAST_EVENT_INFO_EXIT_PROCESS = _DEBUG_LAST_EVENT_INFO_EXIT_PROCESS

class _DEBUG_LAST_EVENT_INFO_LOAD_MODULE(Structure):
    _fields_ = [
        ("Base", ULONG64),
    ]
PDEBUG_LAST_EVENT_INFO_LOAD_MODULE = POINTER(_DEBUG_LAST_EVENT_INFO_LOAD_MODULE)
DEBUG_LAST_EVENT_INFO_LOAD_MODULE = _DEBUG_LAST_EVENT_INFO_LOAD_MODULE

class _DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE(Structure):
    _fields_ = [
        ("Base", ULONG64),
    ]
PDEBUG_LAST_EVENT_INFO_UNLOAD_MODULE = POINTER(_DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE)
DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE = _DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE

class _DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR(Structure):
    _fields_ = [
        ("Error", ULONG),
        ("Level", ULONG),
    ]
PDEBUG_LAST_EVENT_INFO_SYSTEM_ERROR = POINTER(_DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR)
DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR = _DEBUG_LAST_EVENT_INFO_SYSTEM_ERROR

class _DEBUG_SPECIFIC_FILTER_PARAMETERS(Structure):
    _fields_ = [
        ("ExecutionOption", ULONG),
        ("ContinueOption", ULONG),
        ("TextSize", ULONG),
        ("CommandSize", ULONG),
        ("ArgumentSize", ULONG),
    ]
DEBUG_SPECIFIC_FILTER_PARAMETERS = _DEBUG_SPECIFIC_FILTER_PARAMETERS
PDEBUG_SPECIFIC_FILTER_PARAMETERS = POINTER(_DEBUG_SPECIFIC_FILTER_PARAMETERS)

class _DEBUG_EXCEPTION_FILTER_PARAMETERS(Structure):
    _fields_ = [
        ("ExecutionOption", ULONG),
        ("ContinueOption", ULONG),
        ("TextSize", ULONG),
        ("CommandSize", ULONG),
        ("SecondCommandSize", ULONG),
        ("ExceptionCode", ULONG),
    ]
PDEBUG_EXCEPTION_FILTER_PARAMETERS = POINTER(_DEBUG_EXCEPTION_FILTER_PARAMETERS)
DEBUG_EXCEPTION_FILTER_PARAMETERS = _DEBUG_EXCEPTION_FILTER_PARAMETERS

class _GUID(Structure):
    _fields_ = [
        ("Data1", ULONG),
        ("Data2", USHORT),
        ("Data3", USHORT),
        ("Data4", BYTE * 8),
    ]
IID = _GUID
REFCLSID = POINTER(_GUID)
GUID = _GUID
REFIID = POINTER(_GUID)

class _TMP_signscale(Structure):
    _fields_ = [
        ("scale", BYTE),
        ("sign", BYTE),
    ]


class _TMP_lowmid(Structure):
    _fields_ = [
        ("Lo32", ULONG),
        ("Mid32", ULONG),
    ]


class TMP_signscale_union(Union):
    _fields_ = [
        ("s", _TMP_signscale),
        ("signscale", USHORT),
    ]


class TMP_lowmid_union(Union):
    _fields_ = [
        ("s", _TMP_lowmid),
        ("Lo64", ULONGLONG),
    ]


class tagDEC(Structure):
    _fields_ = [
        ("wReserved", USHORT),
        ("u1", TMP_signscale_union),
        ("Hi32", ULONG),
        ("u2", TMP_signscale_union),
    ]
DECIMAL = tagDEC

class __tagBRECORD(Structure):
    _fields_ = [
        ("pvRecord", PVOID),
        ("pRecInfo", PVOID),
    ]
_tagBRECORD = __tagBRECORD

class TMP_variant_sub_union(Union):
    _fields_ = [
        ("llVal", LONGLONG),
        ("lVal", LONG),
        ("bVal", BYTE),
        ("iVal", SHORT),
        ("fltVal", FLOAT),
        ("dblVal", DOUBLE),
        ("boolVal", VARIANT_BOOL),
        ("scode", SCODE),
        ("bstrVal", BSTR),
        ("punkVal", PVOID),
        ("pdispVal", PVOID),
        ("parray", POINTER(SAFEARRAY)),
        ("pbVal", POINTER(BYTE)),
        ("piVal", POINTER(SHORT)),
        ("plVal", POINTER(LONG)),
        ("pllVal", POINTER(LONGLONG)),
        ("pfltVal", POINTER(FLOAT)),
        ("pdblVal", POINTER(DOUBLE)),
        ("pboolVal", POINTER(VARIANT_BOOL)),
        ("pscode", POINTER(SCODE)),
        ("pbstrVal", POINTER(BSTR)),
        ("byref", PVOID),
        ("cVal", CHAR),
        ("uiVal", USHORT),
        ("ulVal", ULONG),
        ("ullVal", ULONGLONG),
        ("intVal", INT),
        ("uintVal", UINT),
        ("pcVal", POINTER(CHAR)),
        ("puiVal", POINTER(USHORT)),
        ("pulVal", POINTER(ULONG)),
        ("pullVal", POINTER(ULONGLONG)),
        ("pintVal", POINTER(INT)),
        ("puintVal", POINTER(UINT)),
        ("_VARIANT_NAME_4", _tagBRECORD),
    ]


class __tagVARIANT(Structure):
    _fields_ = [
        ("vt", VARTYPE),
        ("wReserved1", WORD),
        ("wReserved2", WORD),
        ("wReserved3", WORD),
        ("_VARIANT_NAME_3", TMP_variant_sub_union),
    ]
LPVARIANTARG = POINTER(__tagVARIANT)
VARIANTARG = __tagVARIANT
VARIANT = __tagVARIANT
LPVARIANT = POINTER(__tagVARIANT)
_tagVARIANT = __tagVARIANT

class tagDISPPARAMS(Structure):
    _fields_ = [
        ("rgvarg", POINTER(VARIANTARG)),
        ("rgdispidNamedArgs", POINTER(DISPID)),
        ("cArgs", UINT),
        ("cNamedArgs", UINT),
    ]
DISPPARAMS = tagDISPPARAMS

class tagEXCEPINFO(Structure):
    _fields_ = [
        ("wCode", WORD),
        ("wReserved", WORD),
        ("bstrSource", BSTR),
        ("bstrDescription", BSTR),
        ("bstrHelpFile", BSTR),
        ("dwHelpContext", DWORD),
        ("pvReserved", ULONG_PTR),
        ("pfnDeferredFillIn", ULONG_PTR),
        ("scode", SCODE),
    ]
EXCEPINFO = tagEXCEPINFO

class _CRYPTOAPI_BLOB(Structure):
    _fields_ = [
        ("cbData", DWORD),
        ("pbData", POINTER(BYTE)),
    ]
CRYPT_INTEGER_BLOB = _CRYPTOAPI_BLOB
PCRYPT_DATA_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_OBJID_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_DER_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRL_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_UINT_BLOB = POINTER(_CRYPTOAPI_BLOB)
CERT_NAME_BLOB = _CRYPTOAPI_BLOB
PCRYPT_DIGEST_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_INTEGER_BLOB = POINTER(_CRYPTOAPI_BLOB)
CERT_RDN_VALUE_BLOB = _CRYPTOAPI_BLOB
PCERT_NAME_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_HASH_BLOB = POINTER(_CRYPTOAPI_BLOB)
CRYPT_DATA_BLOB = _CRYPTOAPI_BLOB
DATA_BLOB = _CRYPTOAPI_BLOB
CRYPT_UINT_BLOB = _CRYPTOAPI_BLOB
PCERT_RDN_VALUE_BLOB = POINTER(_CRYPTOAPI_BLOB)
CRYPT_HASH_BLOB = _CRYPTOAPI_BLOB
CRL_BLOB = _CRYPTOAPI_BLOB
PCERT_BLOB = POINTER(_CRYPTOAPI_BLOB)
CRYPT_DIGEST_BLOB = _CRYPTOAPI_BLOB
CRYPT_OBJID_BLOB = _CRYPTOAPI_BLOB
CERT_BLOB = _CRYPTOAPI_BLOB
CRYPT_DER_BLOB = _CRYPTOAPI_BLOB
PDATA_BLOB = POINTER(_CRYPTOAPI_BLOB)
PCRYPT_ATTR_BLOB = POINTER(_CRYPTOAPI_BLOB)
CRYPT_ATTR_BLOB = _CRYPTOAPI_BLOB

class WINTRUST_FILE_INFO_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("pcwszFilePath", LPCWSTR),
        ("hFile", HANDLE),
        ("pgKnownSubject", POINTER(GUID)),
    ]
WINTRUST_FILE_INFO = WINTRUST_FILE_INFO_
PWINTRUST_FILE_INFO = POINTER(WINTRUST_FILE_INFO_)

class _CRYPT_ATTRIBUTE(Structure):
    _fields_ = [
        ("pszObjId", LPSTR),
        ("cValue", DWORD),
        ("rgValue", PCRYPT_ATTR_BLOB),
    ]
PCRYPT_ATTRIBUTE = POINTER(_CRYPT_ATTRIBUTE)
CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE

class _CTL_ENTRY(Structure):
    _fields_ = [
        ("SubjectIdentifier", CRYPT_DATA_BLOB),
        ("cAttribute", DWORD),
        ("rgAttribute", PCRYPT_ATTRIBUTE),
    ]
PCTL_ENTRY = POINTER(_CTL_ENTRY)
CTL_ENTRY = _CTL_ENTRY

class _CRYPT_ATTRIBUTE(Structure):
    _fields_ = [
        ("pszObjId", LPSTR),
        ("cValue", DWORD),
        ("rgValue", PCRYPT_ATTR_BLOB),
    ]
PCRYPT_ATTRIBUTE = POINTER(_CRYPT_ATTRIBUTE)
CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE

class _CRYPT_ATTRIBUTES(Structure):
    _fields_ = [
        ("cAttr", DWORD),
        ("rgAttr", PCRYPT_ATTRIBUTE),
    ]
CRYPT_ATTRIBUTES = _CRYPT_ATTRIBUTES
PCRYPT_ATTRIBUTES = POINTER(_CRYPT_ATTRIBUTES)

class _CRYPT_ALGORITHM_IDENTIFIER(Structure):
    _fields_ = [
        ("pszObjId", LPSTR),
        ("Parameters", CRYPT_OBJID_BLOB),
    ]
CRYPT_ALGORITHM_IDENTIFIER = _CRYPT_ALGORITHM_IDENTIFIER
PCRYPT_ALGORITHM_IDENTIFIER = POINTER(_CRYPT_ALGORITHM_IDENTIFIER)

class _CMSG_SIGNER_INFO(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("Issuer", CERT_NAME_BLOB),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("HashAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("HashEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("EncryptedHash", CRYPT_DATA_BLOB),
        ("AuthAttrs", CRYPT_ATTRIBUTES),
        ("UnauthAttrs", CRYPT_ATTRIBUTES),
    ]
CMSG_SIGNER_INFO = _CMSG_SIGNER_INFO
PCMSG_SIGNER_INFO = POINTER(_CMSG_SIGNER_INFO)

class _CERT_EXTENSION(Structure):
    _fields_ = [
        ("pszObjId", LPSTR),
        ("fCritical", BOOL),
        ("Value", CRYPT_OBJID_BLOB),
    ]
CERT_EXTENSION = _CERT_EXTENSION
PCERT_EXTENSION = POINTER(_CERT_EXTENSION)

class _CTL_USAGE(Structure):
    _fields_ = [
        ("cUsageIdentifier", DWORD),
        ("rgpszUsageIdentifier", POINTER(LPSTR)),
    ]
CERT_ENHKEY_USAGE = _CTL_USAGE
PCTL_USAGE = POINTER(_CTL_USAGE)
CTL_USAGE = _CTL_USAGE
PCERT_ENHKEY_USAGE = POINTER(_CTL_USAGE)

class _CTL_INFO(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("SubjectUsage", CTL_USAGE),
        ("ListIdentifier", CRYPT_DATA_BLOB),
        ("SequenceNumber", CRYPT_INTEGER_BLOB),
        ("ThisUpdate", FILETIME),
        ("NextUpdate", FILETIME),
        ("SubjectAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("cCTLEntry", DWORD),
        ("rgCTLEntry", PCTL_ENTRY),
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
CTL_INFO = _CTL_INFO
PCTL_INFO = POINTER(_CTL_INFO)

class _CTL_CONTEXT(Structure):
    _fields_ = [
        ("dwMsgAndCertEncodingType", DWORD),
        ("pbCtlEncoded", POINTER(BYTE)),
        ("cbCtlEncoded", DWORD),
        ("pCtlInfo", PCTL_INFO),
        ("hCertStore", HCERTSTORE),
        ("hCryptMsg", HCRYPTMSG),
        ("pbCtlContent", POINTER(BYTE)),
        ("cbCtlContent", DWORD),
    ]
PCTL_CONTEXT = POINTER(_CTL_CONTEXT)
CTL_CONTEXT = _CTL_CONTEXT
PCCTL_CONTEXT = POINTER(_CTL_CONTEXT)

class WINTRUST_CATALOG_INFO_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("dwCatalogVersion", DWORD),
        ("pcwszCatalogFilePath", LPCWSTR),
        ("pcwszMemberTag", LPCWSTR),
        ("pcwszMemberFilePath", LPCWSTR),
        ("hMemberFile", HANDLE),
        ("pbCalculatedFileHash", POINTER(BYTE)),
        ("cbCalculatedFileHash", DWORD),
        ("pcCatalogContext", PCCTL_CONTEXT),
    ]
PWINTRUST_CATALOG_INFO = POINTER(WINTRUST_CATALOG_INFO_)
WINTRUST_CATALOG_INFO = WINTRUST_CATALOG_INFO_

class WINTRUST_BLOB_INFO_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("gSubject", GUID),
        ("pcwszDisplayName", LPCWSTR),
        ("cbMemObject", DWORD),
        ("pbMemObject", POINTER(BYTE)),
        ("cbMemSignedMsg", DWORD),
        ("pbMemSignedMsg", POINTER(BYTE)),
    ]
PWINTRUST_BLOB_INFO = POINTER(WINTRUST_BLOB_INFO_)
WINTRUST_BLOB_INFO = WINTRUST_BLOB_INFO_

class _CRYPT_BIT_BLOB(Structure):
    _fields_ = [
        ("cbData", DWORD),
        ("pbData", POINTER(BYTE)),
        ("cUnusedBits", DWORD),
    ]
CRYPT_BIT_BLOB = _CRYPT_BIT_BLOB
PCRYPT_BIT_BLOB = POINTER(_CRYPT_BIT_BLOB)

class _CERT_PUBLIC_KEY_INFO(Structure):
    _fields_ = [
        ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("PublicKey", CRYPT_BIT_BLOB),
    ]
PCERT_PUBLIC_KEY_INFO = POINTER(_CERT_PUBLIC_KEY_INFO)
CERT_PUBLIC_KEY_INFO = _CERT_PUBLIC_KEY_INFO

class _CERT_INFO(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Issuer", CERT_NAME_BLOB),
        ("NotBefore", FILETIME),
        ("NotAfter", FILETIME),
        ("Subject", CERT_NAME_BLOB),
        ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
        ("IssuerUniqueId", CRYPT_BIT_BLOB),
        ("SubjectUniqueId", CRYPT_BIT_BLOB),
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
CERT_INFO = _CERT_INFO
PCERT_INFO = POINTER(_CERT_INFO)

class _CERT_CONTEXT(Structure):
    _fields_ = [
        ("dwCertEncodingType", DWORD),
        ("pbCertEncoded", POINTER(BYTE)),
        ("cbCertEncoded", DWORD),
        ("pCertInfo", PCERT_INFO),
        ("hCertStore", HCERTSTORE),
    ]
CERT_CONTEXT = _CERT_CONTEXT
PCERT_CONTEXT = POINTER(_CERT_CONTEXT)

class WINTRUST_SGNR_INFO_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("pcwszDisplayName", LPCWSTR),
        ("psSignerInfo", POINTER(CMSG_SIGNER_INFO)),
        ("chStores", DWORD),
        ("pahStores", POINTER(HCERTSTORE)),
    ]
WINTRUST_SGNR_INFO = WINTRUST_SGNR_INFO_
PWINTRUST_SGNR_INFO = POINTER(WINTRUST_SGNR_INFO_)

class _FILETIME(Structure):
    _fields_ = [
        ("dwLowDateTime", DWORD),
        ("dwHighDateTime", DWORD),
    ]
LPFILETIME = POINTER(_FILETIME)
PFILETIME = POINTER(_FILETIME)
FILETIME = _FILETIME

class WINTRUST_CERT_INFO_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("pcwszDisplayName", LPCWSTR),
        ("psCertContext", POINTER(CERT_CONTEXT)),
        ("chStores", DWORD),
        ("pahStores", POINTER(HCERTSTORE)),
        ("dwFlags", DWORD),
        ("psftVerifyAsOf", POINTER(FILETIME)),
    ]
WINTRUST_CERT_INFO = WINTRUST_CERT_INFO_
PWINTRUST_CERT_INFO = POINTER(WINTRUST_CERT_INFO_)

class _TMP_WINTRUST_UNION_TYPE(Union):
    _fields_ = [
        ("pFile", POINTER(WINTRUST_FILE_INFO_)),
        ("pCatalog", POINTER(WINTRUST_CATALOG_INFO_)),
        ("pBlob", POINTER(WINTRUST_BLOB_INFO_)),
        ("pSgnr", POINTER(WINTRUST_SGNR_INFO_)),
        ("pCert", POINTER(WINTRUST_CERT_INFO_)),
    ]
TMP_WINTRUST_UNION_TYPE = _TMP_WINTRUST_UNION_TYPE

class _WINTRUST_DATA(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("pPolicyCallbackData", LPVOID),
        ("pSIPClientData", LPVOID),
        ("dwUIChoice", DWORD),
        ("fdwRevocationChecks", DWORD),
        ("dwUnionChoice", DWORD),
        ("tmp_union", TMP_WINTRUST_UNION_TYPE),
        ("dwStateAction", DWORD),
        ("hWVTStateData", HANDLE),
        ("pwszURLReference", POINTER(WCHAR)),
        ("dwProvFlags", DWORD),
        ("dwUIContext", DWORD),
    ]
PWINTRUST_DATA = POINTER(_WINTRUST_DATA)
WINTRUST_DATA = _WINTRUST_DATA

class _PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus", NTSTATUS),
        ("PebBaseAddress", PPEB),
        ("AffinityMask", ULONG_PTR),
        ("BasePriority", KPRIORITY),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", HANDLE),
    ]
PPROCESS_BASIC_INFORMATION = POINTER(_PROCESS_BASIC_INFORMATION)
PROCESS_BASIC_INFORMATION = _PROCESS_BASIC_INFORMATION

class _JIT_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("dwProcessorArchitecture", DWORD),
        ("dwThreadID", DWORD),
        ("dwReserved0", DWORD),
        ("lpExceptionAddress", ULONG64),
        ("lpExceptionRecord", ULONG64),
        ("lpContextRecord", ULONG64),
    ]
LPJIT_DEBUG_INFO = POINTER(_JIT_DEBUG_INFO)
JIT_DEBUG_INFO = _JIT_DEBUG_INFO

class _SID_IDENTIFIER_AUTHORITY(Structure):
    _fields_ = [
        ("Value", BYTE * 6),
    ]
SID_IDENTIFIER_AUTHORITY = _SID_IDENTIFIER_AUTHORITY
PSID_IDENTIFIER_AUTHORITY = POINTER(_SID_IDENTIFIER_AUTHORITY)

class _EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", DWORD),
    ]
LPEXCEPTION_DEBUG_INFO = POINTER(_EXCEPTION_DEBUG_INFO)
EXCEPTION_DEBUG_INFO = _EXCEPTION_DEBUG_INFO

class _CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPTHREAD_START_ROUTINE),
    ]
LPCREATE_THREAD_DEBUG_INFO = POINTER(_CREATE_THREAD_DEBUG_INFO)
CREATE_THREAD_DEBUG_INFO = _CREATE_THREAD_DEBUG_INFO

class _CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", HANDLE),
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("lpBaseOfImage", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPTHREAD_START_ROUTINE),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]
CREATE_PROCESS_DEBUG_INFO = _CREATE_PROCESS_DEBUG_INFO
LPCREATE_PROCESS_DEBUG_INFO = POINTER(_CREATE_PROCESS_DEBUG_INFO)

class _EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", DWORD),
    ]
EXIT_THREAD_DEBUG_INFO = _EXIT_THREAD_DEBUG_INFO
LPEXIT_THREAD_DEBUG_INFO = POINTER(_EXIT_THREAD_DEBUG_INFO)

class _EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", DWORD),
    ]
LPEXIT_PROCESS_DEBUG_INFO = POINTER(_EXIT_PROCESS_DEBUG_INFO)
EXIT_PROCESS_DEBUG_INFO = _EXIT_PROCESS_DEBUG_INFO

class _LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]
LPLOAD_DLL_DEBUG_INFO = POINTER(_LOAD_DLL_DEBUG_INFO)
LOAD_DLL_DEBUG_INFO = _LOAD_DLL_DEBUG_INFO

class _UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", LPVOID),
    ]
UNLOAD_DLL_DEBUG_INFO = _UNLOAD_DLL_DEBUG_INFO
LPUNLOAD_DLL_DEBUG_INFO = POINTER(_UNLOAD_DLL_DEBUG_INFO)

class _OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData", LPSTR),
        ("fUnicode", WORD),
        ("nDebugStringLength", WORD),
    ]
OUTPUT_DEBUG_STRING_INFO = _OUTPUT_DEBUG_STRING_INFO
LPOUTPUT_DEBUG_STRING_INFO = POINTER(_OUTPUT_DEBUG_STRING_INFO)

class _RIP_INFO(Structure):
    _fields_ = [
        ("dwError", DWORD),
        ("dwType", DWORD),
    ]
LPRIP_INFO = POINTER(_RIP_INFO)
RIP_INFO = _RIP_INFO

class _TMP_UNION_DEBUG_INFO(Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]
TMP_UNION_DEBUG_INFO = _TMP_UNION_DEBUG_INFO

class _DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", _TMP_UNION_DEBUG_INFO),
    ]
LPDEBUG_EVENT = POINTER(_DEBUG_EVENT)
DEBUG_EVENT = _DEBUG_EVENT

class _STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPCSTR),
    ]
PCANSI_STRING = POINTER(_STRING)
PSTRING = POINTER(_STRING)
STRING = _STRING
PANSI_STRING = POINTER(_STRING)

class _OBJECT_ATTRIBUTES(Structure):
    _fields_ = [
        ("Length", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", PUNICODE_STRING),
        ("Attributes", ULONG),
        ("SecurityDescriptor", PVOID),
        ("SecurityQualityOfService", PVOID),
    ]
POBJECT_ATTRIBUTES = POINTER(_OBJECT_ATTRIBUTES)
OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES

class _TMP_UNION_IO_STATUS_BLOCK(Union):
    _fields_ = [
        ("Status", NTSTATUS),
        ("Pointer", PVOID),
    ]
TMP_UNION_IO_STATUS_BLOCK = _TMP_UNION_IO_STATUS_BLOCK

class _IO_STATUS_BLOCK(Structure):
    _fields_ = [
        ("DUMMYUNIONNAME", TMP_UNION_IO_STATUS_BLOCK),
        ("Information", ULONG_PTR),
    ]
IO_STATUS_BLOCK = _IO_STATUS_BLOCK
PIO_STATUS_BLOCK = POINTER(_IO_STATUS_BLOCK)

class _SECURITY_QUALITY_OF_SERVICE(Structure):
    _fields_ = [
        ("Length", DWORD),
        ("ImpersonationLevel", SECURITY_IMPERSONATION_LEVEL),
        ("ContextTrackingMode", SECURITY_CONTEXT_TRACKING_MODE),
        ("EffectiveOnly", BOOLEAN),
    ]
PSECURITY_QUALITY_OF_SERVICE = POINTER(_SECURITY_QUALITY_OF_SERVICE)
SECURITY_QUALITY_OF_SERVICE = _SECURITY_QUALITY_OF_SERVICE

class _SERVICE_STATUS(Structure):
    _fields_ = [
        ("dwServiceType", DWORD),
        ("dwCurrentState", DWORD),
        ("dwControlsAccepted", DWORD),
        ("dwWin32ExitCode", DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint", DWORD),
        ("dwWaitHint", DWORD),
    ]
SERVICE_STATUS = _SERVICE_STATUS
LPSERVICE_STATUS = POINTER(_SERVICE_STATUS)

class _SERVICE_STATUS_PROCESS(Structure):
    _fields_ = [
        ("dwServiceType", DWORD),
        ("dwCurrentState", DWORD),
        ("dwControlsAccepted", DWORD),
        ("dwWin32ExitCode", DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint", DWORD),
        ("dwWaitHint", DWORD),
        ("dwProcessId", DWORD),
        ("dwServiceFlags", DWORD),
    ]
LPSERVICE_STATUS_PROCESS = POINTER(_SERVICE_STATUS_PROCESS)
SERVICE_STATUS_PROCESS = _SERVICE_STATUS_PROCESS

class _ENUM_SERVICE_STATUS_PROCESSA(Structure):
    _fields_ = [
        ("lpServiceName", LPSTR),
        ("lpDisplayName", LPSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]
LPENUM_SERVICE_STATUS_PROCESSA = POINTER(_ENUM_SERVICE_STATUS_PROCESSA)
ENUM_SERVICE_STATUS_PROCESSA = _ENUM_SERVICE_STATUS_PROCESSA

class _ENUM_SERVICE_STATUS_PROCESSW(Structure):
    _fields_ = [
        ("lpServiceName", LPWSTR),
        ("lpDisplayName", LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]
ENUM_SERVICE_STATUS_PROCESSW = _ENUM_SERVICE_STATUS_PROCESSW
LPENUM_SERVICE_STATUS_PROCESSW = POINTER(_ENUM_SERVICE_STATUS_PROCESSW)

class CATALOG_INFO_(Structure):
    _fields_ = [
        ("cbStruct", DWORD),
        ("wszCatalogFile", WCHAR * MAX_PATH),
    ]
CATALOG_INFO = CATALOG_INFO_

class _SYSTEM_HANDLE(Structure):
    _fields_ = [
        ("dwProcessId", DWORD),
        ("bObjectType", BYTE),
        ("bFlags", BYTE),
        ("wValue", WORD),
        ("pAddress", PVOID),
        ("GrantedAccess", DWORD),
    ]
SYSTEM_HANDLE = _SYSTEM_HANDLE

class _SYSTEM_HANDLE_INFORMATION(Structure):
    _fields_ = [
        ("HandleCount", ULONG),
        ("Handles", SYSTEM_HANDLE * 1),
    ]
PSYSTEM_HANDLE_INFORMATION = POINTER(_SYSTEM_HANDLE_INFORMATION)
SYSTEM_HANDLE_INFORMATION = _SYSTEM_HANDLE_INFORMATION

class __PUBLIC_OBJECT_TYPE_INFORMATION(Structure):
    _fields_ = [
        ("TypeName", UNICODE_STRING),
        ("Reserved", ULONG * 22),
    ]
PPUBLIC_OBJECT_TYPE_INFORMATION = POINTER(__PUBLIC_OBJECT_TYPE_INFORMATION)
PUBLIC_OBJECT_TYPE_INFORMATION = __PUBLIC_OBJECT_TYPE_INFORMATION

class _PUBLIC_OBJECT_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("Attributes", ULONG),
        ("GrantedAccess", ACCESS_MASK),
        ("HandleCount", ULONG),
        ("PointerCount", ULONG),
        ("Reserved", ULONG * 10),
    ]
PUBLIC_OBJECT_BASIC_INFORMATION = _PUBLIC_OBJECT_BASIC_INFORMATION
PPUBLIC_OBJECT_BASIC_INFORMATION = POINTER(_PUBLIC_OBJECT_BASIC_INFORMATION)

class _EVENTLOGRECORD(Structure):
    _fields_ = [
        ("Length", DWORD),
        ("Reserved", DWORD),
        ("RecordNumber", DWORD),
        ("TimeGenerated", DWORD),
        ("TimeWritten", DWORD),
        ("EventID", DWORD),
        ("EventType", WORD),
        ("NumStrings", WORD),
        ("EventCategory", WORD),
        ("ReservedFlags", WORD),
        ("ClosingRecordNumber", DWORD),
        ("StringOffset", DWORD),
        ("UserSidLength", DWORD),
        ("UserSidOffset", DWORD),
        ("DataLength", DWORD),
        ("DataOffset", DWORD),
    ]
PEVENTLOGRECORD = POINTER(_EVENTLOGRECORD)
EVENTLOGRECORD = _EVENTLOGRECORD

class tagSOLE_AUTHENTICATION_SERVICE(Structure):
    _fields_ = [
        ("dwAuthnSvc", DWORD),
        ("dwAuthzSvc", DWORD),
        ("pPrincipalName", POINTER(OLECHAR)),
        ("hr", HRESULT),
    ]
PSOLE_AUTHENTICATION_SERVICE = POINTER(tagSOLE_AUTHENTICATION_SERVICE)
SOLE_AUTHENTICATION_SERVICE = tagSOLE_AUTHENTICATION_SERVICE

class _OBJECT_DIRECTORY_INFORMATION(Structure):
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("TypeName", UNICODE_STRING),
    ]
OBJECT_DIRECTORY_INFORMATION = _OBJECT_DIRECTORY_INFORMATION
POBJECT_DIRECTORY_INFORMATION = POINTER(_OBJECT_DIRECTORY_INFORMATION)

class _DEBUG_VALUE_TMP_SUBSTRUCT1(Structure):
    _fields_ = [
        ("I64", ULONG64),
        ("Nat", BOOL),
    ]
DEBUG_VALUE_TMP_SUBSTRUCT1 = _DEBUG_VALUE_TMP_SUBSTRUCT1

class _DEBUG_VALUE_TMP_SUBSTRUCT2(Structure):
    _fields_ = [
        ("LowPart", ULONG),
        ("HighPart", ULONG),
    ]
DEBUG_VALUE_TMP_SUBSTRUCT2 = _DEBUG_VALUE_TMP_SUBSTRUCT2

class _DEBUG_VALUE_TMP_SUBSTRUCT3(Structure):
    _fields_ = [
        ("LowPart", ULONG64),
        ("HighPart", LONG64),
    ]
DEBUG_VALUE_TMP_SUBSTRUCT3 = _DEBUG_VALUE_TMP_SUBSTRUCT3

class _DEBUG_VALUE_TMP_UNION(Union):
    _fields_ = [
        ("I8", UCHAR),
        ("I16", USHORT),
        ("I32", ULONG),
        ("tmp_sub_struct_1", _DEBUG_VALUE_TMP_SUBSTRUCT1),
        ("F32", FLOAT),
        ("F64", DOUBLE),
        ("F80Bytes", UCHAR * 10),
        ("F82Bytes", UCHAR * 11),
        ("F128Bytes", UCHAR * 16),
        ("VI8", UCHAR * 16),
        ("VI16", USHORT * 8),
        ("VI32", ULONG * 4),
        ("VI64", ULONG64 * 2),
        ("VF32", FLOAT * 4),
        ("VF64", DOUBLE * 2),
        ("I64Parts32", DEBUG_VALUE_TMP_SUBSTRUCT2),
        ("F128Parts64", DEBUG_VALUE_TMP_SUBSTRUCT3),
        ("RawBytes", UCHAR * 24),
    ]
DEBUG_VALUE_TMP_UNION = _DEBUG_VALUE_TMP_UNION

class _DEBUG_VALUE(Structure):
    _fields_ = [
        ("u", _DEBUG_VALUE_TMP_UNION),
        ("TailOfRawBytes", ULONG),
        ("Type", ULONG),
    ]
DEBUG_VALUE = _DEBUG_VALUE
PDEBUG_VALUE = POINTER(_DEBUG_VALUE)

class _DEBUG_SYMBOL_PARAMETERS(Structure):
    _fields_ = [
        ("Module", ULONG64),
        ("TypeId", ULONG),
        ("ParentSymbol", ULONG),
        ("SubElements", ULONG),
        ("Flags", ULONG),
        ("Reserved", ULONG64),
    ]
DEBUG_SYMBOL_PARAMETERS = _DEBUG_SYMBOL_PARAMETERS
PDEBUG_SYMBOL_PARAMETERS = POINTER(_DEBUG_SYMBOL_PARAMETERS)

class _DEBUG_SYMBOL_ENTRY(Structure):
    _fields_ = [
        ("ModuleBase", ULONG64),
        ("Offset", ULONG64),
        ("Id", ULONG64),
        ("Arg64", ULONG64),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("TypeId", ULONG),
        ("NameSize", ULONG),
        ("Token", ULONG),
        ("Tag", ULONG),
        ("Arg32", ULONG),
        ("Reserved", ULONG),
    ]
PDEBUG_SYMBOL_ENTRY = POINTER(_DEBUG_SYMBOL_ENTRY)
DEBUG_SYMBOL_ENTRY = _DEBUG_SYMBOL_ENTRY

class _DEBUG_MODULE_PARAMETERS(Structure):
    _fields_ = [
        ("Base", ULONG64),
        ("Size", ULONG),
        ("TimeDateStamp", ULONG),
        ("Checksum", ULONG),
        ("Flags", ULONG),
        ("SymbolType", ULONG),
        ("ImageNameSize", ULONG),
        ("ModuleNameSize", ULONG),
        ("LoadedImageNameSize", ULONG),
        ("SymbolFileNameSize", ULONG),
        ("MappedImageNameSize", ULONG),
        ("Reserved", ULONG64 * 2),
    ]
PDEBUG_MODULE_PARAMETERS = POINTER(_DEBUG_MODULE_PARAMETERS)
DEBUG_MODULE_PARAMETERS = _DEBUG_MODULE_PARAMETERS

class _DEBUG_MODULE_AND_ID(Structure):
    _fields_ = [
        ("ModuleBase", ULONG64),
        ("Id", ULONG64),
    ]
DEBUG_MODULE_AND_ID = _DEBUG_MODULE_AND_ID
PDEBUG_MODULE_AND_ID = POINTER(_DEBUG_MODULE_AND_ID)

class _DEBUG_OFFSET_REGION(Structure):
    _fields_ = [
        ("Base", ULONG64),
        ("Size", ULONG64),
    ]
DEBUG_OFFSET_REGION = _DEBUG_OFFSET_REGION
PDEBUG_OFFSET_REGION = POINTER(_DEBUG_OFFSET_REGION)

class _DEBUG_SYMBOL_SOURCE_ENTRY(Structure):
    _fields_ = [
        ("ModuleBase", ULONG64),
        ("Offset", ULONG64),
        ("FileNameId", ULONG64),
        ("EngineInternal", ULONG64),
        ("Size", ULONG),
        ("Flags", ULONG),
        ("FileNameSize", ULONG),
        ("StartLine", ULONG),
        ("EndLine", ULONG),
        ("StartColumn", ULONG),
        ("EndColumn", ULONG),
        ("Reserved", ULONG),
    ]
DEBUG_SYMBOL_SOURCE_ENTRY = _DEBUG_SYMBOL_SOURCE_ENTRY
PDEBUG_SYMBOL_SOURCE_ENTRY = POINTER(_DEBUG_SYMBOL_SOURCE_ENTRY)

class _CMSG_SIGNER_INFO(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("Issuer", CERT_NAME_BLOB),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("HashAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("HashEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("EncryptedHash", CRYPT_DATA_BLOB),
        ("AuthAttrs", CRYPT_ATTRIBUTES),
        ("UnauthAttrs", CRYPT_ATTRIBUTES),
    ]
CMSG_SIGNER_INFO = _CMSG_SIGNER_INFO
PCMSG_SIGNER_INFO = POINTER(_CMSG_SIGNER_INFO)

class _SPC_SERIALIZED_OBJECT(Structure):
    _fields_ = [
        ("ClassId", SPC_UUID),
        ("SerializedData", CRYPT_DATA_BLOB),
    ]
SPC_SERIALIZED_OBJECT = _SPC_SERIALIZED_OBJECT
PSPC_SERIALIZED_OBJECT = POINTER(_SPC_SERIALIZED_OBJECT)

class _TMP_SPC_LINK_UNION(Union):
    _fields_ = [
        ("pwszUrl", LPWSTR),
        ("Moniker", SPC_SERIALIZED_OBJECT),
        ("pwszFile", LPWSTR),
    ]
TMP_SPC_LINK_UNION = _TMP_SPC_LINK_UNION

class SPC_LINK_(Structure):
    _fields_ = [
        ("dwLinkChoice", DWORD),
        ("u", TMP_SPC_LINK_UNION),
    ]
PSPC_LINK = POINTER(SPC_LINK_)
SPC_LINK = SPC_LINK_

class _SPC_SP_OPUS_INFO(Structure):
    _fields_ = [
        ("pwszProgramName", LPCWSTR),
        ("pMoreInfo", POINTER(SPC_LINK_)),
        ("pPublisherInfo", POINTER(SPC_LINK_)),
    ]
PSPC_SP_OPUS_INFO = POINTER(_SPC_SP_OPUS_INFO)
SPC_SP_OPUS_INFO = _SPC_SP_OPUS_INFO

class _CERT_TRUST_STATUS(Structure):
    _fields_ = [
        ("dwErrorStatus", DWORD),
        ("dwInfoStatus", DWORD),
    ]
PCERT_TRUST_STATUS = POINTER(_CERT_TRUST_STATUS)
CERT_TRUST_STATUS = _CERT_TRUST_STATUS

class _CERT_TRUST_LIST_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("pCtlEntry", PCTL_ENTRY),
        ("pCtlContext", PCCTL_CONTEXT),
    ]
PCERT_TRUST_LIST_INFO = POINTER(_CERT_TRUST_LIST_INFO)
CERT_TRUST_LIST_INFO = _CERT_TRUST_LIST_INFO

class _CERT_CONTEXT(Structure):
    _fields_ = [
        ("dwCertEncodingType", DWORD),
        ("pbCertEncoded", POINTER(BYTE)),
        ("cbCertEncoded", DWORD),
        ("pCertInfo", PCERT_INFO),
        ("hCertStore", HCERTSTORE),
    ]
PCCERT_CONTEXT = POINTER(_CERT_CONTEXT)
CERT_CONTEXT = _CERT_CONTEXT
PCERT_CONTEXT = POINTER(_CERT_CONTEXT)

class _CRL_ENTRY(Structure):
    _fields_ = [
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("RevocationDate", FILETIME),
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
CRL_ENTRY = _CRL_ENTRY
PCRL_ENTRY = POINTER(_CRL_ENTRY)

class _CRL_INFO(Structure):
    _fields_ = [
        ("dwVersion", DWORD),
        ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Issuer", CERT_NAME_BLOB),
        ("ThisUpdate", FILETIME),
        ("NextUpdate", FILETIME),
        ("cCRLEntry", DWORD),
        ("rgCRLEntry", PCRL_ENTRY),
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
CRL_INFO = _CRL_INFO
PCRL_INFO = POINTER(_CRL_INFO)

class _CRL_CONTEXT(Structure):
    _fields_ = [
        ("dwCertEncodingType", DWORD),
        ("pbCrlEncoded", POINTER(BYTE)),
        ("cbCrlEncoded", DWORD),
        ("pCrlInfo", PCRL_INFO),
        ("hCertStore", HCERTSTORE),
    ]
PCCRL_CONTEXT = POINTER(_CRL_CONTEXT)
CRL_CONTEXT = _CRL_CONTEXT
PCRL_CONTEXT = POINTER(_CRL_CONTEXT)

class _CERT_REVOCATION_CRL_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("pBaseCrlContext", PCCRL_CONTEXT),
        ("pDeltaCrlContext", PCCRL_CONTEXT),
        ("pCrlEntry", PCRL_ENTRY),
        ("fDeltaCrlEntry", BOOL),
    ]
CERT_REVOCATION_CRL_INFO = _CERT_REVOCATION_CRL_INFO
PCERT_REVOCATION_CRL_INFO = POINTER(_CERT_REVOCATION_CRL_INFO)

class _CERT_REVOCATION_INFO(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwRevocationResult", DWORD),
        ("pszRevocationOid", LPCSTR),
        ("pvOidSpecificInfo", LPVOID),
        ("fHasFreshnessTime", BOOL),
        ("dwFreshnessTime", DWORD),
        ("pCrlInfo", PCERT_REVOCATION_CRL_INFO),
    ]
CERT_REVOCATION_INFO = _CERT_REVOCATION_INFO
PCERT_REVOCATION_INFO = POINTER(_CERT_REVOCATION_INFO)

class _CERT_CHAIN_ELEMENT(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("pCertContext", PCCERT_CONTEXT),
        ("TrustStatus", CERT_TRUST_STATUS),
        ("pRevocationInfo", PCERT_REVOCATION_INFO),
        ("pIssuanceUsage", PCERT_ENHKEY_USAGE),
        ("pApplicationUsage", PCERT_ENHKEY_USAGE),
        ("pwszExtendedErrorInfo", LPCWSTR),
    ]
PCERT_CHAIN_ELEMENT = POINTER(_CERT_CHAIN_ELEMENT)
CERT_CHAIN_ELEMENT = _CERT_CHAIN_ELEMENT
PCCERT_CHAIN_ELEMENT = POINTER(_CERT_CHAIN_ELEMENT)

class _CERT_SIMPLE_CHAIN(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("TrustStatus", CERT_TRUST_STATUS),
        ("cElement", DWORD),
        ("rgpElement", POINTER(PCERT_CHAIN_ELEMENT)),
        ("pTrustListInfo", PCERT_TRUST_LIST_INFO),
        ("fHasRevocationFreshnessTime", BOOL),
        ("dwRevocationFreshnessTime", DWORD),
    ]
CERT_SIMPLE_CHAIN = _CERT_SIMPLE_CHAIN
PCERT_SIMPLE_CHAIN = POINTER(_CERT_SIMPLE_CHAIN)
PCCERT_SIMPLE_CHAIN = POINTER(_CERT_SIMPLE_CHAIN)

# Self referencing struct tricks
class _CERT_CHAIN_CONTEXT(Structure): pass
CERT_CHAIN_CONTEXT = _CERT_CHAIN_CONTEXT
PCERT_CHAIN_CONTEXT = POINTER(_CERT_CHAIN_CONTEXT)
PCCERT_CHAIN_CONTEXT = POINTER(_CERT_CHAIN_CONTEXT)
_CERT_CHAIN_CONTEXT._fields_ = [
    ("cbSize", DWORD),
    ("TrustStatus", CERT_TRUST_STATUS),
    ("cChain", DWORD),
    ("rgpChain", POINTER(PCERT_SIMPLE_CHAIN)),
    ("cLowerQualityChainContext", DWORD),
    ("rgpLowerQualityChainContext", POINTER(PCCERT_CHAIN_CONTEXT)),
    ("fHasRevocationFreshnessTime", BOOL),
    ("dwRevocationFreshnessTime", DWORD),
    ("dwCreateFlags", DWORD),
    ("ChainId", GUID),
]

class _CERT_USAGE_MATCH(Structure):
    _fields_ = [
        ("dwType", DWORD),
        ("Usage", CERT_ENHKEY_USAGE),
    ]
CERT_USAGE_MATCH = _CERT_USAGE_MATCH
PCERT_USAGE_MATCH = POINTER(_CERT_USAGE_MATCH)

class _CERT_CHAIN_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("RequestedUsage", CERT_USAGE_MATCH),
        ("RequestedIssuancePolicy", CERT_USAGE_MATCH),
        ("dwUrlRetrievalTimeout", DWORD),
        ("fCheckRevocationFreshnessTime", BOOL),
        ("dwRevocationFreshnessTime", DWORD),
        ("pftCacheResync", LPFILETIME),
    ]
CERT_CHAIN_PARA = _CERT_CHAIN_PARA
PCERT_CHAIN_PARA = POINTER(_CERT_CHAIN_PARA)

class _CERT_CHAIN_ENGINE_CONFIG(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("hRestrictedRoot", HCERTSTORE),
        ("hRestrictedTrust", HCERTSTORE),
        ("hRestrictedOther", HCERTSTORE),
        ("cAdditionalStore", DWORD),
        ("rghAdditionalStore", POINTER(HCERTSTORE)),
        ("dwFlags", DWORD),
        ("dwUrlRetrievalTimeout", DWORD),
        ("MaximumCachedCertificates", DWORD),
        ("CycleDetectionModulus", DWORD),
    ]
CERT_CHAIN_ENGINE_CONFIG = _CERT_CHAIN_ENGINE_CONFIG
PCERT_CHAIN_ENGINE_CONFIG = POINTER(_CERT_CHAIN_ENGINE_CONFIG)

class _SYSTEMTIME(Structure):
    _fields_ = [
        ("wYear", WORD),
        ("wMonth", WORD),
        ("wDayOfWeek", WORD),
        ("wDay", WORD),
        ("wHour", WORD),
        ("wMinute", WORD),
        ("wSecond", WORD),
        ("wMilliseconds", WORD),
    ]
SYSTEMTIME = _SYSTEMTIME
PSYSTEMTIME = POINTER(_SYSTEMTIME)

class _CERT_EXTENSIONS(Structure):
    _fields_ = [
        ("cExtension", DWORD),
        ("rgExtension", PCERT_EXTENSION),
    ]
PCERT_EXTENSIONS = POINTER(_CERT_EXTENSIONS)
CERT_EXTENSIONS = _CERT_EXTENSIONS

class _CRYPT_KEY_PROV_PARAM(Structure):
    _fields_ = [
        ("dwParam", DWORD),
        ("pbData", POINTER(BYTE)),
        ("cbData", DWORD),
        ("dwFlags", DWORD),
    ]
CRYPT_KEY_PROV_PARAM = _CRYPT_KEY_PROV_PARAM
PCRYPT_KEY_PROV_PARAM = POINTER(_CRYPT_KEY_PROV_PARAM)

class _CRYPT_KEY_PROV_INFO(Structure):
    _fields_ = [
        ("pwszContainerName", LPWSTR),
        ("pwszProvName", LPWSTR),
        ("dwProvType", DWORD),
        ("dwFlags", DWORD),
        ("cProvParam", DWORD),
        ("rgProvParam", PCRYPT_KEY_PROV_PARAM),
        ("dwKeySpec", DWORD),
    ]
CRYPT_KEY_PROV_INFO = _CRYPT_KEY_PROV_INFO
PCRYPT_KEY_PROV_INFO = POINTER(_CRYPT_KEY_PROV_INFO)

class _CRYPT_ENCRYPT_MESSAGE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwMsgEncodingType", DWORD),
        ("hCryptProv", HCRYPTPROV_LEGACY),
        ("ContentEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("pvEncryptionAuxInfo", POINTER(VOID)),
        ("dwFlags", DWORD),
        ("dwInnerContentType", DWORD),
    ]
PCRYPT_ENCRYPT_MESSAGE_PARA = POINTER(_CRYPT_ENCRYPT_MESSAGE_PARA)
CRYPT_ENCRYPT_MESSAGE_PARA = _CRYPT_ENCRYPT_MESSAGE_PARA

class _CRYPT_DECRYPT_MESSAGE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("dwMsgAndCertEncodingType", DWORD),
        ("cCertStore", DWORD),
        ("rghCertStore", POINTER(HCERTSTORE)),
        ("dwFlags", DWORD),
    ]
PCRYPT_DECRYPT_MESSAGE_PARA = POINTER(_CRYPT_DECRYPT_MESSAGE_PARA)
CRYPT_DECRYPT_MESSAGE_PARA = _CRYPT_DECRYPT_MESSAGE_PARA

class _CERT_KEY_CONTEXT(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("hCryptProv", HCRYPTPROV),
        ("dwKeySpec", DWORD),
    ]
CERT_KEY_CONTEXT = _CERT_KEY_CONTEXT
PCERT_KEY_CONTEXT = POINTER(_CERT_KEY_CONTEXT)

class _CRYPT_ENCODE_PARA(Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("pfnAlloc", PVOID),
        ("pfnFree", PVOID),
    ]
PCRYPT_ENCODE_PARA = POINTER(_CRYPT_ENCODE_PARA)
CRYPT_ENCODE_PARA = _CRYPT_ENCODE_PARA

class tagPOINT(Structure):
    _fields_ = [
        ("x", LONG),
        ("y", LONG),
    ]
LPPOINT = POINTER(tagPOINT)
PPOINT = POINTER(tagPOINT)
POINT = tagPOINT

class _ACL(Structure):
    _fields_ = [
        ("AclRevision", BYTE),
        ("Sbz1", BYTE),
        ("AclSize", WORD),
        ("AceCount", WORD),
        ("Sbz2", WORD),
    ]
PACL = POINTER(_ACL)
ACL = _ACL

class _ACE_HEADER(Structure):
    _fields_ = [
        ("AceType", BYTE),
        ("AceFlags", BYTE),
        ("AceSize", WORD),
    ]
PACE_HEADER = POINTER(_ACE_HEADER)
ACE_HEADER = _ACE_HEADER

class _ACCESS_ALLOWED_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
PACCESS_ALLOWED_ACE = POINTER(_ACCESS_ALLOWED_ACE)
ACCESS_ALLOWED_ACE = _ACCESS_ALLOWED_ACE

class _ACCESS_ALLOWED_CALLBACK_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
PACCESS_ALLOWED_CALLBACK_ACE = POINTER(_ACCESS_ALLOWED_CALLBACK_ACE)
ACCESS_ALLOWED_CALLBACK_ACE = _ACCESS_ALLOWED_CALLBACK_ACE

class _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
PACCESS_ALLOWED_CALLBACK_OBJECT_ACE = POINTER(_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE)
ACCESS_ALLOWED_CALLBACK_OBJECT_ACE = _ACCESS_ALLOWED_CALLBACK_OBJECT_ACE

class _ACCESS_ALLOWED_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
PACCESS_ALLOWED_OBJECT_ACE = POINTER(_ACCESS_ALLOWED_OBJECT_ACE)
ACCESS_ALLOWED_OBJECT_ACE = _ACCESS_ALLOWED_OBJECT_ACE

class _ACCESS_DENIED_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
ACCESS_DENIED_ACE = _ACCESS_DENIED_ACE
PACCESS_DENIED_ACE = POINTER(_ACCESS_DENIED_ACE)

class _ACCESS_DENIED_CALLBACK_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
ACCESS_DENIED_CALLBACK_ACE = _ACCESS_DENIED_CALLBACK_ACE
PACCESS_DENIED_CALLBACK_ACE = POINTER(_ACCESS_DENIED_CALLBACK_ACE)

class _ACCESS_DENIED_OBJECT_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("Flags", DWORD),
        ("ObjectType", GUID),
        ("InheritedObjectType", GUID),
        ("SidStart", DWORD),
    ]
ACCESS_DENIED_OBJECT_ACE = _ACCESS_DENIED_OBJECT_ACE
PACCESS_DENIED_OBJECT_ACE = POINTER(_ACCESS_DENIED_OBJECT_ACE)

class _SYSTEM_MANDATORY_LABEL_ACE(Structure):
    _fields_ = [
        ("Header", ACE_HEADER),
        ("Mask", ACCESS_MASK),
        ("SidStart", DWORD),
    ]
SYSTEM_MANDATORY_LABEL_ACE = _SYSTEM_MANDATORY_LABEL_ACE
PSYSTEM_MANDATORY_LABEL_ACE = POINTER(_SYSTEM_MANDATORY_LABEL_ACE)

class tagRECT(Structure):
    _fields_ = [
        ("left", LONG),
        ("top", LONG),
        ("right", LONG),
        ("bottom", LONG),
    ]
LPRECT = POINTER(tagRECT)
NPRECT = POINTER(tagRECT)
RECT = tagRECT
PRECT = POINTER(tagRECT)

class tagRGBTRIPLE(Structure):
    _fields_ = [
        ("rgbtBlue", BYTE),
        ("rgbtGreen", BYTE),
        ("rgbtRed", BYTE),
    ]
NPRGBTRIPLE = POINTER(tagRGBTRIPLE)
LPRGBTRIPLE = POINTER(tagRGBTRIPLE)
RGBTRIPLE = tagRGBTRIPLE
PRGBTRIPLE = POINTER(tagRGBTRIPLE)

class tagBITMAPFILEHEADER(Structure):
    _pack_ = 2
    _fields_ = [
        ("bfType", WORD),
        ("bfSize", DWORD),
        ("bfReserved1", WORD),
        ("bfReserved2", WORD),
        ("bfOffBits", DWORD),
    ]
BITMAPFILEHEADER = tagBITMAPFILEHEADER
PBITMAPFILEHEADER = POINTER(tagBITMAPFILEHEADER)
LPBITMAPFILEHEADER = POINTER(tagBITMAPFILEHEADER)

class tagBITMAPCOREHEADER(Structure):
    _fields_ = [
        ("bcSize", DWORD),
        ("bcWidth", WORD),
        ("bcHeight", WORD),
        ("bcPlanes", WORD),
        ("bcBitCount", WORD),
    ]
LPBITMAPCOREHEADER = POINTER(tagBITMAPCOREHEADER)
PBITMAPCOREHEADER = POINTER(tagBITMAPCOREHEADER)
BITMAPCOREHEADER = tagBITMAPCOREHEADER

class tagBITMAP(Structure):
    _fields_ = [
        ("bmType", LONG),
        ("bmWidth", LONG),
        ("bmHeight", LONG),
        ("bmWidthBytes", LONG),
        ("bmPlanes", WORD),
        ("bmBitsPixel", WORD),
        ("bmBits", LPVOID),
    ]
NPBITMAP = POINTER(tagBITMAP)
LPBITMAP = POINTER(tagBITMAP)
PBITMAP = POINTER(tagBITMAP)
BITMAP = tagBITMAP

class tagBITMAPINFOHEADER(Structure):
    _fields_ = [
        ("biSize", DWORD),
        ("biWidth", LONG),
        ("biHeight", LONG),
        ("biPlanes", WORD),
        ("biBitCount", WORD),
        ("biCompression", DWORD),
        ("biSizeImage", DWORD),
        ("biXPelsPerMeter", LONG),
        ("biYPelsPerMeter", LONG),
        ("biClrUsed", DWORD),
        ("biClrImportant", DWORD),
    ]
BITMAPINFOHEADER = tagBITMAPINFOHEADER
PBITMAPINFOHEADER = POINTER(tagBITMAPINFOHEADER)
LPBITMAPINFOHEADER = POINTER(tagBITMAPINFOHEADER)

class tagRGBQUAD(Structure):
    _fields_ = [
        ("rgbBlue", BYTE),
        ("rgbGreen", BYTE),
        ("rgbRed", BYTE),
        ("rgbReserved", BYTE),
    ]
RGBQUAD = tagRGBQUAD

class tagBITMAPINFO(Structure):
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", RGBQUAD * 1),
    ]
LPBITMAPINFO = POINTER(tagBITMAPINFO)
PBITMAPINFO = POINTER(tagBITMAPINFO)
BITMAPINFO = tagBITMAPINFO

class tagBITMAPCOREINFO(Structure):
    _fields_ = [
        ("bmciHeader", BITMAPCOREHEADER),
        ("bmciColors", RGBTRIPLE * 1),
    ]
LPBITMAPCOREINFO = POINTER(tagBITMAPCOREINFO)
BITMAPCOREINFO = tagBITMAPCOREINFO
PBITMAPCOREINFO = POINTER(tagBITMAPCOREINFO)

class _BG_FILE_PROGRESS(Structure):
    _fields_ = [
        ("BytesTotal", UINT64),
        ("BytesTransferred", UINT64),
        ("Completed", BOOL),
    ]
BG_FILE_PROGRESS = _BG_FILE_PROGRESS

class _BG_JOB_PROGRESS(Structure):
    _fields_ = [
        ("BytesTotal", UINT64),
        ("BytesTransferred", UINT64),
        ("FilesTotal", ULONG),
        ("FilesTransferred", ULONG),
    ]
BG_JOB_PROGRESS = _BG_JOB_PROGRESS

class _BG_FILE_INFO(Structure):
    _fields_ = [
        ("RemoteName", LPWSTR),
        ("LocalName", LPWSTR),
    ]
BG_FILE_INFO = _BG_FILE_INFO

class _BG_JOB_TIMES(Structure):
    _fields_ = [
        ("CreationTime", FILETIME),
        ("ModificationTime", FILETIME),
        ("TransferCompletionTime", FILETIME),
    ]
BG_JOB_TIMES = _BG_JOB_TIMES

class _ALPC_PORT_ATTRIBUTES32(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SecurityQos", SECURITY_QUALITY_OF_SERVICE),
        ("MaxMessageLength", SIZE_T),
        ("MemoryBandwidth", SIZE_T),
        ("MaxPoolUsage", SIZE_T),
        ("MaxSectionSize", SIZE_T),
        ("MaxViewSize", SIZE_T),
        ("MaxTotalSectionSize", SIZE_T),
        ("DupObjectTypes", ULONG),
    ]
PALPC_PORT_ATTRIBUTES32 = POINTER(_ALPC_PORT_ATTRIBUTES32)
ALPC_PORT_ATTRIBUTES32 = _ALPC_PORT_ATTRIBUTES32

class _ALPC_PORT_ATTRIBUTES64(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SecurityQos", SECURITY_QUALITY_OF_SERVICE),
        ("MaxMessageLength", SIZE_T),
        ("MemoryBandwidth", SIZE_T),
        ("MaxPoolUsage", SIZE_T),
        ("MaxSectionSize", SIZE_T),
        ("MaxViewSize", SIZE_T),
        ("MaxTotalSectionSize", SIZE_T),
        ("DupObjectTypes", ULONG),
        ("Reserved", ULONG),
    ]
ALPC_PORT_ATTRIBUTES64 = _ALPC_PORT_ATTRIBUTES64
PALPC_PORT_ATTRIBUTES64 = POINTER(_ALPC_PORT_ATTRIBUTES64)

class _ALPC_MESSAGE_ATTRIBUTES(Structure):
    _fields_ = [
        ("AllocatedAttributes", ULONG),
        ("ValidAttributes", ULONG),
    ]
ALPC_MESSAGE_ATTRIBUTES = _ALPC_MESSAGE_ATTRIBUTES
PALPC_MESSAGE_ATTRIBUTES = POINTER(_ALPC_MESSAGE_ATTRIBUTES)

class _PORT_MESSAGE32_TMP_UNION(Union):
    _fields_ = [
        ("ClientViewSize", ULONG),
        ("CallbackId", ULONG),
    ]
PORT_MESSAGE_TMP_UNION = _PORT_MESSAGE32_TMP_UNION

class _PORT_MESSAGE64_TMP_UNION(Union):
    _fields_ = [
        ("ClientViewSize", ULONGLONG),
        ("CallbackId", ULONG),
    ]
PORT_MESSAGE_TMP_UNION = _PORT_MESSAGE64_TMP_UNION

class _PORT_MESSAGE_TMP_SUBSTRUCT_S1(Structure):
    _fields_ = [
        ("DataLength", CSHORT),
        ("TotalLength", CSHORT),
    ]
_PORT_MESSAGE_TMP_SUBSTRUCT_S1 = _PORT_MESSAGE_TMP_SUBSTRUCT_S1

class _PORT_MESSAGE_TMP_UNION_U1(Union):
    _fields_ = [
        ("Length", ULONG),
        ("s1", _PORT_MESSAGE_TMP_SUBSTRUCT_S1),
    ]
_PORT_MESSAGE_TMP_UNION_U1 = _PORT_MESSAGE_TMP_UNION_U1

class _PORT_MESSAGE_TMP_SUBSTRUCT_S2(Structure):
    _fields_ = [
        ("Type", CSHORT),
        ("DataInfoOffset", CSHORT),
    ]
_PORT_MESSAGE_TMP_SUBSTRUCT_S2 = _PORT_MESSAGE_TMP_SUBSTRUCT_S2

class _PORT_MESSAGE_TMP_UNION_U2(Union):
    _fields_ = [
        ("ZeroInit", ULONG),
        ("s2", _PORT_MESSAGE_TMP_SUBSTRUCT_S2),
    ]
_PORT_MESSAGE_TMP_UNION_U2 = _PORT_MESSAGE_TMP_UNION_U2

class _PORT_MESSAGE32(Structure):
    _fields_ = [
        ("u1", _PORT_MESSAGE_TMP_UNION_U1),
        ("u2", _PORT_MESSAGE_TMP_UNION_U2),
        ("ClientId", CLIENT_ID32),
        ("MessageId", ULONG),
        ("tmp_union", _PORT_MESSAGE32_TMP_UNION),
    ]
PORT_MESSAGE32 = _PORT_MESSAGE32
PPORT_MESSAGE32 = POINTER(_PORT_MESSAGE32)

class _PORT_MESSAGE64(Structure):
    _fields_ = [
        ("u1", _PORT_MESSAGE_TMP_UNION_U1),
        ("u2", _PORT_MESSAGE_TMP_UNION_U2),
        ("ClientId", CLIENT_ID64),
        ("MessageId", ULONG),
        ("tmp_union", _PORT_MESSAGE64_TMP_UNION),
    ]
PPORT_MESSAGE64 = POINTER(_PORT_MESSAGE64)
PORT_MESSAGE64 = _PORT_MESSAGE64

class _ALPC_SERVER_INFORMATION_TMP_IN(Structure):
    _fields_ = [
        ("ThreadHandle", HANDLE),
    ]
ALPC_SERVER_INFORMATION_TMP_IN = _ALPC_SERVER_INFORMATION_TMP_IN

class _ALPC_SERVER_INFORMATION_TMP_OUT(Structure):
    _fields_ = [
        ("ThreadBlocked", BOOLEAN),
        ("ConnectedProcessId", HANDLE),
        ("ConnectionPortName", UNICODE_STRING),
    ]
ALPC_SERVER_INFORMATION_TMP_OUT = _ALPC_SERVER_INFORMATION_TMP_OUT

class ALPC_SERVER_INFORMATION(Union):
    _fields_ = [
        ("In", ALPC_SERVER_INFORMATION_TMP_IN),
        ("Out", ALPC_SERVER_INFORMATION_TMP_OUT),
    ]
ALPC_SERVER_INFORMATION = ALPC_SERVER_INFORMATION

class _ALPC_CONTEXT_ATTR(Structure):
    _fields_ = [
        ("PortContext", PVOID),
        ("MessageContext", PVOID),
        ("Sequence", ULONG),
        ("MessageId", ULONG),
        ("CallbackId", ULONG),
    ]
PALPC_CONTEXT_ATTR = POINTER(_ALPC_CONTEXT_ATTR)
ALPC_CONTEXT_ATTR = _ALPC_CONTEXT_ATTR

class _ALPC_CONTEXT_ATTR32(Structure):
    _fields_ = [
        ("PortContext", ULONG),
        ("MessageContext", ULONG),
        ("Sequence", ULONG),
        ("MessageId", ULONG),
        ("CallbackId", ULONG),
    ]
ALPC_CONTEXT_ATTR32 = _ALPC_CONTEXT_ATTR32
PALPC_CONTEXT_ATTR32 = POINTER(_ALPC_CONTEXT_ATTR32)

class _ALPC_CONTEXT_ATTR64(Structure):
    _fields_ = [
        ("PortContext", ULONGLONG),
        ("MessageContext", ULONGLONG),
        ("Sequence", ULONG),
        ("MessageId", ULONG),
        ("CallbackId", ULONG),
    ]
ALPC_CONTEXT_ATTR64 = _ALPC_CONTEXT_ATTR64
PALPC_CONTEXT_ATTR64 = POINTER(_ALPC_CONTEXT_ATTR64)

class _ALPC_HANDLE_ATTR(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("Handle", HANDLE),
        ("ObjectType", ULONG),
        ("DesiredAccess", ACCESS_MASK),
    ]
PALPC_HANDLE_ATTR = POINTER(_ALPC_HANDLE_ATTR)
ALPC_HANDLE_ATTR = _ALPC_HANDLE_ATTR

class _ALPC_HANDLE_ATTR32(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("Handle", ULONG),
        ("ObjectType", ULONG),
        ("DesiredAccess", ACCESS_MASK),
    ]
ALPC_HANDLE_ATTR32 = _ALPC_HANDLE_ATTR32
PALPC_HANDLE_ATTR32 = POINTER(_ALPC_HANDLE_ATTR32)

class _ALPC_HANDLE_ATTR64(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("Handle", ULONGLONG),
        ("ObjectType", ULONG),
        ("DesiredAccess", ACCESS_MASK),
    ]
PALPC_HANDLE_ATTR64 = POINTER(_ALPC_HANDLE_ATTR64)
ALPC_HANDLE_ATTR64 = _ALPC_HANDLE_ATTR64

class _ALPC_SECURITY_ATTR(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("QoS", PSECURITY_QUALITY_OF_SERVICE),
        ("ContextHandle", ALPC_HANDLE),
    ]
PALPC_SECURITY_ATTR = POINTER(_ALPC_SECURITY_ATTR)
ALPC_SECURITY_ATTR = _ALPC_SECURITY_ATTR

class _ALPC_SECURITY_ATTR32(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("QoS", ULONG),
        ("ContextHandle", ULONG),
    ]
ALPC_SECURITY_ATTR32 = _ALPC_SECURITY_ATTR32
PALPC_SECURITY_ATTR32 = POINTER(_ALPC_SECURITY_ATTR32)

class _ALPC_SECURITY_ATTR64(Structure):
    _fields_ = [
        ("Flags", ULONGLONG),
        ("QoS", ULONGLONG),
        ("ContextHandle", ULONGLONG),
    ]
PALPC_SECURITY_ATTR64 = POINTER(_ALPC_SECURITY_ATTR64)
ALPC_SECURITY_ATTR64 = _ALPC_SECURITY_ATTR64

class _ALPC_DATA_VIEW_ATTR(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SectionHandle", ALPC_HANDLE),
        ("ViewBase", PVOID),
        ("ViewSize", PVOID),
    ]
PALPC_DATA_VIEW_ATTR = POINTER(_ALPC_DATA_VIEW_ATTR)
ALPC_DATA_VIEW_ATTR = _ALPC_DATA_VIEW_ATTR

class _ALPC_DATA_VIEW_ATTR32(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SectionHandle", ULONG),
        ("ViewBase", ULONG),
        ("ViewSize", ULONG),
    ]
PALPC_DATA_VIEW_ATTR32 = POINTER(_ALPC_DATA_VIEW_ATTR32)
ALPC_DATA_VIEW_ATTR32 = _ALPC_DATA_VIEW_ATTR32

class _ALPC_DATA_VIEW_ATTR64(Structure):
    _fields_ = [
        ("Flags", ULONG),
        ("SectionHandle", ULONGLONG),
        ("ViewBase", ULONGLONG),
        ("ViewSize", ULONGLONG),
    ]
PALPC_DATA_VIEW_ATTR64 = POINTER(_ALPC_DATA_VIEW_ATTR64)
ALPC_DATA_VIEW_ATTR64 = _ALPC_DATA_VIEW_ATTR64

class _ALPC_TOKEN_ATTR(Structure):
    _fields_ = [
        ("TokenId", ULONGLONG),
        ("AuthenticationId", ULONGLONG),
        ("ModifiedId", ULONGLONG),
    ]
ALPC_TOKEN_ATTR = _ALPC_TOKEN_ATTR
PALPC_TOKEN_ATTR = POINTER(_ALPC_TOKEN_ATTR)

class _ALPC_DIRECT_ATTR(Structure):
    _fields_ = [
        ("Event", HANDLE),
    ]
ALPC_DIRECT_ATTR = _ALPC_DIRECT_ATTR
PALPC_DIRECT_ATTR = POINTER(_ALPC_DIRECT_ATTR)

class _ALPC_DIRECT_ATTR32(Structure):
    _fields_ = [
        ("Event", ULONG),
    ]
PALPC_DIRECT_ATTR32 = POINTER(_ALPC_DIRECT_ATTR32)
ALPC_DIRECT_ATTR32 = _ALPC_DIRECT_ATTR32

class _ALPC_DIRECT_ATTR64(Structure):
    _fields_ = [
        ("Event", ULONGLONG),
    ]
ALPC_DIRECT_ATTR64 = _ALPC_DIRECT_ATTR64
PALPC_DIRECT_ATTR64 = POINTER(_ALPC_DIRECT_ATTR64)

class _ALPC_WORK_ON_BEHALF_ATTR(Structure):
    _fields_ = [
        ("Ticket", ULONGLONG),
    ]
PALPC_WORK_ON_BEHALF_ATTR = POINTER(_ALPC_WORK_ON_BEHALF_ATTR)
ALPC_WORK_ON_BEHALF_ATTR = _ALPC_WORK_ON_BEHALF_ATTR
