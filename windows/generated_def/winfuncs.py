from interfaces import *
from winstructs import *
#def ObjectFromLresult(lResult, riid, wParam, ppvObject):
#    return ObjectFromLresult.ctypes_function(lResult, riid, wParam, ppvObject)
ObjectFromLresultPrototype = WINFUNCTYPE(HRESULT, LRESULT, REFIID, WPARAM, POINTER(PVOID))
ObjectFromLresultParams = ((1, 'lResult'), (1, 'riid'), (1, 'wParam'), (1, 'ppvObject'))

#def NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes):
#    return NtOpenKey.ctypes_function(KeyHandle, DesiredAccess, ObjectAttributes)
NtOpenKeyPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenKeyParams = ((1, 'KeyHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

#def NtCreateKey(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition):
#    return NtCreateKey.ctypes_function(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition)
NtCreateKeyPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG)
NtCreateKeyParams = ((1, 'pKeyHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'TitleIndex'), (1, 'Class'), (1, 'CreateOptions'), (1, 'Disposition'))

#def NtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize):
#    return NtSetValueKey.ctypes_function(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize)
NtSetValueKeyPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG)
NtSetValueKeyParams = ((1, 'KeyHandle'), (1, 'ValueName'), (1, 'TitleIndex'), (1, 'Type'), (1, 'Data'), (1, 'DataSize'))

#def NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength):
#    return NtQueryValueKey.ctypes_function(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)
NtQueryValueKeyPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQueryValueKeyParams = ((1, 'KeyHandle'), (1, 'ValueName'), (1, 'KeyValueInformationClass'), (1, 'KeyValueInformation'), (1, 'Length'), (1, 'ResultLength'))

#def NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength):
#    return NtEnumerateValueKey.ctypes_function(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)
NtEnumerateValueKeyPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtEnumerateValueKeyParams = ((1, 'KeyHandle'), (1, 'Index'), (1, 'KeyValueInformationClass'), (1, 'KeyValueInformation'), (1, 'Length'), (1, 'ResultLength'))

#def NtAlpcCreatePort(PortHandle, ObjectAttributes, PortAttributes):
#    return NtAlpcCreatePort.ctypes_function(PortHandle, ObjectAttributes, PortAttributes)
NtAlpcCreatePortPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES)
NtAlpcCreatePortParams = ((1, 'PortHandle'), (1, 'ObjectAttributes'), (1, 'PortAttributes'))

#def NtAlpcQueryInformation(PortHandle, PortInformationClass, PortInformation, Length, ReturnLength):
#    return NtAlpcQueryInformation.ctypes_function(PortHandle, PortInformationClass, PortInformation, Length, ReturnLength)
NtAlpcQueryInformationPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ALPC_PORT_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtAlpcQueryInformationParams = ((1, 'PortHandle'), (1, 'PortInformationClass'), (1, 'PortInformation'), (1, 'Length'), (1, 'ReturnLength'))

#def NtAlpcQueryInformationMessage(PortHandle, PortMessage, MessageInformationClass, MessageInformation, Length, ReturnLength):
#    return NtAlpcQueryInformationMessage.ctypes_function(PortHandle, PortMessage, MessageInformationClass, MessageInformation, Length, ReturnLength)
NtAlpcQueryInformationMessagePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PPORT_MESSAGE, ALPC_MESSAGE_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtAlpcQueryInformationMessageParams = ((1, 'PortHandle'), (1, 'PortMessage'), (1, 'MessageInformationClass'), (1, 'MessageInformation'), (1, 'Length'), (1, 'ReturnLength'))

#def NtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout):
#    return NtAlpcConnectPort.ctypes_function(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)
NtAlpcConnectPortPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, ULONG, PSID, PPORT_MESSAGE, PULONG, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER)
NtAlpcConnectPortParams = ((1, 'PortHandle'), (1, 'PortName'), (1, 'ObjectAttributes'), (1, 'PortAttributes'), (1, 'Flags'), (1, 'RequiredServerSid'), (1, 'ConnectionMessage'), (1, 'BufferLength'), (1, 'OutMessageAttributes'), (1, 'InMessageAttributes'), (1, 'Timeout'))

#def NtAlpcConnectPortEx(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout):
#    return NtAlpcConnectPortEx.ctypes_function(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)
NtAlpcConnectPortExPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, ULONG, PSECURITY_DESCRIPTOR, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER)
NtAlpcConnectPortExParams = ((1, 'PortHandle'), (1, 'ConnectionPortObjectAttributes'), (1, 'ClientPortObjectAttributes'), (1, 'PortAttributes'), (1, 'Flags'), (1, 'ServerSecurityRequirements'), (1, 'ConnectionMessage'), (1, 'BufferLength'), (1, 'OutMessageAttributes'), (1, 'InMessageAttributes'), (1, 'Timeout'))

#def NtAlpcAcceptConnectPort(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection):
#    return NtAlpcAcceptConnectPort.ctypes_function(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection)
NtAlpcAcceptConnectPortPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, HANDLE, ULONG, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, PVOID, PPORT_MESSAGE, PALPC_MESSAGE_ATTRIBUTES, BOOLEAN)
NtAlpcAcceptConnectPortParams = ((1, 'PortHandle'), (1, 'ConnectionPortHandle'), (1, 'Flags'), (1, 'ObjectAttributes'), (1, 'PortAttributes'), (1, 'PortContext'), (1, 'ConnectionRequest'), (1, 'ConnectionMessageAttributes'), (1, 'AcceptConnection'))

#def AlpcInitializeMessageAttribute(AttributeFlags, Buffer, BufferSize, RequiredBufferSize):
#    return AlpcInitializeMessageAttribute.ctypes_function(AttributeFlags, Buffer, BufferSize, RequiredBufferSize)
AlpcInitializeMessageAttributePrototype = WINFUNCTYPE(NTSTATUS, ULONG, PALPC_MESSAGE_ATTRIBUTES, ULONG, PULONG)
AlpcInitializeMessageAttributeParams = ((1, 'AttributeFlags'), (1, 'Buffer'), (1, 'BufferSize'), (1, 'RequiredBufferSize'))

#def AlpcGetMessageAttribute(Buffer, AttributeFlag):
#    return AlpcGetMessageAttribute.ctypes_function(Buffer, AttributeFlag)
AlpcGetMessageAttributePrototype = WINFUNCTYPE(PVOID, PALPC_MESSAGE_ATTRIBUTES, ULONG)
AlpcGetMessageAttributeParams = ((1, 'Buffer'), (1, 'AttributeFlag'))

#def NtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout):
#    return NtAlpcSendWaitReceivePort.ctypes_function(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout)
NtAlpcSendWaitReceivePortPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, PPORT_MESSAGE, PALPC_MESSAGE_ATTRIBUTES, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER)
NtAlpcSendWaitReceivePortParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'SendMessage'), (1, 'SendMessageAttributes'), (1, 'ReceiveMessage'), (1, 'BufferLength'), (1, 'ReceiveMessageAttributes'), (1, 'Timeout'))

#def NtAlpcDisconnectPort(PortHandle, Flags):
#    return NtAlpcDisconnectPort.ctypes_function(PortHandle, Flags)
NtAlpcDisconnectPortPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG)
NtAlpcDisconnectPortParams = ((1, 'PortHandle'), (1, 'Flags'))

#def NtAlpcCreatePortSection(PortHandle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize):
#    return NtAlpcCreatePortSection.ctypes_function(PortHandle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize)
NtAlpcCreatePortSectionPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, HANDLE, SIZE_T, PALPC_HANDLE, PSIZE_T)
NtAlpcCreatePortSectionParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'SectionHandle'), (1, 'SectionSize'), (1, 'AlpcSectionHandle'), (1, 'ActualSectionSize'))

#def NtAlpcDeletePortSection(PortHandle, Flags, SectionHandle):
#    return NtAlpcDeletePortSection.ctypes_function(PortHandle, Flags, SectionHandle)
NtAlpcDeletePortSectionPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, ALPC_HANDLE)
NtAlpcDeletePortSectionParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'SectionHandle'))

#def NtAlpcCreateResourceReserve(PortHandle, Flags, MessageSize, ResourceId):
#    return NtAlpcCreateResourceReserve.ctypes_function(PortHandle, Flags, MessageSize, ResourceId)
NtAlpcCreateResourceReservePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, SIZE_T, PALPC_HANDLE)
NtAlpcCreateResourceReserveParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'MessageSize'), (1, 'ResourceId'))

#def NtAlpcDeleteResourceReserve(PortHandle, Flags, ResourceId):
#    return NtAlpcDeleteResourceReserve.ctypes_function(PortHandle, Flags, ResourceId)
NtAlpcDeleteResourceReservePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, ALPC_HANDLE)
NtAlpcDeleteResourceReserveParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'ResourceId'))

#def NtAlpcCreateSectionView(PortHandle, Flags, ViewAttributes):
#    return NtAlpcCreateSectionView.ctypes_function(PortHandle, Flags, ViewAttributes)
NtAlpcCreateSectionViewPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, PALPC_DATA_VIEW_ATTR)
NtAlpcCreateSectionViewParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'ViewAttributes'))

#def NtAlpcDeleteSectionView(PortHandle, Flags, ViewBase):
#    return NtAlpcDeleteSectionView.ctypes_function(PortHandle, Flags, ViewBase)
NtAlpcDeleteSectionViewPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, PVOID)
NtAlpcDeleteSectionViewParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'ViewBase'))

#def NtAlpcCreateSecurityContext(PortHandle, Flags, SecurityAttribute):
#    return NtAlpcCreateSecurityContext.ctypes_function(PortHandle, Flags, SecurityAttribute)
NtAlpcCreateSecurityContextPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, PALPC_SECURITY_ATTR)
NtAlpcCreateSecurityContextParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'SecurityAttribute'))

#def NtAlpcDeleteSecurityContext(PortHandle, Flags, ContextHandle):
#    return NtAlpcDeleteSecurityContext.ctypes_function(PortHandle, Flags, ContextHandle)
NtAlpcDeleteSecurityContextPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, ALPC_HANDLE)
NtAlpcDeleteSecurityContextParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'ContextHandle'))

#def NtAlpcRevokeSecurityContext(PortHandle, Flags, ContextHandle):
#    return NtAlpcRevokeSecurityContext.ctypes_function(PortHandle, Flags, ContextHandle)
NtAlpcRevokeSecurityContextPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, ALPC_HANDLE)
NtAlpcRevokeSecurityContextParams = ((1, 'PortHandle'), (1, 'Flags'), (1, 'ContextHandle'))

#def OpenEventLogA(lpUNCServerName, lpSourceName):
#    return OpenEventLogA.ctypes_function(lpUNCServerName, lpSourceName)
OpenEventLogAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, LPCSTR)
OpenEventLogAParams = ((1, 'lpUNCServerName'), (1, 'lpSourceName'))

#def OpenEventLogW(lpUNCServerName, lpSourceName):
#    return OpenEventLogW.ctypes_function(lpUNCServerName, lpSourceName)
OpenEventLogWPrototype = WINFUNCTYPE(HANDLE, LPWSTR, LPWSTR)
OpenEventLogWParams = ((1, 'lpUNCServerName'), (1, 'lpSourceName'))

#def OpenBackupEventLogA(lpUNCServerName, lpSourceName):
#    return OpenBackupEventLogA.ctypes_function(lpUNCServerName, lpSourceName)
OpenBackupEventLogAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, LPCSTR)
OpenBackupEventLogAParams = ((1, 'lpUNCServerName'), (1, 'lpSourceName'))

#def OpenBackupEventLogW(lpUNCServerName, lpSourceName):
#    return OpenBackupEventLogW.ctypes_function(lpUNCServerName, lpSourceName)
OpenBackupEventLogWPrototype = WINFUNCTYPE(HANDLE, LPWSTR, LPWSTR)
OpenBackupEventLogWParams = ((1, 'lpUNCServerName'), (1, 'lpSourceName'))

#def ReadEventLogA(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded):
#    return ReadEventLogA.ctypes_function(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded)
ReadEventLogAPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, DWORD, LPVOID, DWORD, POINTER(DWORD), POINTER(DWORD))
ReadEventLogAParams = ((1, 'hEventLog'), (1, 'dwReadFlags'), (1, 'dwRecordOffset'), (1, 'lpBuffer'), (1, 'nNumberOfBytesToRead'), (1, 'pnBytesRead'), (1, 'pnMinNumberOfBytesNeeded'))

#def ReadEventLogW(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded):
#    return ReadEventLogW.ctypes_function(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded)
ReadEventLogWPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, DWORD, LPVOID, DWORD, POINTER(DWORD), POINTER(DWORD))
ReadEventLogWParams = ((1, 'hEventLog'), (1, 'dwReadFlags'), (1, 'dwRecordOffset'), (1, 'lpBuffer'), (1, 'nNumberOfBytesToRead'), (1, 'pnBytesRead'), (1, 'pnMinNumberOfBytesNeeded'))

#def GetEventLogInformation(hEventLog, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded):
#    return GetEventLogInformation.ctypes_function(hEventLog, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)
GetEventLogInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, LPVOID, DWORD, LPDWORD)
GetEventLogInformationParams = ((1, 'hEventLog'), (1, 'dwInfoLevel'), (1, 'lpBuffer'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'))

#def GetNumberOfEventLogRecords(hEventLog, NumberOfRecords):
#    return GetNumberOfEventLogRecords.ctypes_function(hEventLog, NumberOfRecords)
GetNumberOfEventLogRecordsPrototype = WINFUNCTYPE(BOOL, HANDLE, PDWORD)
GetNumberOfEventLogRecordsParams = ((1, 'hEventLog'), (1, 'NumberOfRecords'))

#def CloseEventLog(hEventLog):
#    return CloseEventLog.ctypes_function(hEventLog)
CloseEventLogPrototype = WINFUNCTYPE(BOOL, HANDLE)
CloseEventLogParams = ((1, 'hEventLog'),)

#def EvtOpenLog(Session, Path, Flags):
#    return EvtOpenLog.ctypes_function(Session, Path, Flags)
EvtOpenLogPrototype = WINFUNCTYPE(EVT_HANDLE, EVT_HANDLE, LPCWSTR, DWORD)
EvtOpenLogParams = ((1, 'Session'), (1, 'Path'), (1, 'Flags'))

#def EvtQuery(Session, Path, Query, Flags):
#    return EvtQuery.ctypes_function(Session, Path, Query, Flags)
EvtQueryPrototype = WINFUNCTYPE(EVT_HANDLE, EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD)
EvtQueryParams = ((1, 'Session'), (1, 'Path'), (1, 'Query'), (1, 'Flags'))

#def EvtNext(ResultSet, EventArraySize, EventArray, Timeout, Flags, Returned):
#    return EvtNext.ctypes_function(ResultSet, EventArraySize, EventArray, Timeout, Flags, Returned)
EvtNextPrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, DWORD, POINTER(EVT_HANDLE), DWORD, DWORD, PDWORD)
EvtNextParams = ((1, 'ResultSet'), (1, 'EventArraySize'), (1, 'EventArray'), (1, 'Timeout'), (1, 'Flags'), (1, 'Returned'))

#def EvtCreateRenderContext(ValuePathsCount, ValuePaths, Flags):
#    return EvtCreateRenderContext.ctypes_function(ValuePathsCount, ValuePaths, Flags)
EvtCreateRenderContextPrototype = WINFUNCTYPE(EVT_HANDLE, DWORD, POINTER(LPCWSTR), DWORD)
EvtCreateRenderContextParams = ((1, 'ValuePathsCount'), (1, 'ValuePaths'), (1, 'Flags'))

#def EvtRender(Context, Fragment, Flags, BufferSize, Buffer, BufferUsed, PropertyCount):
#    return EvtRender.ctypes_function(Context, Fragment, Flags, BufferSize, Buffer, BufferUsed, PropertyCount)
EvtRenderPrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, PVOID, PDWORD, PDWORD)
EvtRenderParams = ((1, 'Context'), (1, 'Fragment'), (1, 'Flags'), (1, 'BufferSize'), (1, 'Buffer'), (1, 'BufferUsed'), (1, 'PropertyCount'))

#def EvtClose(Object):
#    return EvtClose.ctypes_function(Object)
EvtClosePrototype = WINFUNCTYPE(BOOL, EVT_HANDLE)
EvtCloseParams = ((1, 'Object'),)

#def EvtOpenChannelEnum(Session, Flags):
#    return EvtOpenChannelEnum.ctypes_function(Session, Flags)
EvtOpenChannelEnumPrototype = WINFUNCTYPE(EVT_HANDLE, EVT_HANDLE, DWORD)
EvtOpenChannelEnumParams = ((1, 'Session'), (1, 'Flags'))

#def EvtNextChannelPath(ChannelEnum, ChannelPathBufferSize, ChannelPathBuffer, ChannelPathBufferUsed):
#    return EvtNextChannelPath.ctypes_function(ChannelEnum, ChannelPathBufferSize, ChannelPathBuffer, ChannelPathBufferUsed)
EvtNextChannelPathPrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, DWORD, LPWSTR, PDWORD)
EvtNextChannelPathParams = ((1, 'ChannelEnum'), (1, 'ChannelPathBufferSize'), (1, 'ChannelPathBuffer'), (1, 'ChannelPathBufferUsed'))

#def EvtOpenPublisherEnum(Session, Flags):
#    return EvtOpenPublisherEnum.ctypes_function(Session, Flags)
EvtOpenPublisherEnumPrototype = WINFUNCTYPE(EVT_HANDLE, EVT_HANDLE, DWORD)
EvtOpenPublisherEnumParams = ((1, 'Session'), (1, 'Flags'))

#def EvtNextPublisherId(PublisherEnum, PublisherIdBufferSize, PublisherIdBuffer, PublisherIdBufferUsed):
#    return EvtNextPublisherId.ctypes_function(PublisherEnum, PublisherIdBufferSize, PublisherIdBuffer, PublisherIdBufferUsed)
EvtNextPublisherIdPrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, DWORD, LPWSTR, PDWORD)
EvtNextPublisherIdParams = ((1, 'PublisherEnum'), (1, 'PublisherIdBufferSize'), (1, 'PublisherIdBuffer'), (1, 'PublisherIdBufferUsed'))

#def EvtGetLogInfo(Log, PropertyId, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed):
#    return EvtGetLogInfo.ctypes_function(Log, PropertyId, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)
EvtGetLogInfoPrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, EVT_LOG_PROPERTY_ID, DWORD, PEVT_VARIANT, PDWORD)
EvtGetLogInfoParams = ((1, 'Log'), (1, 'PropertyId'), (1, 'PropertyValueBufferSize'), (1, 'PropertyValueBuffer'), (1, 'PropertyValueBufferUsed'))

#def EvtOpenChannelConfig(Session, ChannelPath, Flags):
#    return EvtOpenChannelConfig.ctypes_function(Session, ChannelPath, Flags)
EvtOpenChannelConfigPrototype = WINFUNCTYPE(EVT_HANDLE, EVT_HANDLE, LPCWSTR, DWORD)
EvtOpenChannelConfigParams = ((1, 'Session'), (1, 'ChannelPath'), (1, 'Flags'))

#def EvtGetChannelConfigProperty(ChannelConfig, PropertyId, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed):
#    return EvtGetChannelConfigProperty.ctypes_function(ChannelConfig, PropertyId, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)
EvtGetChannelConfigPropertyPrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, EVT_CHANNEL_CONFIG_PROPERTY_ID, DWORD, DWORD, PEVT_VARIANT, PDWORD)
EvtGetChannelConfigPropertyParams = ((1, 'ChannelConfig'), (1, 'PropertyId'), (1, 'Flags'), (1, 'PropertyValueBufferSize'), (1, 'PropertyValueBuffer'), (1, 'PropertyValueBufferUsed'))

#def EvtOpenPublisherMetadata(Session, PublisherIdentity, LogFilePath, Locale, Flags):
#    return EvtOpenPublisherMetadata.ctypes_function(Session, PublisherIdentity, LogFilePath, Locale, Flags)
EvtOpenPublisherMetadataPrototype = WINFUNCTYPE(EVT_HANDLE, EVT_HANDLE, LPCWSTR, LPCWSTR, LCID, DWORD)
EvtOpenPublisherMetadataParams = ((1, 'Session'), (1, 'PublisherIdentity'), (1, 'LogFilePath'), (1, 'Locale'), (1, 'Flags'))

#def EvtOpenEventMetadataEnum(PublisherMetadata, Flags):
#    return EvtOpenEventMetadataEnum.ctypes_function(PublisherMetadata, Flags)
EvtOpenEventMetadataEnumPrototype = WINFUNCTYPE(EVT_HANDLE, EVT_HANDLE, DWORD)
EvtOpenEventMetadataEnumParams = ((1, 'PublisherMetadata'), (1, 'Flags'))

#def EvtNextEventMetadata(EventMetadataEnum, Flags):
#    return EvtNextEventMetadata.ctypes_function(EventMetadataEnum, Flags)
EvtNextEventMetadataPrototype = WINFUNCTYPE(EVT_HANDLE, EVT_HANDLE, DWORD)
EvtNextEventMetadataParams = ((1, 'EventMetadataEnum'), (1, 'Flags'))

#def EvtGetEventMetadataProperty(EventMetadata, PropertyId, Flags, EventMetadataPropertyBufferSize, EventMetadataPropertyBuffer, EventMetadataPropertyBufferUsed):
#    return EvtGetEventMetadataProperty.ctypes_function(EventMetadata, PropertyId, Flags, EventMetadataPropertyBufferSize, EventMetadataPropertyBuffer, EventMetadataPropertyBufferUsed)
EvtGetEventMetadataPropertyPrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, EVT_EVENT_METADATA_PROPERTY_ID, DWORD, DWORD, PEVT_VARIANT, PDWORD)
EvtGetEventMetadataPropertyParams = ((1, 'EventMetadata'), (1, 'PropertyId'), (1, 'Flags'), (1, 'EventMetadataPropertyBufferSize'), (1, 'EventMetadataPropertyBuffer'), (1, 'EventMetadataPropertyBufferUsed'))

#def EvtGetPublisherMetadataProperty(PublisherMetadata, PropertyId, Flags, PublisherMetadataPropertyBufferSize, PublisherMetadataPropertyBuffer, PublisherMetadataPropertyBufferUsed):
#    return EvtGetPublisherMetadataProperty.ctypes_function(PublisherMetadata, PropertyId, Flags, PublisherMetadataPropertyBufferSize, PublisherMetadataPropertyBuffer, PublisherMetadataPropertyBufferUsed)
EvtGetPublisherMetadataPropertyPrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, EVT_PUBLISHER_METADATA_PROPERTY_ID, DWORD, DWORD, PEVT_VARIANT, PDWORD)
EvtGetPublisherMetadataPropertyParams = ((1, 'PublisherMetadata'), (1, 'PropertyId'), (1, 'Flags'), (1, 'PublisherMetadataPropertyBufferSize'), (1, 'PublisherMetadataPropertyBuffer'), (1, 'PublisherMetadataPropertyBufferUsed'))

#def EvtGetObjectArraySize(ObjectArray, ObjectArraySize):
#    return EvtGetObjectArraySize.ctypes_function(ObjectArray, ObjectArraySize)
EvtGetObjectArraySizePrototype = WINFUNCTYPE(BOOL, EVT_OBJECT_ARRAY_PROPERTY_HANDLE, PDWORD)
EvtGetObjectArraySizeParams = ((1, 'ObjectArray'), (1, 'ObjectArraySize'))

#def EvtGetObjectArrayProperty(ObjectArray, PropertyId, ArrayIndex, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed):
#    return EvtGetObjectArrayProperty.ctypes_function(ObjectArray, PropertyId, ArrayIndex, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)
EvtGetObjectArrayPropertyPrototype = WINFUNCTYPE(BOOL, EVT_OBJECT_ARRAY_PROPERTY_HANDLE, DWORD, DWORD, DWORD, DWORD, PEVT_VARIANT, PDWORD)
EvtGetObjectArrayPropertyParams = ((1, 'ObjectArray'), (1, 'PropertyId'), (1, 'ArrayIndex'), (1, 'Flags'), (1, 'PropertyValueBufferSize'), (1, 'PropertyValueBuffer'), (1, 'PropertyValueBufferUsed'))

#def EvtFormatMessage(PublisherMetadata, Event, MessageId, ValueCount, Values, Flags, BufferSize, Buffer, BufferUsed):
#    return EvtFormatMessage.ctypes_function(PublisherMetadata, Event, MessageId, ValueCount, Values, Flags, BufferSize, Buffer, BufferUsed)
EvtFormatMessagePrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, PEVT_VARIANT, DWORD, DWORD, LPWSTR, PDWORD)
EvtFormatMessageParams = ((1, 'PublisherMetadata'), (1, 'Event'), (1, 'MessageId'), (1, 'ValueCount'), (1, 'Values'), (1, 'Flags'), (1, 'BufferSize'), (1, 'Buffer'), (1, 'BufferUsed'))

#def StrStrIW(pszFirst, pszSrch):
#    return StrStrIW.ctypes_function(pszFirst, pszSrch)
StrStrIWPrototype = WINFUNCTYPE(PWSTR, PWSTR, PWSTR)
StrStrIWParams = ((1, 'pszFirst'), (1, 'pszSrch'))

#def StrStrIA(pszFirst, pszSrch):
#    return StrStrIA.ctypes_function(pszFirst, pszSrch)
StrStrIAPrototype = WINFUNCTYPE(PCSTR, PCSTR, PCSTR)
StrStrIAParams = ((1, 'pszFirst'), (1, 'pszSrch'))

#def IsOS(dwOS):
#    return IsOS.ctypes_function(dwOS)
IsOSPrototype = WINFUNCTYPE(BOOL, DWORD)
IsOSParams = ((1, 'dwOS'),)

#def IsValidSecurityDescriptor(pSecurityDescriptor):
#    return IsValidSecurityDescriptor.ctypes_function(pSecurityDescriptor)
IsValidSecurityDescriptorPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR)
IsValidSecurityDescriptorParams = ((1, 'pSecurityDescriptor'),)

#def ConvertStringSecurityDescriptorToSecurityDescriptorA(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize):
#    return ConvertStringSecurityDescriptorToSecurityDescriptorA.ctypes_function(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)
ConvertStringSecurityDescriptorToSecurityDescriptorAPrototype = WINFUNCTYPE(BOOL, LPCSTR, DWORD, POINTER(PSECURITY_DESCRIPTOR), PULONG)
ConvertStringSecurityDescriptorToSecurityDescriptorAParams = ((1, 'StringSecurityDescriptor'), (1, 'StringSDRevision'), (1, 'SecurityDescriptor'), (1, 'SecurityDescriptorSize'))

#def ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize):
#    return ConvertStringSecurityDescriptorToSecurityDescriptorW.ctypes_function(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)
ConvertStringSecurityDescriptorToSecurityDescriptorWPrototype = WINFUNCTYPE(BOOL, LPWSTR, DWORD, POINTER(PSECURITY_DESCRIPTOR), PULONG)
ConvertStringSecurityDescriptorToSecurityDescriptorWParams = ((1, 'StringSecurityDescriptor'), (1, 'StringSDRevision'), (1, 'SecurityDescriptor'), (1, 'SecurityDescriptorSize'))

#def ConvertSecurityDescriptorToStringSecurityDescriptorA(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen):
#    return ConvertSecurityDescriptorToStringSecurityDescriptorA.ctypes_function(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)
ConvertSecurityDescriptorToStringSecurityDescriptorAPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, DWORD, DWORD, POINTER(LPCSTR), PULONG)
ConvertSecurityDescriptorToStringSecurityDescriptorAParams = ((1, 'SecurityDescriptor'), (1, 'RequestedStringSDRevision'), (1, 'SecurityInformation'), (1, 'StringSecurityDescriptor'), (1, 'StringSecurityDescriptorLen'))

#def ConvertSecurityDescriptorToStringSecurityDescriptorW(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen):
#    return ConvertSecurityDescriptorToStringSecurityDescriptorW.ctypes_function(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)
ConvertSecurityDescriptorToStringSecurityDescriptorWPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, DWORD, DWORD, POINTER(LPWSTR), PULONG)
ConvertSecurityDescriptorToStringSecurityDescriptorWParams = ((1, 'SecurityDescriptor'), (1, 'RequestedStringSDRevision'), (1, 'SecurityInformation'), (1, 'StringSecurityDescriptor'), (1, 'StringSecurityDescriptorLen'))

#def GetSecurityDescriptorControl(pSecurityDescriptor, pControl, lpdwRevision):
#    return GetSecurityDescriptorControl.ctypes_function(pSecurityDescriptor, pControl, lpdwRevision)
GetSecurityDescriptorControlPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR_CONTROL, LPDWORD)
GetSecurityDescriptorControlParams = ((1, 'pSecurityDescriptor'), (1, 'pControl'), (1, 'lpdwRevision'))

#def GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted):
#    return GetSecurityDescriptorDacl.ctypes_function(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted)
GetSecurityDescriptorDaclPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, LPBOOL, POINTER(PACL), LPBOOL)
GetSecurityDescriptorDaclParams = ((1, 'pSecurityDescriptor'), (1, 'lpbDaclPresent'), (1, 'pDacl'), (1, 'lpbDaclDefaulted'))

#def GetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, lpbGroupDefaulted):
#    return GetSecurityDescriptorGroup.ctypes_function(pSecurityDescriptor, pGroup, lpbGroupDefaulted)
GetSecurityDescriptorGroupPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, POINTER(PSID), LPBOOL)
GetSecurityDescriptorGroupParams = ((1, 'pSecurityDescriptor'), (1, 'pGroup'), (1, 'lpbGroupDefaulted'))

#def GetSecurityDescriptorLength(pSecurityDescriptor):
#    return GetSecurityDescriptorLength.ctypes_function(pSecurityDescriptor)
GetSecurityDescriptorLengthPrototype = WINFUNCTYPE(DWORD, PSECURITY_DESCRIPTOR)
GetSecurityDescriptorLengthParams = ((1, 'pSecurityDescriptor'),)

#def GetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, lpbOwnerDefaulted):
#    return GetSecurityDescriptorOwner.ctypes_function(pSecurityDescriptor, pOwner, lpbOwnerDefaulted)
GetSecurityDescriptorOwnerPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, POINTER(PSID), LPBOOL)
GetSecurityDescriptorOwnerParams = ((1, 'pSecurityDescriptor'), (1, 'pOwner'), (1, 'lpbOwnerDefaulted'))

#def GetSecurityDescriptorRMControl(SecurityDescriptor, RMControl):
#    return GetSecurityDescriptorRMControl.ctypes_function(SecurityDescriptor, RMControl)
GetSecurityDescriptorRMControlPrototype = WINFUNCTYPE(DWORD, PSECURITY_DESCRIPTOR, PUCHAR)
GetSecurityDescriptorRMControlParams = ((1, 'SecurityDescriptor'), (1, 'RMControl'))

#def GetSecurityDescriptorSacl(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted):
#    return GetSecurityDescriptorSacl.ctypes_function(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted)
GetSecurityDescriptorSaclPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, LPBOOL, POINTER(PACL), LPBOOL)
GetSecurityDescriptorSaclParams = ((1, 'pSecurityDescriptor'), (1, 'lpbSaclPresent'), (1, 'pSacl'), (1, 'lpbSaclDefaulted'))

#def GetLengthSid(pSid):
#    return GetLengthSid.ctypes_function(pSid)
GetLengthSidPrototype = WINFUNCTYPE(DWORD, PSID)
GetLengthSidParams = ((1, 'pSid'),)

#def EqualSid(pSid1, pSid2):
#    return EqualSid.ctypes_function(pSid1, pSid2)
EqualSidPrototype = WINFUNCTYPE(BOOL, PSID, PSID)
EqualSidParams = ((1, 'pSid1'), (1, 'pSid2'))

#def CopySid(nDestinationSidLength, pDestinationSid, pSourceSid):
#    return CopySid.ctypes_function(nDestinationSidLength, pDestinationSid, pSourceSid)
CopySidPrototype = WINFUNCTYPE(BOOL, DWORD, PSID, PSID)
CopySidParams = ((1, 'nDestinationSidLength'), (1, 'pDestinationSid'), (1, 'pSourceSid'))

#def GetSidIdentifierAuthority(pSid):
#    return GetSidIdentifierAuthority.ctypes_function(pSid)
GetSidIdentifierAuthorityPrototype = WINFUNCTYPE(PSID_IDENTIFIER_AUTHORITY, PSID)
GetSidIdentifierAuthorityParams = ((1, 'pSid'),)

#def GetSidLengthRequired(nSubAuthorityCount):
#    return GetSidLengthRequired.ctypes_function(nSubAuthorityCount)
GetSidLengthRequiredPrototype = WINFUNCTYPE(DWORD, UCHAR)
GetSidLengthRequiredParams = ((1, 'nSubAuthorityCount'),)

#def GetSidSubAuthority(pSid, nSubAuthority):
#    return GetSidSubAuthority.ctypes_function(pSid, nSubAuthority)
GetSidSubAuthorityPrototype = WINFUNCTYPE(PDWORD, PSID, DWORD)
GetSidSubAuthorityParams = ((1, 'pSid'), (1, 'nSubAuthority'))

#def GetSidSubAuthorityCount(pSid):
#    return GetSidSubAuthorityCount.ctypes_function(pSid)
GetSidSubAuthorityCountPrototype = WINFUNCTYPE(LPBYTE, PSID)
GetSidSubAuthorityCountParams = ((1, 'pSid'),)

#def FreeSid(pSid):
#    return FreeSid.ctypes_function(pSid)
FreeSidPrototype = WINFUNCTYPE(PVOID, PSID)
FreeSidParams = ((1, 'pSid'),)

#def GetAce(pAcl, dwAceIndex, pAce):
#    return GetAce.ctypes_function(pAcl, dwAceIndex, pAce)
GetAcePrototype = WINFUNCTYPE(BOOL, PACL, DWORD, POINTER(LPVOID))
GetAceParams = ((1, 'pAcl'), (1, 'dwAceIndex'), (1, 'pAce'))

#def GetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass):
#    return GetAclInformation.ctypes_function(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass)
GetAclInformationPrototype = WINFUNCTYPE(BOOL, PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS)
GetAclInformationParams = ((1, 'pAcl'), (1, 'pAclInformation'), (1, 'nAclInformationLength'), (1, 'dwAclInformationClass'))

#def TpCallbackSendAlpcMessageOnCompletion(TpHandle, PortHandle, Flags, SendMessage):
#    return TpCallbackSendAlpcMessageOnCompletion.ctypes_function(TpHandle, PortHandle, Flags, SendMessage)
TpCallbackSendAlpcMessageOnCompletionPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, HANDLE, ULONG, PPORT_MESSAGE)
TpCallbackSendAlpcMessageOnCompletionParams = ((1, 'TpHandle'), (1, 'PortHandle'), (1, 'Flags'), (1, 'SendMessage'))

#def NtQueryLicenseValue(Name, Type, Buffer, Length, DataLength):
#    return NtQueryLicenseValue.ctypes_function(Name, Type, Buffer, Length, DataLength)
NtQueryLicenseValuePrototype = WINFUNCTYPE(NTSTATUS, PUNICODE_STRING, POINTER(ULONG), PVOID, ULONG, POINTER(ULONG))
NtQueryLicenseValueParams = ((1, 'Name'), (1, 'Type'), (1, 'Buffer'), (1, 'Length'), (1, 'DataLength'))

#def NtQueryEaFile(FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan):
#    return NtQueryEaFile.ctypes_function(FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan)
NtQueryEaFilePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN)
NtQueryEaFileParams = ((1, 'FileHandle'), (1, 'IoStatusBlock'), (1, 'Buffer'), (1, 'Length'), (1, 'ReturnSingleEntry'), (1, 'EaList'), (1, 'EaListLength'), (1, 'EaIndex'), (1, 'RestartScan'))

#def NtSetEaFile(FileHandle, IoStatusBlock, Buffer, Length):
#    return NtSetEaFile.ctypes_function(FileHandle, IoStatusBlock, Buffer, Length)
NtSetEaFilePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG)
NtSetEaFileParams = ((1, 'FileHandle'), (1, 'IoStatusBlock'), (1, 'Buffer'), (1, 'Length'))

#def NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob):
#    return NtCreateProcessEx.ctypes_function(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob)
NtCreateProcessExPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN)
NtCreateProcessExParams = ((1, 'ProcessHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'ParentProcess'), (1, 'Flags'), (1, 'SectionHandle'), (1, 'DebugPort'), (1, 'ExceptionPort'), (1, 'InJob'))

#def CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags):
#    return CryptCATAdminCalcHashFromFileHandle.ctypes_function(hFile, pcbHash, pbHash, dwFlags)
CryptCATAdminCalcHashFromFileHandlePrototype = WINFUNCTYPE(BOOL, HANDLE, POINTER(DWORD), POINTER(BYTE), DWORD)
CryptCATAdminCalcHashFromFileHandleParams = ((1, 'hFile'), (1, 'pcbHash'), (1, 'pbHash'), (1, 'dwFlags'))

#def CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, pcbHash, pbHash, dwFlags):
#    return CryptCATAdminCalcHashFromFileHandle2.ctypes_function(hCatAdmin, hFile, pcbHash, pbHash, dwFlags)
CryptCATAdminCalcHashFromFileHandle2Prototype = WINFUNCTYPE(BOOL, HCATADMIN, HANDLE, POINTER(DWORD), POINTER(BYTE), DWORD)
CryptCATAdminCalcHashFromFileHandle2Params = ((1, 'hCatAdmin'), (1, 'hFile'), (1, 'pcbHash'), (1, 'pbHash'), (1, 'dwFlags'))

#def CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo):
#    return CryptCATAdminEnumCatalogFromHash.ctypes_function(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo)
CryptCATAdminEnumCatalogFromHashPrototype = WINFUNCTYPE(HCATINFO, HCATADMIN, POINTER(BYTE), DWORD, DWORD, POINTER(HCATINFO))
CryptCATAdminEnumCatalogFromHashParams = ((1, 'hCatAdmin'), (1, 'pbHash'), (1, 'cbHash'), (1, 'dwFlags'), (1, 'phPrevCatInfo'))

#def CryptCATAdminAcquireContext(phCatAdmin, pgSubsystem, dwFlags):
#    return CryptCATAdminAcquireContext.ctypes_function(phCatAdmin, pgSubsystem, dwFlags)
CryptCATAdminAcquireContextPrototype = WINFUNCTYPE(BOOL, POINTER(HCATADMIN), POINTER(GUID), DWORD)
CryptCATAdminAcquireContextParams = ((1, 'phCatAdmin'), (1, 'pgSubsystem'), (1, 'dwFlags'))

#def CryptCATAdminAcquireContext2(phCatAdmin, pgSubsystem, pwszHashAlgorithm, pStrongHashPolicy, dwFlags):
#    return CryptCATAdminAcquireContext2.ctypes_function(phCatAdmin, pgSubsystem, pwszHashAlgorithm, pStrongHashPolicy, dwFlags)
CryptCATAdminAcquireContext2Prototype = WINFUNCTYPE(BOOL, POINTER(HCATADMIN), POINTER(GUID), PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD)
CryptCATAdminAcquireContext2Params = ((1, 'phCatAdmin'), (1, 'pgSubsystem'), (1, 'pwszHashAlgorithm'), (1, 'pStrongHashPolicy'), (1, 'dwFlags'))

#def CryptCATCatalogInfoFromContext(hCatInfo, psCatInfo, dwFlags):
#    return CryptCATCatalogInfoFromContext.ctypes_function(hCatInfo, psCatInfo, dwFlags)
CryptCATCatalogInfoFromContextPrototype = WINFUNCTYPE(BOOL, HCATINFO, POINTER(CATALOG_INFO), DWORD)
CryptCATCatalogInfoFromContextParams = ((1, 'hCatInfo'), (1, 'psCatInfo'), (1, 'dwFlags'))

#def CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwFlags):
#    return CryptCATAdminReleaseCatalogContext.ctypes_function(hCatAdmin, hCatInfo, dwFlags)
CryptCATAdminReleaseCatalogContextPrototype = WINFUNCTYPE(BOOL, HCATADMIN, HCATINFO, DWORD)
CryptCATAdminReleaseCatalogContextParams = ((1, 'hCatAdmin'), (1, 'hCatInfo'), (1, 'dwFlags'))

#def CryptCATAdminReleaseContext(hCatAdmin, dwFlags):
#    return CryptCATAdminReleaseContext.ctypes_function(hCatAdmin, dwFlags)
CryptCATAdminReleaseContextPrototype = WINFUNCTYPE(BOOL, HCATADMIN, DWORD)
CryptCATAdminReleaseContextParams = ((1, 'hCatAdmin'), (1, 'dwFlags'))

#def CryptCATGetAttrInfo(hCatalog, pCatMember, pwszReferenceTag):
#    return CryptCATGetAttrInfo.ctypes_function(hCatalog, pCatMember, pwszReferenceTag)
CryptCATGetAttrInfoPrototype = WINFUNCTYPE(POINTER(CRYPTCATATTRIBUTE), HANDLE, POINTER(CRYPTCATMEMBER), LPWSTR)
CryptCATGetAttrInfoParams = ((1, 'hCatalog'), (1, 'pCatMember'), (1, 'pwszReferenceTag'))

#def CryptCATGetMemberInfo(hCatalog, pwszReferenceTag):
#    return CryptCATGetMemberInfo.ctypes_function(hCatalog, pwszReferenceTag)
CryptCATGetMemberInfoPrototype = WINFUNCTYPE(POINTER(CRYPTCATMEMBER), HANDLE, LPWSTR)
CryptCATGetMemberInfoParams = ((1, 'hCatalog'), (1, 'pwszReferenceTag'))

#def CryptCATGetAttrInfo(hCatalog, pCatMember, pwszReferenceTag):
#    return CryptCATGetAttrInfo.ctypes_function(hCatalog, pCatMember, pwszReferenceTag)
CryptCATGetAttrInfoPrototype = WINFUNCTYPE(POINTER(CRYPTCATATTRIBUTE), HANDLE, POINTER(CRYPTCATMEMBER), LPWSTR)
CryptCATGetAttrInfoParams = ((1, 'hCatalog'), (1, 'pCatMember'), (1, 'pwszReferenceTag'))

#def CryptCATEnumerateCatAttr(hCatalog, pPrevAttr):
#    return CryptCATEnumerateCatAttr.ctypes_function(hCatalog, pPrevAttr)
CryptCATEnumerateCatAttrPrototype = WINFUNCTYPE(POINTER(CRYPTCATATTRIBUTE), HANDLE, POINTER(CRYPTCATATTRIBUTE))
CryptCATEnumerateCatAttrParams = ((1, 'hCatalog'), (1, 'pPrevAttr'))

#def CryptCATEnumerateAttr(hCatalog, pCatMember, pPrevAttr):
#    return CryptCATEnumerateAttr.ctypes_function(hCatalog, pCatMember, pPrevAttr)
CryptCATEnumerateAttrPrototype = WINFUNCTYPE(POINTER(CRYPTCATATTRIBUTE), HANDLE, POINTER(CRYPTCATMEMBER), POINTER(CRYPTCATATTRIBUTE))
CryptCATEnumerateAttrParams = ((1, 'hCatalog'), (1, 'pCatMember'), (1, 'pPrevAttr'))

#def CryptCATEnumerateMember(hCatalog, pPrevMember):
#    return CryptCATEnumerateMember.ctypes_function(hCatalog, pPrevMember)
CryptCATEnumerateMemberPrototype = WINFUNCTYPE(POINTER(CRYPTCATMEMBER), HANDLE, POINTER(CRYPTCATMEMBER))
CryptCATEnumerateMemberParams = ((1, 'hCatalog'), (1, 'pPrevMember'))

#def CryptQueryObject(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext):
#    return CryptQueryObject.ctypes_function(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext)
CryptQueryObjectPrototype = WINFUNCTYPE(BOOL, DWORD, PVOID, DWORD, DWORD, DWORD, POINTER(DWORD), POINTER(DWORD), POINTER(DWORD), POINTER(HCERTSTORE), POINTER(HCRYPTMSG), POINTER(PVOID))
CryptQueryObjectParams = ((1, 'dwObjectType'), (1, 'pvObject'), (1, 'dwExpectedContentTypeFlags'), (1, 'dwExpectedFormatTypeFlags'), (1, 'dwFlags'), (1, 'pdwMsgAndCertEncodingType'), (1, 'pdwContentType'), (1, 'pdwFormatType'), (1, 'phCertStore'), (1, 'phMsg'), (1, 'ppvContext'))

#def CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, pvData, pcbData):
#    return CryptMsgGetParam.ctypes_function(hCryptMsg, dwParamType, dwIndex, pvData, pcbData)
CryptMsgGetParamPrototype = WINFUNCTYPE(BOOL, HCRYPTMSG, DWORD, DWORD, PVOID, POINTER(DWORD))
CryptMsgGetParamParams = ((1, 'hCryptMsg'), (1, 'dwParamType'), (1, 'dwIndex'), (1, 'pvData'), (1, 'pcbData'))

#def CryptDecodeObject(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo):
#    return CryptDecodeObject.ctypes_function(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo)
CryptDecodeObjectPrototype = WINFUNCTYPE(BOOL, DWORD, LPCSTR, POINTER(BYTE), DWORD, DWORD, PVOID, POINTER(DWORD))
CryptDecodeObjectParams = ((1, 'dwCertEncodingType'), (1, 'lpszStructType'), (1, 'pbEncoded'), (1, 'cbEncoded'), (1, 'dwFlags'), (1, 'pvStructInfo'), (1, 'pcbStructInfo'))

#def CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext):
#    return CertFindCertificateInStore.ctypes_function(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext)
CertFindCertificateInStorePrototype = WINFUNCTYPE(PCCERT_CONTEXT, HCERTSTORE, DWORD, DWORD, DWORD, PVOID, PCCERT_CONTEXT)
CertFindCertificateInStoreParams = ((1, 'hCertStore'), (1, 'dwCertEncodingType'), (1, 'dwFindFlags'), (1, 'dwFindType'), (1, 'pvFindPara'), (1, 'pPrevCertContext'))

#def CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString):
#    return CertGetNameStringA.ctypes_function(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)
CertGetNameStringAPrototype = WINFUNCTYPE(DWORD, PCCERT_CONTEXT, DWORD, DWORD, PVOID, LPCSTR, DWORD)
CertGetNameStringAParams = ((1, 'pCertContext'), (1, 'dwType'), (1, 'dwFlags'), (1, 'pvTypePara'), (1, 'pszNameString'), (1, 'cchNameString'))

#def CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString):
#    return CertGetNameStringW.ctypes_function(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)
CertGetNameStringWPrototype = WINFUNCTYPE(DWORD, PCCERT_CONTEXT, DWORD, DWORD, PVOID, LPWSTR, DWORD)
CertGetNameStringWParams = ((1, 'pCertContext'), (1, 'dwType'), (1, 'dwFlags'), (1, 'pvTypePara'), (1, 'pszNameString'), (1, 'cchNameString'))

#def CertGetCertificateChain(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext):
#    return CertGetCertificateChain.ctypes_function(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext)
CertGetCertificateChainPrototype = WINFUNCTYPE(BOOL, HCERTCHAINENGINE, PCCERT_CONTEXT, LPFILETIME, HCERTSTORE, PCERT_CHAIN_PARA, DWORD, LPVOID, POINTER(PCCERT_CHAIN_CONTEXT))
CertGetCertificateChainParams = ((1, 'hChainEngine'), (1, 'pCertContext'), (1, 'pTime'), (1, 'hAdditionalStore'), (1, 'pChainPara'), (1, 'dwFlags'), (1, 'pvReserved'), (1, 'ppChainContext'))

#def CertCreateSelfSignCertificate(hCryptProvOrNCryptKey, pSubjectIssuerBlob, dwFlags, pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions):
#    return CertCreateSelfSignCertificate.ctypes_function(hCryptProvOrNCryptKey, pSubjectIssuerBlob, dwFlags, pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions)
CertCreateSelfSignCertificatePrototype = WINFUNCTYPE(PCCERT_CONTEXT, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, PCERT_NAME_BLOB, DWORD, PCRYPT_KEY_PROV_INFO, PCRYPT_ALGORITHM_IDENTIFIER, PSYSTEMTIME, PSYSTEMTIME, PCERT_EXTENSIONS)
CertCreateSelfSignCertificateParams = ((1, 'hCryptProvOrNCryptKey'), (1, 'pSubjectIssuerBlob'), (1, 'dwFlags'), (1, 'pKeyProvInfo'), (1, 'pSignatureAlgorithm'), (1, 'pStartTime'), (1, 'pEndTime'), (1, 'pExtensions'))

#def CertStrToNameA(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError):
#    return CertStrToNameA.ctypes_function(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)
CertStrToNameAPrototype = WINFUNCTYPE(BOOL, DWORD, LPCSTR, DWORD, PVOID, POINTER(BYTE), POINTER(DWORD), POINTER(LPCSTR))
CertStrToNameAParams = ((1, 'dwCertEncodingType'), (1, 'pszX500'), (1, 'dwStrType'), (1, 'pvReserved'), (1, 'pbEncoded'), (1, 'pcbEncoded'), (1, 'ppszError'))

#def CertStrToNameW(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError):
#    return CertStrToNameW.ctypes_function(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)
CertStrToNameWPrototype = WINFUNCTYPE(BOOL, DWORD, LPWSTR, DWORD, PVOID, POINTER(BYTE), POINTER(DWORD), POINTER(LPWSTR))
CertStrToNameWParams = ((1, 'dwCertEncodingType'), (1, 'pszX500'), (1, 'dwStrType'), (1, 'pvReserved'), (1, 'pbEncoded'), (1, 'pcbEncoded'), (1, 'ppszError'))

#def CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara):
#    return CertOpenStore.ctypes_function(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara)
CertOpenStorePrototype = WINFUNCTYPE(HCERTSTORE, LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, PVOID)
CertOpenStoreParams = ((1, 'lpszStoreProvider'), (1, 'dwMsgAndCertEncodingType'), (1, 'hCryptProv'), (1, 'dwFlags'), (1, 'pvPara'))

#def CertAddCertificateContextToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext):
#    return CertAddCertificateContextToStore.ctypes_function(hCertStore, pCertContext, dwAddDisposition, ppStoreContext)
CertAddCertificateContextToStorePrototype = WINFUNCTYPE(BOOL, HCERTSTORE, PCCERT_CONTEXT, DWORD, POINTER(PCCERT_CONTEXT))
CertAddCertificateContextToStoreParams = ((1, 'hCertStore'), (1, 'pCertContext'), (1, 'dwAddDisposition'), (1, 'ppStoreContext'))

#def CertFreeCertificateContext(pCertContext):
#    return CertFreeCertificateContext.ctypes_function(pCertContext)
CertFreeCertificateContextPrototype = WINFUNCTYPE(BOOL, PCCERT_CONTEXT)
CertFreeCertificateContextParams = ((1, 'pCertContext'),)

#def PFXExportCertStoreEx(hStore, pPFX, szPassword, pvPara, dwFlags):
#    return PFXExportCertStoreEx.ctypes_function(hStore, pPFX, szPassword, pvPara, dwFlags)
PFXExportCertStoreExPrototype = WINFUNCTYPE(BOOL, HCERTSTORE, POINTER(CRYPT_DATA_BLOB), LPCWSTR, PVOID, DWORD)
PFXExportCertStoreExParams = ((1, 'hStore'), (1, 'pPFX'), (1, 'szPassword'), (1, 'pvPara'), (1, 'dwFlags'))

#def PFXImportCertStore(pPFX, szPassword, dwFlags):
#    return PFXImportCertStore.ctypes_function(pPFX, szPassword, dwFlags)
PFXImportCertStorePrototype = WINFUNCTYPE(HCERTSTORE, POINTER(CRYPT_DATA_BLOB), LPCWSTR, DWORD)
PFXImportCertStoreParams = ((1, 'pPFX'), (1, 'szPassword'), (1, 'dwFlags'))

#def CryptGenKey(hProv, Algid, dwFlags, phKey):
#    return CryptGenKey.ctypes_function(hProv, Algid, dwFlags, phKey)
CryptGenKeyPrototype = WINFUNCTYPE(BOOL, HCRYPTPROV, ALG_ID, DWORD, POINTER(HCRYPTKEY))
CryptGenKeyParams = ((1, 'hProv'), (1, 'Algid'), (1, 'dwFlags'), (1, 'phKey'))

#def CryptDestroyKey(hKey):
#    return CryptDestroyKey.ctypes_function(hKey)
CryptDestroyKeyPrototype = WINFUNCTYPE(BOOL, HCRYPTKEY)
CryptDestroyKeyParams = ((1, 'hKey'),)

#def CryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags):
#    return CryptAcquireContextA.ctypes_function(phProv, pszContainer, pszProvider, dwProvType, dwFlags)
CryptAcquireContextAPrototype = WINFUNCTYPE(BOOL, POINTER(HCRYPTPROV), LPCSTR, LPCSTR, DWORD, DWORD)
CryptAcquireContextAParams = ((1, 'phProv'), (1, 'pszContainer'), (1, 'pszProvider'), (1, 'dwProvType'), (1, 'dwFlags'))

#def CryptAcquireContextW(phProv, pszContainer, pszProvider, dwProvType, dwFlags):
#    return CryptAcquireContextW.ctypes_function(phProv, pszContainer, pszProvider, dwProvType, dwFlags)
CryptAcquireContextWPrototype = WINFUNCTYPE(BOOL, POINTER(HCRYPTPROV), LPWSTR, LPWSTR, DWORD, DWORD)
CryptAcquireContextWParams = ((1, 'phProv'), (1, 'pszContainer'), (1, 'pszProvider'), (1, 'dwProvType'), (1, 'dwFlags'))

#def CryptReleaseContext(hProv, dwFlags):
#    return CryptReleaseContext.ctypes_function(hProv, dwFlags)
CryptReleaseContextPrototype = WINFUNCTYPE(BOOL, HCRYPTPROV, DWORD)
CryptReleaseContextParams = ((1, 'hProv'), (1, 'dwFlags'))

#def CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen):
#    return CryptExportKey.ctypes_function(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen)
CryptExportKeyPrototype = WINFUNCTYPE(BOOL, HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, POINTER(BYTE), POINTER(DWORD))
CryptExportKeyParams = ((1, 'hKey'), (1, 'hExpKey'), (1, 'dwBlobType'), (1, 'dwFlags'), (1, 'pbData'), (1, 'pdwDataLen'))

#def CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, pcbData):
#    return CertGetCertificateContextProperty.ctypes_function(pCertContext, dwPropId, pvData, pcbData)
CertGetCertificateContextPropertyPrototype = WINFUNCTYPE(BOOL, PCCERT_CONTEXT, DWORD, PVOID, POINTER(DWORD))
CertGetCertificateContextPropertyParams = ((1, 'pCertContext'), (1, 'dwPropId'), (1, 'pvData'), (1, 'pcbData'))

#def CertEnumCertificateContextProperties(pCertContext, dwPropId):
#    return CertEnumCertificateContextProperties.ctypes_function(pCertContext, dwPropId)
CertEnumCertificateContextPropertiesPrototype = WINFUNCTYPE(DWORD, PCCERT_CONTEXT, DWORD)
CertEnumCertificateContextPropertiesParams = ((1, 'pCertContext'), (1, 'dwPropId'))

#def CryptEncryptMessage(pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob, pcbEncryptedBlob):
#    return CryptEncryptMessage.ctypes_function(pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob, pcbEncryptedBlob)
CryptEncryptMessagePrototype = WINFUNCTYPE(BOOL, PCRYPT_ENCRYPT_MESSAGE_PARA, DWORD, POINTER(PCCERT_CONTEXT), POINTER(BYTE), DWORD, POINTER(BYTE), POINTER(DWORD))
CryptEncryptMessageParams = ((1, 'pEncryptPara'), (1, 'cRecipientCert'), (1, 'rgpRecipientCert'), (1, 'pbToBeEncrypted'), (1, 'cbToBeEncrypted'), (1, 'pbEncryptedBlob'), (1, 'pcbEncryptedBlob'))

#def CryptDecryptMessage(pDecryptPara, pbEncryptedBlob, cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert):
#    return CryptDecryptMessage.ctypes_function(pDecryptPara, pbEncryptedBlob, cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert)
CryptDecryptMessagePrototype = WINFUNCTYPE(BOOL, PCRYPT_DECRYPT_MESSAGE_PARA, POINTER(BYTE), DWORD, POINTER(BYTE), POINTER(DWORD), POINTER(PCCERT_CONTEXT))
CryptDecryptMessageParams = ((1, 'pDecryptPara'), (1, 'pbEncryptedBlob'), (1, 'cbEncryptedBlob'), (1, 'pbDecrypted'), (1, 'pcbDecrypted'), (1, 'ppXchgCert'))

#def CryptAcquireCertificatePrivateKey(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey):
#    return CryptAcquireCertificatePrivateKey.ctypes_function(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey)
CryptAcquireCertificatePrivateKeyPrototype = WINFUNCTYPE(BOOL, PCCERT_CONTEXT, DWORD, PVOID, POINTER(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE), POINTER(DWORD), POINTER(BOOL))
CryptAcquireCertificatePrivateKeyParams = ((1, 'pCert'), (1, 'dwFlags'), (1, 'pvParameters'), (1, 'phCryptProvOrNCryptKey'), (1, 'pdwKeySpec'), (1, 'pfCallerFreeProvOrNCryptKey'))

#def CertDuplicateCertificateContext(pCertContext):
#    return CertDuplicateCertificateContext.ctypes_function(pCertContext)
CertDuplicateCertificateContextPrototype = WINFUNCTYPE(PCCERT_CONTEXT, PCCERT_CONTEXT)
CertDuplicateCertificateContextParams = ((1, 'pCertContext'),)

#def CertEnumCertificatesInStore(hCertStore, pPrevCertContext):
#    return CertEnumCertificatesInStore.ctypes_function(hCertStore, pPrevCertContext)
CertEnumCertificatesInStorePrototype = WINFUNCTYPE(PCCERT_CONTEXT, HCERTSTORE, PCCERT_CONTEXT)
CertEnumCertificatesInStoreParams = ((1, 'hCertStore'), (1, 'pPrevCertContext'))

#def CryptEncodeObjectEx(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded):
#    return CryptEncodeObjectEx.ctypes_function(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded)
CryptEncodeObjectExPrototype = WINFUNCTYPE(BOOL, DWORD, LPCSTR, PVOID, DWORD, PCRYPT_ENCODE_PARA, PVOID, POINTER(DWORD))
CryptEncodeObjectExParams = ((1, 'dwCertEncodingType'), (1, 'lpszStructType'), (1, 'pvStructInfo'), (1, 'dwFlags'), (1, 'pEncodePara'), (1, 'pvEncoded'), (1, 'pcbEncoded'))

#def CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded):
#    return CertCreateCertificateContext.ctypes_function(dwCertEncodingType, pbCertEncoded, cbCertEncoded)
CertCreateCertificateContextPrototype = WINFUNCTYPE(PCCERT_CONTEXT, DWORD, POINTER(BYTE), DWORD)
CertCreateCertificateContextParams = ((1, 'dwCertEncodingType'), (1, 'pbCertEncoded'), (1, 'cbCertEncoded'))

#def CertCompareCertificate(dwCertEncodingType, pCertId1, pCertId2):
#    return CertCompareCertificate.ctypes_function(dwCertEncodingType, pCertId1, pCertId2)
CertCompareCertificatePrototype = WINFUNCTYPE(BOOL, DWORD, PCERT_INFO, PCERT_INFO)
CertCompareCertificateParams = ((1, 'dwCertEncodingType'), (1, 'pCertId1'), (1, 'pCertId2'))

#def CertEnumCTLsInStore(hCertStore, pPrevCtlContext):
#    return CertEnumCTLsInStore.ctypes_function(hCertStore, pPrevCtlContext)
CertEnumCTLsInStorePrototype = WINFUNCTYPE(PCCTL_CONTEXT, HCERTSTORE, PCCTL_CONTEXT)
CertEnumCTLsInStoreParams = ((1, 'hCertStore'), (1, 'pPrevCtlContext'))

#def CertDuplicateCTLContext(pCtlContext):
#    return CertDuplicateCTLContext.ctypes_function(pCtlContext)
CertDuplicateCTLContextPrototype = WINFUNCTYPE(PCCTL_CONTEXT, PCCTL_CONTEXT)
CertDuplicateCTLContextParams = ((1, 'pCtlContext'),)

#def CertFreeCTLContext(pCtlContext):
#    return CertFreeCTLContext.ctypes_function(pCtlContext)
CertFreeCTLContextPrototype = WINFUNCTYPE(BOOL, PCCTL_CONTEXT)
CertFreeCTLContextParams = ((1, 'pCtlContext'),)

#def CryptUIDlgViewContext(dwContextType, pvContext, hwnd, pwszTitle, dwFlags, pvReserved):
#    return CryptUIDlgViewContext.ctypes_function(dwContextType, pvContext, hwnd, pwszTitle, dwFlags, pvReserved)
CryptUIDlgViewContextPrototype = WINFUNCTYPE(BOOL, DWORD, PVOID, HWND, LPCWSTR, DWORD, PVOID)
CryptUIDlgViewContextParams = ((1, 'dwContextType'), (1, 'pvContext'), (1, 'hwnd'), (1, 'pwszTitle'), (1, 'dwFlags'), (1, 'pvReserved'))

#def CryptMsgVerifyCountersignatureEncoded(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, pciCountersigner):
#    return CryptMsgVerifyCountersignatureEncoded.ctypes_function(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, pciCountersigner)
CryptMsgVerifyCountersignatureEncodedPrototype = WINFUNCTYPE(BOOL, HCRYPTPROV_LEGACY, DWORD, PBYTE, DWORD, PBYTE, DWORD, PCERT_INFO)
CryptMsgVerifyCountersignatureEncodedParams = ((1, 'hCryptProv'), (1, 'dwEncodingType'), (1, 'pbSignerInfo'), (1, 'cbSignerInfo'), (1, 'pbSignerInfoCountersignature'), (1, 'cbSignerInfoCountersignature'), (1, 'pciCountersigner'))

#def CryptMsgVerifyCountersignatureEncodedEx(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, dwSignerType, pvSigner, dwFlags, pvExtra):
#    return CryptMsgVerifyCountersignatureEncodedEx.ctypes_function(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, dwSignerType, pvSigner, dwFlags, pvExtra)
CryptMsgVerifyCountersignatureEncodedExPrototype = WINFUNCTYPE(BOOL, HCRYPTPROV_LEGACY, DWORD, PBYTE, DWORD, PBYTE, DWORD, DWORD, PVOID, DWORD, PVOID)
CryptMsgVerifyCountersignatureEncodedExParams = ((1, 'hCryptProv'), (1, 'dwEncodingType'), (1, 'pbSignerInfo'), (1, 'cbSignerInfo'), (1, 'pbSignerInfoCountersignature'), (1, 'cbSignerInfoCountersignature'), (1, 'dwSignerType'), (1, 'pvSigner'), (1, 'dwFlags'), (1, 'pvExtra'))

#def CryptHashCertificate(hCryptProv, Algid, dwFlags, pbEncoded, cbEncoded, pbComputedHash, pcbComputedHash):
#    return CryptHashCertificate.ctypes_function(hCryptProv, Algid, dwFlags, pbEncoded, cbEncoded, pbComputedHash, pcbComputedHash)
CryptHashCertificatePrototype = WINFUNCTYPE(BOOL, HCRYPTPROV_LEGACY, ALG_ID, DWORD, POINTER(BYTE), DWORD, POINTER(BYTE), POINTER(DWORD))
CryptHashCertificateParams = ((1, 'hCryptProv'), (1, 'Algid'), (1, 'dwFlags'), (1, 'pbEncoded'), (1, 'cbEncoded'), (1, 'pbComputedHash'), (1, 'pcbComputedHash'))

#def CryptSignMessage(pSignPara, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, pbSignedBlob, pcbSignedBlob):
#    return CryptSignMessage.ctypes_function(pSignPara, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, pbSignedBlob, pcbSignedBlob)
CryptSignMessagePrototype = WINFUNCTYPE(BOOL, PCRYPT_SIGN_MESSAGE_PARA, BOOL, DWORD, POINTER(PBYTE), POINTER(DWORD), POINTER(BYTE), POINTER(DWORD))
CryptSignMessageParams = ((1, 'pSignPara'), (1, 'fDetachedSignature'), (1, 'cToBeSigned'), (1, 'rgpbToBeSigned'), (1, 'rgcbToBeSigned'), (1, 'pbSignedBlob'), (1, 'pcbSignedBlob'))

#def CryptSignAndEncryptMessage(pSignPara, pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeSignedAndEncrypted, cbToBeSignedAndEncrypted, pbSignedAndEncryptedBlob, pcbSignedAndEncryptedBlob):
#    return CryptSignAndEncryptMessage.ctypes_function(pSignPara, pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeSignedAndEncrypted, cbToBeSignedAndEncrypted, pbSignedAndEncryptedBlob, pcbSignedAndEncryptedBlob)
CryptSignAndEncryptMessagePrototype = WINFUNCTYPE(BOOL, PCRYPT_SIGN_MESSAGE_PARA, PCRYPT_ENCRYPT_MESSAGE_PARA, DWORD, POINTER(PCCERT_CONTEXT), POINTER(BYTE), DWORD, POINTER(BYTE), POINTER(DWORD))
CryptSignAndEncryptMessageParams = ((1, 'pSignPara'), (1, 'pEncryptPara'), (1, 'cRecipientCert'), (1, 'rgpRecipientCert'), (1, 'pbToBeSignedAndEncrypted'), (1, 'cbToBeSignedAndEncrypted'), (1, 'pbSignedAndEncryptedBlob'), (1, 'pcbSignedAndEncryptedBlob'))

#def CryptVerifyMessageSignature(pVerifyPara, dwSignerIndex, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded, ppSignerCert):
#    return CryptVerifyMessageSignature.ctypes_function(pVerifyPara, dwSignerIndex, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded, ppSignerCert)
CryptVerifyMessageSignaturePrototype = WINFUNCTYPE(BOOL, PCRYPT_VERIFY_MESSAGE_PARA, DWORD, POINTER(BYTE), DWORD, POINTER(BYTE), POINTER(DWORD), POINTER(PCCERT_CONTEXT))
CryptVerifyMessageSignatureParams = ((1, 'pVerifyPara'), (1, 'dwSignerIndex'), (1, 'pbSignedBlob'), (1, 'cbSignedBlob'), (1, 'pbDecoded'), (1, 'pcbDecoded'), (1, 'ppSignerCert'))

#def CryptVerifyMessageSignatureWithKey(pVerifyPara, pPublicKeyInfo, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded):
#    return CryptVerifyMessageSignatureWithKey.ctypes_function(pVerifyPara, pPublicKeyInfo, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded)
CryptVerifyMessageSignatureWithKeyPrototype = WINFUNCTYPE(BOOL, PCRYPT_KEY_VERIFY_MESSAGE_PARA, PCERT_PUBLIC_KEY_INFO, POINTER(BYTE), DWORD, POINTER(BYTE), POINTER(DWORD))
CryptVerifyMessageSignatureWithKeyParams = ((1, 'pVerifyPara'), (1, 'pPublicKeyInfo'), (1, 'pbSignedBlob'), (1, 'cbSignedBlob'), (1, 'pbDecoded'), (1, 'pcbDecoded'))

#def CryptVerifyMessageHash(pHashPara, pbHashedBlob, cbHashedBlob, pbToBeHashed, pcbToBeHashed, pbComputedHash, pcbComputedHash):
#    return CryptVerifyMessageHash.ctypes_function(pHashPara, pbHashedBlob, cbHashedBlob, pbToBeHashed, pcbToBeHashed, pbComputedHash, pcbComputedHash)
CryptVerifyMessageHashPrototype = WINFUNCTYPE(BOOL, PCRYPT_HASH_MESSAGE_PARA, POINTER(BYTE), DWORD, POINTER(BYTE), POINTER(DWORD), POINTER(BYTE), POINTER(DWORD))
CryptVerifyMessageHashParams = ((1, 'pHashPara'), (1, 'pbHashedBlob'), (1, 'cbHashedBlob'), (1, 'pbToBeHashed'), (1, 'pcbToBeHashed'), (1, 'pbComputedHash'), (1, 'pcbComputedHash'))

#def PfnCryptGetSignerCertificate(pvGetArg, dwCertEncodingType, pSignerId, hMsgCertStore):
#    return PfnCryptGetSignerCertificate.ctypes_function(pvGetArg, dwCertEncodingType, pSignerId, hMsgCertStore)
PfnCryptGetSignerCertificatePrototype = WINFUNCTYPE(PCCERT_CONTEXT, PVOID, DWORD, PCERT_INFO, HCERTSTORE)
PfnCryptGetSignerCertificateParams = ((1, 'pvGetArg'), (1, 'dwCertEncodingType'), (1, 'pSignerId'), (1, 'hMsgCertStore'))

#def CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen):
#    return CryptEncrypt.ctypes_function(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
CryptEncryptPrototype = WINFUNCTYPE(BOOL, HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, POINTER(BYTE), POINTER(DWORD), DWORD)
CryptEncryptParams = ((1, 'hKey'), (1, 'hHash'), (1, 'Final'), (1, 'dwFlags'), (1, 'pbData'), (1, 'pdwDataLen'), (1, 'dwBufLen'))

#def CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen):
#    return CryptDecrypt.ctypes_function(hKey, hHash, Final, dwFlags, pbData, pdwDataLen)
CryptDecryptPrototype = WINFUNCTYPE(BOOL, HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, POINTER(BYTE), POINTER(DWORD))
CryptDecryptParams = ((1, 'hKey'), (1, 'hHash'), (1, 'Final'), (1, 'dwFlags'), (1, 'pbData'), (1, 'pdwDataLen'))

#def CryptMsgOpenToEncode(dwMsgEncodingType, dwFlags, dwMsgType, pvMsgEncodeInfo, pszInnerContentObjID, pStreamInfo):
#    return CryptMsgOpenToEncode.ctypes_function(dwMsgEncodingType, dwFlags, dwMsgType, pvMsgEncodeInfo, pszInnerContentObjID, pStreamInfo)
CryptMsgOpenToEncodePrototype = WINFUNCTYPE(HCRYPTMSG, DWORD, DWORD, DWORD, PVOID, LPSTR, PCMSG_STREAM_INFO)
CryptMsgOpenToEncodeParams = ((1, 'dwMsgEncodingType'), (1, 'dwFlags'), (1, 'dwMsgType'), (1, 'pvMsgEncodeInfo'), (1, 'pszInnerContentObjID'), (1, 'pStreamInfo'))

#def CryptMsgOpenToDecode(dwMsgEncodingType, dwFlags, dwMsgType, hCryptProv, pRecipientInfo, pStreamInfo):
#    return CryptMsgOpenToDecode.ctypes_function(dwMsgEncodingType, dwFlags, dwMsgType, hCryptProv, pRecipientInfo, pStreamInfo)
CryptMsgOpenToDecodePrototype = WINFUNCTYPE(HCRYPTMSG, DWORD, DWORD, DWORD, HCRYPTPROV_LEGACY, PCERT_INFO, PCMSG_STREAM_INFO)
CryptMsgOpenToDecodeParams = ((1, 'dwMsgEncodingType'), (1, 'dwFlags'), (1, 'dwMsgType'), (1, 'hCryptProv'), (1, 'pRecipientInfo'), (1, 'pStreamInfo'))

#def CryptMsgUpdate(hCryptMsg, pbData, cbData, fFinal):
#    return CryptMsgUpdate.ctypes_function(hCryptMsg, pbData, cbData, fFinal)
CryptMsgUpdatePrototype = WINFUNCTYPE(BOOL, HCRYPTMSG, POINTER(BYTE), DWORD, BOOL)
CryptMsgUpdateParams = ((1, 'hCryptMsg'), (1, 'pbData'), (1, 'cbData'), (1, 'fFinal'))

#def CryptMsgControl(hCryptMsg, dwFlags, dwCtrlType, pvCtrlPara):
#    return CryptMsgControl.ctypes_function(hCryptMsg, dwFlags, dwCtrlType, pvCtrlPara)
CryptMsgControlPrototype = WINFUNCTYPE(BOOL, HCRYPTMSG, DWORD, DWORD, PVOID)
CryptMsgControlParams = ((1, 'hCryptMsg'), (1, 'dwFlags'), (1, 'dwCtrlType'), (1, 'pvCtrlPara'))

#def CryptMsgClose(hCryptMsg):
#    return CryptMsgClose.ctypes_function(hCryptMsg)
CryptMsgClosePrototype = WINFUNCTYPE(BOOL, HCRYPTMSG)
CryptMsgCloseParams = ((1, 'hCryptMsg'),)

#def CoInitializeEx(pvReserved, dwCoInit):
#    return CoInitializeEx.ctypes_function(pvReserved, dwCoInit)
CoInitializeExPrototype = WINFUNCTYPE(HRESULT, LPVOID, DWORD)
CoInitializeExParams = ((1, 'pvReserved'), (1, 'dwCoInit'))

#def CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3):
#    return CoInitializeSecurity.ctypes_function(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3)
CoInitializeSecurityPrototype = WINFUNCTYPE(HRESULT, PSECURITY_DESCRIPTOR, LONG, POINTER(SOLE_AUTHENTICATION_SERVICE), PVOID, DWORD, DWORD, PVOID, DWORD, PVOID)
CoInitializeSecurityParams = ((1, 'pSecDesc'), (1, 'cAuthSvc'), (1, 'asAuthSvc'), (1, 'pReserved1'), (1, 'dwAuthnLevel'), (1, 'dwImpLevel'), (1, 'pAuthList'), (1, 'dwCapabilities'), (1, 'pReserved3'))

#def CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv):
#    return CoCreateInstance.ctypes_function(rclsid, pUnkOuter, dwClsContext, riid, ppv)
CoCreateInstancePrototype = WINFUNCTYPE(HRESULT, REFCLSID, LPUNKNOWN, DWORD, REFIID, POINTER(LPVOID))
CoCreateInstanceParams = ((1, 'rclsid'), (1, 'pUnkOuter'), (1, 'dwClsContext'), (1, 'riid'), (1, 'ppv'))

#def CoCreateInstanceEx(rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults):
#    return CoCreateInstanceEx.ctypes_function(rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults)
CoCreateInstanceExPrototype = WINFUNCTYPE(HRESULT, REFCLSID, POINTER(IUnknown), DWORD, POINTER(COSERVERINFO), DWORD, POINTER(MULTI_QI))
CoCreateInstanceExParams = ((1, 'rclsid'), (1, 'punkOuter'), (1, 'dwClsCtx'), (1, 'pServerInfo'), (1, 'dwCount'), (1, 'pResults'))

#def CoGetInterceptor(iidIntercepted, punkOuter, iid, ppv):
#    return CoGetInterceptor.ctypes_function(iidIntercepted, punkOuter, iid, ppv)
CoGetInterceptorPrototype = WINFUNCTYPE(HRESULT, REFIID, POINTER(IUnknown), REFIID, POINTER(PVOID))
CoGetInterceptorParams = ((1, 'iidIntercepted'), (1, 'punkOuter'), (1, 'iid'), (1, 'ppv'))

#def CLSIDFromProgID(lpszProgID, lpclsid):
#    return CLSIDFromProgID.ctypes_function(lpszProgID, lpclsid)
CLSIDFromProgIDPrototype = WINFUNCTYPE(HRESULT, LPCOLESTR, LPCLSID)
CLSIDFromProgIDParams = ((1, 'lpszProgID'), (1, 'lpclsid'))

#def GetCursorPos(lpPoint):
#    return GetCursorPos.ctypes_function(lpPoint)
GetCursorPosPrototype = WINFUNCTYPE(BOOL, LPPOINT)
GetCursorPosParams = ((1, 'lpPoint'),)

#def WindowFromPoint(Point):
#    return WindowFromPoint.ctypes_function(Point)
WindowFromPointPrototype = WINFUNCTYPE(HWND, POINT)
WindowFromPointParams = ((1, 'Point'),)

#def GetWindowRect(hWnd, lpRect):
#    return GetWindowRect.ctypes_function(hWnd, lpRect)
GetWindowRectPrototype = WINFUNCTYPE(BOOL, HWND, LPRECT)
GetWindowRectParams = ((1, 'hWnd'), (1, 'lpRect'))

#def EnumWindows(lpEnumFunc, lParam):
#    return EnumWindows.ctypes_function(lpEnumFunc, lParam)
EnumWindowsPrototype = WINFUNCTYPE(BOOL, WNDENUMPROC, LPARAM)
EnumWindowsParams = ((1, 'lpEnumFunc'), (1, 'lParam'))

#def GetWindowTextA(hWnd, lpString, nMaxCount):
#    return GetWindowTextA.ctypes_function(hWnd, lpString, nMaxCount)
GetWindowTextAPrototype = WINFUNCTYPE(INT, HWND, LPSTR, INT)
GetWindowTextAParams = ((1, 'hWnd'), (1, 'lpString'), (1, 'nMaxCount'))

#def GetParent(hWnd):
#    return GetParent.ctypes_function(hWnd)
GetParentPrototype = WINFUNCTYPE(HWND, HWND)
GetParentParams = ((1, 'hWnd'),)

#def GetWindowTextW(hWnd, lpString, nMaxCount):
#    return GetWindowTextW.ctypes_function(hWnd, lpString, nMaxCount)
GetWindowTextWPrototype = WINFUNCTYPE(INT, HWND, LPWSTR, INT)
GetWindowTextWParams = ((1, 'hWnd'), (1, 'lpString'), (1, 'nMaxCount'))

#def GetWindowModuleFileNameA(hwnd, pszFileName, cchFileNameMax):
#    return GetWindowModuleFileNameA.ctypes_function(hwnd, pszFileName, cchFileNameMax)
GetWindowModuleFileNameAPrototype = WINFUNCTYPE(UINT, HWND, LPSTR, UINT)
GetWindowModuleFileNameAParams = ((1, 'hwnd'), (1, 'pszFileName'), (1, 'cchFileNameMax'))

#def GetWindowModuleFileNameW(hwnd, pszFileName, cchFileNameMax):
#    return GetWindowModuleFileNameW.ctypes_function(hwnd, pszFileName, cchFileNameMax)
GetWindowModuleFileNameWPrototype = WINFUNCTYPE(UINT, HWND, LPWSTR, UINT)
GetWindowModuleFileNameWParams = ((1, 'hwnd'), (1, 'pszFileName'), (1, 'cchFileNameMax'))

#def EnumChildWindows(hWndParent, lpEnumFunc, lParam):
#    return EnumChildWindows.ctypes_function(hWndParent, lpEnumFunc, lParam)
EnumChildWindowsPrototype = WINFUNCTYPE(BOOL, HWND, WNDENUMPROC, LPARAM)
EnumChildWindowsParams = ((1, 'hWndParent'), (1, 'lpEnumFunc'), (1, 'lParam'))

#def CloseWindow(hWnd):
#    return CloseWindow.ctypes_function(hWnd)
CloseWindowPrototype = WINFUNCTYPE(BOOL, HWND)
CloseWindowParams = ((1, 'hWnd'),)

#def GetDesktopWindow():
#    return GetDesktopWindow.ctypes_function()
GetDesktopWindowPrototype = WINFUNCTYPE(HWND)
GetDesktopWindowParams = ()

#def GetForegroundWindow():
#    return GetForegroundWindow.ctypes_function()
GetForegroundWindowPrototype = WINFUNCTYPE(HWND)
GetForegroundWindowParams = ()

#def BringWindowToTop(hWnd):
#    return BringWindowToTop.ctypes_function(hWnd)
BringWindowToTopPrototype = WINFUNCTYPE(BOOL, HWND)
BringWindowToTopParams = ((1, 'hWnd'),)

#def MoveWindow(hWnd, X, Y, nWidth, nHeight, bRepaint):
#    return MoveWindow.ctypes_function(hWnd, X, Y, nWidth, nHeight, bRepaint)
MoveWindowPrototype = WINFUNCTYPE(BOOL, HWND, INT, INT, INT, INT, BOOL)
MoveWindowParams = ((1, 'hWnd'), (1, 'X'), (1, 'Y'), (1, 'nWidth'), (1, 'nHeight'), (1, 'bRepaint'))

#def SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags):
#    return SetWindowPos.ctypes_function(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags)
SetWindowPosPrototype = WINFUNCTYPE(BOOL, HWND, HWND, INT, INT, INT, INT, UINT)
SetWindowPosParams = ((1, 'hWnd'), (1, 'hWndInsertAfter'), (1, 'X'), (1, 'Y'), (1, 'cx'), (1, 'cy'), (1, 'uFlags'))

#def SetWindowTextA(hWnd, lpString):
#    return SetWindowTextA.ctypes_function(hWnd, lpString)
SetWindowTextAPrototype = WINFUNCTYPE(BOOL, HWND, LPCSTR)
SetWindowTextAParams = ((1, 'hWnd'), (1, 'lpString'))

#def SetWindowTextW(hWnd, lpString):
#    return SetWindowTextW.ctypes_function(hWnd, lpString)
SetWindowTextWPrototype = WINFUNCTYPE(BOOL, HWND, LPWSTR)
SetWindowTextWParams = ((1, 'hWnd'), (1, 'lpString'))

#def RealGetWindowClassA(hwnd, pszType, cchType):
#    return RealGetWindowClassA.ctypes_function(hwnd, pszType, cchType)
RealGetWindowClassAPrototype = WINFUNCTYPE(UINT, HWND, LPCSTR, UINT)
RealGetWindowClassAParams = ((1, 'hwnd'), (1, 'pszType'), (1, 'cchType'))

#def RealGetWindowClassW(hwnd, pszType, cchType):
#    return RealGetWindowClassW.ctypes_function(hwnd, pszType, cchType)
RealGetWindowClassWPrototype = WINFUNCTYPE(UINT, HWND, LPWSTR, UINT)
RealGetWindowClassWParams = ((1, 'hwnd'), (1, 'pszType'), (1, 'cchType'))

#def GetClassInfoExA(hinst, lpszClass, lpwcx):
#    return GetClassInfoExA.ctypes_function(hinst, lpszClass, lpwcx)
GetClassInfoExAPrototype = WINFUNCTYPE(BOOL, HINSTANCE, LPCSTR, LPWNDCLASSEXA)
GetClassInfoExAParams = ((1, 'hinst'), (1, 'lpszClass'), (1, 'lpwcx'))

#def GetClassInfoExW(hinst, lpszClass, lpwcx):
#    return GetClassInfoExW.ctypes_function(hinst, lpszClass, lpwcx)
GetClassInfoExWPrototype = WINFUNCTYPE(BOOL, HINSTANCE, LPCWSTR, LPWNDCLASSEXW)
GetClassInfoExWParams = ((1, 'hinst'), (1, 'lpszClass'), (1, 'lpwcx'))

#def GetClassNameA(hWnd, lpClassName, nMaxCount):
#    return GetClassNameA.ctypes_function(hWnd, lpClassName, nMaxCount)
GetClassNameAPrototype = WINFUNCTYPE(INT, HWND, LPCSTR, INT)
GetClassNameAParams = ((1, 'hWnd'), (1, 'lpClassName'), (1, 'nMaxCount'))

#def GetClassNameW(hWnd, lpClassName, nMaxCount):
#    return GetClassNameW.ctypes_function(hWnd, lpClassName, nMaxCount)
GetClassNameWPrototype = WINFUNCTYPE(INT, HWND, LPWSTR, INT)
GetClassNameWParams = ((1, 'hWnd'), (1, 'lpClassName'), (1, 'nMaxCount'))

#def GetWindowThreadProcessId(hWnd, lpdwProcessId):
#    return GetWindowThreadProcessId.ctypes_function(hWnd, lpdwProcessId)
GetWindowThreadProcessIdPrototype = WINFUNCTYPE(DWORD, HWND, LPDWORD)
GetWindowThreadProcessIdParams = ((1, 'hWnd'), (1, 'lpdwProcessId'))

#def FindWindowA(lpClassName, lpWindowName):
#    return FindWindowA.ctypes_function(lpClassName, lpWindowName)
FindWindowAPrototype = WINFUNCTYPE(HWND, LPCSTR, LPCSTR)
FindWindowAParams = ((1, 'lpClassName'), (1, 'lpWindowName'))

#def FindWindowW(lpClassName, lpWindowName):
#    return FindWindowW.ctypes_function(lpClassName, lpWindowName)
FindWindowWPrototype = WINFUNCTYPE(HWND, LPCWSTR, LPCWSTR)
FindWindowWParams = ((1, 'lpClassName'), (1, 'lpWindowName'))

#def ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd):
#    return ShellExecuteA.ctypes_function(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
ShellExecuteAPrototype = WINFUNCTYPE(HINSTANCE, HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT)
ShellExecuteAParams = ((1, 'hwnd'), (1, 'lpOperation'), (1, 'lpFile'), (1, 'lpParameters'), (1, 'lpDirectory'), (1, 'nShowCmd'))

#def ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd):
#    return ShellExecuteW.ctypes_function(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
ShellExecuteWPrototype = WINFUNCTYPE(HINSTANCE, HWND, LPWSTR, LPWSTR, LPWSTR, LPWSTR, INT)
ShellExecuteWParams = ((1, 'hwnd'), (1, 'lpOperation'), (1, 'lpFile'), (1, 'lpParameters'), (1, 'lpDirectory'), (1, 'nShowCmd'))

#def SHGetPathFromIDListA(pidl, pszPath):
#    return SHGetPathFromIDListA.ctypes_function(pidl, pszPath)
SHGetPathFromIDListAPrototype = WINFUNCTYPE(BOOL, PCIDLIST_ABSOLUTE, LPCSTR)
SHGetPathFromIDListAParams = ((1, 'pidl'), (1, 'pszPath'))

#def SHGetPathFromIDListW(pidl, pszPath):
#    return SHGetPathFromIDListW.ctypes_function(pidl, pszPath)
SHGetPathFromIDListWPrototype = WINFUNCTYPE(BOOL, PCIDLIST_ABSOLUTE, LPWSTR)
SHGetPathFromIDListWParams = ((1, 'pidl'), (1, 'pszPath'))

#def ExitProcess(uExitCode):
#    return ExitProcess.ctypes_function(uExitCode)
ExitProcessPrototype = WINFUNCTYPE(VOID, UINT)
ExitProcessParams = ((1, 'uExitCode'),)

#def TerminateProcess(hProcess, uExitCode):
#    return TerminateProcess.ctypes_function(hProcess, uExitCode)
TerminateProcessPrototype = WINFUNCTYPE(BOOL, HANDLE, UINT)
TerminateProcessParams = ((1, 'hProcess'), (1, 'uExitCode'))

#def GetLastError():
#    return GetLastError.ctypes_function()
GetLastErrorPrototype = WINFUNCTYPE(DWORD)
GetLastErrorParams = ()

#def GetCurrentProcess():
#    return GetCurrentProcess.ctypes_function()
GetCurrentProcessPrototype = WINFUNCTYPE(HANDLE)
GetCurrentProcessParams = ()

#def CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):
#    return CreateFileA.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
CreateFileAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
CreateFileAParams = ((1, 'lpFileName'), (1, 'dwDesiredAccess'), (1, 'dwShareMode'), (1, 'lpSecurityAttributes'), (1, 'dwCreationDisposition'), (1, 'dwFlagsAndAttributes'), (1, 'hTemplateFile'))

#def CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):
#    return CreateFileW.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
CreateFileWPrototype = WINFUNCTYPE(HANDLE, LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)
CreateFileWParams = ((1, 'lpFileName'), (1, 'dwDesiredAccess'), (1, 'dwShareMode'), (1, 'lpSecurityAttributes'), (1, 'dwCreationDisposition'), (1, 'dwFlagsAndAttributes'), (1, 'hTemplateFile'))

#def NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength):
#    return NtCreateFile.ctypes_function(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength)
NtCreateFilePrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG)
NtCreateFileParams = ((1, 'FileHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'IoStatusBlock'), (1, 'AllocationSize'), (1, 'FileAttributes'), (1, 'ShareAccess'), (1, 'CreateDisposition'), (1, 'CreateOptions'), (1, 'EaBuffer'), (1, 'EaLength'))

#def LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle):
#    return LdrLoadDll.ctypes_function(PathToFile, Flags, ModuleFileName, ModuleHandle)
LdrLoadDllPrototype = WINFUNCTYPE(NTSTATUS, LPCWSTR, ULONG, PUNICODE_STRING, PHANDLE)
LdrLoadDllParams = ((1, 'PathToFile'), (1, 'Flags'), (1, 'ModuleFileName'), (1, 'ModuleHandle'))

#def NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength):
#    return NtQuerySystemInformation.ctypes_function(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)
NtQuerySystemInformationPrototype = WINFUNCTYPE(NTSTATUS, SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQuerySystemInformationParams = ((1, 'SystemInformationClass'), (1, 'SystemInformation'), (1, 'SystemInformationLength'), (1, 'ReturnLength'))

#def NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength):
#    return NtQueryInformationProcess.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)
NtQueryInformationProcessPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)
NtQueryInformationProcessParams = ((1, 'ProcessHandle'), (1, 'ProcessInformationClass'), (1, 'ProcessInformation'), (1, 'ProcessInformationLength'), (1, 'ReturnLength'))

#def NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength):
#    return NtSetInformationProcess.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength)
NtSetInformationProcessPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG)
NtSetInformationProcessParams = ((1, 'ProcessHandle'), (1, 'ProcessInformationClass'), (1, 'ProcessInformation'), (1, 'ProcessInformationLength'))

#def NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength):
#    return NtQueryVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength)
NtQueryVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T)
NtQueryVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'MemoryInformationClass'), (1, 'MemoryInformation'), (1, 'MemoryInformationLength'), (1, 'ReturnLength'))

#def NtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass):
#    return NtQueryVolumeInformationFile.ctypes_function(FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass)
NtQueryVolumeInformationFilePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FS_INFORMATION_CLASS)
NtQueryVolumeInformationFileParams = ((1, 'FileHandle'), (1, 'IoStatusBlock'), (1, 'FsInformation'), (1, 'Length'), (1, 'FsInformationClass'))

#def NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3):
#    return NtCreateThreadEx.ctypes_function(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3)
NtCreateThreadExPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, DWORD, DWORD, DWORD, LPVOID)
NtCreateThreadExParams = ((1, 'ThreadHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'ProcessHandle'), (1, 'lpStartAddress'), (1, 'lpParameter'), (1, 'CreateSuspended'), (1, 'dwStackSize'), (1, 'Unknown1'), (1, 'Unknown2'), (1, 'Unknown3'))

#def NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength):
#    return NtQueryInformationThread.ctypes_function(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)
NtQueryInformationThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQueryInformationThreadParams = ((1, 'ThreadHandle'), (1, 'ThreadInformationClass'), (1, 'ThreadInformation'), (1, 'ThreadInformationLength'), (1, 'ReturnLength'))

#def GetExitCodeThread(hThread, lpExitCode):
#    return GetExitCodeThread.ctypes_function(hThread, lpExitCode)
GetExitCodeThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD)
GetExitCodeThreadParams = ((1, 'hThread'), (1, 'lpExitCode'))

#def GetExitCodeProcess(hProcess, lpExitCode):
#    return GetExitCodeProcess.ctypes_function(hProcess, lpExitCode)
GetExitCodeProcessPrototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD)
GetExitCodeProcessParams = ((1, 'hProcess'), (1, 'lpExitCode'))

#def SetPriorityClass(hProcess, dwPriorityClass):
#    return SetPriorityClass.ctypes_function(hProcess, dwPriorityClass)
SetPriorityClassPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD)
SetPriorityClassParams = ((1, 'hProcess'), (1, 'dwPriorityClass'))

#def GetPriorityClass(hProcess):
#    return GetPriorityClass.ctypes_function(hProcess)
GetPriorityClassPrototype = WINFUNCTYPE(DWORD, HANDLE)
GetPriorityClassParams = ((1, 'hProcess'),)

#def VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect):
#    return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)
VirtualAllocPrototype = WINFUNCTYPE(LPVOID, LPVOID, SIZE_T, DWORD, DWORD)
VirtualAllocParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flAllocationType'), (1, 'flProtect'))

#def VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect):
#    return VirtualAllocEx.ctypes_function(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
VirtualAllocExPrototype = WINFUNCTYPE(LPVOID, HANDLE, LPVOID, SIZE_T, DWORD, DWORD)
VirtualAllocExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'flAllocationType'), (1, 'flProtect'))

#def NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect):
#    return NtAllocateVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
NtAllocateVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, POINTER(PVOID), ULONG_PTR, PSIZE_T, ULONG, ULONG)
NtAllocateVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'ZeroBits'), (1, 'RegionSize'), (1, 'AllocationType'), (1, 'Protect'))

#def NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection):
#    return NtProtectVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection)
NtProtectVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, POINTER(PVOID), PULONG, ULONG, PULONG)
NtProtectVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'NumberOfBytesToProtect'), (1, 'NewAccessProtection'), (1, 'OldAccessProtection'))

#def VirtualFree(lpAddress, dwSize, dwFreeType):
#    return VirtualFree.ctypes_function(lpAddress, dwSize, dwFreeType)
VirtualFreePrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD)
VirtualFreeParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'dwFreeType'))

#def VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType):
#    return VirtualFreeEx.ctypes_function(hProcess, lpAddress, dwSize, dwFreeType)
VirtualFreeExPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, SIZE_T, DWORD)
VirtualFreeExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'dwFreeType'))

#def NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType):
#    return NtFreeVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, RegionSize, FreeType)
NtFreeVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, POINTER(PVOID), PSIZE_T, ULONG)
NtFreeVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'RegionSize'), (1, 'FreeType'))

#def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect):
#    return VirtualProtect.ctypes_function(lpAddress, dwSize, flNewProtect, lpflOldProtect)
VirtualProtectPrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD, PDWORD)
VirtualProtectParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flNewProtect'), (1, 'lpflOldProtect'))

#def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect):
#    return VirtualProtectEx.ctypes_function(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)
VirtualProtectExPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, SIZE_T, DWORD, PDWORD)
VirtualProtectExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'flNewProtect'), (1, 'lpflOldProtect'))

#def VirtualQuery(lpAddress, lpBuffer, dwLength):
#    return VirtualQuery.ctypes_function(lpAddress, lpBuffer, dwLength)
VirtualQueryPrototype = WINFUNCTYPE(DWORD, LPCVOID, PMEMORY_BASIC_INFORMATION, DWORD)
VirtualQueryParams = ((1, 'lpAddress'), (1, 'lpBuffer'), (1, 'dwLength'))

#def VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength):
#    return VirtualQueryEx.ctypes_function(hProcess, lpAddress, lpBuffer, dwLength)
VirtualQueryExPrototype = WINFUNCTYPE(SIZE_T, HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T)
VirtualQueryExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'lpBuffer'), (1, 'dwLength'))

#def QueryWorkingSet(hProcess, pv, cb):
#    return QueryWorkingSet.ctypes_function(hProcess, pv, cb)
QueryWorkingSetPrototype = WINFUNCTYPE(BOOL, HANDLE, PVOID, DWORD)
QueryWorkingSetParams = ((1, 'hProcess'), (1, 'pv'), (1, 'cb'))

#def QueryWorkingSetEx(hProcess, pv, cb):
#    return QueryWorkingSetEx.ctypes_function(hProcess, pv, cb)
QueryWorkingSetExPrototype = WINFUNCTYPE(BOOL, HANDLE, PVOID, DWORD)
QueryWorkingSetExParams = ((1, 'hProcess'), (1, 'pv'), (1, 'cb'))

#def GetModuleFileNameA(hModule, lpFilename, nSize):
#    return GetModuleFileNameA.ctypes_function(hModule, lpFilename, nSize)
GetModuleFileNameAPrototype = WINFUNCTYPE(DWORD, HMODULE, LPSTR, DWORD)
GetModuleFileNameAParams = ((1, 'hModule'), (1, 'lpFilename'), (1, 'nSize'))

#def GetModuleFileNameW(hModule, lpFilename, nSize):
#    return GetModuleFileNameW.ctypes_function(hModule, lpFilename, nSize)
GetModuleFileNameWPrototype = WINFUNCTYPE(DWORD, HMODULE, LPWSTR, DWORD)
GetModuleFileNameWParams = ((1, 'hModule'), (1, 'lpFilename'), (1, 'nSize'))

#def CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
#    return CreateThread.ctypes_function(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)
CreateThreadPrototype = WINFUNCTYPE(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)
CreateThreadParams = ((1, 'lpThreadAttributes'), (1, 'dwStackSize'), (1, 'lpStartAddress'), (1, 'lpParameter'), (1, 'dwCreationFlags'), (1, 'lpThreadId'))

#def CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):
#    return CreateRemoteThread.ctypes_function(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)
CreateRemoteThreadPrototype = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)
CreateRemoteThreadParams = ((1, 'hProcess'), (1, 'lpThreadAttributes'), (1, 'dwStackSize'), (1, 'lpStartAddress'), (1, 'lpParameter'), (1, 'dwCreationFlags'), (1, 'lpThreadId'))

#def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect):
#    return VirtualProtect.ctypes_function(lpAddress, dwSize, flNewProtect, lpflOldProtect)
VirtualProtectPrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD, PDWORD)
VirtualProtectParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'flNewProtect'), (1, 'lpflOldProtect'))

#def CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
#    return CreateProcessA.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
CreateProcessAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)
CreateProcessAParams = ((1, 'lpApplicationName'), (1, 'lpCommandLine'), (1, 'lpProcessAttributes'), (1, 'lpThreadAttributes'), (1, 'bInheritHandles'), (1, 'dwCreationFlags'), (1, 'lpEnvironment'), (1, 'lpCurrentDirectory'), (1, 'lpStartupInfo'), (1, 'lpProcessInformation'))

#def CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
#    return CreateProcessW.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
CreateProcessWPrototype = WINFUNCTYPE(BOOL, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION)
CreateProcessWParams = ((1, 'lpApplicationName'), (1, 'lpCommandLine'), (1, 'lpProcessAttributes'), (1, 'lpThreadAttributes'), (1, 'bInheritHandles'), (1, 'dwCreationFlags'), (1, 'lpEnvironment'), (1, 'lpCurrentDirectory'), (1, 'lpStartupInfo'), (1, 'lpProcessInformation'))

#def CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
#    return CreateProcessAsUserA.ctypes_function(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
CreateProcessAsUserAPrototype = WINFUNCTYPE(BOOL, HANDLE, LPSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)
CreateProcessAsUserAParams = ((1, 'hToken'), (1, 'lpApplicationName'), (1, 'lpCommandLine'), (1, 'lpProcessAttributes'), (1, 'lpThreadAttributes'), (1, 'bInheritHandles'), (1, 'dwCreationFlags'), (1, 'lpEnvironment'), (1, 'lpCurrentDirectory'), (1, 'lpStartupInfo'), (1, 'lpProcessInformation'))

#def CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
#    return CreateProcessAsUserW.ctypes_function(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
CreateProcessAsUserWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION)
CreateProcessAsUserWParams = ((1, 'hToken'), (1, 'lpApplicationName'), (1, 'lpCommandLine'), (1, 'lpProcessAttributes'), (1, 'lpThreadAttributes'), (1, 'bInheritHandles'), (1, 'dwCreationFlags'), (1, 'lpEnvironment'), (1, 'lpCurrentDirectory'), (1, 'lpStartupInfo'), (1, 'lpProcessInformation'))

#def GetThreadContext(hThread, lpContext):
#    return GetThreadContext.ctypes_function(hThread, lpContext)
GetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
GetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

#def NtGetContextThread(hThread, lpContext):
#    return NtGetContextThread.ctypes_function(hThread, lpContext)
NtGetContextThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, LPCONTEXT)
NtGetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

#def SetThreadContext(hThread, lpContext):
#    return SetThreadContext.ctypes_function(hThread, lpContext)
SetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
SetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

#def NtSetContextThread(hThread, lpContext):
#    return NtSetContextThread.ctypes_function(hThread, lpContext)
NtSetContextThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, LPCONTEXT)
NtSetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

#def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
#    return OpenThread.ctypes_function(dwDesiredAccess, bInheritHandle, dwThreadId)
OpenThreadPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, DWORD)
OpenThreadParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'dwThreadId'))

#def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
#    return OpenProcess.ctypes_function(dwDesiredAccess, bInheritHandle, dwProcessId)
OpenProcessPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, DWORD)
OpenProcessParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'dwProcessId'))

#def CloseHandle(hObject):
#    return CloseHandle.ctypes_function(hObject)
CloseHandlePrototype = WINFUNCTYPE(BOOL, HANDLE)
CloseHandleParams = ((1, 'hObject'),)

#def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
#    return ReadProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
ReadProcessMemoryPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCVOID, LPVOID, SIZE_T, POINTER(SIZE_T))
ReadProcessMemoryParams = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesRead'))

#def NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
#    return NtWow64ReadVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
NtWow64ReadVirtualMemory64Prototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG64, LPVOID, ULONG64, PULONG64)
NtWow64ReadVirtualMemory64Params = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesRead'))

#def NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
#    return NtReadVirtualMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
NtReadVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID, LPVOID, ULONG, PULONG)
NtReadVirtualMemoryParams = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesRead'))

#def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten):
#    return WriteProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
WriteProcessMemoryPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemoryParams = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesWritten'))

#def NtWow64WriteVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten):
#    return NtWow64WriteVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
NtWow64WriteVirtualMemory64Prototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG64, LPVOID, ULONG64, PULONG64)
NtWow64WriteVirtualMemory64Params = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesWritten'))

#def NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten):
#    return NtWriteVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)
NtWriteVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID, PVOID, ULONG, PULONG)
NtWriteVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'Buffer'), (1, 'NumberOfBytesToWrite'), (1, 'NumberOfBytesWritten'))

#def CreateToolhelp32Snapshot(dwFlags, th32ProcessID):
#    return CreateToolhelp32Snapshot.ctypes_function(dwFlags, th32ProcessID)
CreateToolhelp32SnapshotPrototype = WINFUNCTYPE(HANDLE, DWORD, DWORD)
CreateToolhelp32SnapshotParams = ((1, 'dwFlags'), (1, 'th32ProcessID'))

#def Thread32First(hSnapshot, lpte):
#    return Thread32First.ctypes_function(hSnapshot, lpte)
Thread32FirstPrototype = WINFUNCTYPE(BOOL, HANDLE, LPTHREADENTRY32)
Thread32FirstParams = ((1, 'hSnapshot'), (1, 'lpte'))

#def Thread32Next(hSnapshot, lpte):
#    return Thread32Next.ctypes_function(hSnapshot, lpte)
Thread32NextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPTHREADENTRY32)
Thread32NextParams = ((1, 'hSnapshot'), (1, 'lpte'))

#def Process32First(hSnapshot, lppe):
#    return Process32First.ctypes_function(hSnapshot, lppe)
Process32FirstPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32)
Process32FirstParams = ((1, 'hSnapshot'), (1, 'lppe'))

#def Process32Next(hSnapshot, lppe):
#    return Process32Next.ctypes_function(hSnapshot, lppe)
Process32NextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32)
Process32NextParams = ((1, 'hSnapshot'), (1, 'lppe'))

#def Process32FirstW(hSnapshot, lppe):
#    return Process32FirstW.ctypes_function(hSnapshot, lppe)
Process32FirstWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32W)
Process32FirstWParams = ((1, 'hSnapshot'), (1, 'lppe'))

#def Process32NextW(hSnapshot, lppe):
#    return Process32NextW.ctypes_function(hSnapshot, lppe)
Process32NextWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPPROCESSENTRY32W)
Process32NextWParams = ((1, 'hSnapshot'), (1, 'lppe'))

#def GetProcAddress(hModule, lpProcName):
#    return GetProcAddress.ctypes_function(hModule, lpProcName)
GetProcAddressPrototype = WINFUNCTYPE(FARPROC, HMODULE, LPCSTR)
GetProcAddressParams = ((1, 'hModule'), (1, 'lpProcName'))

#def LoadLibraryA(lpFileName):
#    return LoadLibraryA.ctypes_function(lpFileName)
LoadLibraryAPrototype = WINFUNCTYPE(HMODULE, LPCSTR)
LoadLibraryAParams = ((1, 'lpFileName'),)

#def LoadLibraryW(lpFileName):
#    return LoadLibraryW.ctypes_function(lpFileName)
LoadLibraryWPrototype = WINFUNCTYPE(HMODULE, LPCWSTR)
LoadLibraryWParams = ((1, 'lpFileName'),)

#def LoadLibraryExA(lpLibFileName, hFile, dwFlags):
#    return LoadLibraryExA.ctypes_function(lpLibFileName, hFile, dwFlags)
LoadLibraryExAPrototype = WINFUNCTYPE(HMODULE, LPCSTR, HANDLE, DWORD)
LoadLibraryExAParams = ((1, 'lpLibFileName'), (1, 'hFile'), (1, 'dwFlags'))

#def LoadLibraryExW(lpLibFileName, hFile, dwFlags):
#    return LoadLibraryExW.ctypes_function(lpLibFileName, hFile, dwFlags)
LoadLibraryExWPrototype = WINFUNCTYPE(HMODULE, LPCWSTR, HANDLE, DWORD)
LoadLibraryExWParams = ((1, 'lpLibFileName'), (1, 'hFile'), (1, 'dwFlags'))

#def FreeLibrary(hLibModule):
#    return FreeLibrary.ctypes_function(hLibModule)
FreeLibraryPrototype = WINFUNCTYPE(BOOL, HMODULE)
FreeLibraryParams = ((1, 'hLibModule'),)

#def OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle):
#    return OpenProcessToken.ctypes_function(ProcessHandle, DesiredAccess, TokenHandle)
OpenProcessTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, PHANDLE)
OpenProcessTokenParams = ((1, 'ProcessHandle'), (1, 'DesiredAccess'), (1, 'TokenHandle'))

#def DuplicateToken(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle):
#    return DuplicateToken.ctypes_function(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle)
DuplicateTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, SECURITY_IMPERSONATION_LEVEL, PHANDLE)
DuplicateTokenParams = ((1, 'ExistingTokenHandle'), (1, 'ImpersonationLevel'), (1, 'DuplicateTokenHandle'))

#def DuplicateTokenEx(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken):
#    return DuplicateTokenEx.ctypes_function(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken)
DuplicateTokenExPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE)
DuplicateTokenExParams = ((1, 'hExistingToken'), (1, 'dwDesiredAccess'), (1, 'lpTokenAttributes'), (1, 'ImpersonationLevel'), (1, 'TokenType'), (1, 'phNewToken'))

#def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle):
#    return OpenThreadToken.ctypes_function(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle)
OpenThreadTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, BOOL, PHANDLE)
OpenThreadTokenParams = ((1, 'ThreadHandle'), (1, 'DesiredAccess'), (1, 'OpenAsSelf'), (1, 'TokenHandle'))

#def SetThreadToken(Thread, Token):
#    return SetThreadToken.ctypes_function(Thread, Token)
SetThreadTokenPrototype = WINFUNCTYPE(BOOL, PHANDLE, HANDLE)
SetThreadTokenParams = ((1, 'Thread'), (1, 'Token'))

#def LookupPrivilegeValueA(lpSystemName, lpName, lpLuid):
#    return LookupPrivilegeValueA.ctypes_function(lpSystemName, lpName, lpLuid)
LookupPrivilegeValueAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPCSTR, PLUID)
LookupPrivilegeValueAParams = ((1, 'lpSystemName'), (1, 'lpName'), (1, 'lpLuid'))

#def LookupPrivilegeValueW(lpSystemName, lpName, lpLuid):
#    return LookupPrivilegeValueW.ctypes_function(lpSystemName, lpName, lpLuid)
LookupPrivilegeValueWPrototype = WINFUNCTYPE(BOOL, LPCWSTR, LPCWSTR, PLUID)
LookupPrivilegeValueWParams = ((1, 'lpSystemName'), (1, 'lpName'), (1, 'lpLuid'))

#def LookupPrivilegeNameA(lpSystemName, lpLuid, lpName, cchName):
#    return LookupPrivilegeNameA.ctypes_function(lpSystemName, lpLuid, lpName, cchName)
LookupPrivilegeNameAPrototype = WINFUNCTYPE(BOOL, LPCSTR, PLUID, LPCSTR, LPDWORD)
LookupPrivilegeNameAParams = ((1, 'lpSystemName'), (1, 'lpLuid'), (1, 'lpName'), (1, 'cchName'))

#def LookupPrivilegeNameW(lpSystemName, lpLuid, lpName, cchName):
#    return LookupPrivilegeNameW.ctypes_function(lpSystemName, lpLuid, lpName, cchName)
LookupPrivilegeNameWPrototype = WINFUNCTYPE(BOOL, LPCWSTR, PLUID, LPCWSTR, LPDWORD)
LookupPrivilegeNameWParams = ((1, 'lpSystemName'), (1, 'lpLuid'), (1, 'lpName'), (1, 'cchName'))

#def AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength):
#    return AdjustTokenPrivileges.ctypes_function(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength)
AdjustTokenPrivilegesPrototype = WINFUNCTYPE(BOOL, HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD)
AdjustTokenPrivilegesParams = ((1, 'TokenHandle'), (1, 'DisableAllPrivileges'), (1, 'NewState'), (1, 'BufferLength'), (1, 'PreviousState'), (1, 'ReturnLength'))

#def FindResourceA(hModule, lpName, lpType):
#    return FindResourceA.ctypes_function(hModule, lpName, lpType)
FindResourceAPrototype = WINFUNCTYPE(HRSRC, HMODULE, LPCSTR, LPCSTR)
FindResourceAParams = ((1, 'hModule'), (1, 'lpName'), (1, 'lpType'))

#def FindResourceW(hModule, lpName, lpType):
#    return FindResourceW.ctypes_function(hModule, lpName, lpType)
FindResourceWPrototype = WINFUNCTYPE(HRSRC, HMODULE, LPCWSTR, LPCWSTR)
FindResourceWParams = ((1, 'hModule'), (1, 'lpName'), (1, 'lpType'))

#def SizeofResource(hModule, hResInfo):
#    return SizeofResource.ctypes_function(hModule, hResInfo)
SizeofResourcePrototype = WINFUNCTYPE(DWORD, HMODULE, HRSRC)
SizeofResourceParams = ((1, 'hModule'), (1, 'hResInfo'))

#def LoadResource(hModule, hResInfo):
#    return LoadResource.ctypes_function(hModule, hResInfo)
LoadResourcePrototype = WINFUNCTYPE(HGLOBAL, HMODULE, HRSRC)
LoadResourceParams = ((1, 'hModule'), (1, 'hResInfo'))

#def LockResource(hResData):
#    return LockResource.ctypes_function(hResData)
LockResourcePrototype = WINFUNCTYPE(LPVOID, HGLOBAL)
LockResourceParams = ((1, 'hResData'),)

#def GetVersionExA(lpVersionInformation):
#    return GetVersionExA.ctypes_function(lpVersionInformation)
GetVersionExAPrototype = WINFUNCTYPE(BOOL, LPOSVERSIONINFOA)
GetVersionExAParams = ((1, 'lpVersionInformation'),)

#def GetVersionExW(lpVersionInformation):
#    return GetVersionExW.ctypes_function(lpVersionInformation)
GetVersionExWPrototype = WINFUNCTYPE(BOOL, LPOSVERSIONINFOW)
GetVersionExWParams = ((1, 'lpVersionInformation'),)

#def GetVersion():
#    return GetVersion.ctypes_function()
GetVersionPrototype = WINFUNCTYPE(DWORD)
GetVersionParams = ()

#def GetCurrentThread():
#    return GetCurrentThread.ctypes_function()
GetCurrentThreadPrototype = WINFUNCTYPE(HANDLE)
GetCurrentThreadParams = ()

#def GetCurrentThreadId():
#    return GetCurrentThreadId.ctypes_function()
GetCurrentThreadIdPrototype = WINFUNCTYPE(DWORD)
GetCurrentThreadIdParams = ()

#def GetCurrentProcessorNumber():
#    return GetCurrentProcessorNumber.ctypes_function()
GetCurrentProcessorNumberPrototype = WINFUNCTYPE(DWORD)
GetCurrentProcessorNumberParams = ()

#def AllocConsole():
#    return AllocConsole.ctypes_function()
AllocConsolePrototype = WINFUNCTYPE(BOOL)
AllocConsoleParams = ()

#def FreeConsole():
#    return FreeConsole.ctypes_function()
FreeConsolePrototype = WINFUNCTYPE(BOOL)
FreeConsoleParams = ()

#def GetStdHandle(nStdHandle):
#    return GetStdHandle.ctypes_function(nStdHandle)
GetStdHandlePrototype = WINFUNCTYPE(HANDLE, DWORD)
GetStdHandleParams = ((1, 'nStdHandle'),)

#def SetStdHandle(nStdHandle, hHandle):
#    return SetStdHandle.ctypes_function(nStdHandle, hHandle)
SetStdHandlePrototype = WINFUNCTYPE(BOOL, DWORD, HANDLE)
SetStdHandleParams = ((1, 'nStdHandle'), (1, 'hHandle'))

#def SetThreadAffinityMask(hThread, dwThreadAffinityMask):
#    return SetThreadAffinityMask.ctypes_function(hThread, dwThreadAffinityMask)
SetThreadAffinityMaskPrototype = WINFUNCTYPE(DWORD, HANDLE, DWORD)
SetThreadAffinityMaskParams = ((1, 'hThread'), (1, 'dwThreadAffinityMask'))

#def ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):
#    return ReadFile.ctypes_function(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
ReadFilePrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
ReadFileParams = ((1, 'hFile'), (1, 'lpBuffer'), (1, 'nNumberOfBytesToRead'), (1, 'lpNumberOfBytesRead'), (1, 'lpOverlapped'))

#def WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
#    return WriteFile.ctypes_function(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)
WriteFilePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)
WriteFileParams = ((1, 'hFile'), (1, 'lpBuffer'), (1, 'nNumberOfBytesToWrite'), (1, 'lpNumberOfBytesWritten'), (1, 'lpOverlapped'))

#def GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved):
#    return GetExtendedTcpTable.ctypes_function(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)
GetExtendedTcpTablePrototype = WINFUNCTYPE(DWORD, PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG)
GetExtendedTcpTableParams = ((1, 'pTcpTable'), (1, 'pdwSize'), (1, 'bOrder'), (1, 'ulAf'), (1, 'TableClass'), (1, 'Reserved'))

#def GetExtendedUdpTable(pUdpTable, pdwSize, bOrder, ulAf, TableClass, Reserved):
#    return GetExtendedUdpTable.ctypes_function(pUdpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)
GetExtendedUdpTablePrototype = WINFUNCTYPE(DWORD, PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG)
GetExtendedUdpTableParams = ((1, 'pUdpTable'), (1, 'pdwSize'), (1, 'bOrder'), (1, 'ulAf'), (1, 'TableClass'), (1, 'Reserved'))

#def SetTcpEntry(pTcpRow):
#    return SetTcpEntry.ctypes_function(pTcpRow)
SetTcpEntryPrototype = WINFUNCTYPE(DWORD, PMIB_TCPROW)
SetTcpEntryParams = ((1, 'pTcpRow'),)

#def AddVectoredContinueHandler(FirstHandler, VectoredHandler):
#    return AddVectoredContinueHandler.ctypes_function(FirstHandler, VectoredHandler)
AddVectoredContinueHandlerPrototype = WINFUNCTYPE(PVOID, ULONG, PVECTORED_EXCEPTION_HANDLER)
AddVectoredContinueHandlerParams = ((1, 'FirstHandler'), (1, 'VectoredHandler'))

#def AddVectoredExceptionHandler(FirstHandler, VectoredHandler):
#    return AddVectoredExceptionHandler.ctypes_function(FirstHandler, VectoredHandler)
AddVectoredExceptionHandlerPrototype = WINFUNCTYPE(PVOID, ULONG, PVECTORED_EXCEPTION_HANDLER)
AddVectoredExceptionHandlerParams = ((1, 'FirstHandler'), (1, 'VectoredHandler'))

#def TerminateThread(hThread, dwExitCode):
#    return TerminateThread.ctypes_function(hThread, dwExitCode)
TerminateThreadPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD)
TerminateThreadParams = ((1, 'hThread'), (1, 'dwExitCode'))

#def ExitThread(dwExitCode):
#    return ExitThread.ctypes_function(dwExitCode)
ExitThreadPrototype = WINFUNCTYPE(VOID, DWORD)
ExitThreadParams = ((1, 'dwExitCode'),)

#def RemoveVectoredExceptionHandler(Handler):
#    return RemoveVectoredExceptionHandler.ctypes_function(Handler)
RemoveVectoredExceptionHandlerPrototype = WINFUNCTYPE(ULONG, PVOID)
RemoveVectoredExceptionHandlerParams = ((1, 'Handler'),)

#def ResumeThread(hThread):
#    return ResumeThread.ctypes_function(hThread)
ResumeThreadPrototype = WINFUNCTYPE(DWORD, HANDLE)
ResumeThreadParams = ((1, 'hThread'),)

#def SuspendThread(hThread):
#    return SuspendThread.ctypes_function(hThread)
SuspendThreadPrototype = WINFUNCTYPE(DWORD, HANDLE)
SuspendThreadParams = ((1, 'hThread'),)

#def WaitForSingleObject(hHandle, dwMilliseconds):
#    return WaitForSingleObject.ctypes_function(hHandle, dwMilliseconds)
WaitForSingleObjectPrototype = WINFUNCTYPE(DWORD, HANDLE, DWORD)
WaitForSingleObjectParams = ((1, 'hHandle'), (1, 'dwMilliseconds'))

#def GetThreadId(Thread):
#    return GetThreadId.ctypes_function(Thread)
GetThreadIdPrototype = WINFUNCTYPE(DWORD, HANDLE)
GetThreadIdParams = ((1, 'Thread'),)

#def LoadLibraryExA(lpFileName, hFile, dwFlags):
#    return LoadLibraryExA.ctypes_function(lpFileName, hFile, dwFlags)
LoadLibraryExAPrototype = WINFUNCTYPE(HMODULE, LPCSTR, HANDLE, DWORD)
LoadLibraryExAParams = ((1, 'lpFileName'), (1, 'hFile'), (1, 'dwFlags'))

#def LoadLibraryExW(lpFileName, hFile, dwFlags):
#    return LoadLibraryExW.ctypes_function(lpFileName, hFile, dwFlags)
LoadLibraryExWPrototype = WINFUNCTYPE(HMODULE, LPCWSTR, HANDLE, DWORD)
LoadLibraryExWParams = ((1, 'lpFileName'), (1, 'hFile'), (1, 'dwFlags'))

#def SymInitialize(hProcess, UserSearchPath, fInvadeProcess):
#    return SymInitialize.ctypes_function(hProcess, UserSearchPath, fInvadeProcess)
SymInitializePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCSTR, BOOL)
SymInitializeParams = ((1, 'hProcess'), (1, 'UserSearchPath'), (1, 'fInvadeProcess'))

#def SymFromName(hProcess, Name, Symbol):
#    return SymFromName.ctypes_function(hProcess, Name, Symbol)
SymFromNamePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCSTR, PSYMBOL_INFO)
SymFromNameParams = ((1, 'hProcess'), (1, 'Name'), (1, 'Symbol'))

#def SymLoadModuleEx(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
#    return SymLoadModuleEx.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)
SymLoadModuleExPrototype = WINFUNCTYPE(DWORD64, HANDLE, HANDLE, LPCSTR, LPCSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD)
SymLoadModuleExParams = ((1, 'hProcess'), (1, 'hFile'), (1, 'ImageName'), (1, 'ModuleName'), (1, 'BaseOfDll'), (1, 'DllSize'), (1, 'Data'), (1, 'Flags'))

#def SymSetOptions(SymOptions):
#    return SymSetOptions.ctypes_function(SymOptions)
SymSetOptionsPrototype = WINFUNCTYPE(DWORD, DWORD)
SymSetOptionsParams = ((1, 'SymOptions'),)

#def SymGetTypeInfo(hProcess, ModBase, TypeId, GetType, pInfo):
#    return SymGetTypeInfo.ctypes_function(hProcess, ModBase, TypeId, GetType, pInfo)
SymGetTypeInfoPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64, ULONG, IMAGEHLP_SYMBOL_TYPE_INFO, PVOID)
SymGetTypeInfoParams = ((1, 'hProcess'), (1, 'ModBase'), (1, 'TypeId'), (1, 'GetType'), (1, 'pInfo'))

#def DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped):
#    return DeviceIoControl.ctypes_function(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)
DeviceIoControlPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
DeviceIoControlParams = ((1, 'hDevice'), (1, 'dwIoControlCode'), (1, 'lpInBuffer'), (1, 'nInBufferSize'), (1, 'lpOutBuffer'), (1, 'nOutBufferSize'), (1, 'lpBytesReturned'), (1, 'lpOverlapped'))

#def GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength):
#    return GetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength)
GetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD)
GetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'), (1, 'ReturnLength'))

#def RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult):
#    return RegOpenKeyExA.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)
RegOpenKeyExAPrototype = WINFUNCTYPE(LONG, HKEY, LPCSTR, DWORD, REGSAM, PHKEY)
RegOpenKeyExAParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'ulOptions'), (1, 'samDesired'), (1, 'phkResult'))

#def RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult):
#    return RegOpenKeyExW.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)
RegOpenKeyExWPrototype = WINFUNCTYPE(LONG, HKEY, LPWSTR, DWORD, REGSAM, PHKEY)
RegOpenKeyExWParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'ulOptions'), (1, 'samDesired'), (1, 'phkResult'))

#def RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
#    return RegGetValueA.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
RegGetValueAPrototype = WINFUNCTYPE(LONG, HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD)
RegGetValueAParams = ((1, 'hkey'), (1, 'lpSubKey'), (1, 'lpValue'), (1, 'dwFlags'), (1, 'pdwType'), (1, 'pvData'), (1, 'pcbData'))

#def RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
#    return RegGetValueW.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
RegGetValueWPrototype = WINFUNCTYPE(LONG, HKEY, LPWSTR, LPWSTR, DWORD, LPDWORD, PVOID, LPDWORD)
RegGetValueWParams = ((1, 'hkey'), (1, 'lpSubKey'), (1, 'lpValue'), (1, 'dwFlags'), (1, 'pdwType'), (1, 'pvData'), (1, 'pcbData'))

#def RegCloseKey(hKey):
#    return RegCloseKey.ctypes_function(hKey)
RegCloseKeyPrototype = WINFUNCTYPE(LONG, HKEY)
RegCloseKeyParams = ((1, 'hKey'),)

#def Wow64DisableWow64FsRedirection(OldValue):
#    return Wow64DisableWow64FsRedirection.ctypes_function(OldValue)
Wow64DisableWow64FsRedirectionPrototype = WINFUNCTYPE(BOOL, POINTER(PVOID))
Wow64DisableWow64FsRedirectionParams = ((1, 'OldValue'),)

#def Wow64RevertWow64FsRedirection(OldValue):
#    return Wow64RevertWow64FsRedirection.ctypes_function(OldValue)
Wow64RevertWow64FsRedirectionPrototype = WINFUNCTYPE(BOOL, PVOID)
Wow64RevertWow64FsRedirectionParams = ((1, 'OldValue'),)

#def Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection):
#    return Wow64EnableWow64FsRedirection.ctypes_function(Wow64FsEnableRedirection)
Wow64EnableWow64FsRedirectionPrototype = WINFUNCTYPE(BOOLEAN, BOOLEAN)
Wow64EnableWow64FsRedirectionParams = ((1, 'Wow64FsEnableRedirection'),)

#def Wow64GetThreadContext(hThread, lpContext):
#    return Wow64GetThreadContext.ctypes_function(hThread, lpContext)
Wow64GetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, PWOW64_CONTEXT)
Wow64GetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

#def SetConsoleCtrlHandler(HandlerRoutine, Add):
#    return SetConsoleCtrlHandler.ctypes_function(HandlerRoutine, Add)
SetConsoleCtrlHandlerPrototype = WINFUNCTYPE(BOOL, PHANDLER_ROUTINE, BOOL)
SetConsoleCtrlHandlerParams = ((1, 'HandlerRoutine'), (1, 'Add'))

#def WinVerifyTrust(hwnd, pgActionID, pWVTData):
#    return WinVerifyTrust.ctypes_function(hwnd, pgActionID, pWVTData)
WinVerifyTrustPrototype = WINFUNCTYPE(LONG, HWND, POINTER(GUID), LPVOID)
WinVerifyTrustParams = ((1, 'hwnd'), (1, 'pgActionID'), (1, 'pWVTData'))

#def GlobalAlloc(uFlags, dwBytes):
#    return GlobalAlloc.ctypes_function(uFlags, dwBytes)
GlobalAllocPrototype = WINFUNCTYPE(HGLOBAL, UINT, SIZE_T)
GlobalAllocParams = ((1, 'uFlags'), (1, 'dwBytes'))

#def GlobalFree(hMem):
#    return GlobalFree.ctypes_function(hMem)
GlobalFreePrototype = WINFUNCTYPE(HGLOBAL, HGLOBAL)
GlobalFreeParams = ((1, 'hMem'),)

#def GlobalUnlock(hMem):
#    return GlobalUnlock.ctypes_function(hMem)
GlobalUnlockPrototype = WINFUNCTYPE(BOOL, HGLOBAL)
GlobalUnlockParams = ((1, 'hMem'),)

#def GlobalLock(hMem):
#    return GlobalLock.ctypes_function(hMem)
GlobalLockPrototype = WINFUNCTYPE(LPVOID, HGLOBAL)
GlobalLockParams = ((1, 'hMem'),)

#def OpenClipboard(hWndNewOwner):
#    return OpenClipboard.ctypes_function(hWndNewOwner)
OpenClipboardPrototype = WINFUNCTYPE(BOOL, HWND)
OpenClipboardParams = ((1, 'hWndNewOwner'),)

#def EmptyClipboard():
#    return EmptyClipboard.ctypes_function()
EmptyClipboardPrototype = WINFUNCTYPE(BOOL)
EmptyClipboardParams = ()

#def CloseClipboard():
#    return CloseClipboard.ctypes_function()
CloseClipboardPrototype = WINFUNCTYPE(BOOL)
CloseClipboardParams = ()

#def SetClipboardData(uFormat, hMem):
#    return SetClipboardData.ctypes_function(uFormat, hMem)
SetClipboardDataPrototype = WINFUNCTYPE(HANDLE, UINT, HANDLE)
SetClipboardDataParams = ((1, 'uFormat'), (1, 'hMem'))

#def GetClipboardData(uFormat):
#    return GetClipboardData.ctypes_function(uFormat)
GetClipboardDataPrototype = WINFUNCTYPE(HANDLE, UINT)
GetClipboardDataParams = ((1, 'uFormat'),)

#def EnumClipboardFormats(format):
#    return EnumClipboardFormats.ctypes_function(format)
EnumClipboardFormatsPrototype = WINFUNCTYPE(UINT, UINT)
EnumClipboardFormatsParams = ((1, 'format'),)

#def GetClipboardFormatNameA(format, lpszFormatName, cchMaxCount):
#    return GetClipboardFormatNameA.ctypes_function(format, lpszFormatName, cchMaxCount)
GetClipboardFormatNameAPrototype = WINFUNCTYPE(INT, UINT, LPCSTR, INT)
GetClipboardFormatNameAParams = ((1, 'format'), (1, 'lpszFormatName'), (1, 'cchMaxCount'))

#def GetClipboardFormatNameW(format, lpszFormatName, cchMaxCount):
#    return GetClipboardFormatNameW.ctypes_function(format, lpszFormatName, cchMaxCount)
GetClipboardFormatNameWPrototype = WINFUNCTYPE(INT, UINT, LPCWSTR, INT)
GetClipboardFormatNameWParams = ((1, 'format'), (1, 'lpszFormatName'), (1, 'cchMaxCount'))

#def WinVerifyTrust(hWnd, pgActionID, pWVTData):
#    return WinVerifyTrust.ctypes_function(hWnd, pgActionID, pWVTData)
WinVerifyTrustPrototype = WINFUNCTYPE(LONG, HWND, POINTER(GUID), LPVOID)
WinVerifyTrustParams = ((1, 'hWnd'), (1, 'pgActionID'), (1, 'pWVTData'))

#def OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle):
#    return OpenProcessToken.ctypes_function(ProcessHandle, DesiredAccess, TokenHandle)
OpenProcessTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, PHANDLE)
OpenProcessTokenParams = ((1, 'ProcessHandle'), (1, 'DesiredAccess'), (1, 'TokenHandle'))

#def OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle):
#    return OpenThreadToken.ctypes_function(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle)
OpenThreadTokenPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, BOOL, PHANDLE)
OpenThreadTokenParams = ((1, 'ThreadHandle'), (1, 'DesiredAccess'), (1, 'OpenAsSelf'), (1, 'TokenHandle'))

#def GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength):
#    return GetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength)
GetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD)
GetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'), (1, 'ReturnLength'))

#def SetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength):
#    return SetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength)
SetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD)
SetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'))

#def CreateWellKnownSid(WellKnownSidType, DomainSid, pSid, cbSid):
#    return CreateWellKnownSid.ctypes_function(WellKnownSidType, DomainSid, pSid, cbSid)
CreateWellKnownSidPrototype = WINFUNCTYPE(BOOL, WELL_KNOWN_SID_TYPE, PSID, PSID, POINTER(DWORD))
CreateWellKnownSidParams = ((1, 'WellKnownSidType'), (1, 'DomainSid'), (1, 'pSid'), (1, 'cbSid'))

#def DebugBreak():
#    return DebugBreak.ctypes_function()
DebugBreakPrototype = WINFUNCTYPE(VOID)
DebugBreakParams = ()

#def WaitForDebugEvent(lpDebugEvent, dwMilliseconds):
#    return WaitForDebugEvent.ctypes_function(lpDebugEvent, dwMilliseconds)
WaitForDebugEventPrototype = WINFUNCTYPE(BOOL, LPDEBUG_EVENT, DWORD)
WaitForDebugEventParams = ((1, 'lpDebugEvent'), (1, 'dwMilliseconds'))

#def ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus):
#    return ContinueDebugEvent.ctypes_function(dwProcessId, dwThreadId, dwContinueStatus)
ContinueDebugEventPrototype = WINFUNCTYPE(BOOL, DWORD, DWORD, DWORD)
ContinueDebugEventParams = ((1, 'dwProcessId'), (1, 'dwThreadId'), (1, 'dwContinueStatus'))

#def DebugActiveProcess(dwProcessId):
#    return DebugActiveProcess.ctypes_function(dwProcessId)
DebugActiveProcessPrototype = WINFUNCTYPE(BOOL, DWORD)
DebugActiveProcessParams = ((1, 'dwProcessId'),)

#def DebugActiveProcessStop(dwProcessId):
#    return DebugActiveProcessStop.ctypes_function(dwProcessId)
DebugActiveProcessStopPrototype = WINFUNCTYPE(BOOL, DWORD)
DebugActiveProcessStopParams = ((1, 'dwProcessId'),)

#def DebugSetProcessKillOnExit(KillOnExit):
#    return DebugSetProcessKillOnExit.ctypes_function(KillOnExit)
DebugSetProcessKillOnExitPrototype = WINFUNCTYPE(BOOL, BOOL)
DebugSetProcessKillOnExitParams = ((1, 'KillOnExit'),)

#def DebugBreakProcess(Process):
#    return DebugBreakProcess.ctypes_function(Process)
DebugBreakProcessPrototype = WINFUNCTYPE(BOOL, HANDLE)
DebugBreakProcessParams = ((1, 'Process'),)

#def GetProcessId(Process):
#    return GetProcessId.ctypes_function(Process)
GetProcessIdPrototype = WINFUNCTYPE(DWORD, HANDLE)
GetProcessIdParams = ((1, 'Process'),)

#def Wow64SetThreadContext(hThread, lpContext):
#    return Wow64SetThreadContext.ctypes_function(hThread, lpContext)
Wow64SetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, POINTER(WOW64_CONTEXT))
Wow64SetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

#def GetMappedFileNameW(hProcess, lpv, lpFilename, nSize):
#    return GetMappedFileNameW.ctypes_function(hProcess, lpv, lpFilename, nSize)
GetMappedFileNameWPrototype = WINFUNCTYPE(DWORD, HANDLE, LPVOID, PVOID, DWORD)
GetMappedFileNameWParams = ((1, 'hProcess'), (1, 'lpv'), (1, 'lpFilename'), (1, 'nSize'))

#def GetMappedFileNameA(hProcess, lpv, lpFilename, nSize):
#    return GetMappedFileNameA.ctypes_function(hProcess, lpv, lpFilename, nSize)
GetMappedFileNameAPrototype = WINFUNCTYPE(DWORD, HANDLE, LPVOID, PVOID, DWORD)
GetMappedFileNameAParams = ((1, 'hProcess'), (1, 'lpv'), (1, 'lpFilename'), (1, 'nSize'))

#def RtlInitString(DestinationString, SourceString):
#    return RtlInitString.ctypes_function(DestinationString, SourceString)
RtlInitStringPrototype = WINFUNCTYPE(VOID, PSTRING, LPCSTR)
RtlInitStringParams = ((1, 'DestinationString'), (1, 'SourceString'))

#def RtlInitUnicodeString(DestinationString, SourceString):
#    return RtlInitUnicodeString.ctypes_function(DestinationString, SourceString)
RtlInitUnicodeStringPrototype = WINFUNCTYPE(VOID, PUNICODE_STRING, LPCWSTR)
RtlInitUnicodeStringParams = ((1, 'DestinationString'), (1, 'SourceString'))

#def RtlAnsiStringToUnicodeString(DestinationString, SourceString, AllocateDestinationString):
#    return RtlAnsiStringToUnicodeString.ctypes_function(DestinationString, SourceString, AllocateDestinationString)
RtlAnsiStringToUnicodeStringPrototype = WINFUNCTYPE(NTSTATUS, PUNICODE_STRING, PCANSI_STRING, BOOLEAN)
RtlAnsiStringToUnicodeStringParams = ((1, 'DestinationString'), (1, 'SourceString'), (1, 'AllocateDestinationString'))

#def RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize):
#    return RtlDecompressBuffer.ctypes_function(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize)
RtlDecompressBufferPrototype = WINFUNCTYPE(NTSTATUS, USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG)
RtlDecompressBufferParams = ((1, 'CompressionFormat'), (1, 'UncompressedBuffer'), (1, 'UncompressedBufferSize'), (1, 'CompressedBuffer'), (1, 'CompressedBufferSize'), (1, 'FinalUncompressedSize'))

#def RtlDecompressBufferEx(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize, WorkSpace):
#    return RtlDecompressBufferEx.ctypes_function(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize, WorkSpace)
RtlDecompressBufferExPrototype = WINFUNCTYPE(NTSTATUS, USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID)
RtlDecompressBufferExParams = ((1, 'CompressionFormat'), (1, 'UncompressedBuffer'), (1, 'UncompressedBufferSize'), (1, 'CompressedBuffer'), (1, 'CompressedBufferSize'), (1, 'FinalUncompressedSize'), (1, 'WorkSpace'))

#def RtlGetCompressionWorkSpaceSize(CompressionFormatAndEngine, CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize):
#    return RtlGetCompressionWorkSpaceSize.ctypes_function(CompressionFormatAndEngine, CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize)
RtlGetCompressionWorkSpaceSizePrototype = WINFUNCTYPE(NTSTATUS, USHORT, PULONG, PULONG)
RtlGetCompressionWorkSpaceSizeParams = ((1, 'CompressionFormatAndEngine'), (1, 'CompressBufferWorkSpaceSize'), (1, 'CompressFragmentWorkSpaceSize'))

#def NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle):
#    return NtCreateSection.ctypes_function(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle)
NtCreateSectionPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE)
NtCreateSectionParams = ((1, 'SectionHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'MaximumSize'), (1, 'SectionPageProtection'), (1, 'AllocationAttributes'), (1, 'FileHandle'))

#def NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes):
#    return NtOpenSection.ctypes_function(SectionHandle, DesiredAccess, ObjectAttributes)
NtOpenSectionPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenSectionParams = ((1, 'SectionHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

#def NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect):
#    return NtMapViewOfSection.ctypes_function(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect)
NtMapViewOfSectionPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, HANDLE, POINTER(PVOID), ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG)
NtMapViewOfSectionParams = ((1, 'SectionHandle'), (1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'ZeroBits'), (1, 'CommitSize'), (1, 'SectionOffset'), (1, 'ViewSize'), (1, 'InheritDisposition'), (1, 'AllocationType'), (1, 'Win32Protect'))

#def NtUnmapViewOfSection(ProcessHandle, BaseAddress):
#    return NtUnmapViewOfSection.ctypes_function(ProcessHandle, BaseAddress)
NtUnmapViewOfSectionPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID)
NtUnmapViewOfSectionParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'))

#def OpenEventA(dwDesiredAccess, bInheritHandle, lpName):
#    return OpenEventA.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)
OpenEventAPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCSTR)
OpenEventAParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

#def OpenEventW(dwDesiredAccess, bInheritHandle, lpName):
#    return OpenEventW.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)
OpenEventWPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCWSTR)
OpenEventWParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

#def NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes):
#    return NtOpenEvent.ctypes_function(EventHandle, DesiredAccess, ObjectAttributes)
NtOpenEventPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenEventParams = ((1, 'EventHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

#def lstrcmpA(lpString1, lpString2):
#    return lstrcmpA.ctypes_function(lpString1, lpString2)
lstrcmpAPrototype = WINFUNCTYPE(INT, LPCSTR, LPCSTR)
lstrcmpAParams = ((1, 'lpString1'), (1, 'lpString2'))

#def lstrcmpW(lpString1, lpString2):
#    return lstrcmpW.ctypes_function(lpString1, lpString2)
lstrcmpWPrototype = WINFUNCTYPE(INT, LPCWSTR, LPCWSTR)
lstrcmpWParams = ((1, 'lpString1'), (1, 'lpString2'))

#def CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
#    return CreateFileMappingA.ctypes_function(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
CreateFileMappingAPrototype = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR)
CreateFileMappingAParams = ((1, 'hFile'), (1, 'lpFileMappingAttributes'), (1, 'flProtect'), (1, 'dwMaximumSizeHigh'), (1, 'dwMaximumSizeLow'), (1, 'lpName'))

#def CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
#    return CreateFileMappingW.ctypes_function(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
CreateFileMappingWPrototype = WINFUNCTYPE(HANDLE, HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR)
CreateFileMappingWParams = ((1, 'hFile'), (1, 'lpFileMappingAttributes'), (1, 'flProtect'), (1, 'dwMaximumSizeHigh'), (1, 'dwMaximumSizeLow'), (1, 'lpName'))

#def MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap):
#    return MapViewOfFile.ctypes_function(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)
MapViewOfFilePrototype = WINFUNCTYPE(LPVOID, HANDLE, DWORD, DWORD, DWORD, SIZE_T)
MapViewOfFileParams = ((1, 'hFileMappingObject'), (1, 'dwDesiredAccess'), (1, 'dwFileOffsetHigh'), (1, 'dwFileOffsetLow'), (1, 'dwNumberOfBytesToMap'))

#def OpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess):
#    return OpenSCManagerA.ctypes_function(lpMachineName, lpDatabaseName, dwDesiredAccess)
OpenSCManagerAPrototype = WINFUNCTYPE(SC_HANDLE, LPCSTR, LPCSTR, DWORD)
OpenSCManagerAParams = ((1, 'lpMachineName'), (1, 'lpDatabaseName'), (1, 'dwDesiredAccess'))

#def OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess):
#    return OpenSCManagerW.ctypes_function(lpMachineName, lpDatabaseName, dwDesiredAccess)
OpenSCManagerWPrototype = WINFUNCTYPE(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD)
OpenSCManagerWParams = ((1, 'lpMachineName'), (1, 'lpDatabaseName'), (1, 'dwDesiredAccess'))

#def CloseServiceHandle(hSCObject):
#    return CloseServiceHandle.ctypes_function(hSCObject)
CloseServiceHandlePrototype = WINFUNCTYPE(BOOL, SC_HANDLE)
CloseServiceHandleParams = ((1, 'hSCObject'),)

#def EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
#    return EnumServicesStatusExA.ctypes_function(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)
EnumServicesStatusExAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR)
EnumServicesStatusExAParams = ((1, 'hSCManager'), (1, 'InfoLevel'), (1, 'dwServiceType'), (1, 'dwServiceState'), (1, 'lpServices'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'), (1, 'lpServicesReturned'), (1, 'lpResumeHandle'), (1, 'pszGroupName'))

#def EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName):
#    return EnumServicesStatusExW.ctypes_function(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)
EnumServicesStatusExWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR)
EnumServicesStatusExWParams = ((1, 'hSCManager'), (1, 'InfoLevel'), (1, 'dwServiceType'), (1, 'dwServiceState'), (1, 'lpServices'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'), (1, 'lpServicesReturned'), (1, 'lpResumeHandle'), (1, 'pszGroupName'))

#def StartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors):
#    return StartServiceA.ctypes_function(hService, dwNumServiceArgs, lpServiceArgVectors)
StartServiceAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, POINTER(LPCSTR))
StartServiceAParams = ((1, 'hService'), (1, 'dwNumServiceArgs'), (1, 'lpServiceArgVectors'))

#def StartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors):
#    return StartServiceW.ctypes_function(hService, dwNumServiceArgs, lpServiceArgVectors)
StartServiceWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, POINTER(LPCWSTR))
StartServiceWParams = ((1, 'hService'), (1, 'dwNumServiceArgs'), (1, 'lpServiceArgVectors'))

#def OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess):
#    return OpenServiceA.ctypes_function(hSCManager, lpServiceName, dwDesiredAccess)
OpenServiceAPrototype = WINFUNCTYPE(SC_HANDLE, SC_HANDLE, LPCSTR, DWORD)
OpenServiceAParams = ((1, 'hSCManager'), (1, 'lpServiceName'), (1, 'dwDesiredAccess'))

#def OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess):
#    return OpenServiceW.ctypes_function(hSCManager, lpServiceName, dwDesiredAccess)
OpenServiceWPrototype = WINFUNCTYPE(SC_HANDLE, SC_HANDLE, LPCWSTR, DWORD)
OpenServiceWParams = ((1, 'hSCManager'), (1, 'lpServiceName'), (1, 'dwDesiredAccess'))

#def GetLogicalDriveStringsA(nBufferLength, lpBuffer):
#    return GetLogicalDriveStringsA.ctypes_function(nBufferLength, lpBuffer)
GetLogicalDriveStringsAPrototype = WINFUNCTYPE(DWORD, DWORD, LPCSTR)
GetLogicalDriveStringsAParams = ((1, 'nBufferLength'), (1, 'lpBuffer'))

#def GetLogicalDriveStringsW(nBufferLength, lpBuffer):
#    return GetLogicalDriveStringsW.ctypes_function(nBufferLength, lpBuffer)
GetLogicalDriveStringsWPrototype = WINFUNCTYPE(DWORD, DWORD, LPWSTR)
GetLogicalDriveStringsWParams = ((1, 'nBufferLength'), (1, 'lpBuffer'))

#def GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize):
#    return GetVolumeInformationA.ctypes_function(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)
GetVolumeInformationAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPSTR, DWORD)
GetVolumeInformationAParams = ((1, 'lpRootPathName'), (1, 'lpVolumeNameBuffer'), (1, 'nVolumeNameSize'), (1, 'lpVolumeSerialNumber'), (1, 'lpMaximumComponentLength'), (1, 'lpFileSystemFlags'), (1, 'lpFileSystemNameBuffer'), (1, 'nFileSystemNameSize'))

#def GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize):
#    return GetVolumeInformationW.ctypes_function(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)
GetVolumeInformationWPrototype = WINFUNCTYPE(BOOL, LPWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD)
GetVolumeInformationWParams = ((1, 'lpRootPathName'), (1, 'lpVolumeNameBuffer'), (1, 'nVolumeNameSize'), (1, 'lpVolumeSerialNumber'), (1, 'lpMaximumComponentLength'), (1, 'lpFileSystemFlags'), (1, 'lpFileSystemNameBuffer'), (1, 'nFileSystemNameSize'))

#def GetVolumeNameForVolumeMountPointA(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength):
#    return GetVolumeNameForVolumeMountPointA.ctypes_function(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)
GetVolumeNameForVolumeMountPointAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPCSTR, DWORD)
GetVolumeNameForVolumeMountPointAParams = ((1, 'lpszVolumeMountPoint'), (1, 'lpszVolumeName'), (1, 'cchBufferLength'))

#def GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength):
#    return GetVolumeNameForVolumeMountPointW.ctypes_function(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)
GetVolumeNameForVolumeMountPointWPrototype = WINFUNCTYPE(BOOL, LPWSTR, LPWSTR, DWORD)
GetVolumeNameForVolumeMountPointWParams = ((1, 'lpszVolumeMountPoint'), (1, 'lpszVolumeName'), (1, 'cchBufferLength'))

#def GetDriveTypeA(lpRootPathName):
#    return GetDriveTypeA.ctypes_function(lpRootPathName)
GetDriveTypeAPrototype = WINFUNCTYPE(UINT, LPCSTR)
GetDriveTypeAParams = ((1, 'lpRootPathName'),)

#def GetDriveTypeW(lpRootPathName):
#    return GetDriveTypeW.ctypes_function(lpRootPathName)
GetDriveTypeWPrototype = WINFUNCTYPE(UINT, LPWSTR)
GetDriveTypeWParams = ((1, 'lpRootPathName'),)

#def QueryDosDeviceA(lpDeviceName, lpTargetPath, ucchMax):
#    return QueryDosDeviceA.ctypes_function(lpDeviceName, lpTargetPath, ucchMax)
QueryDosDeviceAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPCSTR, DWORD)
QueryDosDeviceAParams = ((1, 'lpDeviceName'), (1, 'lpTargetPath'), (1, 'ucchMax'))

#def QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax):
#    return QueryDosDeviceW.ctypes_function(lpDeviceName, lpTargetPath, ucchMax)
QueryDosDeviceWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPWSTR, DWORD)
QueryDosDeviceWParams = ((1, 'lpDeviceName'), (1, 'lpTargetPath'), (1, 'ucchMax'))

#def FindFirstVolumeA(lpszVolumeName, cchBufferLength):
#    return FindFirstVolumeA.ctypes_function(lpszVolumeName, cchBufferLength)
FindFirstVolumeAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, DWORD)
FindFirstVolumeAParams = ((1, 'lpszVolumeName'), (1, 'cchBufferLength'))

#def FindFirstVolumeW(lpszVolumeName, cchBufferLength):
#    return FindFirstVolumeW.ctypes_function(lpszVolumeName, cchBufferLength)
FindFirstVolumeWPrototype = WINFUNCTYPE(HANDLE, LPWSTR, DWORD)
FindFirstVolumeWParams = ((1, 'lpszVolumeName'), (1, 'cchBufferLength'))

#def FindNextVolumeA(hFindVolume, lpszVolumeName, cchBufferLength):
#    return FindNextVolumeA.ctypes_function(hFindVolume, lpszVolumeName, cchBufferLength)
FindNextVolumeAPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCSTR, DWORD)
FindNextVolumeAParams = ((1, 'hFindVolume'), (1, 'lpszVolumeName'), (1, 'cchBufferLength'))

#def FindNextVolumeW(hFindVolume, lpszVolumeName, cchBufferLength):
#    return FindNextVolumeW.ctypes_function(hFindVolume, lpszVolumeName, cchBufferLength)
FindNextVolumeWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPWSTR, DWORD)
FindNextVolumeWParams = ((1, 'hFindVolume'), (1, 'lpszVolumeName'), (1, 'cchBufferLength'))

#def NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength):
#    return NtQueryObject.ctypes_function(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength)
NtQueryObjectPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQueryObjectParams = ((1, 'Handle'), (1, 'ObjectInformationClass'), (1, 'ObjectInformation'), (1, 'ObjectInformationLength'), (1, 'ReturnLength'))

#def DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions):
#    return DuplicateHandle.ctypes_function(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions)
DuplicateHandlePrototype = WINFUNCTYPE(BOOL, HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD)
DuplicateHandleParams = ((1, 'hSourceProcessHandle'), (1, 'hSourceHandle'), (1, 'hTargetProcessHandle'), (1, 'lpTargetHandle'), (1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'dwOptions'))

#def ZwDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options):
#    return ZwDuplicateObject.ctypes_function(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options)
ZwDuplicateObjectPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG)
ZwDuplicateObjectParams = ((1, 'SourceProcessHandle'), (1, 'SourceHandle'), (1, 'TargetProcessHandle'), (1, 'TargetHandle'), (1, 'DesiredAccess'), (1, 'HandleAttributes'), (1, 'Options'))

#def GetModuleBaseNameA(hProcess, hModule, lpBaseName, nSize):
#    return GetModuleBaseNameA.ctypes_function(hProcess, hModule, lpBaseName, nSize)
GetModuleBaseNameAPrototype = WINFUNCTYPE(DWORD, HANDLE, HMODULE, LPCSTR, DWORD)
GetModuleBaseNameAParams = ((1, 'hProcess'), (1, 'hModule'), (1, 'lpBaseName'), (1, 'nSize'))

#def GetModuleBaseNameW(hProcess, hModule, lpBaseName, nSize):
#    return GetModuleBaseNameW.ctypes_function(hProcess, hModule, lpBaseName, nSize)
GetModuleBaseNameWPrototype = WINFUNCTYPE(DWORD, HANDLE, HMODULE, LPWSTR, DWORD)
GetModuleBaseNameWParams = ((1, 'hProcess'), (1, 'hModule'), (1, 'lpBaseName'), (1, 'nSize'))

#def GetProcessImageFileNameA(hProcess, lpImageFileName, nSize):
#    return GetProcessImageFileNameA.ctypes_function(hProcess, lpImageFileName, nSize)
GetProcessImageFileNameAPrototype = WINFUNCTYPE(DWORD, HANDLE, LPCSTR, DWORD)
GetProcessImageFileNameAParams = ((1, 'hProcess'), (1, 'lpImageFileName'), (1, 'nSize'))

#def GetProcessImageFileNameW(hProcess, lpImageFileName, nSize):
#    return GetProcessImageFileNameW.ctypes_function(hProcess, lpImageFileName, nSize)
GetProcessImageFileNameWPrototype = WINFUNCTYPE(DWORD, HANDLE, LPWSTR, DWORD)
GetProcessImageFileNameWParams = ((1, 'hProcess'), (1, 'lpImageFileName'), (1, 'nSize'))

#def GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData):
#    return GetFileVersionInfoA.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)
GetFileVersionInfoAPrototype = WINFUNCTYPE(BOOL, LPCSTR, DWORD, DWORD, LPVOID)
GetFileVersionInfoAParams = ((1, 'lptstrFilename'), (1, 'dwHandle'), (1, 'dwLen'), (1, 'lpData'))

#def GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData):
#    return GetFileVersionInfoW.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)
GetFileVersionInfoWPrototype = WINFUNCTYPE(BOOL, LPWSTR, DWORD, DWORD, LPVOID)
GetFileVersionInfoWParams = ((1, 'lptstrFilename'), (1, 'dwHandle'), (1, 'dwLen'), (1, 'lpData'))

#def GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle):
#    return GetFileVersionInfoSizeA.ctypes_function(lptstrFilename, lpdwHandle)
GetFileVersionInfoSizeAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPDWORD)
GetFileVersionInfoSizeAParams = ((1, 'lptstrFilename'), (1, 'lpdwHandle'))

#def GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle):
#    return GetFileVersionInfoSizeW.ctypes_function(lptstrFilename, lpdwHandle)
GetFileVersionInfoSizeWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPDWORD)
GetFileVersionInfoSizeWParams = ((1, 'lptstrFilename'), (1, 'lpdwHandle'))

#def VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen):
#    return VerQueryValueA.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)
VerQueryValueAPrototype = WINFUNCTYPE(BOOL, LPCVOID, LPCSTR, POINTER(LPVOID), PUINT)
VerQueryValueAParams = ((1, 'pBlock'), (1, 'lpSubBlock'), (1, 'lplpBuffer'), (1, 'puLen'))

#def VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen):
#    return VerQueryValueW.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)
VerQueryValueWPrototype = WINFUNCTYPE(BOOL, LPCVOID, LPWSTR, POINTER(LPVOID), PUINT)
VerQueryValueWParams = ((1, 'pBlock'), (1, 'lpSubBlock'), (1, 'lplpBuffer'), (1, 'puLen'))

#def GetSystemMetrics(nIndex):
#    return GetSystemMetrics.ctypes_function(nIndex)
GetSystemMetricsPrototype = WINFUNCTYPE(INT, INT)
GetSystemMetricsParams = ((1, 'nIndex'),)

#def GetComputerNameA(lpBuffer, lpnSize):
#    return GetComputerNameA.ctypes_function(lpBuffer, lpnSize)
GetComputerNameAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPDWORD)
GetComputerNameAParams = ((1, 'lpBuffer'), (1, 'lpnSize'))

#def GetComputerNameW(lpBuffer, lpnSize):
#    return GetComputerNameW.ctypes_function(lpBuffer, lpnSize)
GetComputerNameWPrototype = WINFUNCTYPE(BOOL, LPWSTR, LPDWORD)
GetComputerNameWParams = ((1, 'lpBuffer'), (1, 'lpnSize'))

#def LookupAccountSidA(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
#    return LookupAccountSidA.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)
LookupAccountSidAPrototype = WINFUNCTYPE(BOOL, LPCSTR, PSID, LPCSTR, LPDWORD, LPCSTR, LPDWORD, PSID_NAME_USE)
LookupAccountSidAParams = ((1, 'lpSystemName'), (1, 'lpSid'), (1, 'lpName'), (1, 'cchName'), (1, 'lpReferencedDomainName'), (1, 'cchReferencedDomainName'), (1, 'peUse'))

#def LookupAccountSidW(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse):
#    return LookupAccountSidW.ctypes_function(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)
LookupAccountSidWPrototype = WINFUNCTYPE(BOOL, LPWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE)
LookupAccountSidWParams = ((1, 'lpSystemName'), (1, 'lpSid'), (1, 'lpName'), (1, 'cchName'), (1, 'lpReferencedDomainName'), (1, 'cchReferencedDomainName'), (1, 'peUse'))

#def GetInterfaceInfo(pIfTable, dwOutBufLen):
#    return GetInterfaceInfo.ctypes_function(pIfTable, dwOutBufLen)
GetInterfaceInfoPrototype = WINFUNCTYPE(DWORD, PIP_INTERFACE_INFO, PULONG)
GetInterfaceInfoParams = ((1, 'pIfTable'), (1, 'dwOutBufLen'))

#def GetIfTable(pIfTable, pdwSize, bOrder):
#    return GetIfTable.ctypes_function(pIfTable, pdwSize, bOrder)
GetIfTablePrototype = WINFUNCTYPE(DWORD, PMIB_IFTABLE, PULONG, BOOL)
GetIfTableParams = ((1, 'pIfTable'), (1, 'pdwSize'), (1, 'bOrder'))

#def GetIpAddrTable(pIpAddrTable, pdwSize, bOrder):
#    return GetIpAddrTable.ctypes_function(pIpAddrTable, pdwSize, bOrder)
GetIpAddrTablePrototype = WINFUNCTYPE(DWORD, PMIB_IPADDRTABLE, PULONG, BOOL)
GetIpAddrTableParams = ((1, 'pIpAddrTable'), (1, 'pdwSize'), (1, 'bOrder'))

#def NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes):
#    return NtOpenDirectoryObject.ctypes_function(DirectoryHandle, DesiredAccess, ObjectAttributes)
NtOpenDirectoryObjectPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenDirectoryObjectParams = ((1, 'DirectoryHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

#def NtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength):
#    return NtQueryDirectoryObject.ctypes_function(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength)
NtQueryDirectoryObjectPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG)
NtQueryDirectoryObjectParams = ((1, 'DirectoryHandle'), (1, 'Buffer'), (1, 'Length'), (1, 'ReturnSingleEntry'), (1, 'RestartScan'), (1, 'Context'), (1, 'ReturnLength'))

#def NtQuerySymbolicLinkObject(LinkHandle, LinkTarget, ReturnedLength):
#    return NtQuerySymbolicLinkObject.ctypes_function(LinkHandle, LinkTarget, ReturnedLength)
NtQuerySymbolicLinkObjectPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PUNICODE_STRING, PULONG)
NtQuerySymbolicLinkObjectParams = ((1, 'LinkHandle'), (1, 'LinkTarget'), (1, 'ReturnedLength'))

#def NtOpenSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes):
#    return NtOpenSymbolicLinkObject.ctypes_function(LinkHandle, DesiredAccess, ObjectAttributes)
NtOpenSymbolicLinkObjectPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenSymbolicLinkObjectParams = ((1, 'LinkHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

#def GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime):
#    return GetProcessTimes.ctypes_function(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime)
GetProcessTimesPrototype = WINFUNCTYPE(BOOL, HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME)
GetProcessTimesParams = ((1, 'hProcess'), (1, 'lpCreationTime'), (1, 'lpExitTime'), (1, 'lpKernelTime'), (1, 'lpUserTime'))

#def GetShortPathNameA(lpszLongPath, lpszShortPath, cchBuffer):
#    return GetShortPathNameA.ctypes_function(lpszLongPath, lpszShortPath, cchBuffer)
GetShortPathNameAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPCSTR, DWORD)
GetShortPathNameAParams = ((1, 'lpszLongPath'), (1, 'lpszShortPath'), (1, 'cchBuffer'))

#def GetShortPathNameW(lpszLongPath, lpszShortPath, cchBuffer):
#    return GetShortPathNameW.ctypes_function(lpszLongPath, lpszShortPath, cchBuffer)
GetShortPathNameWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPWSTR, DWORD)
GetShortPathNameWParams = ((1, 'lpszLongPath'), (1, 'lpszShortPath'), (1, 'cchBuffer'))

#def GetLongPathNameA(lpszShortPath, lpszLongPath, cchBuffer):
#    return GetLongPathNameA.ctypes_function(lpszShortPath, lpszLongPath, cchBuffer)
GetLongPathNameAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPCSTR, DWORD)
GetLongPathNameAParams = ((1, 'lpszShortPath'), (1, 'lpszLongPath'), (1, 'cchBuffer'))

#def GetLongPathNameW(lpszShortPath, lpszLongPath, cchBuffer):
#    return GetLongPathNameW.ctypes_function(lpszShortPath, lpszLongPath, cchBuffer)
GetLongPathNameWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPWSTR, DWORD)
GetLongPathNameWParams = ((1, 'lpszShortPath'), (1, 'lpszLongPath'), (1, 'cchBuffer'))

#def GetProcessDEPPolicy(hProcess, lpFlags, lpPermanent):
#    return GetProcessDEPPolicy.ctypes_function(hProcess, lpFlags, lpPermanent)
GetProcessDEPPolicyPrototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD, PBOOL)
GetProcessDEPPolicyParams = ((1, 'hProcess'), (1, 'lpFlags'), (1, 'lpPermanent'))

#def GetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor):
#    return GetNamedSecurityInfoA.ctypes_function(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)
GetNamedSecurityInfoAPrototype = WINFUNCTYPE(DWORD, LPCSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, POINTER(PSID), POINTER(PSID), POINTER(PACL), POINTER(PACL), POINTER(PSECURITY_DESCRIPTOR))
GetNamedSecurityInfoAParams = ((1, 'pObjectName'), (1, 'ObjectType'), (1, 'SecurityInfo'), (1, 'ppsidOwner'), (1, 'ppsidGroup'), (1, 'ppDacl'), (1, 'ppSacl'), (1, 'ppSecurityDescriptor'))

#def GetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor):
#    return GetNamedSecurityInfoW.ctypes_function(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)
GetNamedSecurityInfoWPrototype = WINFUNCTYPE(DWORD, LPWSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, POINTER(PSID), POINTER(PSID), POINTER(PACL), POINTER(PACL), POINTER(PSECURITY_DESCRIPTOR))
GetNamedSecurityInfoWParams = ((1, 'pObjectName'), (1, 'ObjectType'), (1, 'SecurityInfo'), (1, 'ppsidOwner'), (1, 'ppsidGroup'), (1, 'ppDacl'), (1, 'ppSacl'), (1, 'ppSecurityDescriptor'))

#def GetSecurityInfo(handle, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor):
#    return GetSecurityInfo.ctypes_function(handle, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)
GetSecurityInfoPrototype = WINFUNCTYPE(DWORD, HANDLE, SE_OBJECT_TYPE, SECURITY_INFORMATION, POINTER(PSID), POINTER(PSID), POINTER(PACL), POINTER(PACL), POINTER(PSECURITY_DESCRIPTOR))
GetSecurityInfoParams = ((1, 'handle'), (1, 'ObjectType'), (1, 'SecurityInfo'), (1, 'ppsidOwner'), (1, 'ppsidGroup'), (1, 'ppDacl'), (1, 'ppSacl'), (1, 'ppSecurityDescriptor'))

#def ConvertStringSidToSidA(StringSid, Sid):
#    return ConvertStringSidToSidA.ctypes_function(StringSid, Sid)
ConvertStringSidToSidAPrototype = WINFUNCTYPE(BOOL, LPCSTR, POINTER(PSID))
ConvertStringSidToSidAParams = ((1, 'StringSid'), (1, 'Sid'))

#def ConvertStringSidToSidW(StringSid, Sid):
#    return ConvertStringSidToSidW.ctypes_function(StringSid, Sid)
ConvertStringSidToSidWPrototype = WINFUNCTYPE(BOOL, LPWSTR, POINTER(PSID))
ConvertStringSidToSidWParams = ((1, 'StringSid'), (1, 'Sid'))

#def ConvertSidToStringSidA(Sid, StringSid):
#    return ConvertSidToStringSidA.ctypes_function(Sid, StringSid)
ConvertSidToStringSidAPrototype = WINFUNCTYPE(BOOL, PSID, POINTER(LPCSTR))
ConvertSidToStringSidAParams = ((1, 'Sid'), (1, 'StringSid'))

#def ConvertSidToStringSidW(Sid, StringSid):
#    return ConvertSidToStringSidW.ctypes_function(Sid, StringSid)
ConvertSidToStringSidWPrototype = WINFUNCTYPE(BOOL, PSID, POINTER(LPWSTR))
ConvertSidToStringSidWParams = ((1, 'Sid'), (1, 'StringSid'))

#def LocalFree(hMem):
#    return LocalFree.ctypes_function(hMem)
LocalFreePrototype = WINFUNCTYPE(HLOCAL, HLOCAL)
LocalFreeParams = ((1, 'hMem'),)

#def RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
#    return RegQueryValueExA.ctypes_function(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
RegQueryValueExAPrototype = WINFUNCTYPE(LONG, HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD)
RegQueryValueExAParams = ((1, 'hKey'), (1, 'lpValueName'), (1, 'lpReserved'), (1, 'lpType'), (1, 'lpData'), (1, 'lpcbData'))

#def RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
#    return RegQueryValueExW.ctypes_function(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
RegQueryValueExWPrototype = WINFUNCTYPE(LONG, HKEY, LPWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD)
RegQueryValueExWParams = ((1, 'hKey'), (1, 'lpValueName'), (1, 'lpReserved'), (1, 'lpType'), (1, 'lpData'), (1, 'lpcbData'))

#def InitializeProcThreadAttributeList(lpAttributeList, dwAttributeCount, dwFlags, lpSize):
#    return InitializeProcThreadAttributeList.ctypes_function(lpAttributeList, dwAttributeCount, dwFlags, lpSize)
InitializeProcThreadAttributeListPrototype = WINFUNCTYPE(BOOL, LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T)
InitializeProcThreadAttributeListParams = ((1, 'lpAttributeList'), (1, 'dwAttributeCount'), (1, 'dwFlags'), (1, 'lpSize'))

#def UpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize):
#    return UpdateProcThreadAttribute.ctypes_function(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize)
UpdateProcThreadAttributePrototype = WINFUNCTYPE(BOOL, LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T)
UpdateProcThreadAttributeParams = ((1, 'lpAttributeList'), (1, 'dwFlags'), (1, 'Attribute'), (1, 'lpValue'), (1, 'cbSize'), (1, 'lpPreviousValue'), (1, 'lpReturnSize'))

#def DeleteProcThreadAttributeList(lpAttributeList):
#    return DeleteProcThreadAttributeList.ctypes_function(lpAttributeList)
DeleteProcThreadAttributeListPrototype = WINFUNCTYPE(VOID, LPPROC_THREAD_ATTRIBUTE_LIST)
DeleteProcThreadAttributeListParams = ((1, 'lpAttributeList'),)

#def MessageBoxA(hWnd, lpText, lpCaption, uType):
#    return MessageBoxA.ctypes_function(hWnd, lpText, lpCaption, uType)
MessageBoxAPrototype = WINFUNCTYPE(INT, HWND, LPCSTR, LPCSTR, UINT)
MessageBoxAParams = ((1, 'hWnd'), (1, 'lpText'), (1, 'lpCaption'), (1, 'uType'))

#def MessageBoxW(hWnd, lpText, lpCaption, uType):
#    return MessageBoxW.ctypes_function(hWnd, lpText, lpCaption, uType)
MessageBoxWPrototype = WINFUNCTYPE(INT, HWND, LPWSTR, LPWSTR, UINT)
MessageBoxWParams = ((1, 'hWnd'), (1, 'lpText'), (1, 'lpCaption'), (1, 'uType'))

#def GetWindowsDirectoryA(lpBuffer, uSize):
#    return GetWindowsDirectoryA.ctypes_function(lpBuffer, uSize)
GetWindowsDirectoryAPrototype = WINFUNCTYPE(UINT, LPCSTR, UINT)
GetWindowsDirectoryAParams = ((1, 'lpBuffer'), (1, 'uSize'))

#def GetWindowsDirectoryW(lpBuffer, uSize):
#    return GetWindowsDirectoryW.ctypes_function(lpBuffer, uSize)
GetWindowsDirectoryWPrototype = WINFUNCTYPE(UINT, LPWSTR, UINT)
GetWindowsDirectoryWParams = ((1, 'lpBuffer'), (1, 'uSize'))

#def RtlGetUnloadEventTraceEx(ElementSize, ElementCount, EventTrace):
#    return RtlGetUnloadEventTraceEx.ctypes_function(ElementSize, ElementCount, EventTrace)
RtlGetUnloadEventTraceExPrototype = WINFUNCTYPE(VOID, POINTER(PULONG), POINTER(PULONG), POINTER(PVOID))
RtlGetUnloadEventTraceExParams = ((1, 'ElementSize'), (1, 'ElementCount'), (1, 'EventTrace'))

#def NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass):
#    return NtQueryInformationFile.ctypes_function(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)
NtQueryInformationFilePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS)
NtQueryInformationFileParams = ((1, 'FileHandle'), (1, 'IoStatusBlock'), (1, 'FileInformation'), (1, 'Length'), (1, 'FileInformationClass'))

#def NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan):
#    return NtQueryDirectoryFile.ctypes_function(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan)
NtQueryDirectoryFilePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN)
NtQueryDirectoryFileParams = ((1, 'FileHandle'), (1, 'Event'), (1, 'ApcRoutine'), (1, 'ApcContext'), (1, 'IoStatusBlock'), (1, 'FileInformation'), (1, 'Length'), (1, 'FileInformationClass'), (1, 'ReturnSingleEntry'), (1, 'FileName'), (1, 'RestartScan'))

#def RtlDosPathNameToNtPathName_U(DosName, NtName, PartName, RelativeName):
#    return RtlDosPathNameToNtPathName_U.ctypes_function(DosName, NtName, PartName, RelativeName)
RtlDosPathNameToNtPathName_UPrototype = WINFUNCTYPE(BOOLEAN, PCWSTR, PUNICODE_STRING, POINTER(PCWSTR), PRTL_RELATIVE_NAME_U)
RtlDosPathNameToNtPathName_UParams = ((1, 'DosName'), (1, 'NtName'), (1, 'PartName'), (1, 'RelativeName'))

#def ApiSetResolveToHost(Schema, FileNameIn, ParentName, Resolved, HostBinary):
#    return ApiSetResolveToHost.ctypes_function(Schema, FileNameIn, ParentName, Resolved, HostBinary)
ApiSetResolveToHostPrototype = WINFUNCTYPE(NTSTATUS, PVOID, PUNICODE_STRING, PUNICODE_STRING, PBOOLEAN, PUNICODE_STRING)
ApiSetResolveToHostParams = ((1, 'Schema'), (1, 'FileNameIn'), (1, 'ParentName'), (1, 'Resolved'), (1, 'HostBinary'))

#def Sleep(dwMilliseconds):
#    return Sleep.ctypes_function(dwMilliseconds)
SleepPrototype = WINFUNCTYPE(VOID, DWORD)
SleepParams = ((1, 'dwMilliseconds'),)

#def SleepEx(dwMilliseconds, bAlertable):
#    return SleepEx.ctypes_function(dwMilliseconds, bAlertable)
SleepExPrototype = WINFUNCTYPE(DWORD, DWORD, BOOL)
SleepExParams = ((1, 'dwMilliseconds'), (1, 'bAlertable'))

#def GetProcessMitigationPolicy(hProcess, MitigationPolicy, lpBuffer, dwLength):
#    return GetProcessMitigationPolicy.ctypes_function(hProcess, MitigationPolicy, lpBuffer, dwLength)
GetProcessMitigationPolicyPrototype = WINFUNCTYPE(BOOL, HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T)
GetProcessMitigationPolicyParams = ((1, 'hProcess'), (1, 'MitigationPolicy'), (1, 'lpBuffer'), (1, 'dwLength'))

#def SetProcessMitigationPolicy(MitigationPolicy, lpBuffer, dwLength):
#    return SetProcessMitigationPolicy.ctypes_function(MitigationPolicy, lpBuffer, dwLength)
SetProcessMitigationPolicyPrototype = WINFUNCTYPE(BOOL, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T)
SetProcessMitigationPolicyParams = ((1, 'MitigationPolicy'), (1, 'lpBuffer'), (1, 'dwLength'))

#def GetProductInfo(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType):
#    return GetProductInfo.ctypes_function(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType)
GetProductInfoPrototype = WINFUNCTYPE(BOOL, DWORD, DWORD, DWORD, DWORD, PDWORD)
GetProductInfoParams = ((1, 'dwOSMajorVersion'), (1, 'dwOSMinorVersion'), (1, 'dwSpMajorVersion'), (1, 'dwSpMinorVersion'), (1, 'pdwReturnedProductType'))

#def NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass):
#    return NtSetInformationFile.ctypes_function(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)
NtSetInformationFilePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS)
NtSetInformationFileParams = ((1, 'FileHandle'), (1, 'IoStatusBlock'), (1, 'FileInformation'), (1, 'Length'), (1, 'FileInformationClass'))

#def GetProcessMemoryInfo(Process, ppsmemCounters, cb):
#    return GetProcessMemoryInfo.ctypes_function(Process, ppsmemCounters, cb)
GetProcessMemoryInfoPrototype = WINFUNCTYPE(BOOL, HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD)
GetProcessMemoryInfoParams = ((1, 'Process'), (1, 'ppsmemCounters'), (1, 'cb'))

#def GetModuleHandleA(lpModuleName):
#    return GetModuleHandleA.ctypes_function(lpModuleName)
GetModuleHandleAPrototype = WINFUNCTYPE(HMODULE, LPCSTR)
GetModuleHandleAParams = ((1, 'lpModuleName'),)

#def GetModuleHandleW(lpModuleName):
#    return GetModuleHandleW.ctypes_function(lpModuleName)
GetModuleHandleWPrototype = WINFUNCTYPE(HMODULE, LPWSTR)
GetModuleHandleWParams = ((1, 'lpModuleName'),)

#def RtlEqualUnicodeString(String1, String2, CaseInSensitive):
#    return RtlEqualUnicodeString.ctypes_function(String1, String2, CaseInSensitive)
RtlEqualUnicodeStringPrototype = WINFUNCTYPE(BOOLEAN, PUNICODE_STRING, PUNICODE_STRING, BOOLEAN)
RtlEqualUnicodeStringParams = ((1, 'String1'), (1, 'String2'), (1, 'CaseInSensitive'))

#def GetFirmwareEnvironmentVariableA(lpName, lpGuid, pBuffer, nSize):
#    return GetFirmwareEnvironmentVariableA.ctypes_function(lpName, lpGuid, pBuffer, nSize)
GetFirmwareEnvironmentVariableAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPCSTR, PVOID, DWORD)
GetFirmwareEnvironmentVariableAParams = ((1, 'lpName'), (1, 'lpGuid'), (1, 'pBuffer'), (1, 'nSize'))

#def GetFirmwareEnvironmentVariableW(lpName, lpGuid, pBuffer, nSize):
#    return GetFirmwareEnvironmentVariableW.ctypes_function(lpName, lpGuid, pBuffer, nSize)
GetFirmwareEnvironmentVariableWPrototype = WINFUNCTYPE(DWORD, LPCWSTR, LPCWSTR, PVOID, DWORD)
GetFirmwareEnvironmentVariableWParams = ((1, 'lpName'), (1, 'lpGuid'), (1, 'pBuffer'), (1, 'nSize'))

#def GetFirmwareEnvironmentVariableExA(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes):
#    return GetFirmwareEnvironmentVariableExA.ctypes_function(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes)
GetFirmwareEnvironmentVariableExAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPCSTR, PVOID, DWORD, PDWORD)
GetFirmwareEnvironmentVariableExAParams = ((1, 'lpName'), (1, 'lpGuid'), (1, 'pBuffer'), (1, 'nSize'), (1, 'pdwAttribubutes'))

#def GetFirmwareEnvironmentVariableExW(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes):
#    return GetFirmwareEnvironmentVariableExW.ctypes_function(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes)
GetFirmwareEnvironmentVariableExWPrototype = WINFUNCTYPE(DWORD, LPCWSTR, LPCWSTR, PVOID, DWORD, PDWORD)
GetFirmwareEnvironmentVariableExWParams = ((1, 'lpName'), (1, 'lpGuid'), (1, 'pBuffer'), (1, 'nSize'), (1, 'pdwAttribubutes'))

#def NtEnumerateSystemEnvironmentValuesEx(InformationClass, Buffer, BufferLength):
#    return NtEnumerateSystemEnvironmentValuesEx.ctypes_function(InformationClass, Buffer, BufferLength)
NtEnumerateSystemEnvironmentValuesExPrototype = WINFUNCTYPE(NTSTATUS, ULONG, PVOID, ULONG)
NtEnumerateSystemEnvironmentValuesExParams = ((1, 'InformationClass'), (1, 'Buffer'), (1, 'BufferLength'))

#def CreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize):
#    return CreatePipe.ctypes_function(hReadPipe, hWritePipe, lpPipeAttributes, nSize)
CreatePipePrototype = WINFUNCTYPE(BOOL, PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD)
CreatePipeParams = ((1, 'hReadPipe'), (1, 'hWritePipe'), (1, 'lpPipeAttributes'), (1, 'nSize'))

#def CreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes):
#    return CreateNamedPipeA.ctypes_function(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes)
CreateNamedPipeAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES)
CreateNamedPipeAParams = ((1, 'lpName'), (1, 'dwOpenMode'), (1, 'dwPipeMode'), (1, 'nMaxInstances'), (1, 'nOutBufferSize'), (1, 'nInBufferSize'), (1, 'nDefaultTimeOut'), (1, 'lpSecurityAttributes'))

#def CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes):
#    return CreateNamedPipeW.ctypes_function(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes)
CreateNamedPipeWPrototype = WINFUNCTYPE(HANDLE, LPWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES)
CreateNamedPipeWParams = ((1, 'lpName'), (1, 'dwOpenMode'), (1, 'dwPipeMode'), (1, 'nMaxInstances'), (1, 'nOutBufferSize'), (1, 'nInBufferSize'), (1, 'nDefaultTimeOut'), (1, 'lpSecurityAttributes'))

#def ConnectNamedPipe(hNamedPipe, lpOverlapped):
#    return ConnectNamedPipe.ctypes_function(hNamedPipe, lpOverlapped)
ConnectNamedPipePrototype = WINFUNCTYPE(BOOL, HANDLE, LPOVERLAPPED)
ConnectNamedPipeParams = ((1, 'hNamedPipe'), (1, 'lpOverlapped'))

#def SetNamedPipeHandleState(hNamedPipe, lpMode, lpMaxCollectionCount, lpCollectDataTimeout):
#    return SetNamedPipeHandleState.ctypes_function(hNamedPipe, lpMode, lpMaxCollectionCount, lpCollectDataTimeout)
SetNamedPipeHandleStatePrototype = WINFUNCTYPE(BOOL, HANDLE, LPDWORD, LPDWORD, LPDWORD)
SetNamedPipeHandleStateParams = ((1, 'hNamedPipe'), (1, 'lpMode'), (1, 'lpMaxCollectionCount'), (1, 'lpCollectDataTimeout'))

#def PeekNamedPipe(hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage):
#    return PeekNamedPipe.ctypes_function(hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage)
PeekNamedPipePrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD)
PeekNamedPipeParams = ((1, 'hNamedPipe'), (1, 'lpBuffer'), (1, 'nBufferSize'), (1, 'lpBytesRead'), (1, 'lpTotalBytesAvail'), (1, 'lpBytesLeftThisMessage'))

#def SymLoadModuleExA(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
#    return SymLoadModuleExA.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)
SymLoadModuleExAPrototype = WINFUNCTYPE(DWORD64, HANDLE, HANDLE, PCSTR, PCSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD)
SymLoadModuleExAParams = ((1, 'hProcess'), (1, 'hFile'), (1, 'ImageName'), (1, 'ModuleName'), (1, 'BaseOfDll'), (1, 'DllSize'), (1, 'Data'), (1, 'Flags'))

#def SymLoadModuleExW(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
#    return SymLoadModuleExW.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)
SymLoadModuleExWPrototype = WINFUNCTYPE(DWORD64, HANDLE, HANDLE, PCWSTR, PCWSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD)
SymLoadModuleExWParams = ((1, 'hProcess'), (1, 'hFile'), (1, 'ImageName'), (1, 'ModuleName'), (1, 'BaseOfDll'), (1, 'DllSize'), (1, 'Data'), (1, 'Flags'))

#def SymFromAddr(hProcess, Address, Displacement, Symbol):
#    return SymFromAddr.ctypes_function(hProcess, Address, Displacement, Symbol)
SymFromAddrPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64, PDWORD64, PSYMBOL_INFO)
SymFromAddrParams = ((1, 'hProcess'), (1, 'Address'), (1, 'Displacement'), (1, 'Symbol'))

#def SymGetModuleInfo64(hProcess, dwAddr, ModuleInfo):
#    return SymGetModuleInfo64.ctypes_function(hProcess, dwAddr, ModuleInfo)
SymGetModuleInfo64Prototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64, PIMAGEHLP_MODULE64)
SymGetModuleInfo64Params = ((1, 'hProcess'), (1, 'dwAddr'), (1, 'ModuleInfo'))

#def CreateFileTransactedA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter):
#    return CreateFileTransactedA.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter)
CreateFileTransactedAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE, HANDLE, PUSHORT, PVOID)
CreateFileTransactedAParams = ((1, 'lpFileName'), (1, 'dwDesiredAccess'), (1, 'dwShareMode'), (1, 'lpSecurityAttributes'), (1, 'dwCreationDisposition'), (1, 'dwFlagsAndAttributes'), (1, 'hTemplateFile'), (1, 'hTransaction'), (1, 'pusMiniVersion'), (1, 'pExtendedParameter'))

#def CreateFileTransactedW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter):
#    return CreateFileTransactedW.ctypes_function(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter)
CreateFileTransactedWPrototype = WINFUNCTYPE(HANDLE, LPWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE, HANDLE, PUSHORT, PVOID)
CreateFileTransactedWParams = ((1, 'lpFileName'), (1, 'dwDesiredAccess'), (1, 'dwShareMode'), (1, 'lpSecurityAttributes'), (1, 'dwCreationDisposition'), (1, 'dwFlagsAndAttributes'), (1, 'hTemplateFile'), (1, 'hTransaction'), (1, 'pusMiniVersion'), (1, 'pExtendedParameter'))

#def CommitTransaction(TransactionHandle):
#    return CommitTransaction.ctypes_function(TransactionHandle)
CommitTransactionPrototype = WINFUNCTYPE(BOOL, HANDLE)
CommitTransactionParams = ((1, 'TransactionHandle'),)

#def CreateTransaction(lpTransactionAttributes, UOW, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description):
#    return CreateTransaction.ctypes_function(lpTransactionAttributes, UOW, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description)
CreateTransactionPrototype = WINFUNCTYPE(HANDLE, LPSECURITY_ATTRIBUTES, LPGUID, DWORD, DWORD, DWORD, DWORD, LPWSTR)
CreateTransactionParams = ((1, 'lpTransactionAttributes'), (1, 'UOW'), (1, 'CreateOptions'), (1, 'IsolationLevel'), (1, 'IsolationFlags'), (1, 'Timeout'), (1, 'Description'))

#def RollbackTransaction(TransactionHandle):
#    return RollbackTransaction.ctypes_function(TransactionHandle)
RollbackTransactionPrototype = WINFUNCTYPE(BOOL, HANDLE)
RollbackTransactionParams = ((1, 'TransactionHandle'),)

#def OpenTransaction(dwDesiredAccess, TransactionId):
#    return OpenTransaction.ctypes_function(dwDesiredAccess, TransactionId)
OpenTransactionPrototype = WINFUNCTYPE(HANDLE, DWORD, LPGUID)
OpenTransactionParams = ((1, 'dwDesiredAccess'), (1, 'TransactionId'))

