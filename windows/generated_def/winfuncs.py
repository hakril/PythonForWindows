from .interfaces import *
from .winstructs import *
#def ObjectFromLresult(lResult, riid, wParam, ppvObject):
#    return ObjectFromLresult.ctypes_function(lResult, riid, wParam, ppvObject)
ObjectFromLresultPrototype = WINFUNCTYPE(HRESULT, LRESULT, REFIID, WPARAM, POINTER(PVOID))
ObjectFromLresultParams = ((1, 'lResult'), (1, 'riid'), (1, 'wParam'), (1, 'ppvObject'))

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

#def NtConnectPort(PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength, ConnectionInformation, ConnectionInformationLength):
#    return NtConnectPort.ctypes_function(PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength, ConnectionInformation, ConnectionInformationLength)
NtConnectPortPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE, PPORT_VIEW, PREMOTE_PORT_VIEW, PULONG, PVOID, PULONG)
NtConnectPortParams = ((1, 'PortHandle'), (1, 'PortName'), (1, 'SecurityQos'), (1, 'ClientView'), (1, 'ServerView'), (1, 'MaxMessageLength'), (1, 'ConnectionInformation'), (1, 'ConnectionInformationLength'))

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

#def NtAlpcImpersonateClientOfPort(PortHandle, Message, Flags):
#    return NtAlpcImpersonateClientOfPort.ctypes_function(PortHandle, Message, Flags)
NtAlpcImpersonateClientOfPortPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PPORT_MESSAGE, PVOID)
NtAlpcImpersonateClientOfPortParams = ((1, 'PortHandle'), (1, 'Message'), (1, 'Flags'))

#def TpCallbackSendAlpcMessageOnCompletion(TpHandle, PortHandle, Flags, SendMessage):
#    return TpCallbackSendAlpcMessageOnCompletion.ctypes_function(TpHandle, PortHandle, Flags, SendMessage)
TpCallbackSendAlpcMessageOnCompletionPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, HANDLE, ULONG, PPORT_MESSAGE)
TpCallbackSendAlpcMessageOnCompletionParams = ((1, 'TpHandle'), (1, 'PortHandle'), (1, 'Flags'), (1, 'SendMessage'))

#def AddAtomA(lpString):
#    return AddAtomA.ctypes_function(lpString)
AddAtomAPrototype = WINFUNCTYPE(ATOM, LPCSTR)
AddAtomAParams = ((1, 'lpString'),)

#def AddAtomW(lpString):
#    return AddAtomW.ctypes_function(lpString)
AddAtomWPrototype = WINFUNCTYPE(ATOM, LPCWSTR)
AddAtomWParams = ((1, 'lpString'),)

#def GlobalAddAtomA(lpString):
#    return GlobalAddAtomA.ctypes_function(lpString)
GlobalAddAtomAPrototype = WINFUNCTYPE(ATOM, LPCSTR)
GlobalAddAtomAParams = ((1, 'lpString'),)

#def GlobalAddAtomExA(lpString, Flags):
#    return GlobalAddAtomExA.ctypes_function(lpString, Flags)
GlobalAddAtomExAPrototype = WINFUNCTYPE(ATOM, LPCSTR, DWORD)
GlobalAddAtomExAParams = ((1, 'lpString'), (1, 'Flags'))

#def GlobalAddAtomExW(lpString, Flags):
#    return GlobalAddAtomExW.ctypes_function(lpString, Flags)
GlobalAddAtomExWPrototype = WINFUNCTYPE(ATOM, LPCWSTR, DWORD)
GlobalAddAtomExWParams = ((1, 'lpString'), (1, 'Flags'))

#def GlobalAddAtomW(lpString):
#    return GlobalAddAtomW.ctypes_function(lpString)
GlobalAddAtomWPrototype = WINFUNCTYPE(ATOM, LPCWSTR)
GlobalAddAtomWParams = ((1, 'lpString'),)

#def GlobalDeleteAtom(nAtom):
#    return GlobalDeleteAtom.ctypes_function(nAtom)
GlobalDeleteAtomPrototype = WINFUNCTYPE(ATOM, ATOM)
GlobalDeleteAtomParams = ((1, 'nAtom'),)

#def GlobalGetAtomNameA(nAtom, lpBuffer, nSize):
#    return GlobalGetAtomNameA.ctypes_function(nAtom, lpBuffer, nSize)
GlobalGetAtomNameAPrototype = WINFUNCTYPE(UINT, ATOM, LPSTR, INT)
GlobalGetAtomNameAParams = ((1, 'nAtom'), (1, 'lpBuffer'), (1, 'nSize'))

#def GlobalGetAtomNameW(nAtom, lpBuffer, nSize):
#    return GlobalGetAtomNameW.ctypes_function(nAtom, lpBuffer, nSize)
GlobalGetAtomNameWPrototype = WINFUNCTYPE(UINT, ATOM, LPWSTR, INT)
GlobalGetAtomNameWParams = ((1, 'nAtom'), (1, 'lpBuffer'), (1, 'nSize'))

#def CM_Enumerate_Classes(ulClassIndex, ClassGuid, ulFlags):
#    return CM_Enumerate_Classes.ctypes_function(ulClassIndex, ClassGuid, ulFlags)
CM_Enumerate_ClassesPrototype = WINFUNCTYPE(CONFIGRET, ULONG, LPGUID, ULONG)
CM_Enumerate_ClassesParams = ((1, 'ulClassIndex'), (1, 'ClassGuid'), (1, 'ulFlags'))

#def CM_Enumerate_Classes_Ex(ulClassIndex, ClassGuid, ulFlags, hMachine):
#    return CM_Enumerate_Classes_Ex.ctypes_function(ulClassIndex, ClassGuid, ulFlags, hMachine)
CM_Enumerate_Classes_ExPrototype = WINFUNCTYPE(CONFIGRET, ULONG, LPGUID, ULONG, HMACHINE)
CM_Enumerate_Classes_ExParams = ((1, 'ulClassIndex'), (1, 'ClassGuid'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Get_First_Log_Conf(plcLogConf, dnDevInst, ulFlags):
#    return CM_Get_First_Log_Conf.ctypes_function(plcLogConf, dnDevInst, ulFlags)
CM_Get_First_Log_ConfPrototype = WINFUNCTYPE(CONFIGRET, PLOG_CONF, DEVINST, ULONG)
CM_Get_First_Log_ConfParams = ((1, 'plcLogConf'), (1, 'dnDevInst'), (1, 'ulFlags'))

#def CM_Get_First_Log_Conf_Ex(plcLogConf, dnDevInst, ulFlags, hMachine):
#    return CM_Get_First_Log_Conf_Ex.ctypes_function(plcLogConf, dnDevInst, ulFlags, hMachine)
CM_Get_First_Log_Conf_ExPrototype = WINFUNCTYPE(CONFIGRET, PLOG_CONF, DEVINST, ULONG, HMACHINE)
CM_Get_First_Log_Conf_ExParams = ((1, 'plcLogConf'), (1, 'dnDevInst'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Get_Log_Conf_Priority(lcLogConf, pPriority, ulFlags):
#    return CM_Get_Log_Conf_Priority.ctypes_function(lcLogConf, pPriority, ulFlags)
CM_Get_Log_Conf_PriorityPrototype = WINFUNCTYPE(CONFIGRET, LOG_CONF, PPRIORITY, ULONG)
CM_Get_Log_Conf_PriorityParams = ((1, 'lcLogConf'), (1, 'pPriority'), (1, 'ulFlags'))

#def CM_Get_Log_Conf_Priority_Ex(lcLogConf, pPriority, ulFlags, hMachine):
#    return CM_Get_Log_Conf_Priority_Ex.ctypes_function(lcLogConf, pPriority, ulFlags, hMachine)
CM_Get_Log_Conf_Priority_ExPrototype = WINFUNCTYPE(CONFIGRET, LOG_CONF, PPRIORITY, ULONG, HMACHINE)
CM_Get_Log_Conf_Priority_ExParams = ((1, 'lcLogConf'), (1, 'pPriority'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Get_Next_Log_Conf(plcLogConf, lcLogConf, ulFlags):
#    return CM_Get_Next_Log_Conf.ctypes_function(plcLogConf, lcLogConf, ulFlags)
CM_Get_Next_Log_ConfPrototype = WINFUNCTYPE(CONFIGRET, PLOG_CONF, LOG_CONF, ULONG)
CM_Get_Next_Log_ConfParams = ((1, 'plcLogConf'), (1, 'lcLogConf'), (1, 'ulFlags'))

#def CM_Get_Next_Log_Conf_Ex(plcLogConf, lcLogConf, ulFlags, hMachine):
#    return CM_Get_Next_Log_Conf_Ex.ctypes_function(plcLogConf, lcLogConf, ulFlags, hMachine)
CM_Get_Next_Log_Conf_ExPrototype = WINFUNCTYPE(CONFIGRET, PLOG_CONF, LOG_CONF, ULONG, HMACHINE)
CM_Get_Next_Log_Conf_ExParams = ((1, 'plcLogConf'), (1, 'lcLogConf'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Free_Res_Des_Handle(rdResDes):
#    return CM_Free_Res_Des_Handle.ctypes_function(rdResDes)
CM_Free_Res_Des_HandlePrototype = WINFUNCTYPE(CONFIGRET, RES_DES)
CM_Free_Res_Des_HandleParams = ((1, 'rdResDes'),)

#def CM_Get_Child(pdnDevInst, dnDevInst, ulFlags):
#    return CM_Get_Child.ctypes_function(pdnDevInst, dnDevInst, ulFlags)
CM_Get_ChildPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINST, ULONG)
CM_Get_ChildParams = ((1, 'pdnDevInst'), (1, 'dnDevInst'), (1, 'ulFlags'))

#def CM_Get_Child_Ex(pdnDevInst, dnDevInst, ulFlags, hMachine):
#    return CM_Get_Child_Ex.ctypes_function(pdnDevInst, dnDevInst, ulFlags, hMachine)
CM_Get_Child_ExPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINST, ULONG, HMACHINE)
CM_Get_Child_ExParams = ((1, 'pdnDevInst'), (1, 'dnDevInst'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Get_Next_Res_Des(prdResDes, rdResDes, ForResource, pResourceID, ulFlags):
#    return CM_Get_Next_Res_Des.ctypes_function(prdResDes, rdResDes, ForResource, pResourceID, ulFlags)
CM_Get_Next_Res_DesPrototype = WINFUNCTYPE(CONFIGRET, PRES_DES, RES_DES, RESOURCEID, PRESOURCEID, ULONG)
CM_Get_Next_Res_DesParams = ((1, 'prdResDes'), (1, 'rdResDes'), (1, 'ForResource'), (1, 'pResourceID'), (1, 'ulFlags'))

#def CM_Get_Parent(pdnDevInst, dnDevInst, ulFlags):
#    return CM_Get_Parent.ctypes_function(pdnDevInst, dnDevInst, ulFlags)
CM_Get_ParentPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINST, ULONG)
CM_Get_ParentParams = ((1, 'pdnDevInst'), (1, 'dnDevInst'), (1, 'ulFlags'))

#def CM_Get_Parent_Ex(pdnDevInst, dnDevInst, ulFlags, hMachine):
#    return CM_Get_Parent_Ex.ctypes_function(pdnDevInst, dnDevInst, ulFlags, hMachine)
CM_Get_Parent_ExPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINST, ULONG, HMACHINE)
CM_Get_Parent_ExParams = ((1, 'pdnDevInst'), (1, 'dnDevInst'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Get_Res_Des_Data(rdResDes, Buffer, BufferLen, ulFlags):
#    return CM_Get_Res_Des_Data.ctypes_function(rdResDes, Buffer, BufferLen, ulFlags)
CM_Get_Res_Des_DataPrototype = WINFUNCTYPE(CONFIGRET, RES_DES, PVOID, ULONG, ULONG)
CM_Get_Res_Des_DataParams = ((1, 'rdResDes'), (1, 'Buffer'), (1, 'BufferLen'), (1, 'ulFlags'))

#def CM_Get_Next_Res_Des_Ex(prdResDes, rdResDes, ForResource, pResourceID, ulFlags, hMachine):
#    return CM_Get_Next_Res_Des_Ex.ctypes_function(prdResDes, rdResDes, ForResource, pResourceID, ulFlags, hMachine)
CM_Get_Next_Res_Des_ExPrototype = WINFUNCTYPE(CONFIGRET, PRES_DES, RES_DES, RESOURCEID, PRESOURCEID, ULONG, HMACHINE)
CM_Get_Next_Res_Des_ExParams = ((1, 'prdResDes'), (1, 'rdResDes'), (1, 'ForResource'), (1, 'pResourceID'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Get_Res_Des_Data_Size(pulSize, rdResDes, ulFlags):
#    return CM_Get_Res_Des_Data_Size.ctypes_function(pulSize, rdResDes, ulFlags)
CM_Get_Res_Des_Data_SizePrototype = WINFUNCTYPE(CONFIGRET, PULONG, RES_DES, ULONG)
CM_Get_Res_Des_Data_SizeParams = ((1, 'pulSize'), (1, 'rdResDes'), (1, 'ulFlags'))

#def CM_Get_Res_Des_Data_Size_Ex(pulSize, rdResDes, ulFlags, hMachine):
#    return CM_Get_Res_Des_Data_Size_Ex.ctypes_function(pulSize, rdResDes, ulFlags, hMachine)
CM_Get_Res_Des_Data_Size_ExPrototype = WINFUNCTYPE(CONFIGRET, PULONG, RES_DES, ULONG, HMACHINE)
CM_Get_Res_Des_Data_Size_ExParams = ((1, 'pulSize'), (1, 'rdResDes'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Get_Sibling(pdnDevInst, dnDevInst, ulFlags):
#    return CM_Get_Sibling.ctypes_function(pdnDevInst, dnDevInst, ulFlags)
CM_Get_SiblingPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINST, ULONG)
CM_Get_SiblingParams = ((1, 'pdnDevInst'), (1, 'dnDevInst'), (1, 'ulFlags'))

#def CM_Get_Sibling_Ex(pdnDevInst, dnDevInst, ulFlags, hMachine):
#    return CM_Get_Sibling_Ex.ctypes_function(pdnDevInst, dnDevInst, ulFlags, hMachine)
CM_Get_Sibling_ExPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINST, ULONG, HMACHINE)
CM_Get_Sibling_ExParams = ((1, 'pdnDevInst'), (1, 'dnDevInst'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Get_Version():
#    return CM_Get_Version.ctypes_function()
CM_Get_VersionPrototype = WINFUNCTYPE(WORD)
CM_Get_VersionParams = ()

#def CM_Get_Version_Ex(hMachine):
#    return CM_Get_Version_Ex.ctypes_function(hMachine)
CM_Get_Version_ExPrototype = WINFUNCTYPE(WORD, HMACHINE)
CM_Get_Version_ExParams = ((1, 'hMachine'),)

#def CM_Locate_DevNodeA(pdnDevInst, pDeviceID, ulFlags):
#    return CM_Locate_DevNodeA.ctypes_function(pdnDevInst, pDeviceID, ulFlags)
CM_Locate_DevNodeAPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINSTID_A, ULONG)
CM_Locate_DevNodeAParams = ((1, 'pdnDevInst'), (1, 'pDeviceID'), (1, 'ulFlags'))

#def CM_Locate_DevNodeW(pdnDevInst, pDeviceID, ulFlags):
#    return CM_Locate_DevNodeW.ctypes_function(pdnDevInst, pDeviceID, ulFlags)
CM_Locate_DevNodeWPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINSTID_W, ULONG)
CM_Locate_DevNodeWParams = ((1, 'pdnDevInst'), (1, 'pDeviceID'), (1, 'ulFlags'))

#def CM_Locate_DevNode_ExA(pdnDevInst, pDeviceID, ulFlags, hMachine):
#    return CM_Locate_DevNode_ExA.ctypes_function(pdnDevInst, pDeviceID, ulFlags, hMachine)
CM_Locate_DevNode_ExAPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINSTID_A, ULONG, HMACHINE)
CM_Locate_DevNode_ExAParams = ((1, 'pdnDevInst'), (1, 'pDeviceID'), (1, 'ulFlags'), (1, 'hMachine'))

#def CM_Locate_DevNode_ExW(pdnDevInst, pDeviceID, ulFlags, hMachine):
#    return CM_Locate_DevNode_ExW.ctypes_function(pdnDevInst, pDeviceID, ulFlags, hMachine)
CM_Locate_DevNode_ExWPrototype = WINFUNCTYPE(CONFIGRET, PDEVINST, DEVINSTID_W, ULONG, HMACHINE)
CM_Locate_DevNode_ExWParams = ((1, 'pdnDevInst'), (1, 'pDeviceID'), (1, 'ulFlags'), (1, 'hMachine'))

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

#def CoGetClassObject(rclsid, dwClsContext, pvReserved, riid, ppv):
#    return CoGetClassObject.ctypes_function(rclsid, dwClsContext, pvReserved, riid, ppv)
CoGetClassObjectPrototype = WINFUNCTYPE(HRESULT, REFCLSID, DWORD, LPVOID, REFIID, POINTER(LPVOID))
CoGetClassObjectParams = ((1, 'rclsid'), (1, 'dwClsContext'), (1, 'pvReserved'), (1, 'riid'), (1, 'ppv'))

#def CoGetInterceptor(iidIntercepted, punkOuter, iid, ppv):
#    return CoGetInterceptor.ctypes_function(iidIntercepted, punkOuter, iid, ppv)
CoGetInterceptorPrototype = WINFUNCTYPE(HRESULT, REFIID, POINTER(IUnknown), REFIID, POINTER(PVOID))
CoGetInterceptorParams = ((1, 'iidIntercepted'), (1, 'punkOuter'), (1, 'iid'), (1, 'ppv'))

#def CLSIDFromProgID(lpszProgID, lpclsid):
#    return CLSIDFromProgID.ctypes_function(lpszProgID, lpclsid)
CLSIDFromProgIDPrototype = WINFUNCTYPE(HRESULT, LPCOLESTR, LPCLSID)
CLSIDFromProgIDParams = ((1, 'lpszProgID'), (1, 'lpclsid'))

#def CoTaskMemFree(pv):
#    return CoTaskMemFree.ctypes_function(pv)
CoTaskMemFreePrototype = WINFUNCTYPE(PVOID, LPVOID)
CoTaskMemFreeParams = ((1, 'pv'),)

#def SafeArrayCreate(vt, cDims, rgsabound):
#    return SafeArrayCreate.ctypes_function(vt, cDims, rgsabound)
SafeArrayCreatePrototype = WINFUNCTYPE(LPSAFEARRAY, VARTYPE, UINT, POINTER(SAFEARRAYBOUND))
SafeArrayCreateParams = ((1, 'vt'), (1, 'cDims'), (1, 'rgsabound'))

#def SafeArrayCreateVector(vt, lLbound, cElements):
#    return SafeArrayCreateVector.ctypes_function(vt, lLbound, cElements)
SafeArrayCreateVectorPrototype = WINFUNCTYPE(LPSAFEARRAY, VARTYPE, LONG, ULONG)
SafeArrayCreateVectorParams = ((1, 'vt'), (1, 'lLbound'), (1, 'cElements'))

#def SafeArrayDestroy(psa):
#    return SafeArrayDestroy.ctypes_function(psa)
SafeArrayDestroyPrototype = WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY))
SafeArrayDestroyParams = ((1, 'psa'),)

#def SafeArrayDestroyData(psa):
#    return SafeArrayDestroyData.ctypes_function(psa)
SafeArrayDestroyDataPrototype = WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY))
SafeArrayDestroyDataParams = ((1, 'psa'),)

#def SafeArrayGetElement(psa, rgIndices, pv):
#    return SafeArrayGetElement.ctypes_function(psa, rgIndices, pv)
SafeArrayGetElementPrototype = WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY), POINTER(LONG), PVOID)
SafeArrayGetElementParams = ((1, 'psa'), (1, 'rgIndices'), (1, 'pv'))

#def SafeArrayGetElemsize(psa):
#    return SafeArrayGetElemsize.ctypes_function(psa)
SafeArrayGetElemsizePrototype = WINFUNCTYPE(UINT, POINTER(SAFEARRAY))
SafeArrayGetElemsizeParams = ((1, 'psa'),)

#def SafeArrayGetLBound(psa, nDim, plLbound):
#    return SafeArrayGetLBound.ctypes_function(psa, nDim, plLbound)
SafeArrayGetLBoundPrototype = WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY), UINT, POINTER(LONG))
SafeArrayGetLBoundParams = ((1, 'psa'), (1, 'nDim'), (1, 'plLbound'))

#def SafeArrayGetUBound(psa, nDim, plUbound):
#    return SafeArrayGetUBound.ctypes_function(psa, nDim, plUbound)
SafeArrayGetUBoundPrototype = WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY), UINT, POINTER(LONG))
SafeArrayGetUBoundParams = ((1, 'psa'), (1, 'nDim'), (1, 'plUbound'))

#def SafeArrayGetDim(psa):
#    return SafeArrayGetDim.ctypes_function(psa)
SafeArrayGetDimPrototype = WINFUNCTYPE(UINT, POINTER(SAFEARRAY))
SafeArrayGetDimParams = ((1, 'psa'),)

#def SafeArrayPutElement(psa, rgIndices, pv):
#    return SafeArrayPutElement.ctypes_function(psa, rgIndices, pv)
SafeArrayPutElementPrototype = WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY), POINTER(LONG), PVOID)
SafeArrayPutElementParams = ((1, 'psa'), (1, 'rgIndices'), (1, 'pv'))

#def SafeArrayGetVartype(psa, pvt):
#    return SafeArrayGetVartype.ctypes_function(psa, pvt)
SafeArrayGetVartypePrototype = WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY), POINTER(VARTYPE))
SafeArrayGetVartypeParams = ((1, 'psa'), (1, 'pvt'))

#def SysFreeString(bstrString):
#    return SysFreeString.ctypes_function(bstrString)
SysFreeStringPrototype = WINFUNCTYPE(VOID, BSTR)
SysFreeStringParams = ((1, 'bstrString'),)

#def SafeArrayCopy(psa, ppsaOut):
#    return SafeArrayCopy.ctypes_function(psa, ppsaOut)
SafeArrayCopyPrototype = WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY), POINTER(LPSAFEARRAY))
SafeArrayCopyParams = ((1, 'psa'), (1, 'ppsaOut'))

#def SafeArrayCopyData(psaSource, psaTarget):
#    return SafeArrayCopyData.ctypes_function(psaSource, psaTarget)
SafeArrayCopyDataPrototype = WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY), POINTER(SAFEARRAY))
SafeArrayCopyDataParams = ((1, 'psaSource'), (1, 'psaTarget'))

#def SysAllocString(psz):
#    return SysAllocString.ctypes_function(psz)
SysAllocStringPrototype = WINFUNCTYPE(PVOID, POINTER(OLECHAR))
SysAllocStringParams = ((1, 'psz'),)

#def SysFreeString(bstrString):
#    return SysFreeString.ctypes_function(bstrString)
SysFreeStringPrototype = WINFUNCTYPE(VOID, BSTR)
SysFreeStringParams = ((1, 'bstrString'),)

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

#def CryptCreateHash(hProv, Algid, hKey, dwFlags, phHash):
#    return CryptCreateHash.ctypes_function(hProv, Algid, hKey, dwFlags, phHash)
CryptCreateHashPrototype = WINFUNCTYPE(BOOL, HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, POINTER(HCRYPTHASH))
CryptCreateHashParams = ((1, 'hProv'), (1, 'Algid'), (1, 'hKey'), (1, 'dwFlags'), (1, 'phHash'))

#def CryptHashData(hHash, pbData, dwDataLen, dwFlags):
#    return CryptHashData.ctypes_function(hHash, pbData, dwDataLen, dwFlags)
CryptHashDataPrototype = WINFUNCTYPE(BOOL, HCRYPTHASH, POINTER(BYTE), DWORD, DWORD)
CryptHashDataParams = ((1, 'hHash'), (1, 'pbData'), (1, 'dwDataLen'), (1, 'dwFlags'))

#def CryptGetHashParam(hHash, dwParam, pbData, pdwDataLen, dwFlags):
#    return CryptGetHashParam.ctypes_function(hHash, dwParam, pbData, pdwDataLen, dwFlags)
CryptGetHashParamPrototype = WINFUNCTYPE(BOOL, HCRYPTHASH, DWORD, POINTER(BYTE), POINTER(DWORD), DWORD)
CryptGetHashParamParams = ((1, 'hHash'), (1, 'dwParam'), (1, 'pbData'), (1, 'pdwDataLen'), (1, 'dwFlags'))

#def CryptVerifySignatureA(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags):
#    return CryptVerifySignatureA.ctypes_function(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags)
CryptVerifySignatureAPrototype = WINFUNCTYPE(BOOL, HCRYPTHASH, POINTER(BYTE), DWORD, HCRYPTKEY, LPCSTR, DWORD)
CryptVerifySignatureAParams = ((1, 'hHash'), (1, 'pbSignature'), (1, 'dwSigLen'), (1, 'hPubKey'), (1, 'szDescription'), (1, 'dwFlags'))

#def CryptVerifySignatureW(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags):
#    return CryptVerifySignatureW.ctypes_function(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags)
CryptVerifySignatureWPrototype = WINFUNCTYPE(BOOL, HCRYPTHASH, POINTER(BYTE), DWORD, HCRYPTKEY, LPCWSTR, DWORD)
CryptVerifySignatureWParams = ((1, 'hHash'), (1, 'pbSignature'), (1, 'dwSigLen'), (1, 'hPubKey'), (1, 'szDescription'), (1, 'dwFlags'))

#def CryptSignHashA(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen):
#    return CryptSignHashA.ctypes_function(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen)
CryptSignHashAPrototype = WINFUNCTYPE(BOOL, HCRYPTHASH, DWORD, LPCSTR, DWORD, POINTER(BYTE), POINTER(DWORD))
CryptSignHashAParams = ((1, 'hHash'), (1, 'dwKeySpec'), (1, 'szDescription'), (1, 'dwFlags'), (1, 'pbSignature'), (1, 'pdwSigLen'))

#def CryptSignHashW(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen):
#    return CryptSignHashW.ctypes_function(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen)
CryptSignHashWPrototype = WINFUNCTYPE(BOOL, HCRYPTHASH, DWORD, LPCWSTR, DWORD, POINTER(BYTE), POINTER(DWORD))
CryptSignHashWParams = ((1, 'hHash'), (1, 'dwKeySpec'), (1, 'szDescription'), (1, 'dwFlags'), (1, 'pbSignature'), (1, 'pdwSigLen'))

#def CryptDestroyHash(hHash):
#    return CryptDestroyHash.ctypes_function(hHash)
CryptDestroyHashPrototype = WINFUNCTYPE(BOOL, HCRYPTHASH)
CryptDestroyHashParams = ((1, 'hHash'),)

#def CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen):
#    return CryptEncrypt.ctypes_function(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)
CryptEncryptPrototype = WINFUNCTYPE(BOOL, HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, POINTER(BYTE), POINTER(DWORD), DWORD)
CryptEncryptParams = ((1, 'hKey'), (1, 'hHash'), (1, 'Final'), (1, 'dwFlags'), (1, 'pbData'), (1, 'pdwDataLen'), (1, 'dwBufLen'))

#def CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen):
#    return CryptDecrypt.ctypes_function(hKey, hHash, Final, dwFlags, pbData, pdwDataLen)
CryptDecryptPrototype = WINFUNCTYPE(BOOL, HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, POINTER(BYTE), POINTER(DWORD))
CryptDecryptParams = ((1, 'hKey'), (1, 'hHash'), (1, 'Final'), (1, 'dwFlags'), (1, 'pbData'), (1, 'pdwDataLen'))

#def CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey):
#    return CryptDeriveKey.ctypes_function(hProv, Algid, hBaseData, dwFlags, phKey)
CryptDeriveKeyPrototype = WINFUNCTYPE(BOOL, HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, POINTER(HCRYPTKEY))
CryptDeriveKeyParams = ((1, 'hProv'), (1, 'Algid'), (1, 'hBaseData'), (1, 'dwFlags'), (1, 'phKey'))

#def CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen):
#    return CryptExportKey.ctypes_function(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen)
CryptExportKeyPrototype = WINFUNCTYPE(BOOL, HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, POINTER(BYTE), POINTER(DWORD))
CryptExportKeyParams = ((1, 'hKey'), (1, 'hExpKey'), (1, 'dwBlobType'), (1, 'dwFlags'), (1, 'pbData'), (1, 'pdwDataLen'))

#def CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey):
#    return CryptImportKey.ctypes_function(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey)
CryptImportKeyPrototype = WINFUNCTYPE(BOOL, HCRYPTPROV, POINTER(BYTE), DWORD, HCRYPTKEY, DWORD, POINTER(HCRYPTKEY))
CryptImportKeyParams = ((1, 'hProv'), (1, 'pbData'), (1, 'dwDataLen'), (1, 'hPubKey'), (1, 'dwFlags'), (1, 'phKey'))

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

#def CryptEnumOIDFunction(dwEncodingType, pszFuncName, pszOID, dwFlags, pvArg, pfnEnumOIDFunc):
#    return CryptEnumOIDFunction.ctypes_function(dwEncodingType, pszFuncName, pszOID, dwFlags, pvArg, pfnEnumOIDFunc)
CryptEnumOIDFunctionPrototype = WINFUNCTYPE(BOOL, DWORD, LPCSTR, LPCSTR, DWORD, PVOID, PFN_CRYPT_ENUM_OID_FUNC)
CryptEnumOIDFunctionParams = ((1, 'dwEncodingType'), (1, 'pszFuncName'), (1, 'pszOID'), (1, 'dwFlags'), (1, 'pvArg'), (1, 'pfnEnumOIDFunc'))

#def CryptGetOIDFunctionValue(dwEncodingType, pszFuncName, pszOID, pwszValueName, pdwValueType, pbValueData, pcbValueData):
#    return CryptGetOIDFunctionValue.ctypes_function(dwEncodingType, pszFuncName, pszOID, pwszValueName, pdwValueType, pbValueData, pcbValueData)
CryptGetOIDFunctionValuePrototype = WINFUNCTYPE(BOOL, DWORD, LPCSTR, LPCSTR, LPCWSTR, POINTER(DWORD), POINTER(BYTE), POINTER(DWORD))
CryptGetOIDFunctionValueParams = ((1, 'dwEncodingType'), (1, 'pszFuncName'), (1, 'pszOID'), (1, 'pwszValueName'), (1, 'pdwValueType'), (1, 'pbValueData'), (1, 'pcbValueData'))

#def CertCloseStore(hCertStore, dwFlags):
#    return CertCloseStore.ctypes_function(hCertStore, dwFlags)
CertCloseStorePrototype = WINFUNCTYPE(BOOL, HCERTSTORE, DWORD)
CertCloseStoreParams = ((1, 'hCertStore'), (1, 'dwFlags'))

#def OpenVirtualDisk(VirtualStorageType, Path, VirtualDiskAccessMask, Flags, Parameters, Handle):
#    return OpenVirtualDisk.ctypes_function(VirtualStorageType, Path, VirtualDiskAccessMask, Flags, Parameters, Handle)
OpenVirtualDiskPrototype = WINFUNCTYPE(DWORD, PVIRTUAL_STORAGE_TYPE, PCWSTR, VIRTUAL_DISK_ACCESS_MASK, OPEN_VIRTUAL_DISK_FLAG, POPEN_VIRTUAL_DISK_PARAMETERS, PHANDLE)
OpenVirtualDiskParams = ((1, 'VirtualStorageType'), (1, 'Path'), (1, 'VirtualDiskAccessMask'), (1, 'Flags'), (1, 'Parameters'), (1, 'Handle'))

#def AttachVirtualDisk(VirtualDiskHandle, SecurityDescriptor, Flags, ProviderSpecificFlags, Parameters, Overlapped):
#    return AttachVirtualDisk.ctypes_function(VirtualDiskHandle, SecurityDescriptor, Flags, ProviderSpecificFlags, Parameters, Overlapped)
AttachVirtualDiskPrototype = WINFUNCTYPE(DWORD, HANDLE, PSECURITY_DESCRIPTOR, ATTACH_VIRTUAL_DISK_FLAG, ULONG, PATTACH_VIRTUAL_DISK_PARAMETERS, LPOVERLAPPED)
AttachVirtualDiskParams = ((1, 'VirtualDiskHandle'), (1, 'SecurityDescriptor'), (1, 'Flags'), (1, 'ProviderSpecificFlags'), (1, 'Parameters'), (1, 'Overlapped'))

#def CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut):
#    return CryptProtectData.ctypes_function(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)
CryptProtectDataPrototype = WINFUNCTYPE(BOOL, POINTER(DATA_BLOB), LPCWSTR, POINTER(DATA_BLOB), PVOID, POINTER(CRYPTPROTECT_PROMPTSTRUCT), DWORD, POINTER(DATA_BLOB))
CryptProtectDataParams = ((1, 'pDataIn'), (1, 'szDataDescr'), (1, 'pOptionalEntropy'), (1, 'pvReserved'), (1, 'pPromptStruct'), (1, 'dwFlags'), (1, 'pDataOut'))

#def CryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut):
#    return CryptUnprotectData.ctypes_function(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)
CryptUnprotectDataPrototype = WINFUNCTYPE(BOOL, POINTER(DATA_BLOB), POINTER(LPWSTR), POINTER(DATA_BLOB), PVOID, POINTER(CRYPTPROTECT_PROMPTSTRUCT), DWORD, POINTER(DATA_BLOB))
CryptUnprotectDataParams = ((1, 'pDataIn'), (1, 'ppszDataDescr'), (1, 'pOptionalEntropy'), (1, 'pvReserved'), (1, 'pPromptStruct'), (1, 'dwFlags'), (1, 'pDataOut'))

#def CryptProtectMemory(pDataIn, cbDataIn, dwFlags):
#    return CryptProtectMemory.ctypes_function(pDataIn, cbDataIn, dwFlags)
CryptProtectMemoryPrototype = WINFUNCTYPE(BOOL, LPVOID, DWORD, DWORD)
CryptProtectMemoryParams = ((1, 'pDataIn'), (1, 'cbDataIn'), (1, 'dwFlags'))

#def CryptUnprotectMemory(pDataIn, cbDataIn, dwFlags):
#    return CryptUnprotectMemory.ctypes_function(pDataIn, cbDataIn, dwFlags)
CryptUnprotectMemoryPrototype = WINFUNCTYPE(BOOL, LPVOID, DWORD, DWORD)
CryptUnprotectMemoryParams = ((1, 'pDataIn'), (1, 'cbDataIn'), (1, 'dwFlags'))

#def EnumerateTraceGuidsEx(TraceQueryInfoClass, InBuffer, InBufferSize, OutBuffer, OutBufferSize, ReturnLength):
#    return EnumerateTraceGuidsEx.ctypes_function(TraceQueryInfoClass, InBuffer, InBufferSize, OutBuffer, OutBufferSize, ReturnLength)
EnumerateTraceGuidsExPrototype = WINFUNCTYPE(ULONG, TRACE_QUERY_INFO_CLASS, PVOID, ULONG, PVOID, ULONG, PULONG)
EnumerateTraceGuidsExParams = ((1, 'TraceQueryInfoClass'), (1, 'InBuffer'), (1, 'InBufferSize'), (1, 'OutBuffer'), (1, 'OutBufferSize'), (1, 'ReturnLength'))

#def QueryAllTracesA(PropertyArray, PropertyArrayCount, SessionCount):
#    return QueryAllTracesA.ctypes_function(PropertyArray, PropertyArrayCount, SessionCount)
QueryAllTracesAPrototype = WINFUNCTYPE(ULONG, POINTER(PEVENT_TRACE_PROPERTIES), ULONG, PULONG)
QueryAllTracesAParams = ((1, 'PropertyArray'), (1, 'PropertyArrayCount'), (1, 'SessionCount'))

#def QueryAllTracesW(PropertyArray, PropertyArrayCount, SessionCount):
#    return QueryAllTracesW.ctypes_function(PropertyArray, PropertyArrayCount, SessionCount)
QueryAllTracesWPrototype = WINFUNCTYPE(ULONG, POINTER(PEVENT_TRACE_PROPERTIES), ULONG, PULONG)
QueryAllTracesWParams = ((1, 'PropertyArray'), (1, 'PropertyArrayCount'), (1, 'SessionCount'))

#def OpenTraceA(Logfile):
#    return OpenTraceA.ctypes_function(Logfile)
OpenTraceAPrototype = WINFUNCTYPE(TRACEHANDLE, PEVENT_TRACE_LOGFILEA)
OpenTraceAParams = ((1, 'Logfile'),)

#def OpenTraceW(Logfile):
#    return OpenTraceW.ctypes_function(Logfile)
OpenTraceWPrototype = WINFUNCTYPE(TRACEHANDLE, PEVENT_TRACE_LOGFILEW)
OpenTraceWParams = ((1, 'Logfile'),)

#def StartTraceA(TraceHandle, InstanceName, Properties):
#    return StartTraceA.ctypes_function(TraceHandle, InstanceName, Properties)
StartTraceAPrototype = WINFUNCTYPE(ULONG, PTRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES)
StartTraceAParams = ((1, 'TraceHandle'), (1, 'InstanceName'), (1, 'Properties'))

#def StartTraceW(TraceHandle, InstanceName, Properties):
#    return StartTraceW.ctypes_function(TraceHandle, InstanceName, Properties)
StartTraceWPrototype = WINFUNCTYPE(ULONG, PTRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES)
StartTraceWParams = ((1, 'TraceHandle'), (1, 'InstanceName'), (1, 'Properties'))

#def StopTraceA(TraceHandle, InstanceName, Properties):
#    return StopTraceA.ctypes_function(TraceHandle, InstanceName, Properties)
StopTraceAPrototype = WINFUNCTYPE(ULONG, TRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES)
StopTraceAParams = ((1, 'TraceHandle'), (1, 'InstanceName'), (1, 'Properties'))

#def StopTraceW(TraceHandle, InstanceName, Properties):
#    return StopTraceW.ctypes_function(TraceHandle, InstanceName, Properties)
StopTraceWPrototype = WINFUNCTYPE(ULONG, TRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES)
StopTraceWParams = ((1, 'TraceHandle'), (1, 'InstanceName'), (1, 'Properties'))

#def ControlTraceA(TraceHandle, InstanceName, Properties, ControlCode):
#    return ControlTraceA.ctypes_function(TraceHandle, InstanceName, Properties, ControlCode)
ControlTraceAPrototype = WINFUNCTYPE(ULONG, TRACEHANDLE, LPCSTR, PEVENT_TRACE_PROPERTIES, ULONG)
ControlTraceAParams = ((1, 'TraceHandle'), (1, 'InstanceName'), (1, 'Properties'), (1, 'ControlCode'))

#def ControlTraceW(TraceHandle, InstanceName, Properties, ControlCode):
#    return ControlTraceW.ctypes_function(TraceHandle, InstanceName, Properties, ControlCode)
ControlTraceWPrototype = WINFUNCTYPE(ULONG, TRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES, ULONG)
ControlTraceWParams = ((1, 'TraceHandle'), (1, 'InstanceName'), (1, 'Properties'), (1, 'ControlCode'))

#def ProcessTrace(HandleArray, HandleCount, StartTime, EndTime):
#    return ProcessTrace.ctypes_function(HandleArray, HandleCount, StartTime, EndTime)
ProcessTracePrototype = WINFUNCTYPE(ULONG, PTRACEHANDLE, ULONG, LPFILETIME, LPFILETIME)
ProcessTraceParams = ((1, 'HandleArray'), (1, 'HandleCount'), (1, 'StartTime'), (1, 'EndTime'))

#def EnableTrace(Enable, EnableFlag, EnableLevel, ControlGuid, SessionHandle):
#    return EnableTrace.ctypes_function(Enable, EnableFlag, EnableLevel, ControlGuid, SessionHandle)
EnableTracePrototype = WINFUNCTYPE(ULONG, ULONG, ULONG, ULONG, LPCGUID, TRACEHANDLE)
EnableTraceParams = ((1, 'Enable'), (1, 'EnableFlag'), (1, 'EnableLevel'), (1, 'ControlGuid'), (1, 'SessionHandle'))

#def EnableTraceEx(ProviderId, SourceId, TraceHandle, IsEnabled, Level, MatchAnyKeyword, MatchAllKeyword, EnableProperty, EnableFilterDesc):
#    return EnableTraceEx.ctypes_function(ProviderId, SourceId, TraceHandle, IsEnabled, Level, MatchAnyKeyword, MatchAllKeyword, EnableProperty, EnableFilterDesc)
EnableTraceExPrototype = WINFUNCTYPE(ULONG, LPCGUID, LPCGUID, TRACEHANDLE, ULONG, UCHAR, ULONGLONG, ULONGLONG, ULONG, PEVENT_FILTER_DESCRIPTOR)
EnableTraceExParams = ((1, 'ProviderId'), (1, 'SourceId'), (1, 'TraceHandle'), (1, 'IsEnabled'), (1, 'Level'), (1, 'MatchAnyKeyword'), (1, 'MatchAllKeyword'), (1, 'EnableProperty'), (1, 'EnableFilterDesc'))

#def EnableTraceEx2(TraceHandle, ProviderId, ControlCode, Level, MatchAnyKeyword, MatchAllKeyword, Timeout, EnableParameters):
#    return EnableTraceEx2.ctypes_function(TraceHandle, ProviderId, ControlCode, Level, MatchAnyKeyword, MatchAllKeyword, Timeout, EnableParameters)
EnableTraceEx2Prototype = WINFUNCTYPE(ULONG, TRACEHANDLE, LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, ULONG, PENABLE_TRACE_PARAMETERS)
EnableTraceEx2Params = ((1, 'TraceHandle'), (1, 'ProviderId'), (1, 'ControlCode'), (1, 'Level'), (1, 'MatchAnyKeyword'), (1, 'MatchAllKeyword'), (1, 'Timeout'), (1, 'EnableParameters'))

#def TraceQueryInformation(SessionHandle, InformationClass, TraceInformation, InformationLength, ReturnLength):
#    return TraceQueryInformation.ctypes_function(SessionHandle, InformationClass, TraceInformation, InformationLength, ReturnLength)
TraceQueryInformationPrototype = WINFUNCTYPE(ULONG, TRACEHANDLE, TRACE_QUERY_INFO_CLASS, PVOID, ULONG, PULONG)
TraceQueryInformationParams = ((1, 'SessionHandle'), (1, 'InformationClass'), (1, 'TraceInformation'), (1, 'InformationLength'), (1, 'ReturnLength'))

#def TraceSetInformation(SessionHandle, InformationClass, TraceInformation, InformationLength):
#    return TraceSetInformation.ctypes_function(SessionHandle, InformationClass, TraceInformation, InformationLength)
TraceSetInformationPrototype = WINFUNCTYPE(ULONG, TRACEHANDLE, TRACE_INFO_CLASS, PVOID, ULONG)
TraceSetInformationParams = ((1, 'SessionHandle'), (1, 'InformationClass'), (1, 'TraceInformation'), (1, 'InformationLength'))

#def RegisterTraceGuidsW(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle):
#    return RegisterTraceGuidsW.ctypes_function(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle)
RegisterTraceGuidsWPrototype = WINFUNCTYPE(ULONG, PVOID, PVOID, LPCGUID, ULONG, PTRACE_GUID_REGISTRATION, LPCWSTR, LPCWSTR, PTRACEHANDLE)
RegisterTraceGuidsWParams = ((1, 'RequestAddress'), (1, 'RequestContext'), (1, 'ControlGuid'), (1, 'GuidCount'), (1, 'TraceGuidReg'), (1, 'MofImagePath'), (1, 'MofResourceName'), (1, 'RegistrationHandle'))

#def RegisterTraceGuidsA(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle):
#    return RegisterTraceGuidsA.ctypes_function(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle)
RegisterTraceGuidsAPrototype = WINFUNCTYPE(ULONG, PVOID, PVOID, LPCGUID, ULONG, PTRACE_GUID_REGISTRATION, LPCSTR, LPCSTR, PTRACEHANDLE)
RegisterTraceGuidsAParams = ((1, 'RequestAddress'), (1, 'RequestContext'), (1, 'ControlGuid'), (1, 'GuidCount'), (1, 'TraceGuidReg'), (1, 'MofImagePath'), (1, 'MofResourceName'), (1, 'RegistrationHandle'))

#def TraceEvent(SessionHandle, EventTrace):
#    return TraceEvent.ctypes_function(SessionHandle, EventTrace)
TraceEventPrototype = WINFUNCTYPE(ULONG, TRACEHANDLE, PEVENT_TRACE_HEADER)
TraceEventParams = ((1, 'SessionHandle'), (1, 'EventTrace'))

#def GetTraceLoggerHandle(Buffer):
#    return GetTraceLoggerHandle.ctypes_function(Buffer)
GetTraceLoggerHandlePrototype = WINFUNCTYPE(TRACEHANDLE, PVOID)
GetTraceLoggerHandleParams = ((1, 'Buffer'),)

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

#def EvtOpenSession(LoginClass, Login, Timeout, Flags):
#    return EvtOpenSession.ctypes_function(LoginClass, Login, Timeout, Flags)
EvtOpenSessionPrototype = WINFUNCTYPE(EVT_HANDLE, EVT_LOGIN_CLASS, PVOID, DWORD, DWORD)
EvtOpenSessionParams = ((1, 'LoginClass'), (1, 'Login'), (1, 'Timeout'), (1, 'Flags'))

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

#def EvtSeek(ResultSet, Position, Bookmark, Timeout, Flags):
#    return EvtSeek.ctypes_function(ResultSet, Position, Bookmark, Timeout, Flags)
EvtSeekPrototype = WINFUNCTYPE(BOOL, EVT_HANDLE, LONGLONG, EVT_HANDLE, DWORD, DWORD)
EvtSeekParams = ((1, 'ResultSet'), (1, 'Position'), (1, 'Bookmark'), (1, 'Timeout'), (1, 'Flags'))

#def FindFirstFileA(lpFileName, lpFindFileData):
#    return FindFirstFileA.ctypes_function(lpFileName, lpFindFileData)
FindFirstFileAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, LPWIN32_FIND_DATAA)
FindFirstFileAParams = ((1, 'lpFileName'), (1, 'lpFindFileData'))

#def FindFirstFileW(lpFileName, lpFindFileData):
#    return FindFirstFileW.ctypes_function(lpFileName, lpFindFileData)
FindFirstFileWPrototype = WINFUNCTYPE(HANDLE, LPCWSTR, LPWIN32_FIND_DATAW)
FindFirstFileWParams = ((1, 'lpFileName'), (1, 'lpFindFileData'))

#def FindNextFileA(hFindFile, lpFindFileData):
#    return FindNextFileA.ctypes_function(hFindFile, lpFindFileData)
FindNextFileAPrototype = WINFUNCTYPE(BOOL, HANDLE, LPWIN32_FIND_DATAA)
FindNextFileAParams = ((1, 'hFindFile'), (1, 'lpFindFileData'))

#def FindNextFileW(hFindFile, lpFindFileData):
#    return FindNextFileW.ctypes_function(hFindFile, lpFindFileData)
FindNextFileWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPWIN32_FIND_DATAW)
FindNextFileWParams = ((1, 'hFindFile'), (1, 'lpFindFileData'))

#def FindClose(hFindFile):
#    return FindClose.ctypes_function(hFindFile)
FindClosePrototype = WINFUNCTYPE(BOOL, HANDLE)
FindCloseParams = ((1, 'hFindFile'),)

#def FindFirstChangeNotificationA(lpPathName, bWatchSubtree, dwNotifyFilter):
#    return FindFirstChangeNotificationA.ctypes_function(lpPathName, bWatchSubtree, dwNotifyFilter)
FindFirstChangeNotificationAPrototype = WINFUNCTYPE(HANDLE, LPCSTR, BOOL, DWORD)
FindFirstChangeNotificationAParams = ((1, 'lpPathName'), (1, 'bWatchSubtree'), (1, 'dwNotifyFilter'))

#def FindFirstChangeNotificationW(lpPathName, bWatchSubtree, dwNotifyFilter):
#    return FindFirstChangeNotificationW.ctypes_function(lpPathName, bWatchSubtree, dwNotifyFilter)
FindFirstChangeNotificationWPrototype = WINFUNCTYPE(HANDLE, LPCWSTR, BOOL, DWORD)
FindFirstChangeNotificationWParams = ((1, 'lpPathName'), (1, 'bWatchSubtree'), (1, 'dwNotifyFilter'))

#def FindNextChangeNotification(hChangeHandle):
#    return FindNextChangeNotification.ctypes_function(hChangeHandle)
FindNextChangeNotificationPrototype = WINFUNCTYPE(BOOL, HANDLE)
FindNextChangeNotificationParams = ((1, 'hChangeHandle'),)

#def FindCloseChangeNotification(hChangeHandle):
#    return FindCloseChangeNotification.ctypes_function(hChangeHandle)
FindCloseChangeNotificationPrototype = WINFUNCTYPE(BOOL, HANDLE)
FindCloseChangeNotificationParams = ((1, 'hChangeHandle'),)

#def FindNextChangeNotification(hChangeHandle):
#    return FindNextChangeNotification.ctypes_function(hChangeHandle)
FindNextChangeNotificationPrototype = WINFUNCTYPE(BOOL, HANDLE)
FindNextChangeNotificationParams = ((1, 'hChangeHandle'),)

#def ReadDirectoryChangesW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine):
#    return ReadDirectoryChangesW.ctypes_function(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine)
ReadDirectoryChangesWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, DWORD, BOOL, DWORD, LPDWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE)
ReadDirectoryChangesWParams = ((1, 'hDirectory'), (1, 'lpBuffer'), (1, 'nBufferLength'), (1, 'bWatchSubtree'), (1, 'dwNotifyFilter'), (1, 'lpBytesReturned'), (1, 'lpOverlapped'), (1, 'lpCompletionRoutine'))

#def ReadDirectoryChangesExW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine, ReadDirectoryNotifyInformationClass):
#    return ReadDirectoryChangesExW.ctypes_function(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine, ReadDirectoryNotifyInformationClass)
ReadDirectoryChangesExWPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, DWORD, BOOL, DWORD, LPDWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE, READ_DIRECTORY_NOTIFY_INFORMATION_CLASS)
ReadDirectoryChangesExWParams = ((1, 'hDirectory'), (1, 'lpBuffer'), (1, 'nBufferLength'), (1, 'bWatchSubtree'), (1, 'dwNotifyFilter'), (1, 'lpBytesReturned'), (1, 'lpOverlapped'), (1, 'lpCompletionRoutine'), (1, 'ReadDirectoryNotifyInformationClass'))

#def HeapAlloc(hHeap, dwFlags, dwBytes):
#    return HeapAlloc.ctypes_function(hHeap, dwFlags, dwBytes)
HeapAllocPrototype = WINFUNCTYPE(LPVOID, HANDLE, DWORD, SIZE_T)
HeapAllocParams = ((1, 'hHeap'), (1, 'dwFlags'), (1, 'dwBytes'))

#def InternetCheckConnectionA(lpszUrl, dwFlags, dwReserved):
#    return InternetCheckConnectionA.ctypes_function(lpszUrl, dwFlags, dwReserved)
InternetCheckConnectionAPrototype = WINFUNCTYPE(BOOL, LPCSTR, DWORD, DWORD)
InternetCheckConnectionAParams = ((1, 'lpszUrl'), (1, 'dwFlags'), (1, 'dwReserved'))

#def InternetCheckConnectionW(lpszUrl, dwFlags, dwReserved):
#    return InternetCheckConnectionW.ctypes_function(lpszUrl, dwFlags, dwReserved)
InternetCheckConnectionWPrototype = WINFUNCTYPE(BOOL, LPCWSTR, DWORD, DWORD)
InternetCheckConnectionWParams = ((1, 'lpszUrl'), (1, 'dwFlags'), (1, 'dwReserved'))

#def InternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags):
#    return InternetOpenA.ctypes_function(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags)
InternetOpenAPrototype = WINFUNCTYPE(HINTERNET, LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD)
InternetOpenAParams = ((1, 'lpszAgent'), (1, 'dwAccessType'), (1, 'lpszProxy'), (1, 'lpszProxyBypass'), (1, 'dwFlags'))

#def InternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags):
#    return InternetOpenW.ctypes_function(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags)
InternetOpenWPrototype = WINFUNCTYPE(HINTERNET, LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD)
InternetOpenWParams = ((1, 'lpszAgent'), (1, 'dwAccessType'), (1, 'lpszProxy'), (1, 'lpszProxyBypass'), (1, 'dwFlags'))

#def InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
#    return InternetOpenUrlA.ctypes_function(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext)
InternetOpenUrlAPrototype = WINFUNCTYPE(HINTERNET, HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR)
InternetOpenUrlAParams = ((1, 'hInternet'), (1, 'lpszUrl'), (1, 'lpszHeaders'), (1, 'dwHeadersLength'), (1, 'dwFlags'), (1, 'dwContext'))

#def InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
#    return InternetOpenUrlW.ctypes_function(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext)
InternetOpenUrlWPrototype = WINFUNCTYPE(HINTERNET, HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR)
InternetOpenUrlWParams = ((1, 'hInternet'), (1, 'lpszUrl'), (1, 'lpszHeaders'), (1, 'dwHeadersLength'), (1, 'dwFlags'), (1, 'dwContext'))

#def InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
#    return InternetConnectA.ctypes_function(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)
InternetConnectAPrototype = WINFUNCTYPE(HINTERNET, HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR)
InternetConnectAParams = ((1, 'hInternet'), (1, 'lpszServerName'), (1, 'nServerPort'), (1, 'lpszUserName'), (1, 'lpszPassword'), (1, 'dwService'), (1, 'dwFlags'), (1, 'dwContext'))

#def InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
#    return InternetConnectW.ctypes_function(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)
InternetConnectWPrototype = WINFUNCTYPE(HINTERNET, HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR)
InternetConnectWParams = ((1, 'hInternet'), (1, 'lpszServerName'), (1, 'nServerPort'), (1, 'lpszUserName'), (1, 'lpszPassword'), (1, 'dwService'), (1, 'dwFlags'), (1, 'dwContext'))

#def HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
#    return HttpOpenRequestA.ctypes_function(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)
HttpOpenRequestAPrototype = WINFUNCTYPE(HINTERNET, HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, POINTER(LPCSTR), DWORD, DWORD_PTR)
HttpOpenRequestAParams = ((1, 'hConnect'), (1, 'lpszVerb'), (1, 'lpszObjectName'), (1, 'lpszVersion'), (1, 'lpszReferrer'), (1, 'lplpszAcceptTypes'), (1, 'dwFlags'), (1, 'dwContext'))

#def HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
#    return HttpOpenRequestW.ctypes_function(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)
HttpOpenRequestWPrototype = WINFUNCTYPE(HINTERNET, HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, POINTER(LPCWSTR), DWORD, DWORD_PTR)
HttpOpenRequestWParams = ((1, 'hConnect'), (1, 'lpszVerb'), (1, 'lpszObjectName'), (1, 'lpszVersion'), (1, 'lpszReferrer'), (1, 'lplpszAcceptTypes'), (1, 'dwFlags'), (1, 'dwContext'))

#def InternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength):
#    return InternetSetOptionA.ctypes_function(hInternet, dwOption, lpBuffer, dwBufferLength)
InternetSetOptionAPrototype = WINFUNCTYPE(BOOL, HINTERNET, DWORD, LPVOID, DWORD)
InternetSetOptionAParams = ((1, 'hInternet'), (1, 'dwOption'), (1, 'lpBuffer'), (1, 'dwBufferLength'))

#def InternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength):
#    return InternetSetOptionW.ctypes_function(hInternet, dwOption, lpBuffer, dwBufferLength)
InternetSetOptionWPrototype = WINFUNCTYPE(BOOL, HINTERNET, DWORD, LPVOID, DWORD)
InternetSetOptionWParams = ((1, 'hInternet'), (1, 'dwOption'), (1, 'lpBuffer'), (1, 'dwBufferLength'))

#def HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
#    return HttpSendRequestA.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
HttpSendRequestAPrototype = WINFUNCTYPE(BOOL, HINTERNET, LPCSTR, DWORD, LPVOID, DWORD)
HttpSendRequestAParams = ((1, 'hRequest'), (1, 'lpszHeaders'), (1, 'dwHeadersLength'), (1, 'lpOptional'), (1, 'dwOptionalLength'))

#def HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
#    return HttpSendRequestW.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
HttpSendRequestWPrototype = WINFUNCTYPE(BOOL, HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD)
HttpSendRequestWParams = ((1, 'hRequest'), (1, 'lpszHeaders'), (1, 'dwHeadersLength'), (1, 'lpOptional'), (1, 'dwOptionalLength'))

#def InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead):
#    return InternetReadFile.ctypes_function(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)
InternetReadFilePrototype = WINFUNCTYPE(BOOL, HINTERNET, LPVOID, DWORD, LPDWORD)
InternetReadFileParams = ((1, 'hFile'), (1, 'lpBuffer'), (1, 'dwNumberOfBytesToRead'), (1, 'lpdwNumberOfBytesRead'))

#def InternetReadFileExA(hFile, lpBuffersOut, dwFlags, dwContext):
#    return InternetReadFileExA.ctypes_function(hFile, lpBuffersOut, dwFlags, dwContext)
InternetReadFileExAPrototype = WINFUNCTYPE(BOOL, HINTERNET, LPINTERNET_BUFFERSA, DWORD, DWORD_PTR)
InternetReadFileExAParams = ((1, 'hFile'), (1, 'lpBuffersOut'), (1, 'dwFlags'), (1, 'dwContext'))

#def InternetReadFileExW(hFile, lpBuffersOut, dwFlags, dwContext):
#    return InternetReadFileExW.ctypes_function(hFile, lpBuffersOut, dwFlags, dwContext)
InternetReadFileExWPrototype = WINFUNCTYPE(BOOL, HINTERNET, LPINTERNET_BUFFERSW, DWORD, DWORD_PTR)
InternetReadFileExWParams = ((1, 'hFile'), (1, 'lpBuffersOut'), (1, 'dwFlags'), (1, 'dwContext'))

#def HttpQueryInfoA(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex):
#    return HttpQueryInfoA.ctypes_function(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex)
HttpQueryInfoAPrototype = WINFUNCTYPE(BOOL, HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD)
HttpQueryInfoAParams = ((1, 'hRequest'), (1, 'dwInfoLevel'), (1, 'lpBuffer'), (1, 'lpdwBufferLength'), (1, 'lpdwIndex'))

#def HttpQueryInfoW(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex):
#    return HttpQueryInfoW.ctypes_function(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex)
HttpQueryInfoWPrototype = WINFUNCTYPE(BOOL, HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD)
HttpQueryInfoWParams = ((1, 'hRequest'), (1, 'dwInfoLevel'), (1, 'lpBuffer'), (1, 'lpdwBufferLength'), (1, 'lpdwIndex'))

#def HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
#    return HttpSendRequestA.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
HttpSendRequestAPrototype = WINFUNCTYPE(BOOL, HINTERNET, LPCSTR, DWORD, LPVOID, DWORD)
HttpSendRequestAParams = ((1, 'hRequest'), (1, 'lpszHeaders'), (1, 'dwHeadersLength'), (1, 'lpOptional'), (1, 'dwOptionalLength'))

#def HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):
#    return HttpSendRequestW.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
HttpSendRequestWPrototype = WINFUNCTYPE(BOOL, HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD)
HttpSendRequestWParams = ((1, 'hRequest'), (1, 'lpszHeaders'), (1, 'dwHeadersLength'), (1, 'lpOptional'), (1, 'dwOptionalLength'))

#def WinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags):
#    return WinHttpOpen.ctypes_function(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags)
WinHttpOpenPrototype = WINFUNCTYPE(HINTERNET, LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD)
WinHttpOpenParams = ((1, 'pszAgentW'), (1, 'dwAccessType'), (1, 'pszProxyW'), (1, 'pszProxyBypassW'), (1, 'dwFlags'))

#def WinHttpCloseHandle(hInternet):
#    return WinHttpCloseHandle.ctypes_function(hInternet)
WinHttpCloseHandlePrototype = WINFUNCTYPE(BOOL, HINTERNET)
WinHttpCloseHandleParams = ((1, 'hInternet'),)

#def WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved):
#    return WinHttpConnect.ctypes_function(hSession, pswzServerName, nServerPort, dwReserved)
WinHttpConnectPrototype = WINFUNCTYPE(HINTERNET, HINTERNET, LPCWSTR, INTERNET_PORT, DWORD)
WinHttpConnectParams = ((1, 'hSession'), (1, 'pswzServerName'), (1, 'nServerPort'), (1, 'dwReserved'))

#def WinHttpQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable):
#    return WinHttpQueryDataAvailable.ctypes_function(hRequest, lpdwNumberOfBytesAvailable)
WinHttpQueryDataAvailablePrototype = WINFUNCTYPE(BOOL, HINTERNET, LPDWORD)
WinHttpQueryDataAvailableParams = ((1, 'hRequest'), (1, 'lpdwNumberOfBytesAvailable'))

#def WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead):
#    return WinHttpReadData.ctypes_function(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)
WinHttpReadDataPrototype = WINFUNCTYPE(BOOL, HINTERNET, LPVOID, DWORD, LPDWORD)
WinHttpReadDataParams = ((1, 'hRequest'), (1, 'lpBuffer'), (1, 'dwNumberOfBytesToRead'), (1, 'lpdwNumberOfBytesRead'))

#def WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags):
#    return WinHttpOpenRequest.ctypes_function(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags)
WinHttpOpenRequestPrototype = WINFUNCTYPE(HINTERNET, HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, POINTER(LPCWSTR), DWORD)
WinHttpOpenRequestParams = ((1, 'hConnect'), (1, 'pwszVerb'), (1, 'pwszObjectName'), (1, 'pwszVersion'), (1, 'pwszReferrer'), (1, 'ppwszAcceptTypes'), (1, 'dwFlags'))

#def WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext):
#    return WinHttpSendRequest.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext)
WinHttpSendRequestPrototype = WINFUNCTYPE(BOOL, HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR)
WinHttpSendRequestParams = ((1, 'hRequest'), (1, 'lpszHeaders'), (1, 'dwHeadersLength'), (1, 'lpOptional'), (1, 'dwOptionalLength'), (1, 'dwTotalLength'), (1, 'dwContext'))

#def WinHttpReceiveResponse(hRequest, lpReserved):
#    return WinHttpReceiveResponse.ctypes_function(hRequest, lpReserved)
WinHttpReceiveResponsePrototype = WINFUNCTYPE(BOOL, HINTERNET, LPVOID)
WinHttpReceiveResponseParams = ((1, 'hRequest'), (1, 'lpReserved'))

#def WinHttpAddRequestHeaders(hRequest, lpszHeaders, dwHeadersLength, dwModifiers):
#    return WinHttpAddRequestHeaders.ctypes_function(hRequest, lpszHeaders, dwHeadersLength, dwModifiers)
WinHttpAddRequestHeadersPrototype = WINFUNCTYPE(BOOL, HINTERNET, LPCWSTR, DWORD, DWORD)
WinHttpAddRequestHeadersParams = ((1, 'hRequest'), (1, 'lpszHeaders'), (1, 'dwHeadersLength'), (1, 'dwModifiers'))

#def WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex):
#    return WinHttpQueryHeaders.ctypes_function(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex)
WinHttpQueryHeadersPrototype = WINFUNCTYPE(BOOL, HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD)
WinHttpQueryHeadersParams = ((1, 'hRequest'), (1, 'dwInfoLevel'), (1, 'pwszName'), (1, 'lpBuffer'), (1, 'lpdwBufferLength'), (1, 'lpdwIndex'))

#def LsaOpenPolicy(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle):
#    return LsaOpenPolicy.ctypes_function(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle)
LsaOpenPolicyPrototype = WINFUNCTYPE(NTSTATUS, PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE)
LsaOpenPolicyParams = ((1, 'SystemName'), (1, 'ObjectAttributes'), (1, 'DesiredAccess'), (1, 'PolicyHandle'))

#def LsaQueryInformationPolicy(PolicyHandle, InformationClass, Buffer):
#    return LsaQueryInformationPolicy.ctypes_function(PolicyHandle, InformationClass, Buffer)
LsaQueryInformationPolicyPrototype = WINFUNCTYPE(NTSTATUS, LSA_HANDLE, POLICY_INFORMATION_CLASS, POINTER(PVOID))
LsaQueryInformationPolicyParams = ((1, 'PolicyHandle'), (1, 'InformationClass'), (1, 'Buffer'))

#def LsaClose(ObjectHandle):
#    return LsaClose.ctypes_function(ObjectHandle)
LsaClosePrototype = WINFUNCTYPE(NTSTATUS, LSA_HANDLE)
LsaCloseParams = ((1, 'ObjectHandle'),)

#def LsaNtStatusToWinError(Status):
#    return LsaNtStatusToWinError.ctypes_function(Status)
LsaNtStatusToWinErrorPrototype = WINFUNCTYPE(ULONG, NTSTATUS)
LsaNtStatusToWinErrorParams = ((1, 'Status'),)

#def LsaLookupNames(PolicyHandle, Count, Names, ReferencedDomains, Sids):
#    return LsaLookupNames.ctypes_function(PolicyHandle, Count, Names, ReferencedDomains, Sids)
LsaLookupNamesPrototype = WINFUNCTYPE(NTSTATUS, LSA_HANDLE, ULONG, PLSA_UNICODE_STRING, POINTER(PLSA_REFERENCED_DOMAIN_LIST), POINTER(PLSA_TRANSLATED_SID))
LsaLookupNamesParams = ((1, 'PolicyHandle'), (1, 'Count'), (1, 'Names'), (1, 'ReferencedDomains'), (1, 'Sids'))

#def LsaLookupNames2(PolicyHandle, Flags, Count, Names, ReferencedDomains, Sids):
#    return LsaLookupNames2.ctypes_function(PolicyHandle, Flags, Count, Names, ReferencedDomains, Sids)
LsaLookupNames2Prototype = WINFUNCTYPE(NTSTATUS, LSA_HANDLE, ULONG, ULONG, PLSA_UNICODE_STRING, POINTER(PLSA_REFERENCED_DOMAIN_LIST), POINTER(PLSA_TRANSLATED_SID2))
LsaLookupNames2Params = ((1, 'PolicyHandle'), (1, 'Flags'), (1, 'Count'), (1, 'Names'), (1, 'ReferencedDomains'), (1, 'Sids'))

#def LsaLookupSids(PolicyHandle, Count, Sids, ReferencedDomains, Names):
#    return LsaLookupSids.ctypes_function(PolicyHandle, Count, Sids, ReferencedDomains, Names)
LsaLookupSidsPrototype = WINFUNCTYPE(NTSTATUS, LSA_HANDLE, ULONG, POINTER(PSID), POINTER(PLSA_REFERENCED_DOMAIN_LIST), POINTER(PLSA_TRANSLATED_NAME))
LsaLookupSidsParams = ((1, 'PolicyHandle'), (1, 'Count'), (1, 'Sids'), (1, 'ReferencedDomains'), (1, 'Names'))

#def LsaLookupSids2(PolicyHandle, LookupOptions, Count, Sids, ReferencedDomains, Names):
#    return LsaLookupSids2.ctypes_function(PolicyHandle, LookupOptions, Count, Sids, ReferencedDomains, Names)
LsaLookupSids2Prototype = WINFUNCTYPE(NTSTATUS, LSA_HANDLE, ULONG, ULONG, POINTER(PSID), POINTER(PLSA_REFERENCED_DOMAIN_LIST), POINTER(PLSA_TRANSLATED_NAME))
LsaLookupSids2Params = ((1, 'PolicyHandle'), (1, 'LookupOptions'), (1, 'Count'), (1, 'Sids'), (1, 'ReferencedDomains'), (1, 'Names'))

#def OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName):
#    return OpenFileMappingW.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)
OpenFileMappingWPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCWSTR)
OpenFileMappingWParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

#def OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName):
#    return OpenFileMappingA.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)
OpenFileMappingAPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCSTR)
OpenFileMappingAParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

#def UnmapViewOfFile(lpBaseAddress):
#    return UnmapViewOfFile.ctypes_function(lpBaseAddress)
UnmapViewOfFilePrototype = WINFUNCTYPE(BOOL, LPCVOID)
UnmapViewOfFileParams = ((1, 'lpBaseAddress'),)

#def NetLocalGroupGetMembers(servername, localgroupname, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle):
#    return NetLocalGroupGetMembers.ctypes_function(servername, localgroupname, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)
NetLocalGroupGetMembersPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, LPCWSTR, DWORD, POINTER(LPBYTE), DWORD, LPDWORD, LPDWORD, PDWORD_PTR)
NetLocalGroupGetMembersParams = ((1, 'servername'), (1, 'localgroupname'), (1, 'level'), (1, 'bufptr'), (1, 'prefmaxlen'), (1, 'entriesread'), (1, 'totalentries'), (1, 'resumehandle'))

#def NetQueryDisplayInformation(ServerName, Level, Index, EntriesRequested, PreferredMaximumLength, ReturnedEntryCount, SortedBuffer):
#    return NetQueryDisplayInformation.ctypes_function(ServerName, Level, Index, EntriesRequested, PreferredMaximumLength, ReturnedEntryCount, SortedBuffer)
NetQueryDisplayInformationPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPDWORD, POINTER(PVOID))
NetQueryDisplayInformationParams = ((1, 'ServerName'), (1, 'Level'), (1, 'Index'), (1, 'EntriesRequested'), (1, 'PreferredMaximumLength'), (1, 'ReturnedEntryCount'), (1, 'SortedBuffer'))

#def NetUserEnum(servername, level, filter, bufptr, prefmaxlen, entriesread, totalentries, resume_handle):
#    return NetUserEnum.ctypes_function(servername, level, filter, bufptr, prefmaxlen, entriesread, totalentries, resume_handle)
NetUserEnumPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, DWORD, DWORD, POINTER(LPBYTE), DWORD, LPDWORD, LPDWORD, PDWORD)
NetUserEnumParams = ((1, 'servername'), (1, 'level'), (1, 'filter'), (1, 'bufptr'), (1, 'prefmaxlen'), (1, 'entriesread'), (1, 'totalentries'), (1, 'resume_handle'))

#def NetGroupEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle):
#    return NetGroupEnum.ctypes_function(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle)
NetGroupEnumPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, DWORD, POINTER(LPBYTE), DWORD, LPDWORD, LPDWORD, PDWORD_PTR)
NetGroupEnumParams = ((1, 'servername'), (1, 'level'), (1, 'bufptr'), (1, 'prefmaxlen'), (1, 'entriesread'), (1, 'totalentries'), (1, 'resume_handle'))

#def NetGroupGetInfo(servername, groupname, level, bufptr):
#    return NetGroupGetInfo.ctypes_function(servername, groupname, level, bufptr)
NetGroupGetInfoPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, LPCWSTR, DWORD, POINTER(LPBYTE))
NetGroupGetInfoParams = ((1, 'servername'), (1, 'groupname'), (1, 'level'), (1, 'bufptr'))

#def NetGroupGetUsers(servername, groupname, level, bufptr, prefmaxlen, entriesread, totalentries, ResumeHandle):
#    return NetGroupGetUsers.ctypes_function(servername, groupname, level, bufptr, prefmaxlen, entriesread, totalentries, ResumeHandle)
NetGroupGetUsersPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, LPCWSTR, DWORD, POINTER(LPBYTE), DWORD, LPDWORD, LPDWORD, PDWORD_PTR)
NetGroupGetUsersParams = ((1, 'servername'), (1, 'groupname'), (1, 'level'), (1, 'bufptr'), (1, 'prefmaxlen'), (1, 'entriesread'), (1, 'totalentries'), (1, 'ResumeHandle'))

#def NetLocalGroupEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle):
#    return NetLocalGroupEnum.ctypes_function(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)
NetLocalGroupEnumPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, DWORD, POINTER(LPBYTE), DWORD, LPDWORD, LPDWORD, PDWORD_PTR)
NetLocalGroupEnumParams = ((1, 'servername'), (1, 'level'), (1, 'bufptr'), (1, 'prefmaxlen'), (1, 'entriesread'), (1, 'totalentries'), (1, 'resumehandle'))

#def NetLocalGroupGetInfo(servername, groupname, level, bufptr):
#    return NetLocalGroupGetInfo.ctypes_function(servername, groupname, level, bufptr)
NetLocalGroupGetInfoPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, LPCWSTR, DWORD, POINTER(LPBYTE))
NetLocalGroupGetInfoParams = ((1, 'servername'), (1, 'groupname'), (1, 'level'), (1, 'bufptr'))

#def NetLocalGroupGetMembers(servername, localgroupname, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle):
#    return NetLocalGroupGetMembers.ctypes_function(servername, localgroupname, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)
NetLocalGroupGetMembersPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, LPCWSTR, DWORD, POINTER(LPBYTE), DWORD, LPDWORD, LPDWORD, PDWORD_PTR)
NetLocalGroupGetMembersParams = ((1, 'servername'), (1, 'localgroupname'), (1, 'level'), (1, 'bufptr'), (1, 'prefmaxlen'), (1, 'entriesread'), (1, 'totalentries'), (1, 'resumehandle'))

#def NetLocalGroupGetInfo(servername, groupname, level, bufptr):
#    return NetLocalGroupGetInfo.ctypes_function(servername, groupname, level, bufptr)
NetLocalGroupGetInfoPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, LPCWSTR, DWORD, POINTER(LPBYTE))
NetLocalGroupGetInfoParams = ((1, 'servername'), (1, 'groupname'), (1, 'level'), (1, 'bufptr'))

#def NetLocalGroupEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle):
#    return NetLocalGroupEnum.ctypes_function(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)
NetLocalGroupEnumPrototype = WINFUNCTYPE(NET_API_STATUS, LPCWSTR, DWORD, POINTER(LPBYTE), DWORD, LPDWORD, LPDWORD, PDWORD_PTR)
NetLocalGroupEnumParams = ((1, 'servername'), (1, 'level'), (1, 'bufptr'), (1, 'prefmaxlen'), (1, 'entriesread'), (1, 'totalentries'), (1, 'resumehandle'))

#def NetApiBufferFree(Buffer):
#    return NetApiBufferFree.ctypes_function(Buffer)
NetApiBufferFreePrototype = WINFUNCTYPE(NET_API_STATUS, LPVOID)
NetApiBufferFreeParams = ((1, 'Buffer'),)

#def GetIpNetTable(IpNetTable, SizePointer, Order):
#    return GetIpNetTable.ctypes_function(IpNetTable, SizePointer, Order)
GetIpNetTablePrototype = WINFUNCTYPE(ULONG, PMIB_IPNETTABLE, PULONG, BOOL)
GetIpNetTableParams = ((1, 'IpNetTable'), (1, 'SizePointer'), (1, 'Order'))

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

#def DnsGetCacheDataTable(DnsEntries):
#    return DnsGetCacheDataTable.ctypes_function(DnsEntries)
DnsGetCacheDataTablePrototype = WINFUNCTYPE(DWORD, POINTER(PDNS_CACHE_ENTRY))
DnsGetCacheDataTableParams = ((1, 'DnsEntries'),)

#def DnsFree(pData, FreeType):
#    return DnsFree.ctypes_function(pData, FreeType)
DnsFreePrototype = WINFUNCTYPE(VOID, PVOID, DNS_FREE_TYPE)
DnsFreeParams = ((1, 'pData'), (1, 'FreeType'))

#def DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved):
#    return DnsQuery_A.ctypes_function(pszName, wType, Options, pExtra, ppQueryResults, pReserved)
DnsQuery_APrototype = WINFUNCTYPE(DNS_STATUS, PCSTR, WORD, DWORD, PVOID, POINTER(PDNS_RECORDA), POINTER(PVOID))
DnsQuery_AParams = ((1, 'pszName'), (1, 'wType'), (1, 'Options'), (1, 'pExtra'), (1, 'ppQueryResults'), (1, 'pReserved'))

#def DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved):
#    return DnsQuery_W.ctypes_function(pszName, wType, Options, pExtra, ppQueryResults, pReserved)
DnsQuery_WPrototype = WINFUNCTYPE(DNS_STATUS, PCWSTR, WORD, DWORD, PVOID, POINTER(PDNS_RECORDW), POINTER(PVOID))
DnsQuery_WParams = ((1, 'pszName'), (1, 'wType'), (1, 'Options'), (1, 'pExtra'), (1, 'ppQueryResults'), (1, 'pReserved'))

#def DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle):
#    return DnsQueryEx.ctypes_function(pQueryRequest, pQueryResults, pCancelHandle)
DnsQueryExPrototype = WINFUNCTYPE(DNS_STATUS, PDNS_QUERY_REQUEST, PDNS_QUERY_RESULT, PDNS_QUERY_CANCEL)
DnsQueryExParams = ((1, 'pQueryRequest'), (1, 'pQueryResults'), (1, 'pCancelHandle'))

#def GetAdaptersInfo(AdapterInfo, SizePointer):
#    return GetAdaptersInfo.ctypes_function(AdapterInfo, SizePointer)
GetAdaptersInfoPrototype = WINFUNCTYPE(ULONG, PIP_ADAPTER_INFO, PULONG)
GetAdaptersInfoParams = ((1, 'AdapterInfo'), (1, 'SizePointer'))

#def GetPerAdapterInfo(IfIndex, pPerAdapterInfo, pOutBufLen):
#    return GetPerAdapterInfo.ctypes_function(IfIndex, pPerAdapterInfo, pOutBufLen)
GetPerAdapterInfoPrototype = WINFUNCTYPE(DWORD, ULONG, PIP_PER_ADAPTER_INFO, PULONG)
GetPerAdapterInfoParams = ((1, 'IfIndex'), (1, 'pPerAdapterInfo'), (1, 'pOutBufLen'))

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

#def NtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength):
#    return NtQueryKey.ctypes_function(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength)
NtQueryKeyPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQueryKeyParams = ((1, 'KeyHandle'), (1, 'KeyInformationClass'), (1, 'KeyInformation'), (1, 'Length'), (1, 'ResultLength'))

#def NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength):
#    return NtEnumerateValueKey.ctypes_function(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)
NtEnumerateValueKeyPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtEnumerateValueKeyParams = ((1, 'KeyHandle'), (1, 'Index'), (1, 'KeyValueInformationClass'), (1, 'KeyValueInformation'), (1, 'Length'), (1, 'ResultLength'))

#def NtDeleteValueKey(KeyHandle, ValueName):
#    return NtDeleteValueKey.ctypes_function(KeyHandle, ValueName)
NtDeleteValueKeyPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PUNICODE_STRING)
NtDeleteValueKeyParams = ((1, 'KeyHandle'), (1, 'ValueName'))

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

#def RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
#    return RegQueryValueExA.ctypes_function(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
RegQueryValueExAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD)
RegQueryValueExAParams = ((1, 'hKey'), (1, 'lpValueName'), (1, 'lpReserved'), (1, 'lpType'), (1, 'lpData'), (1, 'lpcbData'))

#def RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
#    return RegQueryValueExW.ctypes_function(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
RegQueryValueExWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD)
RegQueryValueExWParams = ((1, 'hKey'), (1, 'lpValueName'), (1, 'lpReserved'), (1, 'lpType'), (1, 'lpData'), (1, 'lpcbData'))

#def RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult):
#    return RegOpenKeyExA.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)
RegOpenKeyExAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, DWORD, REGSAM, PHKEY)
RegOpenKeyExAParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'ulOptions'), (1, 'samDesired'), (1, 'phkResult'))

#def RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult):
#    return RegOpenKeyExW.ctypes_function(hKey, lpSubKey, ulOptions, samDesired, phkResult)
RegOpenKeyExWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPWSTR, DWORD, REGSAM, PHKEY)
RegOpenKeyExWParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'ulOptions'), (1, 'samDesired'), (1, 'phkResult'))

#def RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
#    return RegCreateKeyExA.ctypes_function(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition)
RegCreateKeyExAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD)
RegCreateKeyExAParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'Reserved'), (1, 'lpClass'), (1, 'dwOptions'), (1, 'samDesired'), (1, 'lpSecurityAttributes'), (1, 'phkResult'), (1, 'lpdwDisposition'))

#def RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition):
#    return RegCreateKeyExW.ctypes_function(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition)
RegCreateKeyExWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD)
RegCreateKeyExWParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'Reserved'), (1, 'lpClass'), (1, 'dwOptions'), (1, 'samDesired'), (1, 'lpSecurityAttributes'), (1, 'phkResult'), (1, 'lpdwDisposition'))

#def RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
#    return RegGetValueA.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
RegGetValueAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD)
RegGetValueAParams = ((1, 'hkey'), (1, 'lpSubKey'), (1, 'lpValue'), (1, 'dwFlags'), (1, 'pdwType'), (1, 'pvData'), (1, 'pcbData'))

#def RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData):
#    return RegGetValueW.ctypes_function(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
RegGetValueWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPWSTR, LPWSTR, DWORD, LPDWORD, PVOID, LPDWORD)
RegGetValueWParams = ((1, 'hkey'), (1, 'lpSubKey'), (1, 'lpValue'), (1, 'dwFlags'), (1, 'pdwType'), (1, 'pvData'), (1, 'pcbData'))

#def RegCloseKey(hKey):
#    return RegCloseKey.ctypes_function(hKey)
RegCloseKeyPrototype = WINFUNCTYPE(LSTATUS, HKEY)
RegCloseKeyParams = ((1, 'hKey'),)

#def RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData):
#    return RegSetValueExW.ctypes_function(hKey, lpValueName, Reserved, dwType, lpData, cbData)
RegSetValueExWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR, DWORD, DWORD, POINTER(BYTE), DWORD)
RegSetValueExWParams = ((1, 'hKey'), (1, 'lpValueName'), (1, 'Reserved'), (1, 'dwType'), (1, 'lpData'), (1, 'cbData'))

#def RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData):
#    return RegSetValueExA.ctypes_function(hKey, lpValueName, Reserved, dwType, lpData, cbData)
RegSetValueExAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, DWORD, DWORD, POINTER(BYTE), DWORD)
RegSetValueExAParams = ((1, 'hKey'), (1, 'lpValueName'), (1, 'Reserved'), (1, 'dwType'), (1, 'lpData'), (1, 'cbData'))

#def RegSetKeyValueA(hKey, lpSubKey, lpValueName, dwType, lpData, cbData):
#    return RegSetKeyValueA.ctypes_function(hKey, lpSubKey, lpValueName, dwType, lpData, cbData)
RegSetKeyValueAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, LPCSTR, DWORD, LPCVOID, DWORD)
RegSetKeyValueAParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'lpValueName'), (1, 'dwType'), (1, 'lpData'), (1, 'cbData'))

#def RegSetKeyValueW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData):
#    return RegSetKeyValueW.ctypes_function(hKey, lpSubKey, lpValueName, dwType, lpData, cbData)
RegSetKeyValueWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR, LPCWSTR, DWORD, LPCVOID, DWORD)
RegSetKeyValueWParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'lpValueName'), (1, 'dwType'), (1, 'lpData'), (1, 'cbData'))

#def RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime):
#    return RegEnumKeyExA.ctypes_function(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime)
RegEnumKeyExAPrototype = WINFUNCTYPE(LSTATUS, HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME)
RegEnumKeyExAParams = ((1, 'hKey'), (1, 'dwIndex'), (1, 'lpName'), (1, 'lpcchName'), (1, 'lpReserved'), (1, 'lpClass'), (1, 'lpcchClass'), (1, 'lpftLastWriteTime'))

#def RegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime):
#    return RegEnumKeyExW.ctypes_function(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime)
RegEnumKeyExWPrototype = WINFUNCTYPE(LSTATUS, HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME)
RegEnumKeyExWParams = ((1, 'hKey'), (1, 'dwIndex'), (1, 'lpName'), (1, 'lpcchName'), (1, 'lpReserved'), (1, 'lpClass'), (1, 'lpcchClass'), (1, 'lpftLastWriteTime'))

#def RegGetKeySecurity(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor):
#    return RegGetKeySecurity.ctypes_function(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor)
RegGetKeySecurityPrototype = WINFUNCTYPE(LSTATUS, HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, LPDWORD)
RegGetKeySecurityParams = ((1, 'hKey'), (1, 'SecurityInformation'), (1, 'pSecurityDescriptor'), (1, 'lpcbSecurityDescriptor'))

#def RegQueryInfoKeyA(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime):
#    return RegQueryInfoKeyA.ctypes_function(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime)
RegQueryInfoKeyAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME)
RegQueryInfoKeyAParams = ((1, 'hKey'), (1, 'lpClass'), (1, 'lpcchClass'), (1, 'lpReserved'), (1, 'lpcSubKeys'), (1, 'lpcbMaxSubKeyLen'), (1, 'lpcbMaxClassLen'), (1, 'lpcValues'), (1, 'lpcbMaxValueNameLen'), (1, 'lpcbMaxValueLen'), (1, 'lpcbSecurityDescriptor'), (1, 'lpftLastWriteTime'))

#def RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime):
#    return RegQueryInfoKeyW.ctypes_function(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime)
RegQueryInfoKeyWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME)
RegQueryInfoKeyWParams = ((1, 'hKey'), (1, 'lpClass'), (1, 'lpcchClass'), (1, 'lpReserved'), (1, 'lpcSubKeys'), (1, 'lpcbMaxSubKeyLen'), (1, 'lpcbMaxClassLen'), (1, 'lpcValues'), (1, 'lpcbMaxValueNameLen'), (1, 'lpcbMaxValueLen'), (1, 'lpcbSecurityDescriptor'), (1, 'lpftLastWriteTime'))

#def RegDeleteKeyValueW(hKey, lpSubKey, lpValueName):
#    return RegDeleteKeyValueW.ctypes_function(hKey, lpSubKey, lpValueName)
RegDeleteKeyValueWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR, LPCWSTR)
RegDeleteKeyValueWParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'lpValueName'))

#def RegDeleteKeyValueA(hKey, lpSubKey, lpValueName):
#    return RegDeleteKeyValueA.ctypes_function(hKey, lpSubKey, lpValueName)
RegDeleteKeyValueAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, LPCSTR)
RegDeleteKeyValueAParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'lpValueName'))

#def RegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved):
#    return RegDeleteKeyExA.ctypes_function(hKey, lpSubKey, samDesired, Reserved)
RegDeleteKeyExAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, REGSAM, DWORD)
RegDeleteKeyExAParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'samDesired'), (1, 'Reserved'))

#def RegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved):
#    return RegDeleteKeyExW.ctypes_function(hKey, lpSubKey, samDesired, Reserved)
RegDeleteKeyExWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR, REGSAM, DWORD)
RegDeleteKeyExWParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'samDesired'), (1, 'Reserved'))

#def RegDeleteValueA(hKey, lpValueName):
#    return RegDeleteValueA.ctypes_function(hKey, lpValueName)
RegDeleteValueAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR)
RegDeleteValueAParams = ((1, 'hKey'), (1, 'lpValueName'))

#def RegDeleteValueW(hKey, lpValueName):
#    return RegDeleteValueW.ctypes_function(hKey, lpValueName)
RegDeleteValueWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR)
RegDeleteValueWParams = ((1, 'hKey'), (1, 'lpValueName'))

#def RegEnumValueA(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData):
#    return RegEnumValueA.ctypes_function(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData)
RegEnumValueAPrototype = WINFUNCTYPE(LSTATUS, HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD)
RegEnumValueAParams = ((1, 'hKey'), (1, 'dwIndex'), (1, 'lpValueName'), (1, 'lpcchValueName'), (1, 'lpReserved'), (1, 'lpType'), (1, 'lpData'), (1, 'lpcbData'))

#def RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData):
#    return RegEnumValueW.ctypes_function(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData)
RegEnumValueWPrototype = WINFUNCTYPE(LSTATUS, HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD)
RegEnumValueWParams = ((1, 'hKey'), (1, 'dwIndex'), (1, 'lpValueName'), (1, 'lpcchValueName'), (1, 'lpReserved'), (1, 'lpType'), (1, 'lpData'), (1, 'lpcbData'))

#def RegDeleteTreeA(hKey, lpSubKey):
#    return RegDeleteTreeA.ctypes_function(hKey, lpSubKey)
RegDeleteTreeAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR)
RegDeleteTreeAParams = ((1, 'hKey'), (1, 'lpSubKey'))

#def RegDeleteTreeW(hKey, lpSubKey):
#    return RegDeleteTreeW.ctypes_function(hKey, lpSubKey)
RegDeleteTreeWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR)
RegDeleteTreeWParams = ((1, 'hKey'), (1, 'lpSubKey'))

#def RegSaveKeyA(hKey, lpFile, lpSecurityAttributes):
#    return RegSaveKeyA.ctypes_function(hKey, lpFile, lpSecurityAttributes)
RegSaveKeyAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, LPSECURITY_ATTRIBUTES)
RegSaveKeyAParams = ((1, 'hKey'), (1, 'lpFile'), (1, 'lpSecurityAttributes'))

#def RegSaveKeyW(hKey, lpFile, lpSecurityAttributes):
#    return RegSaveKeyW.ctypes_function(hKey, lpFile, lpSecurityAttributes)
RegSaveKeyWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR, LPSECURITY_ATTRIBUTES)
RegSaveKeyWParams = ((1, 'hKey'), (1, 'lpFile'), (1, 'lpSecurityAttributes'))

#def RegSaveKeyExA(hKey, lpFile, lpSecurityAttributes, Flags):
#    return RegSaveKeyExA.ctypes_function(hKey, lpFile, lpSecurityAttributes, Flags)
RegSaveKeyExAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, LPSECURITY_ATTRIBUTES, DWORD)
RegSaveKeyExAParams = ((1, 'hKey'), (1, 'lpFile'), (1, 'lpSecurityAttributes'), (1, 'Flags'))

#def RegSaveKeyExW(hKey, lpFile, lpSecurityAttributes, Flags):
#    return RegSaveKeyExW.ctypes_function(hKey, lpFile, lpSecurityAttributes, Flags)
RegSaveKeyExWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR, LPSECURITY_ATTRIBUTES, DWORD)
RegSaveKeyExWParams = ((1, 'hKey'), (1, 'lpFile'), (1, 'lpSecurityAttributes'), (1, 'Flags'))

#def RegLoadKeyA(hKey, lpSubKey, lpFile):
#    return RegLoadKeyA.ctypes_function(hKey, lpSubKey, lpFile)
RegLoadKeyAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR, LPCSTR)
RegLoadKeyAParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'lpFile'))

#def RegLoadKeyW(hKey, lpSubKey, lpFile):
#    return RegLoadKeyW.ctypes_function(hKey, lpSubKey, lpFile)
RegLoadKeyWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR, LPCWSTR)
RegLoadKeyWParams = ((1, 'hKey'), (1, 'lpSubKey'), (1, 'lpFile'))

#def RegUnLoadKeyA(hKey, lpSubKey):
#    return RegUnLoadKeyA.ctypes_function(hKey, lpSubKey)
RegUnLoadKeyAPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCSTR)
RegUnLoadKeyAParams = ((1, 'hKey'), (1, 'lpSubKey'))

#def RegUnLoadKeyW(hKey, lpSubKey):
#    return RegUnLoadKeyW.ctypes_function(hKey, lpSubKey)
RegUnLoadKeyWPrototype = WINFUNCTYPE(LSTATUS, HKEY, LPCWSTR)
RegUnLoadKeyWParams = ((1, 'hKey'), (1, 'lpSubKey'))

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

#def SetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, bOwnerDefaulted):
#    return SetSecurityDescriptorOwner.ctypes_function(pSecurityDescriptor, pOwner, bOwnerDefaulted)
SetSecurityDescriptorOwnerPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, PSID, BOOL)
SetSecurityDescriptorOwnerParams = ((1, 'pSecurityDescriptor'), (1, 'pOwner'), (1, 'bOwnerDefaulted'))

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

#def MapGenericMask(AccessMask, GenericMapping):
#    return MapGenericMask.ctypes_function(AccessMask, GenericMapping)
MapGenericMaskPrototype = WINFUNCTYPE(PVOID, PDWORD, PGENERIC_MAPPING)
MapGenericMaskParams = ((1, 'AccessMask'), (1, 'GenericMapping'))

#def AccessCheck(pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus):
#    return AccessCheck.ctypes_function(pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus)
AccessCheckPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, HANDLE, DWORD, PGENERIC_MAPPING, PPRIVILEGE_SET, LPDWORD, LPDWORD, LPBOOL)
AccessCheckParams = ((1, 'pSecurityDescriptor'), (1, 'ClientToken'), (1, 'DesiredAccess'), (1, 'GenericMapping'), (1, 'PrivilegeSet'), (1, 'PrivilegeSetLength'), (1, 'GrantedAccess'), (1, 'AccessStatus'))

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

#def SetSecurityInfo(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl):
#    return SetSecurityInfo.ctypes_function(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl)
SetSecurityInfoPrototype = WINFUNCTYPE(DWORD, HANDLE, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID, PSID, PACL, PACL)
SetSecurityInfoParams = ((1, 'handle'), (1, 'ObjectType'), (1, 'SecurityInfo'), (1, 'psidOwner'), (1, 'psidGroup'), (1, 'pDacl'), (1, 'pSacl'))

#def SetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl):
#    return SetNamedSecurityInfoA.ctypes_function(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl)
SetNamedSecurityInfoAPrototype = WINFUNCTYPE(DWORD, LPSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID, PSID, PACL, PACL)
SetNamedSecurityInfoAParams = ((1, 'pObjectName'), (1, 'ObjectType'), (1, 'SecurityInfo'), (1, 'psidOwner'), (1, 'psidGroup'), (1, 'pDacl'), (1, 'pSacl'))

#def SetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl):
#    return SetNamedSecurityInfoW.ctypes_function(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl)
SetNamedSecurityInfoWPrototype = WINFUNCTYPE(DWORD, LPWSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID, PSID, PACL, PACL)
SetNamedSecurityInfoWParams = ((1, 'pObjectName'), (1, 'ObjectType'), (1, 'SecurityInfo'), (1, 'psidOwner'), (1, 'psidGroup'), (1, 'pDacl'), (1, 'pSacl'))

#def GetStringConditionFromBinary(BinaryAceCondition, BinaryAceConditionSize, Reserved1, StringAceCondition):
#    return GetStringConditionFromBinary.ctypes_function(BinaryAceCondition, BinaryAceConditionSize, Reserved1, StringAceCondition)
GetStringConditionFromBinaryPrototype = WINFUNCTYPE(DWORD, POINTER(BYTE), DWORD, DWORD, POINTER(LPWSTR))
GetStringConditionFromBinaryParams = ((1, 'BinaryAceCondition'), (1, 'BinaryAceConditionSize'), (1, 'Reserved1'), (1, 'StringAceCondition'))

#def AddAccessAllowedAce(pAcl, dwAceRevision, AccessMask, pSid):
#    return AddAccessAllowedAce.ctypes_function(pAcl, dwAceRevision, AccessMask, pSid)
AddAccessAllowedAcePrototype = WINFUNCTYPE(BOOL, PACL, DWORD, DWORD, PSID)
AddAccessAllowedAceParams = ((1, 'pAcl'), (1, 'dwAceRevision'), (1, 'AccessMask'), (1, 'pSid'))

#def SetSecurityDescriptorDacl(pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted):
#    return SetSecurityDescriptorDacl.ctypes_function(pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted)
SetSecurityDescriptorDaclPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL)
SetSecurityDescriptorDaclParams = ((1, 'pSecurityDescriptor'), (1, 'bDaclPresent'), (1, 'pDacl'), (1, 'bDaclDefaulted'))

#def InitializeAcl(pAcl, nAclLength, dwAclRevision):
#    return InitializeAcl.ctypes_function(pAcl, nAclLength, dwAclRevision)
InitializeAclPrototype = WINFUNCTYPE(BOOL, PACL, DWORD, DWORD)
InitializeAclParams = ((1, 'pAcl'), (1, 'nAclLength'), (1, 'dwAclRevision'))

#def InitializeSecurityDescriptor(pSecurityDescriptor, dwRevision):
#    return InitializeSecurityDescriptor.ctypes_function(pSecurityDescriptor, dwRevision)
InitializeSecurityDescriptorPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, DWORD)
InitializeSecurityDescriptorParams = ((1, 'pSecurityDescriptor'), (1, 'dwRevision'))

#def SetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass):
#    return SetAclInformation.ctypes_function(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass)
SetAclInformationPrototype = WINFUNCTYPE(BOOL, PACL, LPVOID, DWORD, ACL_INFORMATION_CLASS)
SetAclInformationParams = ((1, 'pAcl'), (1, 'pAclInformation'), (1, 'nAclInformationLength'), (1, 'dwAclInformationClass'))

#def AddAccessAllowedAceEx(pAcl, dwAceRevision, AceFlags, AccessMask, pSid):
#    return AddAccessAllowedAceEx.ctypes_function(pAcl, dwAceRevision, AceFlags, AccessMask, pSid)
AddAccessAllowedAceExPrototype = WINFUNCTYPE(BOOL, PACL, DWORD, DWORD, DWORD, PSID)
AddAccessAllowedAceExParams = ((1, 'pAcl'), (1, 'dwAceRevision'), (1, 'AceFlags'), (1, 'AccessMask'), (1, 'pSid'))

#def AddAccessDeniedAce(pAcl, dwAceRevision, AccessMask, pSid):
#    return AddAccessDeniedAce.ctypes_function(pAcl, dwAceRevision, AccessMask, pSid)
AddAccessDeniedAcePrototype = WINFUNCTYPE(BOOL, PACL, DWORD, DWORD, PSID)
AddAccessDeniedAceParams = ((1, 'pAcl'), (1, 'dwAceRevision'), (1, 'AccessMask'), (1, 'pSid'))

#def AddAccessDeniedAceEx(pAcl, dwAceRevision, AceFlags, AccessMask, pSid):
#    return AddAccessDeniedAceEx.ctypes_function(pAcl, dwAceRevision, AceFlags, AccessMask, pSid)
AddAccessDeniedAceExPrototype = WINFUNCTYPE(BOOL, PACL, DWORD, DWORD, DWORD, PSID)
AddAccessDeniedAceExParams = ((1, 'pAcl'), (1, 'dwAceRevision'), (1, 'AceFlags'), (1, 'AccessMask'), (1, 'pSid'))

#def BuildSecurityDescriptorW(pOwner, pGroup, cCountOfAccessEntries, pListOfAccessEntries, cCountOfAuditEntries, pListOfAuditEntries, pOldSD, pSizeNewSD, pNewSD):
#    return BuildSecurityDescriptorW.ctypes_function(pOwner, pGroup, cCountOfAccessEntries, pListOfAccessEntries, cCountOfAuditEntries, pListOfAuditEntries, pOldSD, pSizeNewSD, pNewSD)
BuildSecurityDescriptorWPrototype = WINFUNCTYPE(DWORD, PTRUSTEE_W, PTRUSTEE_W, ULONG, PEXPLICIT_ACCESS_W, ULONG, PEXPLICIT_ACCESS_W, PSECURITY_DESCRIPTOR, PULONG, POINTER(PSECURITY_DESCRIPTOR))
BuildSecurityDescriptorWParams = ((1, 'pOwner'), (1, 'pGroup'), (1, 'cCountOfAccessEntries'), (1, 'pListOfAccessEntries'), (1, 'cCountOfAuditEntries'), (1, 'pListOfAuditEntries'), (1, 'pOldSD'), (1, 'pSizeNewSD'), (1, 'pNewSD'))

#def MakeAbsoluteSD(pSelfRelativeSecurityDescriptor, pAbsoluteSecurityDescriptor, lpdwAbsoluteSecurityDescriptorSize, pDacl, lpdwDaclSize, pSacl, lpdwSaclSize, pOwner, lpdwOwnerSize, pPrimaryGroup, lpdwPrimaryGroupSize):
#    return MakeAbsoluteSD.ctypes_function(pSelfRelativeSecurityDescriptor, pAbsoluteSecurityDescriptor, lpdwAbsoluteSecurityDescriptorSize, pDacl, lpdwDaclSize, pSacl, lpdwSaclSize, pOwner, lpdwOwnerSize, pPrimaryGroup, lpdwPrimaryGroupSize)
MakeAbsoluteSDPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, LPDWORD, PACL, LPDWORD, PACL, LPDWORD, PSID, LPDWORD, PSID, LPDWORD)
MakeAbsoluteSDParams = ((1, 'pSelfRelativeSecurityDescriptor'), (1, 'pAbsoluteSecurityDescriptor'), (1, 'lpdwAbsoluteSecurityDescriptorSize'), (1, 'pDacl'), (1, 'lpdwDaclSize'), (1, 'pSacl'), (1, 'lpdwSaclSize'), (1, 'pOwner'), (1, 'lpdwOwnerSize'), (1, 'pPrimaryGroup'), (1, 'lpdwPrimaryGroupSize'))

#def MakeSelfRelativeSD(pAbsoluteSecurityDescriptor, pSelfRelativeSecurityDescriptor, lpdwBufferLength):
#    return MakeSelfRelativeSD.ctypes_function(pAbsoluteSecurityDescriptor, pSelfRelativeSecurityDescriptor, lpdwBufferLength)
MakeSelfRelativeSDPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, LPDWORD)
MakeSelfRelativeSDParams = ((1, 'pAbsoluteSecurityDescriptor'), (1, 'pSelfRelativeSecurityDescriptor'), (1, 'lpdwBufferLength'))

#def InitializeSecurityDescriptor(pSecurityDescriptor, dwRevision):
#    return InitializeSecurityDescriptor.ctypes_function(pSecurityDescriptor, dwRevision)
InitializeSecurityDescriptorPrototype = WINFUNCTYPE(BOOL, PSECURITY_DESCRIPTOR, DWORD)
InitializeSecurityDescriptorParams = ((1, 'pSecurityDescriptor'), (1, 'dwRevision'))

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

#def ControlService(hService, dwControl, lpServiceStatus):
#    return ControlService.ctypes_function(hService, dwControl, lpServiceStatus)
ControlServicePrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, LPSERVICE_STATUS)
ControlServiceParams = ((1, 'hService'), (1, 'dwControl'), (1, 'lpServiceStatus'))

#def QueryServiceStatus(hService, lpServiceStatus):
#    return QueryServiceStatus.ctypes_function(hService, lpServiceStatus)
QueryServiceStatusPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, LPSERVICE_STATUS)
QueryServiceStatusParams = ((1, 'hService'), (1, 'lpServiceStatus'))

#def QueryServiceStatusEx(hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded):
#    return QueryServiceStatusEx.ctypes_function(hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)
QueryServiceStatusExPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD)
QueryServiceStatusExParams = ((1, 'hService'), (1, 'InfoLevel'), (1, 'lpBuffer'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'))

#def ChangeServiceConfig2A(hService, dwInfoLevel, lpInfo):
#    return ChangeServiceConfig2A.ctypes_function(hService, dwInfoLevel, lpInfo)
ChangeServiceConfig2APrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, LPVOID)
ChangeServiceConfig2AParams = ((1, 'hService'), (1, 'dwInfoLevel'), (1, 'lpInfo'))

#def ChangeServiceConfig2W(hService, dwInfoLevel, lpInfo):
#    return ChangeServiceConfig2W.ctypes_function(hService, dwInfoLevel, lpInfo)
ChangeServiceConfig2WPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, LPVOID)
ChangeServiceConfig2WParams = ((1, 'hService'), (1, 'dwInfoLevel'), (1, 'lpInfo'))

#def ChangeServiceConfigA(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName):
#    return ChangeServiceConfigA.ctypes_function(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName)
ChangeServiceConfigAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR)
ChangeServiceConfigAParams = ((1, 'hService'), (1, 'dwServiceType'), (1, 'dwStartType'), (1, 'dwErrorControl'), (1, 'lpBinaryPathName'), (1, 'lpLoadOrderGroup'), (1, 'lpdwTagId'), (1, 'lpDependencies'), (1, 'lpServiceStartName'), (1, 'lpPassword'), (1, 'lpDisplayName'))

#def ChangeServiceConfigW(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName):
#    return ChangeServiceConfigW.ctypes_function(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName)
ChangeServiceConfigWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR)
ChangeServiceConfigWParams = ((1, 'hService'), (1, 'dwServiceType'), (1, 'dwStartType'), (1, 'dwErrorControl'), (1, 'lpBinaryPathName'), (1, 'lpLoadOrderGroup'), (1, 'lpdwTagId'), (1, 'lpDependencies'), (1, 'lpServiceStartName'), (1, 'lpPassword'), (1, 'lpDisplayName'))

#def QueryServiceConfig2A(hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded):
#    return QueryServiceConfig2A.ctypes_function(hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)
QueryServiceConfig2APrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, LPBYTE, DWORD, LPDWORD)
QueryServiceConfig2AParams = ((1, 'hService'), (1, 'dwInfoLevel'), (1, 'lpBuffer'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'))

#def QueryServiceConfig2W(hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded):
#    return QueryServiceConfig2W.ctypes_function(hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)
QueryServiceConfig2WPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, LPBYTE, DWORD, LPDWORD)
QueryServiceConfig2WParams = ((1, 'hService'), (1, 'dwInfoLevel'), (1, 'lpBuffer'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'))

#def QueryServiceConfigA(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded):
#    return QueryServiceConfigA.ctypes_function(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded)
QueryServiceConfigAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD)
QueryServiceConfigAParams = ((1, 'hService'), (1, 'lpServiceConfig'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'))

#def QueryServiceConfigW(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded):
#    return QueryServiceConfigW.ctypes_function(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded)
QueryServiceConfigWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD)
QueryServiceConfigWParams = ((1, 'hService'), (1, 'lpServiceConfig'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'))

#def QueryServiceDynamicInformation(hServiceStatus, dwInfoLevel, ppDynamicInfo):
#    return QueryServiceDynamicInformation.ctypes_function(hServiceStatus, dwInfoLevel, ppDynamicInfo)
QueryServiceDynamicInformationPrototype = WINFUNCTYPE(BOOL, SERVICE_STATUS_HANDLE, DWORD, POINTER(PVOID))
QueryServiceDynamicInformationParams = ((1, 'hServiceStatus'), (1, 'dwInfoLevel'), (1, 'ppDynamicInfo'))

#def GetServiceDisplayNameA(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer):
#    return GetServiceDisplayNameA.ctypes_function(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer)
GetServiceDisplayNameAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, LPCSTR, LPSTR, LPDWORD)
GetServiceDisplayNameAParams = ((1, 'hSCManager'), (1, 'lpServiceName'), (1, 'lpDisplayName'), (1, 'lpcchBuffer'))

#def GetServiceDisplayNameW(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer):
#    return GetServiceDisplayNameW.ctypes_function(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer)
GetServiceDisplayNameWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, LPCWSTR, LPWSTR, LPDWORD)
GetServiceDisplayNameWParams = ((1, 'hSCManager'), (1, 'lpServiceName'), (1, 'lpDisplayName'), (1, 'lpcchBuffer'))

#def GetServiceKeyNameA(hSCManager, lpDisplayName, lpServiceName, lpcchBuffer):
#    return GetServiceKeyNameA.ctypes_function(hSCManager, lpDisplayName, lpServiceName, lpcchBuffer)
GetServiceKeyNameAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, LPCSTR, LPSTR, LPDWORD)
GetServiceKeyNameAParams = ((1, 'hSCManager'), (1, 'lpDisplayName'), (1, 'lpServiceName'), (1, 'lpcchBuffer'))

#def GetServiceKeyNameW(hSCManager, lpDisplayName, lpServiceName, lpcchBuffer):
#    return GetServiceKeyNameW.ctypes_function(hSCManager, lpDisplayName, lpServiceName, lpcchBuffer)
GetServiceKeyNameWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, LPCWSTR, LPWSTR, LPDWORD)
GetServiceKeyNameWParams = ((1, 'hSCManager'), (1, 'lpDisplayName'), (1, 'lpServiceName'), (1, 'lpcchBuffer'))

#def EnumDependentServicesA(hService, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned):
#    return EnumDependentServicesA.ctypes_function(hService, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned)
EnumDependentServicesAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, LPENUM_SERVICE_STATUSA, DWORD, LPDWORD, LPDWORD)
EnumDependentServicesAParams = ((1, 'hService'), (1, 'dwServiceState'), (1, 'lpServices'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'), (1, 'lpServicesReturned'))

#def EnumDependentServicesW(hService, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned):
#    return EnumDependentServicesW.ctypes_function(hService, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned)
EnumDependentServicesWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, LPENUM_SERVICE_STATUSW, DWORD, LPDWORD, LPDWORD)
EnumDependentServicesWParams = ((1, 'hService'), (1, 'dwServiceState'), (1, 'lpServices'), (1, 'cbBufSize'), (1, 'pcbBytesNeeded'), (1, 'lpServicesReturned'))

#def ControlService(hService, dwControl, lpServiceStatus):
#    return ControlService.ctypes_function(hService, dwControl, lpServiceStatus)
ControlServicePrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, LPSERVICE_STATUS)
ControlServiceParams = ((1, 'hService'), (1, 'dwControl'), (1, 'lpServiceStatus'))

#def ControlServiceExA(hService, dwControl, dwInfoLevel, pControlParams):
#    return ControlServiceExA.ctypes_function(hService, dwControl, dwInfoLevel, pControlParams)
ControlServiceExAPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, DWORD, PVOID)
ControlServiceExAParams = ((1, 'hService'), (1, 'dwControl'), (1, 'dwInfoLevel'), (1, 'pControlParams'))

#def ControlServiceExW(hService, dwControl, dwInfoLevel, pControlParams):
#    return ControlServiceExW.ctypes_function(hService, dwControl, dwInfoLevel, pControlParams)
ControlServiceExWPrototype = WINFUNCTYPE(BOOL, SC_HANDLE, DWORD, DWORD, PVOID)
ControlServiceExWParams = ((1, 'hService'), (1, 'dwControl'), (1, 'dwInfoLevel'), (1, 'pControlParams'))

#def CreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword):
#    return CreateServiceA.ctypes_function(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword)
CreateServiceAPrototype = WINFUNCTYPE(SC_HANDLE, SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR)
CreateServiceAParams = ((1, 'hSCManager'), (1, 'lpServiceName'), (1, 'lpDisplayName'), (1, 'dwDesiredAccess'), (1, 'dwServiceType'), (1, 'dwStartType'), (1, 'dwErrorControl'), (1, 'lpBinaryPathName'), (1, 'lpLoadOrderGroup'), (1, 'lpdwTagId'), (1, 'lpDependencies'), (1, 'lpServiceStartName'), (1, 'lpPassword'))

#def CreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword):
#    return CreateServiceW.ctypes_function(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword)
CreateServiceWPrototype = WINFUNCTYPE(SC_HANDLE, SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR)
CreateServiceWParams = ((1, 'hSCManager'), (1, 'lpServiceName'), (1, 'lpDisplayName'), (1, 'dwDesiredAccess'), (1, 'dwServiceType'), (1, 'dwStartType'), (1, 'dwErrorControl'), (1, 'lpBinaryPathName'), (1, 'lpLoadOrderGroup'), (1, 'lpdwTagId'), (1, 'lpDependencies'), (1, 'lpServiceStartName'), (1, 'lpPassword'))

#def DeleteService(hService):
#    return DeleteService.ctypes_function(hService)
DeleteServicePrototype = WINFUNCTYPE(BOOL, SC_HANDLE)
DeleteServiceParams = ((1, 'hService'),)

#def StartServiceCtrlDispatcherA(lpServiceStartTable):
#    return StartServiceCtrlDispatcherA.ctypes_function(lpServiceStartTable)
StartServiceCtrlDispatcherAPrototype = WINFUNCTYPE(BOOL, POINTER(SERVICE_TABLE_ENTRYA))
StartServiceCtrlDispatcherAParams = ((1, 'lpServiceStartTable'),)

#def StartServiceCtrlDispatcherW(lpServiceStartTable):
#    return StartServiceCtrlDispatcherW.ctypes_function(lpServiceStartTable)
StartServiceCtrlDispatcherWPrototype = WINFUNCTYPE(BOOL, POINTER(SERVICE_TABLE_ENTRYW))
StartServiceCtrlDispatcherWParams = ((1, 'lpServiceStartTable'),)

#def SetupDiClassNameFromGuidA(ClassGuid, ClassName, ClassNameSize, RequiredSize):
#    return SetupDiClassNameFromGuidA.ctypes_function(ClassGuid, ClassName, ClassNameSize, RequiredSize)
SetupDiClassNameFromGuidAPrototype = WINFUNCTYPE(BOOL, POINTER(GUID), PSTR, DWORD, PDWORD)
SetupDiClassNameFromGuidAParams = ((1, 'ClassGuid'), (1, 'ClassName'), (1, 'ClassNameSize'), (1, 'RequiredSize'))

#def SetupDiClassNameFromGuidW(ClassGuid, ClassName, ClassNameSize, RequiredSize):
#    return SetupDiClassNameFromGuidW.ctypes_function(ClassGuid, ClassName, ClassNameSize, RequiredSize)
SetupDiClassNameFromGuidWPrototype = WINFUNCTYPE(BOOL, POINTER(GUID), PWSTR, DWORD, PDWORD)
SetupDiClassNameFromGuidWParams = ((1, 'ClassGuid'), (1, 'ClassName'), (1, 'ClassNameSize'), (1, 'RequiredSize'))

#def SetupDiClassNameFromGuidExA(ClassGuid, ClassName, ClassNameSize, RequiredSize, MachineName, Reserved):
#    return SetupDiClassNameFromGuidExA.ctypes_function(ClassGuid, ClassName, ClassNameSize, RequiredSize, MachineName, Reserved)
SetupDiClassNameFromGuidExAPrototype = WINFUNCTYPE(BOOL, POINTER(GUID), PSTR, DWORD, PDWORD, PCSTR, PVOID)
SetupDiClassNameFromGuidExAParams = ((1, 'ClassGuid'), (1, 'ClassName'), (1, 'ClassNameSize'), (1, 'RequiredSize'), (1, 'MachineName'), (1, 'Reserved'))

#def SetupDiClassNameFromGuidExW(ClassGuid, ClassName, ClassNameSize, RequiredSize, MachineName, Reserved):
#    return SetupDiClassNameFromGuidExW.ctypes_function(ClassGuid, ClassName, ClassNameSize, RequiredSize, MachineName, Reserved)
SetupDiClassNameFromGuidExWPrototype = WINFUNCTYPE(BOOL, POINTER(GUID), PWSTR, DWORD, PDWORD, PCWSTR, PVOID)
SetupDiClassNameFromGuidExWParams = ((1, 'ClassGuid'), (1, 'ClassName'), (1, 'ClassNameSize'), (1, 'RequiredSize'), (1, 'MachineName'), (1, 'Reserved'))

#def SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent, Flags):
#    return SetupDiGetClassDevsA.ctypes_function(ClassGuid, Enumerator, hwndParent, Flags)
SetupDiGetClassDevsAPrototype = WINFUNCTYPE(HDEVINFO, POINTER(GUID), PCSTR, HWND, DWORD)
SetupDiGetClassDevsAParams = ((1, 'ClassGuid'), (1, 'Enumerator'), (1, 'hwndParent'), (1, 'Flags'))

#def SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags):
#    return SetupDiGetClassDevsW.ctypes_function(ClassGuid, Enumerator, hwndParent, Flags)
SetupDiGetClassDevsWPrototype = WINFUNCTYPE(HDEVINFO, POINTER(GUID), PCWSTR, HWND, DWORD)
SetupDiGetClassDevsWParams = ((1, 'ClassGuid'), (1, 'Enumerator'), (1, 'hwndParent'), (1, 'Flags'))

#def SetupDiDeleteDeviceInfo(DeviceInfoSet, DeviceInfoData):
#    return SetupDiDeleteDeviceInfo.ctypes_function(DeviceInfoSet, DeviceInfoData)
SetupDiDeleteDeviceInfoPrototype = WINFUNCTYPE(BOOL, HDEVINFO, PSP_DEVINFO_DATA)
SetupDiDeleteDeviceInfoParams = ((1, 'DeviceInfoSet'), (1, 'DeviceInfoData'))

#def SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData):
#    return SetupDiEnumDeviceInfo.ctypes_function(DeviceInfoSet, MemberIndex, DeviceInfoData)
SetupDiEnumDeviceInfoPrototype = WINFUNCTYPE(BOOL, HDEVINFO, DWORD, PSP_DEVINFO_DATA)
SetupDiEnumDeviceInfoParams = ((1, 'DeviceInfoSet'), (1, 'MemberIndex'), (1, 'DeviceInfoData'))

#def SetupDiDestroyDeviceInfoList(DeviceInfoSet):
#    return SetupDiDestroyDeviceInfoList.ctypes_function(DeviceInfoSet)
SetupDiDestroyDeviceInfoListPrototype = WINFUNCTYPE(BOOL, HDEVINFO)
SetupDiDestroyDeviceInfoListParams = ((1, 'DeviceInfoSet'),)

#def SetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData):
#    return SetupDiEnumDeviceInterfaces.ctypes_function(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData)
SetupDiEnumDeviceInterfacesPrototype = WINFUNCTYPE(BOOL, HDEVINFO, PSP_DEVINFO_DATA, POINTER(GUID), DWORD, PSP_DEVICE_INTERFACE_DATA)
SetupDiEnumDeviceInterfacesParams = ((1, 'DeviceInfoSet'), (1, 'DeviceInfoData'), (1, 'InterfaceClassGuid'), (1, 'MemberIndex'), (1, 'DeviceInterfaceData'))

#def SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize):
#    return SetupDiGetDeviceRegistryPropertyA.ctypes_function(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize)
SetupDiGetDeviceRegistryPropertyAPrototype = WINFUNCTYPE(BOOL, HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD)
SetupDiGetDeviceRegistryPropertyAParams = ((1, 'DeviceInfoSet'), (1, 'DeviceInfoData'), (1, 'Property'), (1, 'PropertyRegDataType'), (1, 'PropertyBuffer'), (1, 'PropertyBufferSize'), (1, 'RequiredSize'))

#def SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize):
#    return SetupDiGetDeviceRegistryPropertyW.ctypes_function(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize)
SetupDiGetDeviceRegistryPropertyWPrototype = WINFUNCTYPE(BOOL, HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD)
SetupDiGetDeviceRegistryPropertyWParams = ((1, 'DeviceInfoSet'), (1, 'DeviceInfoData'), (1, 'Property'), (1, 'PropertyRegDataType'), (1, 'PropertyBuffer'), (1, 'PropertyBufferSize'), (1, 'RequiredSize'))

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

#def SHFileOperationA(lpFileOp):
#    return SHFileOperationA.ctypes_function(lpFileOp)
SHFileOperationAPrototype = WINFUNCTYPE(INT, LPSHFILEOPSTRUCTA)
SHFileOperationAParams = ((1, 'lpFileOp'),)

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

#def SymGetModuleInfoW64(hProcess, qwAddr, ModuleInfo):
#    return SymGetModuleInfoW64.ctypes_function(hProcess, qwAddr, ModuleInfo)
SymGetModuleInfoW64Prototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64, PIMAGEHLP_MODULEW64)
SymGetModuleInfoW64Params = ((1, 'hProcess'), (1, 'qwAddr'), (1, 'ModuleInfo'))

#def SymInitialize(hProcess, UserSearchPath, fInvadeProcess):
#    return SymInitialize.ctypes_function(hProcess, UserSearchPath, fInvadeProcess)
SymInitializePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCSTR, BOOL)
SymInitializeParams = ((1, 'hProcess'), (1, 'UserSearchPath'), (1, 'fInvadeProcess'))

#def SymFromName(hProcess, Name, Symbol):
#    return SymFromName.ctypes_function(hProcess, Name, Symbol)
SymFromNamePrototype = WINFUNCTYPE(BOOL, HANDLE, LPCSTR, PSYMBOL_INFO)
SymFromNameParams = ((1, 'hProcess'), (1, 'Name'), (1, 'Symbol'))

#def SymFromNameW(hProcess, Name, Symbol):
#    return SymFromNameW.ctypes_function(hProcess, Name, Symbol)
SymFromNameWPrototype = WINFUNCTYPE(BOOL, HANDLE, PCWSTR, PSYMBOL_INFOW)
SymFromNameWParams = ((1, 'hProcess'), (1, 'Name'), (1, 'Symbol'))

#def SymLoadModuleEx(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags):
#    return SymLoadModuleEx.ctypes_function(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)
SymLoadModuleExPrototype = WINFUNCTYPE(DWORD64, HANDLE, HANDLE, LPCSTR, LPCSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD)
SymLoadModuleExParams = ((1, 'hProcess'), (1, 'hFile'), (1, 'ImageName'), (1, 'ModuleName'), (1, 'BaseOfDll'), (1, 'DllSize'), (1, 'Data'), (1, 'Flags'))

#def SymSetOptions(SymOptions):
#    return SymSetOptions.ctypes_function(SymOptions)
SymSetOptionsPrototype = WINFUNCTYPE(DWORD, DWORD)
SymSetOptionsParams = ((1, 'SymOptions'),)

#def SymGetOptions():
#    return SymGetOptions.ctypes_function()
SymGetOptionsPrototype = WINFUNCTYPE(DWORD)
SymGetOptionsParams = ()

#def SymEnumSymbols(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext):
#    return SymEnumSymbols.ctypes_function(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext)
SymEnumSymbolsPrototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, PCSTR, PVOID, PVOID)
SymEnumSymbolsParams = ((1, 'hProcess'), (1, 'BaseOfDll'), (1, 'Mask'), (1, 'EnumSymbolsCallback'), (1, 'UserContext'))

#def SymEnumSymbolsEx(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext, Options):
#    return SymEnumSymbolsEx.ctypes_function(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext, Options)
SymEnumSymbolsExPrototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, PCSTR, PVOID, PVOID, DWORD)
SymEnumSymbolsExParams = ((1, 'hProcess'), (1, 'BaseOfDll'), (1, 'Mask'), (1, 'EnumSymbolsCallback'), (1, 'UserContext'), (1, 'Options'))

#def SymEnumTypes(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext):
#    return SymEnumTypes.ctypes_function(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)
SymEnumTypesPrototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, PVOID, PVOID)
SymEnumTypesParams = ((1, 'hProcess'), (1, 'BaseOfDll'), (1, 'EnumSymbolsCallback'), (1, 'UserContext'))

#def SymEnumTypesByName(hProcess, BaseOfDll, mask, EnumSymbolsCallback, UserContext):
#    return SymEnumTypesByName.ctypes_function(hProcess, BaseOfDll, mask, EnumSymbolsCallback, UserContext)
SymEnumTypesByNamePrototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, PCSTR, PVOID, PVOID)
SymEnumTypesByNameParams = ((1, 'hProcess'), (1, 'BaseOfDll'), (1, 'mask'), (1, 'EnumSymbolsCallback'), (1, 'UserContext'))

#def SymEnumerateModules64(hProcess, EnumModulesCallback, UserContext):
#    return SymEnumerateModules64.ctypes_function(hProcess, EnumModulesCallback, UserContext)
SymEnumerateModules64Prototype = WINFUNCTYPE(BOOL, HANDLE, PVOID, PVOID)
SymEnumerateModules64Params = ((1, 'hProcess'), (1, 'EnumModulesCallback'), (1, 'UserContext'))

#def SymNext(hProcess, si):
#    return SymNext.ctypes_function(hProcess, si)
SymNextPrototype = WINFUNCTYPE(BOOL, HANDLE, PSYMBOL_INFO)
SymNextParams = ((1, 'hProcess'), (1, 'si'))

#def SymNextW(hProcess, siw):
#    return SymNextW.ctypes_function(hProcess, siw)
SymNextWPrototype = WINFUNCTYPE(BOOL, HANDLE, PSYMBOL_INFOW)
SymNextWParams = ((1, 'hProcess'), (1, 'siw'))

#def SymPrev(hProcess, si):
#    return SymPrev.ctypes_function(hProcess, si)
SymPrevPrototype = WINFUNCTYPE(BOOL, HANDLE, PSYMBOL_INFO)
SymPrevParams = ((1, 'hProcess'), (1, 'si'))

#def SymPrevW(hProcess, siw):
#    return SymPrevW.ctypes_function(hProcess, siw)
SymPrevWPrototype = WINFUNCTYPE(BOOL, HANDLE, PSYMBOL_INFOW)
SymPrevWParams = ((1, 'hProcess'), (1, 'siw'))

#def SymSetContext(hProcess, StackFrame, Context):
#    return SymSetContext.ctypes_function(hProcess, StackFrame, Context)
SymSetContextPrototype = WINFUNCTYPE(BOOL, HANDLE, PIMAGEHLP_STACK_FRAME, PIMAGEHLP_CONTEXT)
SymSetContextParams = ((1, 'hProcess'), (1, 'StackFrame'), (1, 'Context'))

#def SymSetExtendedOption(option, value):
#    return SymSetExtendedOption.ctypes_function(option, value)
SymSetExtendedOptionPrototype = WINFUNCTYPE(BOOL, IMAGEHLP_EXTENDED_OPTIONS, BOOL)
SymSetExtendedOptionParams = ((1, 'option'), (1, 'value'))

#def SymSrvGetFileIndexes(File, Id, Val1, Val2, Flags):
#    return SymSrvGetFileIndexes.ctypes_function(File, Id, Val1, Val2, Flags)
SymSrvGetFileIndexesPrototype = WINFUNCTYPE(BOOL, PCSTR, POINTER(GUID), PDWORD, PDWORD, DWORD)
SymSrvGetFileIndexesParams = ((1, 'File'), (1, 'Id'), (1, 'Val1'), (1, 'Val2'), (1, 'Flags'))

#def SymSrvGetFileIndexesW(File, Id, Val1, Val2, Flags):
#    return SymSrvGetFileIndexesW.ctypes_function(File, Id, Val1, Val2, Flags)
SymSrvGetFileIndexesWPrototype = WINFUNCTYPE(BOOL, PCWSTR, POINTER(GUID), PDWORD, PDWORD, DWORD)
SymSrvGetFileIndexesWParams = ((1, 'File'), (1, 'Id'), (1, 'Val1'), (1, 'Val2'), (1, 'Flags'))

#def SymSrvGetFileIndexInfo(File, Info, Flags):
#    return SymSrvGetFileIndexInfo.ctypes_function(File, Info, Flags)
SymSrvGetFileIndexInfoPrototype = WINFUNCTYPE(BOOL, PCSTR, PSYMSRV_INDEX_INFO, DWORD)
SymSrvGetFileIndexInfoParams = ((1, 'File'), (1, 'Info'), (1, 'Flags'))

#def SymSrvGetFileIndexInfoW(File, Info, Flags):
#    return SymSrvGetFileIndexInfoW.ctypes_function(File, Info, Flags)
SymSrvGetFileIndexInfoWPrototype = WINFUNCTYPE(BOOL, PCWSTR, PSYMSRV_INDEX_INFOW, DWORD)
SymSrvGetFileIndexInfoWParams = ((1, 'File'), (1, 'Info'), (1, 'Flags'))

#def SymSrvGetFileIndexString(hProcess, SrvPath, File, Index, Size, Flags):
#    return SymSrvGetFileIndexString.ctypes_function(hProcess, SrvPath, File, Index, Size, Flags)
SymSrvGetFileIndexStringPrototype = WINFUNCTYPE(BOOL, HANDLE, PCSTR, PCSTR, PSTR, SIZE_T, DWORD)
SymSrvGetFileIndexStringParams = ((1, 'hProcess'), (1, 'SrvPath'), (1, 'File'), (1, 'Index'), (1, 'Size'), (1, 'Flags'))

#def SymSrvGetFileIndexStringW(hProcess, SrvPath, File, Index, Size, Flags):
#    return SymSrvGetFileIndexStringW.ctypes_function(hProcess, SrvPath, File, Index, Size, Flags)
SymSrvGetFileIndexStringWPrototype = WINFUNCTYPE(BOOL, HANDLE, PCWSTR, PCWSTR, PWSTR, SIZE_T, DWORD)
SymSrvGetFileIndexStringWParams = ((1, 'hProcess'), (1, 'SrvPath'), (1, 'File'), (1, 'Index'), (1, 'Size'), (1, 'Flags'))

#def SymUnDName(sym, UnDecName, UnDecNameLength):
#    return SymUnDName.ctypes_function(sym, UnDecName, UnDecNameLength)
SymUnDNamePrototype = WINFUNCTYPE(BOOL, PIMAGEHLP_SYMBOL, PSTR, DWORD)
SymUnDNameParams = ((1, 'sym'), (1, 'UnDecName'), (1, 'UnDecNameLength'))

#def SymUnDName64(sym, UnDecName, UnDecNameLength):
#    return SymUnDName64.ctypes_function(sym, UnDecName, UnDecNameLength)
SymUnDName64Prototype = WINFUNCTYPE(BOOL, PIMAGEHLP_SYMBOL64, PSTR, DWORD)
SymUnDName64Params = ((1, 'sym'), (1, 'UnDecName'), (1, 'UnDecNameLength'))

#def SymUnloadModule(hProcess, BaseOfDll):
#    return SymUnloadModule.ctypes_function(hProcess, BaseOfDll)
SymUnloadModulePrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD)
SymUnloadModuleParams = ((1, 'hProcess'), (1, 'BaseOfDll'))

#def SymUnloadModule64(hProcess, BaseOfDll):
#    return SymUnloadModule64.ctypes_function(hProcess, BaseOfDll)
SymUnloadModule64Prototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64)
SymUnloadModule64Params = ((1, 'hProcess'), (1, 'BaseOfDll'))

#def UnDecorateSymbolName(name, outputString, maxStringLength, flags):
#    return UnDecorateSymbolName.ctypes_function(name, outputString, maxStringLength, flags)
UnDecorateSymbolNamePrototype = WINFUNCTYPE(DWORD, PCSTR, PSTR, DWORD, DWORD)
UnDecorateSymbolNameParams = ((1, 'name'), (1, 'outputString'), (1, 'maxStringLength'), (1, 'flags'))

#def UnDecorateSymbolNameW(name, outputString, maxStringLength, flags):
#    return UnDecorateSymbolNameW.ctypes_function(name, outputString, maxStringLength, flags)
UnDecorateSymbolNameWPrototype = WINFUNCTYPE(DWORD, PCWSTR, PWSTR, DWORD, DWORD)
UnDecorateSymbolNameWParams = ((1, 'name'), (1, 'outputString'), (1, 'maxStringLength'), (1, 'flags'))

#def SymCleanup(hProcess):
#    return SymCleanup.ctypes_function(hProcess)
SymCleanupPrototype = WINFUNCTYPE(BOOL, HANDLE)
SymCleanupParams = ((1, 'hProcess'),)

#def SymEnumProcesses(EnumProcessesCallback, UserContext):
#    return SymEnumProcesses.ctypes_function(EnumProcessesCallback, UserContext)
SymEnumProcessesPrototype = WINFUNCTYPE(BOOL, PSYM_ENUMPROCESSES_CALLBACK, PVOID)
SymEnumProcessesParams = ((1, 'EnumProcessesCallback'), (1, 'UserContext'))

#def SymEnumSymbolsForAddr(hProcess, Address, EnumSymbolsCallback, UserContext):
#    return SymEnumSymbolsForAddr.ctypes_function(hProcess, Address, EnumSymbolsCallback, UserContext)
SymEnumSymbolsForAddrPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64, PSYM_ENUMERATESYMBOLS_CALLBACK, PVOID)
SymEnumSymbolsForAddrParams = ((1, 'hProcess'), (1, 'Address'), (1, 'EnumSymbolsCallback'), (1, 'UserContext'))

#def SymEnumSymbolsForAddrW(hProcess, Address, EnumSymbolsCallback, UserContext):
#    return SymEnumSymbolsForAddrW.ctypes_function(hProcess, Address, EnumSymbolsCallback, UserContext)
SymEnumSymbolsForAddrWPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64, PSYM_ENUMERATESYMBOLS_CALLBACKW, PVOID)
SymEnumSymbolsForAddrWParams = ((1, 'hProcess'), (1, 'Address'), (1, 'EnumSymbolsCallback'), (1, 'UserContext'))

#def SymGetTypeFromName(hProcess, BaseOfDll, Name, Symbol):
#    return SymGetTypeFromName.ctypes_function(hProcess, BaseOfDll, Name, Symbol)
SymGetTypeFromNamePrototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, PCSTR, PSYMBOL_INFO)
SymGetTypeFromNameParams = ((1, 'hProcess'), (1, 'BaseOfDll'), (1, 'Name'), (1, 'Symbol'))

#def SymGetTypeInfo(hProcess, ModBase, TypeId, GetType, pInfo):
#    return SymGetTypeInfo.ctypes_function(hProcess, ModBase, TypeId, GetType, pInfo)
SymGetTypeInfoPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD64, ULONG, IMAGEHLP_SYMBOL_TYPE_INFO, PVOID)
SymGetTypeInfoParams = ((1, 'hProcess'), (1, 'ModBase'), (1, 'TypeId'), (1, 'GetType'), (1, 'pInfo'))

#def SymSearch(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options):
#    return SymSearch.ctypes_function(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options)
SymSearchPrototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, DWORD, DWORD, PCSTR, DWORD64, PSYM_ENUMERATESYMBOLS_CALLBACK, PVOID, DWORD)
SymSearchParams = ((1, 'hProcess'), (1, 'BaseOfDll'), (1, 'Index'), (1, 'SymTag'), (1, 'Mask'), (1, 'Address'), (1, 'EnumSymbolsCallback'), (1, 'UserContext'), (1, 'Options'))

#def SymSearchW(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options):
#    return SymSearchW.ctypes_function(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options)
SymSearchWPrototype = WINFUNCTYPE(BOOL, HANDLE, ULONG64, DWORD, DWORD, PCWSTR, DWORD64, PSYM_ENUMERATESYMBOLS_CALLBACKW, PVOID, DWORD)
SymSearchWParams = ((1, 'hProcess'), (1, 'BaseOfDll'), (1, 'Index'), (1, 'SymTag'), (1, 'Mask'), (1, 'Address'), (1, 'EnumSymbolsCallback'), (1, 'UserContext'), (1, 'Options'))

#def SymFunctionTableAccess(hProcess, AddrBase):
#    return SymFunctionTableAccess.ctypes_function(hProcess, AddrBase)
SymFunctionTableAccessPrototype = WINFUNCTYPE(PVOID, HANDLE, DWORD)
SymFunctionTableAccessParams = ((1, 'hProcess'), (1, 'AddrBase'))

#def SymFunctionTableAccess64(hProcess, AddrBase):
#    return SymFunctionTableAccess64.ctypes_function(hProcess, AddrBase)
SymFunctionTableAccess64Prototype = WINFUNCTYPE(PVOID, HANDLE, DWORD64)
SymFunctionTableAccess64Params = ((1, 'hProcess'), (1, 'AddrBase'))

#def SymGetModuleBase(hProcess, dwAddr):
#    return SymGetModuleBase.ctypes_function(hProcess, dwAddr)
SymGetModuleBasePrototype = WINFUNCTYPE(DWORD, HANDLE, DWORD)
SymGetModuleBaseParams = ((1, 'hProcess'), (1, 'dwAddr'))

#def SymGetModuleBase64(hProcess, qwAddr):
#    return SymGetModuleBase64.ctypes_function(hProcess, qwAddr)
SymGetModuleBase64Prototype = WINFUNCTYPE(DWORD64, HANDLE, DWORD64)
SymGetModuleBase64Params = ((1, 'hProcess'), (1, 'qwAddr'))

#def SymRefreshModuleList(hProcess):
#    return SymRefreshModuleList.ctypes_function(hProcess)
SymRefreshModuleListPrototype = WINFUNCTYPE(BOOL, HANDLE)
SymRefreshModuleListParams = ((1, 'hProcess'),)

#def SymRegisterCallback(hProcess, CallbackFunction, UserContext):
#    return SymRegisterCallback.ctypes_function(hProcess, CallbackFunction, UserContext)
SymRegisterCallbackPrototype = WINFUNCTYPE(BOOL, HANDLE, PSYMBOL_REGISTERED_CALLBACK, PVOID)
SymRegisterCallbackParams = ((1, 'hProcess'), (1, 'CallbackFunction'), (1, 'UserContext'))

#def SymRegisterCallback64(hProcess, CallbackFunction, UserContext):
#    return SymRegisterCallback64.ctypes_function(hProcess, CallbackFunction, UserContext)
SymRegisterCallback64Prototype = WINFUNCTYPE(BOOL, HANDLE, PSYMBOL_REGISTERED_CALLBACK64, ULONG64)
SymRegisterCallback64Params = ((1, 'hProcess'), (1, 'CallbackFunction'), (1, 'UserContext'))

#def SymRegisterCallbackW64(hProcess, CallbackFunction, UserContext):
#    return SymRegisterCallbackW64.ctypes_function(hProcess, CallbackFunction, UserContext)
SymRegisterCallbackW64Prototype = WINFUNCTYPE(BOOL, HANDLE, PSYMBOL_REGISTERED_CALLBACK64, ULONG64)
SymRegisterCallbackW64Params = ((1, 'hProcess'), (1, 'CallbackFunction'), (1, 'UserContext'))

#def StackWalk64(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress):
#    return StackWalk64.ctypes_function(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress)
StackWalk64Prototype = WINFUNCTYPE(BOOL, DWORD, HANDLE, HANDLE, LPSTACKFRAME64, PVOID, PREAD_PROCESS_MEMORY_ROUTINE64, PFUNCTION_TABLE_ACCESS_ROUTINE64, PGET_MODULE_BASE_ROUTINE64, PTRANSLATE_ADDRESS_ROUTINE64)
StackWalk64Params = ((1, 'MachineType'), (1, 'hProcess'), (1, 'hThread'), (1, 'StackFrame'), (1, 'ContextRecord'), (1, 'ReadMemoryRoutine'), (1, 'FunctionTableAccessRoutine'), (1, 'GetModuleBaseRoutine'), (1, 'TranslateAddress'))

#def StackWalkEx(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress, Flags):
#    return StackWalkEx.ctypes_function(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress, Flags)
StackWalkExPrototype = WINFUNCTYPE(BOOL, DWORD, HANDLE, HANDLE, LPSTACKFRAME_EX, PVOID, PREAD_PROCESS_MEMORY_ROUTINE64, PFUNCTION_TABLE_ACCESS_ROUTINE64, PGET_MODULE_BASE_ROUTINE64, PTRANSLATE_ADDRESS_ROUTINE64, DWORD)
StackWalkExParams = ((1, 'MachineType'), (1, 'hProcess'), (1, 'hThread'), (1, 'StackFrame'), (1, 'ContextRecord'), (1, 'ReadMemoryRoutine'), (1, 'FunctionTableAccessRoutine'), (1, 'GetModuleBaseRoutine'), (1, 'TranslateAddress'), (1, 'Flags'))

#def StackWalk(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress):
#    return StackWalk.ctypes_function(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress)
StackWalkPrototype = WINFUNCTYPE(BOOL, DWORD, HANDLE, HANDLE, LPSTACKFRAME, PVOID, PREAD_PROCESS_MEMORY_ROUTINE, PFUNCTION_TABLE_ACCESS_ROUTINE, PGET_MODULE_BASE_ROUTINE, PTRANSLATE_ADDRESS_ROUTINE)
StackWalkParams = ((1, 'MachineType'), (1, 'hProcess'), (1, 'hThread'), (1, 'StackFrame'), (1, 'ContextRecord'), (1, 'ReadMemoryRoutine'), (1, 'FunctionTableAccessRoutine'), (1, 'GetModuleBaseRoutine'), (1, 'TranslateAddress'))

#def SymGetSearchPath(hProcess, SearchPath, SearchPathLength):
#    return SymGetSearchPath.ctypes_function(hProcess, SearchPath, SearchPathLength)
SymGetSearchPathPrototype = WINFUNCTYPE(BOOL, HANDLE, PSTR, DWORD)
SymGetSearchPathParams = ((1, 'hProcess'), (1, 'SearchPath'), (1, 'SearchPathLength'))

#def SymGetSearchPathW(hProcess, SearchPath, SearchPathLength):
#    return SymGetSearchPathW.ctypes_function(hProcess, SearchPath, SearchPathLength)
SymGetSearchPathWPrototype = WINFUNCTYPE(BOOL, HANDLE, PWSTR, DWORD)
SymGetSearchPathWParams = ((1, 'hProcess'), (1, 'SearchPath'), (1, 'SearchPathLength'))

#def SymSetSearchPath(hProcess, SearchPath):
#    return SymSetSearchPath.ctypes_function(hProcess, SearchPath)
SymSetSearchPathPrototype = WINFUNCTYPE(BOOL, HANDLE, PCSTR)
SymSetSearchPathParams = ((1, 'hProcess'), (1, 'SearchPath'))

#def SymSetSearchPathW(hProcess, SearchPath):
#    return SymSetSearchPathW.ctypes_function(hProcess, SearchPath)
SymSetSearchPathWPrototype = WINFUNCTYPE(BOOL, HANDLE, PCWSTR)
SymSetSearchPathWParams = ((1, 'hProcess'), (1, 'SearchPath'))

#def CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName):
#    return CreateEventA.ctypes_function(lpEventAttributes, bManualReset, bInitialState, lpName)
CreateEventAPrototype = WINFUNCTYPE(HANDLE, LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR)
CreateEventAParams = ((1, 'lpEventAttributes'), (1, 'bManualReset'), (1, 'bInitialState'), (1, 'lpName'))

#def CreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName):
#    return CreateEventW.ctypes_function(lpEventAttributes, bManualReset, bInitialState, lpName)
CreateEventWPrototype = WINFUNCTYPE(HANDLE, LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR)
CreateEventWParams = ((1, 'lpEventAttributes'), (1, 'bManualReset'), (1, 'bInitialState'), (1, 'lpName'))

#def CreateEventExA(lpEventAttributes, lpName, dwFlags, dwDesiredAccess):
#    return CreateEventExA.ctypes_function(lpEventAttributes, lpName, dwFlags, dwDesiredAccess)
CreateEventExAPrototype = WINFUNCTYPE(HANDLE, LPSECURITY_ATTRIBUTES, LPCSTR, DWORD, DWORD)
CreateEventExAParams = ((1, 'lpEventAttributes'), (1, 'lpName'), (1, 'dwFlags'), (1, 'dwDesiredAccess'))

#def CreateEventExW(lpEventAttributes, lpName, dwFlags, dwDesiredAccess):
#    return CreateEventExW.ctypes_function(lpEventAttributes, lpName, dwFlags, dwDesiredAccess)
CreateEventExWPrototype = WINFUNCTYPE(HANDLE, LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD)
CreateEventExWParams = ((1, 'lpEventAttributes'), (1, 'lpName'), (1, 'dwFlags'), (1, 'dwDesiredAccess'))

#def OpenEventA(dwDesiredAccess, bInheritHandle, lpName):
#    return OpenEventA.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)
OpenEventAPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCSTR)
OpenEventAParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

#def OpenEventW(dwDesiredAccess, bInheritHandle, lpName):
#    return OpenEventW.ctypes_function(dwDesiredAccess, bInheritHandle, lpName)
OpenEventWPrototype = WINFUNCTYPE(HANDLE, DWORD, BOOL, LPCWSTR)
OpenEventWParams = ((1, 'dwDesiredAccess'), (1, 'bInheritHandle'), (1, 'lpName'))

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

#def NtCreateNamedPipeFile(NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, WriteModeMessage, ReadModeMessage, NonBlocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTimeOut):
#    return NtCreateNamedPipeFile.ctypes_function(NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, WriteModeMessage, ReadModeMessage, NonBlocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTimeOut)
NtCreateNamedPipeFilePrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, BOOLEAN, BOOLEAN, BOOLEAN, ULONG, ULONG, ULONG, PLARGE_INTEGER)
NtCreateNamedPipeFileParams = ((1, 'NamedPipeFileHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'IoStatusBlock'), (1, 'ShareAccess'), (1, 'CreateDisposition'), (1, 'CreateOptions'), (1, 'WriteModeMessage'), (1, 'ReadModeMessage'), (1, 'NonBlocking'), (1, 'MaxInstances'), (1, 'InBufferSize'), (1, 'OutBufferSize'), (1, 'DefaultTimeOut'))

#def NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength):
#    return NtCreateFile.ctypes_function(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength)
NtCreateFilePrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG)
NtCreateFileParams = ((1, 'FileHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'IoStatusBlock'), (1, 'AllocationSize'), (1, 'FileAttributes'), (1, 'ShareAccess'), (1, 'CreateDisposition'), (1, 'CreateOptions'), (1, 'EaBuffer'), (1, 'EaLength'))

#def NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions):
#    return NtOpenFile.ctypes_function(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions)
NtOpenFilePrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG)
NtOpenFileParams = ((1, 'FileHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'IoStatusBlock'), (1, 'ShareAccess'), (1, 'OpenOptions'))

#def NtCreateSymbolicLinkObject(pHandle, DesiredAccess, ObjectAttributes, DestinationName):
#    return NtCreateSymbolicLinkObject.ctypes_function(pHandle, DesiredAccess, ObjectAttributes, DestinationName)
NtCreateSymbolicLinkObjectPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING)
NtCreateSymbolicLinkObjectParams = ((1, 'pHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'DestinationName'))

#def NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength):
#    return NtSetInformationProcess.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength)
NtSetInformationProcessPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG)
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

#def NtGetContextThread(hThread, lpContext):
#    return NtGetContextThread.ctypes_function(hThread, lpContext)
NtGetContextThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, LPCONTEXT)
NtGetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

#def NtSetContextThread(hThread, lpContext):
#    return NtSetContextThread.ctypes_function(hThread, lpContext)
NtSetContextThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, LPCONTEXT)
NtSetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

#def NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength):
#    return NtQueryInformationThread.ctypes_function(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)
NtQueryInformationThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQueryInformationThreadParams = ((1, 'ThreadHandle'), (1, 'ThreadInformationClass'), (1, 'ThreadInformation'), (1, 'ThreadInformationLength'), (1, 'ReturnLength'))

#def NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect):
#    return NtAllocateVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
NtAllocateVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, POINTER(PVOID), ULONG_PTR, PSIZE_T, ULONG, ULONG)
NtAllocateVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'ZeroBits'), (1, 'RegionSize'), (1, 'AllocationType'), (1, 'Protect'))

#def NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection):
#    return NtProtectVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection)
NtProtectVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, POINTER(PVOID), PULONG, ULONG, PULONG)
NtProtectVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'NumberOfBytesToProtect'), (1, 'NewAccessProtection'), (1, 'OldAccessProtection'))

#def NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength):
#    return NtQuerySystemInformation.ctypes_function(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)
NtQuerySystemInformationPrototype = WINFUNCTYPE(NTSTATUS, SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQuerySystemInformationParams = ((1, 'SystemInformationClass'), (1, 'SystemInformation'), (1, 'SystemInformationLength'), (1, 'ReturnLength'))

#def NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength):
#    return NtQueryInformationProcess.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)
NtQueryInformationProcessPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)
NtQueryInformationProcessParams = ((1, 'ProcessHandle'), (1, 'ProcessInformationClass'), (1, 'ProcessInformation'), (1, 'ProcessInformationLength'), (1, 'ReturnLength'))

#def NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
#    return NtReadVirtualMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
NtReadVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID, LPVOID, ULONG, PULONG)
NtReadVirtualMemoryParams = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesRead'))

#def NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten):
#    return NtWriteVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)
NtWriteVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PVOID, PVOID, ULONG, PULONG)
NtWriteVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'Buffer'), (1, 'NumberOfBytesToWrite'), (1, 'NumberOfBytesWritten'))

#def NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes):
#    return NtOpenEvent.ctypes_function(EventHandle, DesiredAccess, ObjectAttributes)
NtOpenEventPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)
NtOpenEventParams = ((1, 'EventHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'))

#def NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength):
#    return NtQueryObject.ctypes_function(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength)
NtQueryObjectPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG)
NtQueryObjectParams = ((1, 'Handle'), (1, 'ObjectInformationClass'), (1, 'ObjectInformation'), (1, 'ObjectInformationLength'), (1, 'ReturnLength'))

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

#def NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass):
#    return NtQueryInformationFile.ctypes_function(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)
NtQueryInformationFilePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS)
NtQueryInformationFileParams = ((1, 'FileHandle'), (1, 'IoStatusBlock'), (1, 'FileInformation'), (1, 'Length'), (1, 'FileInformationClass'))

#def NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan):
#    return NtQueryDirectoryFile.ctypes_function(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan)
NtQueryDirectoryFilePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN)
NtQueryDirectoryFileParams = ((1, 'FileHandle'), (1, 'Event'), (1, 'ApcRoutine'), (1, 'ApcContext'), (1, 'IoStatusBlock'), (1, 'FileInformation'), (1, 'Length'), (1, 'FileInformationClass'), (1, 'ReturnSingleEntry'), (1, 'FileName'), (1, 'RestartScan'))

#def NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass):
#    return NtSetInformationFile.ctypes_function(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)
NtSetInformationFilePrototype = WINFUNCTYPE(NTSTATUS, HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS)
NtSetInformationFileParams = ((1, 'FileHandle'), (1, 'IoStatusBlock'), (1, 'FileInformation'), (1, 'Length'), (1, 'FileInformationClass'))

#def NtEnumerateSystemEnvironmentValuesEx(InformationClass, Buffer, BufferLength):
#    return NtEnumerateSystemEnvironmentValuesEx.ctypes_function(InformationClass, Buffer, BufferLength)
NtEnumerateSystemEnvironmentValuesExPrototype = WINFUNCTYPE(NTSTATUS, ULONG, PVOID, ULONG)
NtEnumerateSystemEnvironmentValuesExParams = ((1, 'InformationClass'), (1, 'Buffer'), (1, 'BufferLength'))

#def NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType):
#    return NtFreeVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, RegionSize, FreeType)
NtFreeVirtualMemoryPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, POINTER(PVOID), PSIZE_T, ULONG)
NtFreeVirtualMemoryParams = ((1, 'ProcessHandle'), (1, 'BaseAddress'), (1, 'RegionSize'), (1, 'FreeType'))

#def NtGetContextThread(hThread, lpContext):
#    return NtGetContextThread.ctypes_function(hThread, lpContext)
NtGetContextThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, LPCONTEXT)
NtGetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

#def NtSetContextThread(hThread, lpContext):
#    return NtSetContextThread.ctypes_function(hThread, lpContext)
NtSetContextThreadPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, LPCONTEXT)
NtSetContextThreadParams = ((1, 'hThread'), (1, 'lpContext'))

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

#def NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId):
#    return NtOpenProcess.ctypes_function(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId)
NtOpenProcessPrototype = WINFUNCTYPE(NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)
NtOpenProcessParams = ((1, 'ProcessHandle'), (1, 'DesiredAccess'), (1, 'ObjectAttributes'), (1, 'ClientId'))

#def NtDelayExecution(Alertable, DelayInterval):
#    return NtDelayExecution.ctypes_function(Alertable, DelayInterval)
NtDelayExecutionPrototype = WINFUNCTYPE(NTSTATUS, BOOLEAN, PLARGE_INTEGER)
NtDelayExecutionParams = ((1, 'Alertable'), (1, 'DelayInterval'))

#def NtTerminateProcess(ProcessHandle, ExitStatus):
#    return NtTerminateProcess.ctypes_function(ProcessHandle, ExitStatus)
NtTerminateProcessPrototype = WINFUNCTYPE(NTSTATUS, HANDLE, NTSTATUS)
NtTerminateProcessParams = ((1, 'ProcessHandle'), (1, 'ExitStatus'))

#def GetComputerNameExA(NameType, lpBuffer, nSize):
#    return GetComputerNameExA.ctypes_function(NameType, lpBuffer, nSize)
GetComputerNameExAPrototype = WINFUNCTYPE(BOOL, COMPUTER_NAME_FORMAT, LPSTR, LPDWORD)
GetComputerNameExAParams = ((1, 'NameType'), (1, 'lpBuffer'), (1, 'nSize'))

#def GetComputerNameExW(NameType, lpBuffer, nSize):
#    return GetComputerNameExW.ctypes_function(NameType, lpBuffer, nSize)
GetComputerNameExWPrototype = WINFUNCTYPE(BOOL, COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD)
GetComputerNameExWParams = ((1, 'NameType'), (1, 'lpBuffer'), (1, 'nSize'))

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

#def LookupAccountNameA(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse):
#    return LookupAccountNameA.ctypes_function(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse)
LookupAccountNameAPrototype = WINFUNCTYPE(BOOL, LPCSTR, LPCSTR, PSID, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE)
LookupAccountNameAParams = ((1, 'lpSystemName'), (1, 'lpAccountName'), (1, 'Sid'), (1, 'cbSid'), (1, 'ReferencedDomainName'), (1, 'cchReferencedDomainName'), (1, 'peUse'))

#def LookupAccountNameW(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse):
#    return LookupAccountNameW.ctypes_function(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse)
LookupAccountNameWPrototype = WINFUNCTYPE(BOOL, LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE)
LookupAccountNameWParams = ((1, 'lpSystemName'), (1, 'lpAccountName'), (1, 'Sid'), (1, 'cbSid'), (1, 'ReferencedDomainName'), (1, 'cchReferencedDomainName'), (1, 'peUse'))

#def FileTimeToSystemTime(lpFileTime, lpSystemTime):
#    return FileTimeToSystemTime.ctypes_function(lpFileTime, lpSystemTime)
FileTimeToSystemTimePrototype = WINFUNCTYPE(BOOL, POINTER(FILETIME), LPSYSTEMTIME)
FileTimeToSystemTimeParams = ((1, 'lpFileTime'), (1, 'lpSystemTime'))

#def SystemTimeToFileTime(lpSystemTime, lpFileTime):
#    return SystemTimeToFileTime.ctypes_function(lpSystemTime, lpFileTime)
SystemTimeToFileTimePrototype = WINFUNCTYPE(BOOL, POINTER(SYSTEMTIME), LPFILETIME)
SystemTimeToFileTimeParams = ((1, 'lpSystemTime'), (1, 'lpFileTime'))

#def GetSystemTime(lpSystemTime):
#    return GetSystemTime.ctypes_function(lpSystemTime)
GetSystemTimePrototype = WINFUNCTYPE(PVOID, LPSYSTEMTIME)
GetSystemTimeParams = ((1, 'lpSystemTime'),)

#def GetSystemTimes(lpIdleTime, lpKernelTime, lpUserTime):
#    return GetSystemTimes.ctypes_function(lpIdleTime, lpKernelTime, lpUserTime)
GetSystemTimesPrototype = WINFUNCTYPE(BOOL, PFILETIME, PFILETIME, PFILETIME)
GetSystemTimesParams = ((1, 'lpIdleTime'), (1, 'lpKernelTime'), (1, 'lpUserTime'))

#def GetSystemTimeAsFileTime(lpSystemTimeAsFileTime):
#    return GetSystemTimeAsFileTime.ctypes_function(lpSystemTimeAsFileTime)
GetSystemTimeAsFileTimePrototype = WINFUNCTYPE(PVOID, LPFILETIME)
GetSystemTimeAsFileTimeParams = ((1, 'lpSystemTimeAsFileTime'),)

#def GetLocalTime(lpSystemTime):
#    return GetLocalTime.ctypes_function(lpSystemTime)
GetLocalTimePrototype = WINFUNCTYPE(PVOID, LPSYSTEMTIME)
GetLocalTimeParams = ((1, 'lpSystemTime'),)

#def GetTickCount():
#    return GetTickCount.ctypes_function()
GetTickCountPrototype = WINFUNCTYPE(DWORD)
GetTickCountParams = ()

#def GetTickCount64():
#    return GetTickCount64.ctypes_function()
GetTickCount64Prototype = WINFUNCTYPE(ULONGLONG)
GetTickCount64Params = ()

#def TdhEnumerateProviders(pBuffer, pBufferSize):
#    return TdhEnumerateProviders.ctypes_function(pBuffer, pBufferSize)
TdhEnumerateProvidersPrototype = WINFUNCTYPE(TDHSTATUS, PPROVIDER_ENUMERATION_INFO, POINTER(ULONG))
TdhEnumerateProvidersParams = ((1, 'pBuffer'), (1, 'pBufferSize'))

#def GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData):
#    return GetFileVersionInfoA.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)
GetFileVersionInfoAPrototype = WINFUNCTYPE(BOOL, LPCSTR, DWORD, DWORD, LPVOID)
GetFileVersionInfoAParams = ((1, 'lptstrFilename'), (1, 'dwHandle'), (1, 'dwLen'), (1, 'lpData'))

#def GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData):
#    return GetFileVersionInfoW.ctypes_function(lptstrFilename, dwHandle, dwLen, lpData)
GetFileVersionInfoWPrototype = WINFUNCTYPE(BOOL, LPWSTR, DWORD, DWORD, LPVOID)
GetFileVersionInfoWParams = ((1, 'lptstrFilename'), (1, 'dwHandle'), (1, 'dwLen'), (1, 'lpData'))

#def GetFileVersionInfoExA(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData):
#    return GetFileVersionInfoExA.ctypes_function(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData)
GetFileVersionInfoExAPrototype = WINFUNCTYPE(BOOL, DWORD, LPCSTR, DWORD, DWORD, LPVOID)
GetFileVersionInfoExAParams = ((1, 'dwFlags'), (1, 'lpwstrFilename'), (1, 'dwHandle'), (1, 'dwLen'), (1, 'lpData'))

#def GetFileVersionInfoExW(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData):
#    return GetFileVersionInfoExW.ctypes_function(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData)
GetFileVersionInfoExWPrototype = WINFUNCTYPE(BOOL, DWORD, LPCWSTR, DWORD, DWORD, LPVOID)
GetFileVersionInfoExWParams = ((1, 'dwFlags'), (1, 'lpwstrFilename'), (1, 'dwHandle'), (1, 'dwLen'), (1, 'lpData'))

#def GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle):
#    return GetFileVersionInfoSizeA.ctypes_function(lptstrFilename, lpdwHandle)
GetFileVersionInfoSizeAPrototype = WINFUNCTYPE(DWORD, LPCSTR, LPDWORD)
GetFileVersionInfoSizeAParams = ((1, 'lptstrFilename'), (1, 'lpdwHandle'))

#def GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle):
#    return GetFileVersionInfoSizeW.ctypes_function(lptstrFilename, lpdwHandle)
GetFileVersionInfoSizeWPrototype = WINFUNCTYPE(DWORD, LPWSTR, LPDWORD)
GetFileVersionInfoSizeWParams = ((1, 'lptstrFilename'), (1, 'lpdwHandle'))

#def GetFileVersionInfoSizeExA(dwFlags, lpwstrFilename, lpdwHandle):
#    return GetFileVersionInfoSizeExA.ctypes_function(dwFlags, lpwstrFilename, lpdwHandle)
GetFileVersionInfoSizeExAPrototype = WINFUNCTYPE(DWORD, DWORD, LPCSTR, LPDWORD)
GetFileVersionInfoSizeExAParams = ((1, 'dwFlags'), (1, 'lpwstrFilename'), (1, 'lpdwHandle'))

#def GetFileVersionInfoSizeExW(dwFlags, lpwstrFilename, lpdwHandle):
#    return GetFileVersionInfoSizeExW.ctypes_function(dwFlags, lpwstrFilename, lpdwHandle)
GetFileVersionInfoSizeExWPrototype = WINFUNCTYPE(DWORD, DWORD, LPCWSTR, LPDWORD)
GetFileVersionInfoSizeExWParams = ((1, 'dwFlags'), (1, 'lpwstrFilename'), (1, 'lpdwHandle'))

#def VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen):
#    return VerQueryValueA.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)
VerQueryValueAPrototype = WINFUNCTYPE(BOOL, LPCVOID, LPCSTR, POINTER(LPVOID), PUINT)
VerQueryValueAParams = ((1, 'pBlock'), (1, 'lpSubBlock'), (1, 'lplpBuffer'), (1, 'puLen'))

#def VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen):
#    return VerQueryValueW.ctypes_function(pBlock, lpSubBlock, lplpBuffer, puLen)
VerQueryValueWPrototype = WINFUNCTYPE(BOOL, LPCVOID, LPWSTR, POINTER(LPVOID), PUINT)
VerQueryValueWParams = ((1, 'pBlock'), (1, 'lpSubBlock'), (1, 'lplpBuffer'), (1, 'puLen'))

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

#def LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle):
#    return LdrLoadDll.ctypes_function(PathToFile, Flags, ModuleFileName, ModuleHandle)
LdrLoadDllPrototype = WINFUNCTYPE(NTSTATUS, LPCWSTR, PVOID, PUNICODE_STRING, PHANDLE)
LdrLoadDllParams = ((1, 'PathToFile'), (1, 'Flags'), (1, 'ModuleFileName'), (1, 'ModuleHandle'))

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

#def VirtualFree(lpAddress, dwSize, dwFreeType):
#    return VirtualFree.ctypes_function(lpAddress, dwSize, dwFreeType)
VirtualFreePrototype = WINFUNCTYPE(BOOL, LPVOID, SIZE_T, DWORD)
VirtualFreeParams = ((1, 'lpAddress'), (1, 'dwSize'), (1, 'dwFreeType'))

#def VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType):
#    return VirtualFreeEx.ctypes_function(hProcess, lpAddress, dwSize, dwFreeType)
VirtualFreeExPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, SIZE_T, DWORD)
VirtualFreeExParams = ((1, 'hProcess'), (1, 'lpAddress'), (1, 'dwSize'), (1, 'dwFreeType'))

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

#def SetThreadContext(hThread, lpContext):
#    return SetThreadContext.ctypes_function(hThread, lpContext)
SetThreadContextPrototype = WINFUNCTYPE(BOOL, HANDLE, LPCONTEXT)
SetThreadContextParams = ((1, 'hThread'), (1, 'lpContext'))

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

#def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten):
#    return WriteProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
WriteProcessMemoryPrototype = WINFUNCTYPE(BOOL, HANDLE, LPVOID, LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemoryParams = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesWritten'))

#def NtWow64WriteVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten):
#    return NtWow64WriteVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
NtWow64WriteVirtualMemory64Prototype = WINFUNCTYPE(NTSTATUS, HANDLE, ULONG64, LPVOID, ULONG64, PULONG64)
NtWow64WriteVirtualMemory64Params = ((1, 'hProcess'), (1, 'lpBaseAddress'), (1, 'lpBuffer'), (1, 'nSize'), (1, 'lpNumberOfBytesWritten'))

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

#def FreeResource(hResData):
#    return FreeResource.ctypes_function(hResData)
FreeResourcePrototype = WINFUNCTYPE(BOOL, HGLOBAL)
FreeResourceParams = ((1, 'hResData'),)

#def EnumResourceTypesA(hModule, lpEnumFunc, lParam):
#    return EnumResourceTypesA.ctypes_function(hModule, lpEnumFunc, lParam)
EnumResourceTypesAPrototype = WINFUNCTYPE(BOOL, HMODULE, ENUMRESTYPEPROCA, LONG_PTR)
EnumResourceTypesAParams = ((1, 'hModule'), (1, 'lpEnumFunc'), (1, 'lParam'))

#def EnumResourceTypesW(hModule, lpEnumFunc, lParam):
#    return EnumResourceTypesW.ctypes_function(hModule, lpEnumFunc, lParam)
EnumResourceTypesWPrototype = WINFUNCTYPE(BOOL, HMODULE, ENUMRESTYPEPROCW, LONG_PTR)
EnumResourceTypesWParams = ((1, 'hModule'), (1, 'lpEnumFunc'), (1, 'lParam'))

#def EnumResourceNamesA(hModule, lpType, lpEnumFunc, lParam):
#    return EnumResourceNamesA.ctypes_function(hModule, lpType, lpEnumFunc, lParam)
EnumResourceNamesAPrototype = WINFUNCTYPE(BOOL, HMODULE, LPCSTR, ENUMRESNAMEPROCA, LONG_PTR)
EnumResourceNamesAParams = ((1, 'hModule'), (1, 'lpType'), (1, 'lpEnumFunc'), (1, 'lParam'))

#def EnumResourceNamesW(hModule, lpType, lpEnumFunc, lParam):
#    return EnumResourceNamesW.ctypes_function(hModule, lpType, lpEnumFunc, lParam)
EnumResourceNamesWPrototype = WINFUNCTYPE(BOOL, HMODULE, LPCWSTR, ENUMRESNAMEPROCW, LONG_PTR)
EnumResourceNamesWParams = ((1, 'hModule'), (1, 'lpType'), (1, 'lpEnumFunc'), (1, 'lParam'))

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

#def DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped):
#    return DeviceIoControl.ctypes_function(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)
DeviceIoControlPrototype = WINFUNCTYPE(BOOL, HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
DeviceIoControlParams = ((1, 'hDevice'), (1, 'dwIoControlCode'), (1, 'lpInBuffer'), (1, 'nInBufferSize'), (1, 'lpOutBuffer'), (1, 'nOutBufferSize'), (1, 'lpBytesReturned'), (1, 'lpOverlapped'))

#def GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength):
#    return GetTokenInformation.ctypes_function(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength)
GetTokenInformationPrototype = WINFUNCTYPE(BOOL, HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD)
GetTokenInformationParams = ((1, 'TokenHandle'), (1, 'TokenInformationClass'), (1, 'TokenInformation'), (1, 'TokenInformationLength'), (1, 'ReturnLength'))

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

#def RtlCompressBuffer(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, UncompressedChunkSize, FinalCompressedSize, WorkSpace):
#    return RtlCompressBuffer.ctypes_function(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, UncompressedChunkSize, FinalCompressedSize, WorkSpace)
RtlCompressBufferPrototype = WINFUNCTYPE(NTSTATUS, USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID)
RtlCompressBufferParams = ((1, 'CompressionFormatAndEngine'), (1, 'UncompressedBuffer'), (1, 'UncompressedBufferSize'), (1, 'CompressedBuffer'), (1, 'CompressedBufferSize'), (1, 'UncompressedChunkSize'), (1, 'FinalCompressedSize'), (1, 'WorkSpace'))

#def RtlDecompressBufferEx(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize, WorkSpace):
#    return RtlDecompressBufferEx.ctypes_function(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize, WorkSpace)
RtlDecompressBufferExPrototype = WINFUNCTYPE(NTSTATUS, USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID)
RtlDecompressBufferExParams = ((1, 'CompressionFormat'), (1, 'UncompressedBuffer'), (1, 'UncompressedBufferSize'), (1, 'CompressedBuffer'), (1, 'CompressedBufferSize'), (1, 'FinalUncompressedSize'), (1, 'WorkSpace'))

#def RtlGetCompressionWorkSpaceSize(CompressionFormatAndEngine, CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize):
#    return RtlGetCompressionWorkSpaceSize.ctypes_function(CompressionFormatAndEngine, CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize)
RtlGetCompressionWorkSpaceSizePrototype = WINFUNCTYPE(NTSTATUS, USHORT, PULONG, PULONG)
RtlGetCompressionWorkSpaceSizeParams = ((1, 'CompressionFormatAndEngine'), (1, 'CompressBufferWorkSpaceSize'), (1, 'CompressFragmentWorkSpaceSize'))

#def RtlMoveMemory(Destination, Source, Length):
#    return RtlMoveMemory.ctypes_function(Destination, Source, Length)
RtlMoveMemoryPrototype = WINFUNCTYPE(VOID, PVOID, PVOID, SIZE_T)
RtlMoveMemoryParams = ((1, 'Destination'), (1, 'Source'), (1, 'Length'))

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

#def GetSystemMetrics(nIndex):
#    return GetSystemMetrics.ctypes_function(nIndex)
GetSystemMetricsPrototype = WINFUNCTYPE(INT, INT)
GetSystemMetricsParams = ((1, 'nIndex'),)

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

#def IsDebuggerPresent():
#    return IsDebuggerPresent.ctypes_function()
IsDebuggerPresentPrototype = WINFUNCTYPE(BOOL)
IsDebuggerPresentParams = ()

#def WSAStartup(wVersionRequested, lpWSAData):
#    return WSAStartup.ctypes_function(wVersionRequested, lpWSAData)
WSAStartupPrototype = WINFUNCTYPE(INT, WORD, LPWSADATA)
WSAStartupParams = ((1, 'wVersionRequested'), (1, 'lpWSAData'))

#def WSACleanup():
#    return WSACleanup.ctypes_function()
WSACleanupPrototype = WINFUNCTYPE(INT)
WSACleanupParams = ()

#def WSAGetLastError():
#    return WSAGetLastError.ctypes_function()
WSAGetLastErrorPrototype = WINFUNCTYPE(INT)
WSAGetLastErrorParams = ()

#def getaddrinfo(pNodeName, pServiceName, pHints, ppResult):
#    return getaddrinfo.ctypes_function(pNodeName, pServiceName, pHints, ppResult)
getaddrinfoPrototype = WINFUNCTYPE(INT, PCSTR, PCSTR, POINTER(ADDRINFOA), POINTER(PADDRINFOA))
getaddrinfoParams = ((1, 'pNodeName'), (1, 'pServiceName'), (1, 'pHints'), (1, 'ppResult'))

#def GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult):
#    return GetAddrInfoW.ctypes_function(pNodeName, pServiceName, pHints, ppResult)
GetAddrInfoWPrototype = WINFUNCTYPE(INT, PCWSTR, PCWSTR, POINTER(ADDRINFOW), POINTER(PADDRINFOW))
GetAddrInfoWParams = ((1, 'pNodeName'), (1, 'pServiceName'), (1, 'pHints'), (1, 'ppResult'))

#def WSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags):
#    return WSASocketA.ctypes_function(af, type, protocol, lpProtocolInfo, g, dwFlags)
WSASocketAPrototype = WINFUNCTYPE(SOCKET, INT, INT, INT, LPWSAPROTOCOL_INFOA, GROUP, DWORD)
WSASocketAParams = ((1, 'af'), (1, 'type'), (1, 'protocol'), (1, 'lpProtocolInfo'), (1, 'g'), (1, 'dwFlags'))

#def WSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags):
#    return WSASocketW.ctypes_function(af, type, protocol, lpProtocolInfo, g, dwFlags)
WSASocketWPrototype = WINFUNCTYPE(SOCKET, INT, INT, INT, LPWSAPROTOCOL_INFOW, GROUP, DWORD)
WSASocketWParams = ((1, 'af'), (1, 'type'), (1, 'protocol'), (1, 'lpProtocolInfo'), (1, 'g'), (1, 'dwFlags'))

#def socket(af, type, protocol):
#    return socket.ctypes_function(af, type, protocol)
socketPrototype = WINFUNCTYPE(SOCKET, INT, INT, INT)
socketParams = ((1, 'af'), (1, 'type'), (1, 'protocol'))

#def connect(s, name, namelen):
#    return connect.ctypes_function(s, name, namelen)
connectPrototype = WINFUNCTYPE(INT, SOCKET, POINTER(sockaddr), INT)
connectParams = ((1, 's'), (1, 'name'), (1, 'namelen'))

#def send(s, buf, len, flags):
#    return send.ctypes_function(s, buf, len, flags)
sendPrototype = WINFUNCTYPE(INT, SOCKET, POINTER(CHAR), INT, INT)
sendParams = ((1, 's'), (1, 'buf'), (1, 'len'), (1, 'flags'))

#def recv(s, buf, len, flags):
#    return recv.ctypes_function(s, buf, len, flags)
recvPrototype = WINFUNCTYPE(INT, SOCKET, POINTER(CHAR), INT, INT)
recvParams = ((1, 's'), (1, 'buf'), (1, 'len'), (1, 'flags'))

#def shutdown(s, how):
#    return shutdown.ctypes_function(s, how)
shutdownPrototype = WINFUNCTYPE(INT, SOCKET, INT)
shutdownParams = ((1, 's'), (1, 'how'))

#def closesocket(s):
#    return closesocket.ctypes_function(s)
closesocketPrototype = WINFUNCTYPE(INT, SOCKET)
closesocketParams = ((1, 's'),)

