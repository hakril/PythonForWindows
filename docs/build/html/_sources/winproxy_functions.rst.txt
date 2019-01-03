Functions:

* AddVectoredContinueHandler::

    AddVectoredContinueHandler(FirstHandler=1, VectoredHandler=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* AddVectoredExceptionHandler::

    AddVectoredExceptionHandler(FirstHandler=1, VectoredHandler=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* AdjustTokenPrivileges::

    AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges=False, NewState=NeededParameter, BufferLength=None, PreviousState=None, ReturnLength=None)
    Errcheck:
       raise WinproxyError if result is 0

* AllocConsole::

    AllocConsole()
    Errcheck:
       raise WinproxyError if result is 0

* AlpcGetMessageAttribute::

    AlpcGetMessageAttribute(Buffer, AttributeFlag)
    Errcheck:
       raise NtStatusException is result is not 0

* AlpcInitializeMessageAttribute::

    AlpcInitializeMessageAttribute(AttributeFlags, Buffer, BufferSize, RequiredBufferSize)
    Errcheck:
       raise NtStatusException is result is not 0

* CLSIDFromProgID::

    CLSIDFromProgID(lpszProgID, lpclsid)

* CertAddCertificateContextToStore::

    CertAddCertificateContextToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext)
    Errcheck:
       raise WinproxyError if result is 0

* CertCompareCertificate::

    CertCompareCertificate(dwCertEncodingType, pCertId1, pCertId2)
    This function does not raise is compare has failed:
    return 0 if cert are NOT equals

* CertCreateCertificateContext::

    CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded)
    Errcheck:
       raise WinproxyError if result is 0

* CertCreateSelfSignCertificate::

    CertCreateSelfSignCertificate(hCryptProvOrNCryptKey, pSubjectIssuerBlob, dwFlags, pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions)
    Errcheck:
       raise WinproxyError if result is 0

* CertDuplicateCertificateContext::

    CertDuplicateCertificateContext(pCertContext)
    Errcheck:
       raise WinproxyError if result is 0

* CertEnumCTLsInStore::

    CertEnumCTLsInStore(hCertStore, pPrevCtlContext)
    Errcheck:
       raise WinproxyError if result is 0

* CertEnumCertificateContextProperties::

    CertEnumCertificateContextProperties(pCertContext, dwPropId)

* CertEnumCertificatesInStore::

    CertEnumCertificatesInStore(hCertStore, pPrevCertContext)
    Errcheck:
       raise WinproxyError if result is 0

* CertFindCertificateInStore::

    CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext)
    Errcheck:
       raise WinproxyError if result is 0

* CertFreeCertificateContext::

    CertFreeCertificateContext(pCertContext)
    Errcheck:
       raise WinproxyError if result is 0

* CertGetCertificateChain::

    CertGetCertificateChain(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext)
    Errcheck:
       raise WinproxyError if result is 0

* CertGetCertificateContextProperty::

    CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, pcbData)
    Errcheck:
       raise WinproxyError if result is 0

* CertGetNameStringA::

    CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)
    Errcheck:
       raise WinproxyError if result is 0

* CertGetNameStringW::

    CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)
    Errcheck:
       raise WinproxyError if result is 0

* CertOpenStore::

    CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara)
    Errcheck:
       raise WinproxyError if result is 0

* CertStrToNameA::

    CertStrToNameA(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)
    Errcheck:
       raise WinproxyError if result is 0

* CertStrToNameW::

    CertStrToNameW(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)
    Errcheck:
       raise WinproxyError if result is 0

* CloseEventLog::

    CloseEventLog(hEventLog)
    Errcheck:
       raise WinproxyError if result is 0

* CloseHandle::

    CloseHandle(hObject)
    Errcheck:
       raise WinproxyError if result is 0

* CloseServiceHandle::

    CloseServiceHandle(hSCObject)
    Errcheck:
       raise WinproxyError if result is 0

* CoCreateInstance::

    CoCreateInstance(rclsid, pUnkOuter=None, dwClsContext=tagCLSCTX.CLSCTX_INPROC_SERVER(0x1L), riid=NeededParameter, ppv=NeededParameter)

* CoCreateInstanceEx::

    CoCreateInstanceEx(rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults)

* CoGetInterceptor::

    CoGetInterceptor(iidIntercepted, punkOuter, iid, ppv)

* CoInitializeEx::

    CoInitializeEx(pvReserved=None, dwCoInit=tagCOINIT.COINIT_MULTITHREADED(0x0L))

* CoInitializeSecurity::

    CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3)

* CommitTransaction::

    CommitTransaction(TransactionHandle)
    Errcheck:
       raise WinproxyError if result is 0

* ConnectNamedPipe::

    ConnectNamedPipe(hNamedPipe, lpOverlapped)
    Errcheck:
       raise WinproxyError if result is 0

* ContinueDebugEvent::

    ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus)
    Errcheck:
       raise WinproxyError if result is 0

* ConvertSecurityDescriptorToStringSecurityDescriptorA::

    ConvertSecurityDescriptorToStringSecurityDescriptorA(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)
    Errcheck:
       raise WinproxyError if result is 0

* ConvertSecurityDescriptorToStringSecurityDescriptorW::

    ConvertSecurityDescriptorToStringSecurityDescriptorW(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)
    Errcheck:
       raise WinproxyError if result is 0

* ConvertSidToStringSidA::

    ConvertSidToStringSidA(Sid, StringSid)
    Errcheck:
       raise WinproxyError if result is 0

* ConvertSidToStringSidW::

    ConvertSidToStringSidW(Sid, StringSid)
    Errcheck:
       raise WinproxyError if result is 0

* ConvertStringSecurityDescriptorToSecurityDescriptorA::

    ConvertStringSecurityDescriptorToSecurityDescriptorA(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)
    Errcheck:
       raise WinproxyError if result is 0

* ConvertStringSecurityDescriptorToSecurityDescriptorW::

    ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)
    Errcheck:
       raise WinproxyError if result is 0

* ConvertStringSidToSidA::

    ConvertStringSidToSidA(StringSid, Sid)
    Errcheck:
       raise WinproxyError if result is 0

* ConvertStringSidToSidW::

    ConvertStringSidToSidW(StringSid, Sid)
    Errcheck:
       raise WinproxyError if result is 0

* CopySid::

    CopySid(nDestinationSidLength, pDestinationSid, pSourceSid)
    Errcheck:
       raise WinproxyError if result is 0

* CreateFileA::

    CreateFileA(lpFileName, dwDesiredAccess=GENERIC_READ(0x80000000L), dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=OPEN_EXISTING(0x3L), dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL(0x80L), hTemplateFile=None)
    Errcheck:
       raise WinproxyError is result is INVALID_HANDLE_VALUE

* CreateFileMappingA::

    CreateFileMappingA(hFile, lpFileMappingAttributes=None, flProtect=PAGE_READWRITE(0x4L), dwMaximumSizeHigh=0, dwMaximumSizeLow=NeededParameter, lpName=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* CreateFileMappingW::

    CreateFileMappingW(hFile, lpFileMappingAttributes=None, flProtect=PAGE_READWRITE(0x4L), dwMaximumSizeHigh=0, dwMaximumSizeLow=0, lpName=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* CreateFileTransactedA::

    CreateFileTransactedA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter)
    Errcheck:
       raise WinproxyError is result is INVALID_HANDLE_VALUE

* CreateFileTransactedW::

    CreateFileTransactedW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter)
    Errcheck:
       raise WinproxyError is result is INVALID_HANDLE_VALUE

* CreateFileW::

    CreateFileW(lpFileName, dwDesiredAccess=GENERIC_READ(0x80000000L), dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=OPEN_EXISTING(0x3L), dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL(0x80L), hTemplateFile=None)
    Errcheck:
       raise WinproxyError is result is INVALID_HANDLE_VALUE

* CreateNamedPipeA::

    CreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes)
    Errcheck:
       raise WinproxyError if result is 0

* CreateNamedPipeW::

    CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes)
    Errcheck:
       raise WinproxyError if result is 0

* CreateProcessA::

    CreateProcessA(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None)
    Errcheck:
       raise WinproxyError if result is 0

* CreateProcessAsUserA::

    CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None)
    Errcheck:
       raise WinproxyError if result is 0

* CreateProcessAsUserW::

    CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
    Errcheck:
       raise WinproxyError if result is 0

* CreateProcessW::

    CreateProcessW(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None)
    Errcheck:
       raise WinproxyError if result is 0

* CreateRemoteThread::

    CreateRemoteThread(hProcess=NeededParameter, lpThreadAttributes=None, dwStackSize=0, lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None)
    Errcheck:
       raise WinproxyError if result is 0

* CreateThread::

    CreateThread(lpThreadAttributes=None, dwStackSize=0, lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None)
    Errcheck:
       raise WinproxyError if result is 0

* CreateToolhelp32Snapshot::

    CreateToolhelp32Snapshot(dwFlags, th32ProcessID=0)
    Errcheck:
       raise WinproxyError if result is 0

* CreateTransaction::

    CreateTransaction(lpTransactionAttributes, UOW, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description)
    Errcheck:
       raise WinproxyError if result is 0

* CreateWellKnownSid::

    CreateWellKnownSid(WellKnownSidType, DomainSid=None, pSid=None, cbSid=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* CryptAcquireCertificatePrivateKey::

    CryptAcquireCertificatePrivateKey(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey)
    Errcheck:
       raise WinproxyError if result is 0

* CryptAcquireContextA::

    CryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* CryptAcquireContextW::

    CryptAcquireContextW(phProv, pszContainer, pszProvider, dwProvType, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* CryptCATAdminAcquireContext::

    CryptCATAdminAcquireContext(phCatAdmin, pgSubsystem, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* CryptCATAdminAcquireContext2::

    CryptCATAdminAcquireContext2(phCatAdmin, pgSubsystem, pwszHashAlgorithm, pStrongHashPolicy, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* CryptCATAdminCalcHashFromFileHandle::

    CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* CryptCATAdminCalcHashFromFileHandle2::

    CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, pcbHash, pbHash, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* CryptCATAdminEnumCatalogFromHash::

    CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo)

* CryptCATAdminReleaseCatalogContext::

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwFlags)

* CryptCATAdminReleaseContext::

    CryptCATAdminReleaseContext(hCatAdmin, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* CryptCATCatalogInfoFromContext::

    CryptCATCatalogInfoFromContext(hCatInfo, psCatInfo, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* CryptCATEnumerateAttr::

    CryptCATEnumerateAttr(hCatalog, pCatMember, pPrevAttr)

* CryptCATEnumerateCatAttr::

    CryptCATEnumerateCatAttr(hCatalog, pPrevAttr)

* CryptCATEnumerateMember::

    CryptCATEnumerateMember(hCatalog, pPrevMember)

* CryptDecodeObject::

    CryptDecodeObject(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo)
    Errcheck:
       raise WinproxyError if result is 0

* CryptDecryptMessage::

    CryptDecryptMessage(pDecryptPara, pbEncryptedBlob, cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert)
    Errcheck:
       raise WinproxyError if result is 0

* CryptDestroyKey::

    CryptDestroyKey(hKey)
    Errcheck:
       raise WinproxyError if result is 0

* CryptEncodeObjectEx::

    CryptEncodeObjectEx(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded)
    Errcheck:
       raise WinproxyError if result is 0

* CryptEncryptMessage::

    CryptEncryptMessage(pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob, pcbEncryptedBlob)
    Errcheck:
       raise WinproxyError if result is 0

* CryptExportKey::

    CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen)
    Errcheck:
       raise WinproxyError if result is 0

* CryptGenKey::

    CryptGenKey(hProv, Algid, dwFlags, phKey)
    Errcheck:
       raise WinproxyError if result is 0

* CryptHashCertificate::

    CryptHashCertificate(hCryptProv, Algid, dwFlags, pbEncoded, cbEncoded, pbComputedHash, pcbComputedHash)
    Errcheck:
       raise WinproxyError if result is 0

* CryptMsgClose::

    CryptMsgClose(hCryptMsg)
    Errcheck:
       raise WinproxyError if result is 0

* CryptMsgControl::

    CryptMsgControl(hCryptMsg, dwFlags, dwCtrlType, pvCtrlPara)
    Errcheck:
       raise WinproxyError if result is 0

* CryptMsgGetParam::

    CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, pvData, pcbData)
    Errcheck:
       raise WinproxyError if result is 0

* CryptMsgOpenToDecode::

    CryptMsgOpenToDecode(dwMsgEncodingType, dwFlags, dwMsgType, hCryptProv, pRecipientInfo, pStreamInfo)
    Errcheck:
       raise WinproxyError if result is 0

* CryptMsgOpenToEncode::

    CryptMsgOpenToEncode(dwMsgEncodingType, dwFlags, dwMsgType, pvMsgEncodeInfo, pszInnerContentObjID, pStreamInfo)
    Errcheck:
       raise WinproxyError if result is 0

* CryptMsgUpdate::

    CryptMsgUpdate(hCryptMsg, pbData, cbData, fFinal)
    Errcheck:
       raise WinproxyError if result is 0

* CryptMsgVerifyCountersignatureEncoded::

    CryptMsgVerifyCountersignatureEncoded(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, pciCountersigner)
    Errcheck:
       raise WinproxyError if result is 0

* CryptMsgVerifyCountersignatureEncodedEx::

    CryptMsgVerifyCountersignatureEncodedEx(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, dwSignerType, pvSigner, dwFlags, pvExtra)
    Errcheck:
       raise WinproxyError if result is 0

* CryptQueryObject::

    CryptQueryObject(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext)
    Errcheck:
       raise WinproxyError if result is 0

* CryptReleaseContext::

    CryptReleaseContext(hProv, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* CryptSignAndEncryptMessage::

    CryptSignAndEncryptMessage(pSignPara, pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeSignedAndEncrypted, cbToBeSignedAndEncrypted, pbSignedAndEncryptedBlob, pcbSignedAndEncryptedBlob)
    Errcheck:
       raise WinproxyError if result is 0

* CryptSignMessage::

    CryptSignMessage(pSignPara, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, pbSignedBlob, pcbSignedBlob)
    Errcheck:
       raise WinproxyError if result is 0

* CryptUIDlgViewContext::

    CryptUIDlgViewContext(dwContextType, pvContext, hwnd, pwszTitle, dwFlags, pvReserved)
    Errcheck:
       raise WinproxyError if result is 0

* CryptVerifyMessageHash::

    CryptVerifyMessageHash(pHashPara, pbHashedBlob, cbHashedBlob, pbToBeHashed, pcbToBeHashed, pbComputedHash, pcbComputedHash)
    Errcheck:
       raise WinproxyError if result is 0

* CryptVerifyMessageSignature::

    CryptVerifyMessageSignature(pVerifyPara, dwSignerIndex, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded, ppSignerCert)
    Errcheck:
       raise WinproxyError if result is 0

* CryptVerifyMessageSignatureWithKey::

    CryptVerifyMessageSignatureWithKey(pVerifyPara, pPublicKeyInfo, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded)
    Errcheck:
       raise WinproxyError if result is 0

* DebugActiveProcess::

    DebugActiveProcess(dwProcessId)
    Errcheck:
       raise WinproxyError if result is 0

* DebugActiveProcessStop::

    DebugActiveProcessStop(dwProcessId)
    Errcheck:
       raise WinproxyError if result is 0

* DebugBreak::

    DebugBreak()
    Errcheck:
       raise WinproxyError if result is 0

* DebugBreakProcess::

    DebugBreakProcess(Process)
    Errcheck:
       raise WinproxyError if result is 0

* DebugSetProcessKillOnExit::

    DebugSetProcessKillOnExit(KillOnExit)
    Errcheck:
       raise WinproxyError if result is 0

* DeleteProcThreadAttributeList::

    DeleteProcThreadAttributeList(lpAttributeList)
    Errcheck:
       raise WinproxyError if result is 0

* DeviceIoControl::

    DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize=None, lpOutBuffer=NeededParameter, nOutBufferSize=None, lpBytesReturned=None, lpOverlapped=None)
    Errcheck:
       raise WinproxyError if result is 0

* DuplicateHandle::

    DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess=0, bInheritHandle=False, dwOptions=0)
    Errcheck:
       raise WinproxyError if result is 0

* DuplicateToken::

    DuplicateToken(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle)
    Errcheck:
       raise WinproxyError if result is 0

* DuplicateTokenEx::

    DuplicateTokenEx(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken)
    Errcheck:
       raise WinproxyError if result is 0

* EnumChildWindows::

    EnumChildWindows(hWndParent, lpEnumFunc, lParam)
    Errcheck:
       raise WinproxyError if result is 0

* EnumServicesStatusExA::

    EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)
    Errcheck:
       raise WinproxyError if result is 0

* EnumServicesStatusExW::

    EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)
    Errcheck:
       raise WinproxyError if result is 0

* EnumWindows::

    EnumWindows(lpEnumFunc, lParam)
    Errcheck:
       raise WinproxyError if result is 0

* EqualSid::

    EqualSid(pSid1, pSid2)
    Errcheck:
       raise WinproxyError if result is 0

* EvtClose::

    EvtClose(Object)
    Errcheck:
       raise WinproxyError if result is 0

* EvtCreateRenderContext::

    EvtCreateRenderContext(ValuePathsCount, ValuePaths, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* EvtFormatMessage::

    EvtFormatMessage(PublisherMetadata, Event, MessageId, ValueCount, Values, Flags, BufferSize, Buffer, BufferUsed)
    Errcheck:
       raise WinproxyError if result is 0

* EvtGetChannelConfigProperty::

    EvtGetChannelConfigProperty(ChannelConfig, PropertyId, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)
    Errcheck:
       raise WinproxyError if result is 0

* EvtGetEventMetadataProperty::

    EvtGetEventMetadataProperty(EventMetadata, PropertyId, Flags, EventMetadataPropertyBufferSize, EventMetadataPropertyBuffer, EventMetadataPropertyBufferUsed)
    Errcheck:
       raise WinproxyError if result is 0

* EvtGetLogInfo::

    EvtGetLogInfo(Log, PropertyId, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)
    Errcheck:
       raise WinproxyError if result is 0

* EvtGetObjectArrayProperty::

    EvtGetObjectArrayProperty(ObjectArray, PropertyId, ArrayIndex, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)
    Errcheck:
       raise WinproxyError if result is 0

* EvtGetObjectArraySize::

    EvtGetObjectArraySize(ObjectArray, ObjectArraySize)
    Errcheck:
       raise WinproxyError if result is 0

* EvtGetPublisherMetadataProperty::

    EvtGetPublisherMetadataProperty(PublisherMetadata, PropertyId, Flags, PublisherMetadataPropertyBufferSize, PublisherMetadataPropertyBuffer, PublisherMetadataPropertyBufferUsed)
    Errcheck:
       raise WinproxyError if result is 0

* EvtNext::

    EvtNext(ResultSet, EventArraySize, EventArray, Timeout, Flags, Returned)
    Errcheck:
       raise WinproxyError if result is 0

* EvtNextChannelPath::

    EvtNextChannelPath(ChannelEnum, ChannelPathBufferSize, ChannelPathBuffer, ChannelPathBufferUsed)
    Errcheck:
       raise WinproxyError if result is 0

* EvtNextEventMetadata::

    EvtNextEventMetadata(EventMetadataEnum, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* EvtNextPublisherId::

    EvtNextPublisherId(PublisherEnum, PublisherIdBufferSize, PublisherIdBuffer, PublisherIdBufferUsed)
    Errcheck:
       raise WinproxyError if result is 0

* EvtOpenChannelConfig::

    EvtOpenChannelConfig(Session, ChannelPath, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* EvtOpenChannelEnum::

    EvtOpenChannelEnum(Session, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* EvtOpenEventMetadataEnum::

    EvtOpenEventMetadataEnum(PublisherMetadata, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* EvtOpenLog::

    EvtOpenLog(Session, Path, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* EvtOpenPublisherEnum::

    EvtOpenPublisherEnum(Session, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* EvtOpenPublisherMetadata::

    EvtOpenPublisherMetadata(Session, PublisherIdentity, LogFilePath, Locale, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* EvtQuery::

    EvtQuery(Session, Path, Query, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* EvtRender::

    EvtRender(Context, Fragment, Flags, BufferSize, Buffer, BufferUsed, PropertyCount)
    Errcheck:
       raise WinproxyError if result is 0

* ExitProcess::

    ExitProcess(uExitCode)
    Errcheck:
       raise WinproxyError if result is 0

* ExitThread::

    ExitThread(dwExitCode)
    Errcheck:
       raise WinproxyError if result is 0

* FindFirstVolumeA::

    FindFirstVolumeA(lpszVolumeName, cchBufferLength)
    Errcheck:
       raise WinproxyError if result is 0

* FindFirstVolumeW::

    FindFirstVolumeW(lpszVolumeName, cchBufferLength)
    Errcheck:
       raise WinproxyError if result is 0

* FindNextVolumeA::

    FindNextVolumeA(hFindVolume, lpszVolumeName, cchBufferLength)
    Errcheck:
       raise WinproxyError if result is 0

* FindNextVolumeW::

    FindNextVolumeW(hFindVolume, lpszVolumeName, cchBufferLength)
    Errcheck:
       raise WinproxyError if result is 0

* FindWindowA::

    FindWindowA(lpClassName, lpWindowName)
    Errcheck:
       raise WinproxyError if result is 0

* FindWindowW::

    FindWindowW(lpClassName, lpWindowName)
    Errcheck:
       raise WinproxyError if result is 0

* FreeConsole::

    FreeConsole()
    Errcheck:
       raise WinproxyError if result is 0

* FreeLibrary::

    FreeLibrary(hLibModule)
    Errcheck:
       raise WinproxyError if result is 0

* GetAce::

    GetAce(pAcl, dwAceIndex, pAce)
    Errcheck:
       raise WinproxyError if result is 0

* GetAclInformation::

    GetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass)
    Errcheck:
       raise WinproxyError if result is 0

* GetClassInfoExA::

    GetClassInfoExA(hinst, lpszClass, lpwcx)
    Errcheck:
       raise WinproxyError if result is 0

* GetClassInfoExW::

    GetClassInfoExW(hinst, lpszClass, lpwcx)
    Errcheck:
       raise WinproxyError if result is 0

* GetClassNameA::

    GetClassNameA(hwnd, pszType, cchType=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetClassNameW::

    GetClassNameW(hwnd, pszType, cchType=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetComputerNameA::

    GetComputerNameA(lpBuffer, lpnSize)
    Errcheck:
       raise WinproxyError if result is 0

* GetComputerNameW::

    GetComputerNameW(lpBuffer, lpnSize)
    Errcheck:
       raise WinproxyError if result is 0

* GetCurrentProcess::

    GetCurrentProcess()
    Errcheck:
       raise WinproxyError if result is 0

* GetCurrentProcessorNumber::

    GetCurrentProcessorNumber()
    Errcheck:
       raise WinproxyError if result is 0

* GetCurrentThread::

    GetCurrentThread()
    Errcheck:
       raise WinproxyError if result is 0

* GetCurrentThreadId::

    GetCurrentThreadId()
    Errcheck:
       raise WinproxyError if result is 0

* GetCursorPos::

    GetCursorPos(lpPoint)
    Errcheck:
       raise WinproxyError if result is 0

* GetDriveTypeA::

    GetDriveTypeA(lpRootPathName)
    Errcheck:
       raise WinproxyError if result is 0

* GetDriveTypeW::

    GetDriveTypeW(lpRootPathName)
    Errcheck:
       raise WinproxyError if result is 0

* GetEventLogInformation::

    GetEventLogInformation(hEventLog, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)
    Errcheck:
       raise WinproxyError if result is 0

* GetExitCodeProcess::

    GetExitCodeProcess(hProcess, lpExitCode)
    Errcheck:
       raise WinproxyError if result is 0

* GetExitCodeThread::

    GetExitCodeThread(hThread, lpExitCode)
    Errcheck:
       raise WinproxyError if result is 0

* GetExtendedTcpTable::

    GetExtendedTcpTable(pTcpTable, pdwSize=None, bOrder=True, ulAf=NeededParameter, TableClass=_TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL(0x5L), Reserved=0)
    Errcheck:
       raise WinproxyError if result is NOT 0

* GetFileVersionInfoA::

    GetFileVersionInfoA(lptstrFilename, dwHandle=0, dwLen=None, lpData=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* GetFileVersionInfoSizeA::

    GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetFileVersionInfoSizeW::

    GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetFileVersionInfoW::

    GetFileVersionInfoW(lptstrFilename, dwHandle=0, dwLen=None, lpData=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* GetFirmwareEnvironmentVariableA::

    GetFirmwareEnvironmentVariableA(lpName, lpGuid, pBuffer, nSize)
    Errcheck:
       raise WinproxyError if result is 0

* GetFirmwareEnvironmentVariableExA::

    GetFirmwareEnvironmentVariableExA(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes)
    Errcheck:
       raise WinproxyError if result is 0

* GetFirmwareEnvironmentVariableExW::

    GetFirmwareEnvironmentVariableExW(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes)
    Errcheck:
       raise WinproxyError if result is 0

* GetFirmwareEnvironmentVariableW::

    GetFirmwareEnvironmentVariableW(lpName, lpGuid, pBuffer, nSize)
    Errcheck:
       raise WinproxyError if result is 0

* GetIfTable::

    GetIfTable(pIfTable, pdwSize, bOrder=False)
    Errcheck:
       raise WinproxyError if result is NOT 0

* GetInterfaceInfo::

    GetInterfaceInfo(pIfTable, dwOutBufLen=None)
    Errcheck:
       raise WinproxyError if result is NOT 0

* GetIpAddrTable::

    GetIpAddrTable(pIpAddrTable, pdwSize, bOrder=False)
    Errcheck:
       raise WinproxyError if result is NOT 0

* GetLastError::

    GetLastError()

* GetLengthSid::

    GetLengthSid(pSid)
    Errcheck:
       raise WinproxyError if result is 0

* GetLogicalDriveStringsA::

    GetLogicalDriveStringsA(nBufferLength, lpBuffer)
    Errcheck:
       raise WinproxyError if result is 0

* GetLogicalDriveStringsW::

    GetLogicalDriveStringsW(nBufferLength, lpBuffer)
    Errcheck:
       raise WinproxyError if result is 0

* GetLongPathNameA::

    GetLongPathNameA(lpszShortPath, lpszLongPath, cchBuffer=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetLongPathNameW::

    GetLongPathNameW(lpszShortPath, lpszLongPath, cchBuffer=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetMappedFileNameA::

    GetMappedFileNameA(hProcess, lpv, lpFilename, nSize=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetMappedFileNameW::

    GetMappedFileNameW(hProcess, lpv, lpFilename, nSize=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetModuleBaseNameA::

    GetModuleBaseNameA(hProcess, hModule, lpBaseName, nSize=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetModuleBaseNameW::

    GetModuleBaseNameW(hProcess, hModule, lpBaseName, nSize=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetModuleFileNameA::

    GetModuleFileNameA(hModule, lpFilename, nSize)
    Errcheck:
       raise WinproxyError if result is 0

* GetModuleFileNameW::

    GetModuleFileNameW(hModule, lpFilename, nSize)
    Errcheck:
       raise WinproxyError if result is 0

* GetModuleHandleA::

    GetModuleHandleA(lpModuleName)
    Errcheck:
       raise WinproxyError if result is 0

* GetModuleHandleW::

    GetModuleHandleW(lpModuleName)
    Errcheck:
       raise WinproxyError if result is 0

* GetNamedSecurityInfoA::

    GetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None)
    Errcheck:
       raise WinproxyError(result) if result is NOT 0

* GetNamedSecurityInfoW::

    GetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None)
    Errcheck:
       raise WinproxyError(result) if result is NOT 0

* GetNumberOfEventLogRecords::

    GetNumberOfEventLogRecords(hEventLog, NumberOfRecords)
    Errcheck:
       raise WinproxyError if result is 0

* GetParent::

    GetParent(hWnd)
    Errcheck:
       raise WinproxyError if result is 0

* GetPriorityClass::

    GetPriorityClass(hProcess)
    Errcheck:
       raise WinproxyError if result is 0

* GetProcAddress::

    GetProcAddress(hModule, lpProcName)
    Errcheck:
       raise WinproxyError if result is 0

* GetProcessDEPPolicy::

    GetProcessDEPPolicy(hProcess, lpFlags, lpPermanent)
    Errcheck:
       raise WinproxyError if result is 0

* GetProcessId::

    GetProcessId(Process)
    Errcheck:
       raise WinproxyError if result is 0

* GetProcessImageFileNameA::

    GetProcessImageFileNameA(hProcess, lpImageFileName, nSize=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetProcessImageFileNameW::

    GetProcessImageFileNameW(hProcess, lpImageFileName, nSize=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetProcessMemoryInfo::

    GetProcessMemoryInfo(Process, ppsmemCounters, cb)
    Errcheck:
       raise WinproxyError if result is 0

* GetProcessMitigationPolicy::

    GetProcessMitigationPolicy(hProcess, MitigationPolicy, lpBuffer, dwLength=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetProcessTimes::

    GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime)
    Errcheck:
       raise WinproxyError if result is 0

* GetProductInfo::

    GetProductInfo(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType)
    Errcheck:
       raise WinproxyError if result is 0

* GetSecurityDescriptorControl::

    GetSecurityDescriptorControl(pSecurityDescriptor, pControl, lpdwRevision)
    Errcheck:
       raise WinproxyError if result is 0

* GetSecurityDescriptorDacl::

    GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted)
    Errcheck:
       raise WinproxyError if result is 0

* GetSecurityDescriptorGroup::

    GetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, lpbGroupDefaulted)
    Errcheck:
       raise WinproxyError if result is 0

* GetSecurityDescriptorLength::

    GetSecurityDescriptorLength(pSecurityDescriptor)
    Errcheck:
       raise WinproxyError if result is 0

* GetSecurityDescriptorOwner::

    GetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, lpbOwnerDefaulted)
    Errcheck:
       raise WinproxyError if result is 0

* GetSecurityDescriptorSacl::

    GetSecurityDescriptorSacl(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted)
    Errcheck:
       raise WinproxyError if result is 0

* GetSecurityInfo::

    GetSecurityInfo(handle, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None)
    Errcheck:
       raise WinproxyError if result is NOT 0

* GetShortPathNameA::

    GetShortPathNameA(lpszLongPath, lpszShortPath, cchBuffer=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetShortPathNameW::

    GetShortPathNameW(lpszLongPath, lpszShortPath, cchBuffer=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetSidSubAuthority::

    GetSidSubAuthority(pSid, nSubAuthority)
    Errcheck:
       raise WinproxyError if result is 0

* GetSidSubAuthorityCount::

    GetSidSubAuthorityCount(pSid)
    Errcheck:
       raise WinproxyError if result is 0

* GetStdHandle::

    GetStdHandle(nStdHandle)
    Errcheck:
       raise WinproxyError if result is 0

* GetSystemMetrics::

    GetSystemMetrics(nIndex)
    Errcheck:
       raise WinproxyError if result is 0

* GetThreadContext::

    GetThreadContext(hThread, lpContext)
    Errcheck:
       raise WinproxyError if result is 0

* GetThreadId::

    GetThreadId(Thread)
    Errcheck:
       raise WinproxyError if result is 0

* GetTokenInformation::

    GetTokenInformation(TokenHandle=NeededParameter, TokenInformationClass=NeededParameter, TokenInformation=None, TokenInformationLength=0, ReturnLength=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetVersionExA::

    GetVersionExA(lpVersionInformation)
    Errcheck:
       raise WinproxyError if result is 0

* GetVersionExW::

    GetVersionExW(lpVersionInformation)
    Errcheck:
       raise WinproxyError if result is 0

* GetVolumeInformationA::

    GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)
    Errcheck:
       raise WinproxyError if result is 0

* GetVolumeInformationW::

    GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer=None, nVolumeNameSize=0, lpVolumeSerialNumber=None, lpMaximumComponentLength=None, lpFileSystemFlags=None, lpFileSystemNameBuffer=None, nFileSystemNameSize=0)
    Errcheck:
       raise WinproxyError if result is 0

* GetVolumeNameForVolumeMountPointA::

    GetVolumeNameForVolumeMountPointA(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)
    Errcheck:
       raise WinproxyError if result is 0

* GetVolumeNameForVolumeMountPointW::

    GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)
    Errcheck:
       raise WinproxyError if result is 0

* GetWindowModuleFileNameA::

    GetWindowModuleFileNameA(hwnd, pszFileName, cchFileNameMax)
    Errcheck:
       raise WinproxyError if result is 0

* GetWindowModuleFileNameW::

    GetWindowModuleFileNameW(hwnd, pszFileName, cchFileNameMax)
    Errcheck:
       raise WinproxyError if result is 0

* GetWindowRect::

    GetWindowRect(hWnd, lpRect)
    Errcheck:
       raise WinproxyError if result is 0

* GetWindowTextA::

    GetWindowTextA(hWnd, lpString, nMaxCount)

* GetWindowTextW::

    GetWindowTextW(hWnd, lpString, nMaxCount)
    Errcheck:
       raise WinproxyError if result is 0

* GetWindowThreadProcessId::

    GetWindowThreadProcessId(hWnd, lpdwProcessId)
    Errcheck:
       raise WinproxyError if result is 0

* GetWindowsDirectoryA::

    GetWindowsDirectoryA(lpBuffer, uSize=None)
    Errcheck:
       raise WinproxyError if result is 0

* GetWindowsDirectoryW::

    GetWindowsDirectoryW(lpBuffer, uSize=None)
    Errcheck:
       raise WinproxyError if result is 0

* InitializeProcThreadAttributeList::

    InitializeProcThreadAttributeList(lpAttributeList=None, dwAttributeCount=NeededParameter, dwFlags=0, lpSize=NeededParameter)

* IsOS::

    IsOS(dwOS)
    Errcheck:
       raise WinproxyError if result is 0

* IsValidSecurityDescriptor::

    IsValidSecurityDescriptor(pSecurityDescriptor)
    Errcheck:
       raise WinproxyError if result is 0

* LdrLoadDll::

    LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle)
    Errcheck:
       raise NtStatusException is result is not 0

* LoadLibraryA::

    LoadLibraryA(lpFileName)
    Errcheck:
       raise WinproxyError if result is 0

* LoadLibraryExA::

    LoadLibraryExA(lpLibFileName, hFile, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* LoadLibraryExW::

    LoadLibraryExW(lpLibFileName, hFile, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* LoadLibraryW::

    LoadLibraryW(lpFileName)
    Errcheck:
       raise WinproxyError if result is 0

* LocalFree::

    LocalFree(hMem)
    Errcheck:
       raise WinproxyError if result is NOT 0

* LookupAccountSidA::

    LookupAccountSidA(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)
    Errcheck:
       raise WinproxyError if result is 0

* LookupAccountSidW::

    LookupAccountSidW(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)
    Errcheck:
       raise WinproxyError if result is 0

* LookupPrivilegeNameA::

    LookupPrivilegeNameA(lpSystemName, lpLuid, lpName, cchName)
    Errcheck:
       raise WinproxyError if result is 0

* LookupPrivilegeNameW::

    LookupPrivilegeNameW(lpSystemName, lpLuid, lpName, cchName)
    Errcheck:
       raise WinproxyError if result is 0

* LookupPrivilegeValueA::

    LookupPrivilegeValueA(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* LookupPrivilegeValueW::

    LookupPrivilegeValueW(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* MapViewOfFile::

    MapViewOfFile(hFileMappingObject, dwDesiredAccess=FILE_MAP_ALL_ACCESS(0xf001fL), dwFileOffsetHigh=0, dwFileOffsetLow=0, dwNumberOfBytesToMap=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* MessageBoxA::

    MessageBoxA(hWnd=0, lpText=NeededParameter, lpCaption=None, uType=0)
    Errcheck:
       raise WinproxyError if result is 0

* MessageBoxW::

    MessageBoxW(hWnd=0, lpText=NeededParameter, lpCaption=None, uType=0)
    Errcheck:
       raise WinproxyError if result is 0

* NtAllocateVirtualMemory::

    NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcAcceptConnectPort::

    NtAlpcAcceptConnectPort(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcConnectPort::

    NtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcConnectPortEx::

    NtAlpcConnectPortEx(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcCreatePort::

    NtAlpcCreatePort(PortHandle, ObjectAttributes, PortAttributes)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcCreatePortSection::

    NtAlpcCreatePortSection(PortHandle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcCreateSectionView::

    NtAlpcCreateSectionView(PortHandle, Flags, ViewAttributes)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcDeletePortSection::

    NtAlpcDeletePortSection(PortHandle, Flags, SectionHandle)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcDeleteSectionView::

    NtAlpcDeleteSectionView(PortHandle, Flags, ViewBase)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcDisconnectPort::

    NtAlpcDisconnectPort(PortHandle, Flags)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcQueryInformation::

    NtAlpcQueryInformation(PortHandle, PortInformationClass, PortInformation, Length, ReturnLength)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcQueryInformationMessage::

    NtAlpcQueryInformationMessage(PortHandle, PortMessage, MessageInformationClass, MessageInformation, Length, ReturnLength)
    Errcheck:
       raise NtStatusException is result is not 0

* NtAlpcSendWaitReceivePort::

    NtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout)
    Errcheck:
       raise NtStatusException is result is not 0

* NtCreateFile::

    NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength)
    Errcheck:
       raise NtStatusException is result is not 0

* NtCreateKey::

    NtCreateKey(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition)
    Errcheck:
       raise NtStatusException is result is not 0

* NtCreateProcessEx::

    NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes=None, ParentProcess=NeededParameter, Flags=NeededParameter, SectionHandle=NeededParameter, DebugPort=None, ExceptionPort=None, InJob=False)
    Errcheck:
       raise NtStatusException is result is not 0

* NtCreateSection::

    NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle)
    Errcheck:
       raise NtStatusException is result is not 0

* NtCreateThreadEx::

    NtCreateThreadEx(ThreadHandle=None, DesiredAccess=2097151, ObjectAttributes=0, ProcessHandle=NeededParameter, lpStartAddress=NeededParameter, lpParameter=NeededParameter, CreateSuspended=0, dwStackSize=0, Unknown1=0, Unknown2=0, Unknown=0)
    Errcheck:
       raise NtStatusException is result is not 0

* NtEnumerateSystemEnvironmentValuesEx::

    NtEnumerateSystemEnvironmentValuesEx(InformationClass, Buffer, BufferLength)
    Errcheck:
       raise NtStatusException is result is not 0

* NtEnumerateValueKey::

    NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)
    Errcheck:
       raise NtStatusException is result is not 0

* NtFreeVirtualMemory::

    NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType)
    Errcheck:
       raise NtStatusException is result is not 0

* NtGetContextThread::

    NtGetContextThread(hThread, lpContext)
    Errcheck:
       raise NtStatusException is result is not 0

* NtMapViewOfSection::

    NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect)
    Errcheck:
       raise NtStatusException is result is not 0

* NtOpenDirectoryObject::

    NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes)
    Errcheck:
       raise NtStatusException is result is not 0

* NtOpenEvent::

    NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes)
    Errcheck:
       raise NtStatusException is result is not 0

* NtOpenKey::

    NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes)
    Errcheck:
       raise NtStatusException is result is not 0

* NtOpenSection::

    NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes)
    Errcheck:
       raise NtStatusException is result is not 0

* NtOpenSymbolicLinkObject::

    NtOpenSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes)
    Errcheck:
       raise NtStatusException is result is not 0

* NtProtectVirtualMemory::

    NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection=None)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryDirectoryFile::

    NtQueryDirectoryFile(FileHandle, Event=None, ApcRoutine=None, ApcContext=None, IoStatusBlock=NeededParameter, FileInformation=NeededParameter, Length=None, FileInformationClass=NeededParameter, ReturnSingleEntry=NeededParameter, FileName=None, RestartScan=NeededParameter)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryDirectoryObject::

    NtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryEaFile::

    NtQueryEaFile(FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryInformationFile::

    NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length=None, FileInformationClass=NeededParameter)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryInformationProcess::

    NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength=0, ReturnLength=None)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryInformationThread::

    NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength=0, ReturnLength=None)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryLicenseValue::

    NtQueryLicenseValue(Name, Type, Buffer, Length=None, DataLength=NeededParameter)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryObject::

    NtQueryObject(Handle, ObjectInformationClass, ObjectInformation=None, ObjectInformationLength=0, ReturnLength=NeededParameter)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQuerySymbolicLinkObject::

    NtQuerySymbolicLinkObject(LinkHandle, LinkTarget, ReturnedLength)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQuerySystemInformation::

    NtQuerySystemInformation(SystemInformationClass, SystemInformation=None, SystemInformationLength=0, ReturnLength=NeededParameter)

* NtQueryValueKey::

    NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryVirtualMemory::

    NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation=NeededParameter, MemoryInformationLength=0, ReturnLength=None)
    Errcheck:
       raise NtStatusException is result is not 0

* NtQueryVolumeInformationFile::

    NtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FsInformation, Length=None, FsInformationClass=NeededParameter)
    Errcheck:
       raise NtStatusException is result is not 0

* NtReadVirtualMemory::

    NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
    Errcheck:
       raise NtStatusException is result is not 0

* NtSetContextThread::

    NtSetContextThread(hThread, lpContext)
    Errcheck:
       raise NtStatusException is result is not 0

* NtSetEaFile::

    NtSetEaFile(FileHandle, IoStatusBlock, Buffer, Length)
    Errcheck:
       raise NtStatusException is result is not 0

* NtSetInformationFile::

    NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)
    Errcheck:
       raise NtStatusException is result is not 0

* NtSetInformationProcess::

    NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength=0)
    Errcheck:
       raise NtStatusException is result is not 0

* NtSetValueKey::

    NtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize)
    Errcheck:
       raise NtStatusException is result is not 0

* NtUnmapViewOfSection::

    NtUnmapViewOfSection(ProcessHandle, BaseAddress)
    Errcheck:
       raise NtStatusException is result is not 0

* NtWow64ReadVirtualMemory64::

    NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None)
    Errcheck:
       raise NtStatusException is result is not 0

* NtWow64WriteVirtualMemory64::

    NtWow64WriteVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten=None)
    Errcheck:
       raise NtStatusException is result is not 0

* NtWriteVirtualMemory::

    NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)
    Errcheck:
       raise NtStatusException is result is not 0

* ObjectFromLresult::

    ObjectFromLresult(lResult, riid, wParam, ppvObject)
    Errcheck:
       raise WinproxyError if result is NOT 0

* OpenBackupEventLogA::

    OpenBackupEventLogA(lpUNCServerName=None, lpSourceName=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* OpenBackupEventLogW::

    OpenBackupEventLogW(lpUNCServerName=None, lpSourceName=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* OpenEventA::

    OpenEventA(dwDesiredAccess, bInheritHandle, lpName)
    Errcheck:
       raise WinproxyError if result is 0

* OpenEventLogA::

    OpenEventLogA(lpUNCServerName=None, lpSourceName=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* OpenEventLogW::

    OpenEventLogW(lpUNCServerName=None, lpSourceName=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* OpenEventW::

    OpenEventW(dwDesiredAccess, bInheritHandle, lpName)
    Errcheck:
       raise WinproxyError if result is 0

* OpenProcess::

    OpenProcess(dwDesiredAccess=PROCESS_ALL_ACCESS(0x1f0fffL), bInheritHandle=0, dwProcessId=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* OpenProcessToken::

    OpenProcessToken(ProcessHandle=None, DesiredAccess=NeededParameter, TokenHandle=NeededParameter)
    If ProcessHandle is None: take the current process
    Errcheck:
       raise WinproxyError if result is 0

* OpenSCManagerA::

    OpenSCManagerA(lpMachineName=None, lpDatabaseName=None, dwDesiredAccess=SC_MANAGER_ALL_ACCESS(0xf003fL))
    Errcheck:
       raise WinproxyError if result is 0

* OpenSCManagerW::

    OpenSCManagerW(lpMachineName=None, lpDatabaseName=None, dwDesiredAccess=SC_MANAGER_ALL_ACCESS(0xf003fL))
    Errcheck:
       raise WinproxyError if result is 0

* OpenServiceA::

    OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess)
    Errcheck:
       raise WinproxyError if result is 0

* OpenServiceW::

    OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess)
    Errcheck:
       raise WinproxyError if result is 0

* OpenThread::

    OpenThread(dwDesiredAccess=THREAD_ALL_ACCESS(0x1f03ffL), bInheritHandle=0, dwThreadId=NeededParameter)
    Errcheck:
       raise WinproxyError if result is 0

* OpenThreadToken::

    OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle)
    Errcheck:
       raise WinproxyError if result is 0

* OpenTransaction::

    OpenTransaction(dwDesiredAccess, TransactionId)
    Errcheck:
       raise WinproxyError if result is 0

* PFXExportCertStoreEx::

    PFXExportCertStoreEx(hStore, pPFX, szPassword, pvPara, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* PFXImportCertStore::

    PFXImportCertStore(pPFX, szPassword, dwFlags)
    Errcheck:
       raise WinproxyError if result is 0

* Process32First::

    Process32First(hSnapshot, lpte)
    Errcheck:
       raise WinproxyError if result is 0

* Process32Next::

    Process32Next(hSnapshot, lpte)

* QueryDosDeviceA::

    QueryDosDeviceA(lpDeviceName, lpTargetPath, ucchMax)
    Errcheck:
       raise WinproxyError if result is 0

* QueryDosDeviceW::

    QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax)
    Errcheck:
       raise WinproxyError if result is 0

* QueryWorkingSet::

    QueryWorkingSet(hProcess, pv, cb)
    Errcheck:
       raise WinproxyError if result is 0

* QueryWorkingSetEx::

    QueryWorkingSetEx(hProcess, pv, cb)
    Errcheck:
       raise WinproxyError if result is 0

* ReadEventLogA::

    ReadEventLogA(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded)
    Errcheck:
       raise WinproxyError if result is 0

* ReadEventLogW::

    ReadEventLogW(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded)
    Errcheck:
       raise WinproxyError if result is 0

* ReadFile::

    ReadFile(hFile, lpBuffer, nNumberOfBytesToRead=None, lpNumberOfBytesRead=None, lpOverlapped=None)
    Errcheck:
       raise WinproxyError if result is 0

* ReadProcessMemory::

    ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None)
    Errcheck:
       raise WinproxyError if result is 0

* RealGetWindowClassA::

    RealGetWindowClassA(hwnd, pszType, cchType=None)
    Errcheck:
       raise WinproxyError if result is 0

* RealGetWindowClassW::

    RealGetWindowClassW(hwnd, pszType, cchType=None)
    Errcheck:
       raise WinproxyError if result is 0

* RegCloseKey::

    RegCloseKey(hKey)
    Errcheck:
       raise WinproxyError if result is NOT 0

* RegGetValueA::

    RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
    Errcheck:
       raise WinproxyError if result is NOT 0

* RegGetValueW::

    RegGetValueW(hkey, lpSubKey=None, lpValue=NeededParameter, dwFlags=0, pdwType=None, pvData=None, pcbData=None)
    Errcheck:
       raise WinproxyError if result is NOT 0

* RegOpenKeyExA::

    RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult)
    Errcheck:
       raise WinproxyError if result is NOT 0

* RegOpenKeyExW::

    RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult)
    Errcheck:
       raise WinproxyError if result is NOT 0

* RegQueryValueExA::

    RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
    Errcheck:
       raise WinproxyError if result is NOT 0

* RegQueryValueExW::

    RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
    Errcheck:
       raise WinproxyError if result is NOT 0

* RemoveVectoredExceptionHandler::

    RemoveVectoredExceptionHandler(Handler)
    Errcheck:
       raise WinproxyError if result is 0

* ResumeThread::

    ResumeThread(hThread)
    Errcheck:
       Raise WinproxyError if call result is -1

* RollbackTransaction::

    RollbackTransaction(TransactionHandle)
    Errcheck:
       raise WinproxyError if result is 0

* RtlDecompressBuffer::

    RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize=None, FinalUncompressedSize=NeededParameter)
    Errcheck:
       raise NtStatusException is result is not 0

* RtlDecompressBufferEx::

    RtlDecompressBufferEx(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize=None, FinalUncompressedSize=NeededParameter, WorkSpace=NeededParameter)
    Errcheck:
       raise NtStatusException is result is not 0

* RtlDosPathNameToNtPathName_U::

    RtlDosPathNameToNtPathName_U(DosName, NtName=None, PartName=None, RelativeName=None)
    Errcheck:
       raise WinproxyError if result is 0

* RtlEqualUnicodeString::

    RtlEqualUnicodeString(String1, String2, CaseInSensitive)
    Errcheck:
       raise NtStatusException is result is not 0

* RtlGetCompressionWorkSpaceSize::

    RtlGetCompressionWorkSpaceSize(CompressionFormatAndEngine, CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize)
    Errcheck:
       raise NtStatusException is result is not 0

* RtlGetUnloadEventTraceEx::

    RtlGetUnloadEventTraceEx(ElementSize, ElementCount, EventTrace)
    Errcheck:
       raise NtStatusException is result is not 0

* SHGetPathFromIDListA::

    SHGetPathFromIDListA(pidl, pszPath)
    Errcheck:
       raise WinproxyError if result is 0

* SHGetPathFromIDListW::

    SHGetPathFromIDListW(pidl, pszPath)
    Errcheck:
       raise WinproxyError if result is 0

* SetConsoleCtrlHandler::

    SetConsoleCtrlHandler(HandlerRoutine, Add)
    Errcheck:
       raise WinproxyError if result is 0

* SetNamedPipeHandleState::

    SetNamedPipeHandleState(hNamedPipe, lpMode, lpMaxCollectionCount, lpCollectDataTimeout)
    Errcheck:
       raise WinproxyError if result is 0

* SetPriorityClass::

    SetPriorityClass(hProcess, dwPriorityClass)
    Errcheck:
       raise WinproxyError if result is 0

* SetProcessMitigationPolicy::

    SetProcessMitigationPolicy(MitigationPolicy, lpBuffer, dwLength=None)
    Errcheck:
       raise WinproxyError if result is 0

* SetStdHandle::

    SetStdHandle(nStdHandle, hHandle)
    Errcheck:
       raise WinproxyError if result is 0

* SetTcpEntry::

    SetTcpEntry(pTcpRow)
    Errcheck:
       raise WinproxyError if result is NOT 0

* SetThreadAffinityMask::

    SetThreadAffinityMask(hThread=None, dwThreadAffinityMask=NeededParameter)
    If hThread is not given, it will be the current thread
    Errcheck:
       raise WinproxyError if result is 0

* SetThreadContext::

    SetThreadContext(hThread, lpContext)
    Errcheck:
       raise WinproxyError if result is 0

* SetThreadToken::

    SetThreadToken(Thread, Token)
    Errcheck:
       raise WinproxyError if result is 0

* SetTokenInformation::

    SetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength)
    Errcheck:
       raise WinproxyError if result is 0

* ShellExecuteA::

    ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    Errcheck:
       raise WinproxyError if result is 0

* ShellExecuteW::

    ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    Errcheck:
       raise WinproxyError if result is 0

* Sleep::

    Sleep(dwMilliseconds)

* SleepEx::

    SleepEx(dwMilliseconds, bAlertable=False)

* StartServiceA::

    StartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors)
    Errcheck:
       raise WinproxyError if result is 0

* StartServiceW::

    StartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors)
    Errcheck:
       raise WinproxyError if result is 0

* StrStrIA::

    StrStrIA(pszFirst, pszSrch)
    Errcheck:
       raise WinproxyError if result is 0

* StrStrIW::

    StrStrIW(pszFirst, pszSrch)
    Errcheck:
       raise WinproxyError if result is 0

* SuspendThread::

    SuspendThread(hThread)
    Errcheck:
       Raise WinproxyError if call result is -1

* SymFromAddr::

    SymFromAddr(hProcess, Address, Displacement, Symbol)
    Errcheck:
       raise WinproxyError if result is 0

* SymGetModuleInfo64::

    SymGetModuleInfo64(hProcess, dwAddr, ModuleInfo)
    Errcheck:
       raise WinproxyError if result is 0

* SymInitialize::

    SymInitialize(hProcess, UserSearchPath, fInvadeProcess)
    Errcheck:
       raise WinproxyError if result is 0

* SymLoadModuleExA::

    SymLoadModuleExA(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* SymLoadModuleExW::

    SymLoadModuleExW(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)
    Errcheck:
       raise WinproxyError if result is 0

* TerminateProcess::

    TerminateProcess(hProcess, uExitCode)
    Errcheck:
       raise WinproxyError if result is 0

* TerminateThread::

    TerminateThread(hThread, dwExitCode)
    Errcheck:
       raise WinproxyError if result is 0

* Thread32First::

    Thread32First(hSnapshot, lpte)
    Set byref(lpte) if needed
    Errcheck:
       raise WinproxyError if result is 0

* Thread32Next::

    Thread32Next(hSnapshot, lpte)
    Set byref(lpte) if needed

* TpCallbackSendAlpcMessageOnCompletion::

    TpCallbackSendAlpcMessageOnCompletion(TpHandle, PortHandle, Flags, SendMessage)
    Errcheck:
       raise NtStatusException is result is not 0

* UpdateProcThreadAttribute::

    UpdateProcThreadAttribute(lpAttributeList, dwFlags=0, Attribute=NeededParameter, lpValue=NeededParameter, cbSize=NeededParameter, lpPreviousValue=None, lpReturnSize=None)
    Errcheck:
       raise WinproxyError if result is 0

* VerQueryValueA::

    VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen)
    Errcheck:
       raise WinproxyError if result is 0

* VerQueryValueW::

    VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen)
    Errcheck:
       raise WinproxyError if result is 0

* VirtualAlloc::

    VirtualAlloc(lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT(0x1000L), flProtect=PAGE_EXECUTE_READWRITE(0x40L))
    Errcheck:
       raise WinproxyError if result is 0

* VirtualAllocEx::

    VirtualAllocEx(hProcess, lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT(0x1000L), flProtect=PAGE_EXECUTE_READWRITE(0x40L))
    Errcheck:
       raise WinproxyError if result is 0

* VirtualFree::

    VirtualFree(lpAddress, dwSize=0, dwFreeType=MEM_RELEASE(0x8000L))
    Errcheck:
       raise WinproxyError if result is 0

* VirtualFreeEx::

    VirtualFreeEx(hProcess, lpAddress, dwSize=0, dwFreeType=MEM_RELEASE(0x8000L))
    Errcheck:
       raise WinproxyError if result is 0

* VirtualProtect::

    VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect=None)
    Errcheck:
       raise WinproxyError if result is 0

* VirtualProtectEx::

    VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect=None)
    Errcheck:
       raise WinproxyError if result is 0

* VirtualQueryEx::

    VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength)
    Errcheck:
       raise WinproxyError if result is 0

* WaitForDebugEvent::

    WaitForDebugEvent(lpDebugEvent, dwMilliseconds=INFINITE(0xffffffffL))
    Errcheck:
       raise WinproxyError if result is 0

* WaitForSingleObject::

    WaitForSingleObject(hHandle, dwMilliseconds=INFINITE(0xffffffffL))
    Errcheck:
       raise WinproxyError if result is NOT 0

* WinVerifyTrust::

    WinVerifyTrust(hwnd, pgActionID, pWVTData)

* WindowFromPoint::

    WindowFromPoint(Point)
    Errcheck:
       raise WinproxyError if result is 0

* Wow64DisableWow64FsRedirection::

    Wow64DisableWow64FsRedirection(OldValue)
    Errcheck:
       raise WinproxyError if result is 0

* Wow64EnableWow64FsRedirection::

    Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection)
    Errcheck:
       raise WinproxyError if result is 0

* Wow64GetThreadContext::

    Wow64GetThreadContext(hThread, lpContext)
    Errcheck:
       raise WinproxyError if result is 0

* Wow64RevertWow64FsRedirection::

    Wow64RevertWow64FsRedirection(OldValue)
    Errcheck:
       raise WinproxyError if result is 0

* Wow64SetThreadContext::

    Wow64SetThreadContext(hThread, lpContext)
    Errcheck:
       raise WinproxyError if result is 0

* WriteFile::

    WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite=None, lpNumberOfBytesWritten=None, lpOverlapped=None)
    Errcheck:
       raise WinproxyError if result is 0

* WriteProcessMemory::

    WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize=None, lpNumberOfBytesWritten=None)
    Computer nSize with len(lpBuffer) if not given
    Errcheck:
       raise WinproxyError if result is 0

* lstrcmpA::

    lstrcmpA(lpString1, lpString2)

* lstrcmpW::

    lstrcmpW(lpString1, lpString2)

