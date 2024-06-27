.. module:: windows.generated_def.winfuncs

Functions
----------
.. function:: ObjectFromLresult(lResult, riid, wParam, ppvObject)

.. function:: NtAlpcCreatePort(PortHandle, ObjectAttributes, PortAttributes)

.. function:: NtAlpcQueryInformation(PortHandle, PortInformationClass, PortInformation, Length, ReturnLength)

.. function:: NtAlpcQueryInformationMessage(PortHandle, PortMessage, MessageInformationClass, MessageInformation, Length, ReturnLength)

.. function:: NtConnectPort(PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength, ConnectionInformation, ConnectionInformationLength)

.. function:: NtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)

.. function:: NtAlpcConnectPortEx(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)

.. function:: NtAlpcAcceptConnectPort(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection)

.. function:: AlpcInitializeMessageAttribute(AttributeFlags, Buffer, BufferSize, RequiredBufferSize)

.. function:: AlpcGetMessageAttribute(Buffer, AttributeFlag)

.. function:: NtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout)

.. function:: NtAlpcDisconnectPort(PortHandle, Flags)

.. function:: NtAlpcCreatePortSection(PortHandle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize)

.. function:: NtAlpcDeletePortSection(PortHandle, Flags, SectionHandle)

.. function:: NtAlpcCreateResourceReserve(PortHandle, Flags, MessageSize, ResourceId)

.. function:: NtAlpcDeleteResourceReserve(PortHandle, Flags, ResourceId)

.. function:: NtAlpcCreateSectionView(PortHandle, Flags, ViewAttributes)

.. function:: NtAlpcDeleteSectionView(PortHandle, Flags, ViewBase)

.. function:: NtAlpcCreateSecurityContext(PortHandle, Flags, SecurityAttribute)

.. function:: NtAlpcDeleteSecurityContext(PortHandle, Flags, ContextHandle)

.. function:: NtAlpcRevokeSecurityContext(PortHandle, Flags, ContextHandle)

.. function:: NtAlpcImpersonateClientOfPort(PortHandle, Message, Flags)

.. function:: TpCallbackSendAlpcMessageOnCompletion(TpHandle, PortHandle, Flags, SendMessage)

.. function:: AddAtomA(lpString)

.. function:: AddAtomW(lpString)

.. function:: GlobalAddAtomA(lpString)

.. function:: GlobalAddAtomExA(lpString, Flags)

.. function:: GlobalAddAtomExW(lpString, Flags)

.. function:: GlobalAddAtomW(lpString)

.. function:: GlobalDeleteAtom(nAtom)

.. function:: GlobalGetAtomNameA(nAtom, lpBuffer, nSize)

.. function:: GlobalGetAtomNameW(nAtom, lpBuffer, nSize)

.. function:: CM_Enumerate_Classes(ulClassIndex, ClassGuid, ulFlags)

.. function:: CM_Enumerate_Classes_Ex(ulClassIndex, ClassGuid, ulFlags, hMachine)

.. function:: CM_Get_First_Log_Conf(plcLogConf, dnDevInst, ulFlags)

.. function:: CM_Get_First_Log_Conf_Ex(plcLogConf, dnDevInst, ulFlags, hMachine)

.. function:: CM_Get_Log_Conf_Priority(lcLogConf, pPriority, ulFlags)

.. function:: CM_Get_Log_Conf_Priority_Ex(lcLogConf, pPriority, ulFlags, hMachine)

.. function:: CM_Get_Next_Log_Conf(plcLogConf, lcLogConf, ulFlags)

.. function:: CM_Get_Next_Log_Conf_Ex(plcLogConf, lcLogConf, ulFlags, hMachine)

.. function:: CM_Free_Res_Des_Handle(rdResDes)

.. function:: CM_Get_Child(pdnDevInst, dnDevInst, ulFlags)

.. function:: CM_Get_Child_Ex(pdnDevInst, dnDevInst, ulFlags, hMachine)

.. function:: CM_Get_Next_Res_Des(prdResDes, rdResDes, ForResource, pResourceID, ulFlags)

.. function:: CM_Get_Parent(pdnDevInst, dnDevInst, ulFlags)

.. function:: CM_Get_Parent_Ex(pdnDevInst, dnDevInst, ulFlags, hMachine)

.. function:: CM_Get_Res_Des_Data(rdResDes, Buffer, BufferLen, ulFlags)

.. function:: CM_Get_Next_Res_Des_Ex(prdResDes, rdResDes, ForResource, pResourceID, ulFlags, hMachine)

.. function:: CM_Get_Res_Des_Data_Size(pulSize, rdResDes, ulFlags)

.. function:: CM_Get_Res_Des_Data_Size_Ex(pulSize, rdResDes, ulFlags, hMachine)

.. function:: CM_Get_Sibling(pdnDevInst, dnDevInst, ulFlags)

.. function:: CM_Get_Sibling_Ex(pdnDevInst, dnDevInst, ulFlags, hMachine)

.. function:: CM_Get_Version()

.. function:: CM_Get_Version_Ex(hMachine)

.. function:: CM_Locate_DevNodeA(pdnDevInst, pDeviceID, ulFlags)

.. function:: CM_Locate_DevNodeW(pdnDevInst, pDeviceID, ulFlags)

.. function:: CM_Locate_DevNode_ExA(pdnDevInst, pDeviceID, ulFlags, hMachine)

.. function:: CM_Locate_DevNode_ExW(pdnDevInst, pDeviceID, ulFlags, hMachine)

.. function:: CoInitializeEx(pvReserved, dwCoInit)

.. function:: CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3)

.. function:: CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv)

.. function:: CoCreateInstanceEx(rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults)

.. function:: CoGetClassObject(rclsid, dwClsContext, pvReserved, riid, ppv)

.. function:: CoGetInterceptor(iidIntercepted, punkOuter, iid, ppv)

.. function:: CLSIDFromProgID(lpszProgID, lpclsid)

.. function:: CoTaskMemFree(pv)

.. function:: SafeArrayCreate(vt, cDims, rgsabound)

.. function:: SafeArrayCreateVector(vt, lLbound, cElements)

.. function:: SafeArrayDestroy(psa)

.. function:: SafeArrayDestroyData(psa)

.. function:: SafeArrayGetElement(psa, rgIndices, pv)

.. function:: SafeArrayGetElemsize(psa)

.. function:: SafeArrayGetLBound(psa, nDim, plLbound)

.. function:: SafeArrayGetUBound(psa, nDim, plUbound)

.. function:: SafeArrayGetDim(psa)

.. function:: SafeArrayPutElement(psa, rgIndices, pv)

.. function:: SafeArrayGetVartype(psa, pvt)

.. function:: SafeArrayCopy(psa, ppsaOut)

.. function:: SafeArrayCopyData(psaSource, psaTarget)

.. function:: SysAllocString(psz)

.. function:: SysFreeString(bstrString)

.. function:: CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags)

.. function:: CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, pcbHash, pbHash, dwFlags)

.. function:: CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo)

.. function:: CryptCATAdminAcquireContext(phCatAdmin, pgSubsystem, dwFlags)

.. function:: CryptCATAdminAcquireContext2(phCatAdmin, pgSubsystem, pwszHashAlgorithm, pStrongHashPolicy, dwFlags)

.. function:: CryptCATCatalogInfoFromContext(hCatInfo, psCatInfo, dwFlags)

.. function:: CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwFlags)

.. function:: CryptCATAdminReleaseContext(hCatAdmin, dwFlags)

.. function:: CryptCATGetMemberInfo(hCatalog, pwszReferenceTag)

.. function:: CryptCATGetAttrInfo(hCatalog, pCatMember, pwszReferenceTag)

.. function:: CryptCATEnumerateCatAttr(hCatalog, pPrevAttr)

.. function:: CryptCATEnumerateAttr(hCatalog, pCatMember, pPrevAttr)

.. function:: CryptCATEnumerateMember(hCatalog, pPrevMember)

.. function:: CryptQueryObject(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext)

.. function:: CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, pvData, pcbData)

.. function:: CryptDecodeObject(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo)

.. function:: CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext)

.. function:: CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)

.. function:: CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)

.. function:: CertGetCertificateChain(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext)

.. function:: CertCreateSelfSignCertificate(hCryptProvOrNCryptKey, pSubjectIssuerBlob, dwFlags, pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions)

.. function:: CertStrToNameA(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)

.. function:: CertStrToNameW(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)

.. function:: CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara)

.. function:: CertAddCertificateContextToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext)

.. function:: CertFreeCertificateContext(pCertContext)

.. function:: PFXExportCertStoreEx(hStore, pPFX, szPassword, pvPara, dwFlags)

.. function:: PFXImportCertStore(pPFX, szPassword, dwFlags)

.. function:: CryptGenKey(hProv, Algid, dwFlags, phKey)

.. function:: CryptDestroyKey(hKey)

.. function:: CryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags)

.. function:: CryptAcquireContextW(phProv, pszContainer, pszProvider, dwProvType, dwFlags)

.. function:: CryptReleaseContext(hProv, dwFlags)

.. function:: CryptCreateHash(hProv, Algid, hKey, dwFlags, phHash)

.. function:: CryptHashData(hHash, pbData, dwDataLen, dwFlags)

.. function:: CryptGetHashParam(hHash, dwParam, pbData, pdwDataLen, dwFlags)

.. function:: CryptVerifySignatureA(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags)

.. function:: CryptVerifySignatureW(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags)

.. function:: CryptSignHashA(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen)

.. function:: CryptSignHashW(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen)

.. function:: CryptDestroyHash(hHash)

.. function:: CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey)

.. function:: CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen)

.. function:: CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey)

.. function:: CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, pcbData)

.. function:: CertEnumCertificateContextProperties(pCertContext, dwPropId)

.. function:: CryptEncryptMessage(pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob, pcbEncryptedBlob)

.. function:: CryptDecryptMessage(pDecryptPara, pbEncryptedBlob, cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert)

.. function:: CryptAcquireCertificatePrivateKey(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey)

.. function:: CertDuplicateCertificateContext(pCertContext)

.. function:: CertEnumCertificatesInStore(hCertStore, pPrevCertContext)

.. function:: CryptEncodeObjectEx(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded)

.. function:: CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded)

.. function:: CertCompareCertificate(dwCertEncodingType, pCertId1, pCertId2)

.. function:: CertEnumCTLsInStore(hCertStore, pPrevCtlContext)

.. function:: CertDuplicateCTLContext(pCtlContext)

.. function:: CertFreeCTLContext(pCtlContext)

.. function:: CryptUIDlgViewContext(dwContextType, pvContext, hwnd, pwszTitle, dwFlags, pvReserved)

.. function:: CryptMsgVerifyCountersignatureEncoded(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, pciCountersigner)

.. function:: CryptMsgVerifyCountersignatureEncodedEx(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, dwSignerType, pvSigner, dwFlags, pvExtra)

.. function:: CryptHashCertificate(hCryptProv, Algid, dwFlags, pbEncoded, cbEncoded, pbComputedHash, pcbComputedHash)

.. function:: CryptSignMessage(pSignPara, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, pbSignedBlob, pcbSignedBlob)

.. function:: CryptSignAndEncryptMessage(pSignPara, pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeSignedAndEncrypted, cbToBeSignedAndEncrypted, pbSignedAndEncryptedBlob, pcbSignedAndEncryptedBlob)

.. function:: CryptVerifyMessageSignature(pVerifyPara, dwSignerIndex, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded, ppSignerCert)

.. function:: CryptVerifyMessageSignatureWithKey(pVerifyPara, pPublicKeyInfo, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded)

.. function:: CryptVerifyMessageHash(pHashPara, pbHashedBlob, cbHashedBlob, pbToBeHashed, pcbToBeHashed, pbComputedHash, pcbComputedHash)

.. function:: PfnCryptGetSignerCertificate(pvGetArg, dwCertEncodingType, pSignerId, hMsgCertStore)

.. function:: CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen)

.. function:: CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen)

.. function:: CryptMsgOpenToEncode(dwMsgEncodingType, dwFlags, dwMsgType, pvMsgEncodeInfo, pszInnerContentObjID, pStreamInfo)

.. function:: CryptMsgOpenToDecode(dwMsgEncodingType, dwFlags, dwMsgType, hCryptProv, pRecipientInfo, pStreamInfo)

.. function:: CryptMsgUpdate(hCryptMsg, pbData, cbData, fFinal)

.. function:: CryptMsgControl(hCryptMsg, dwFlags, dwCtrlType, pvCtrlPara)

.. function:: CryptMsgClose(hCryptMsg)

.. function:: CryptEnumOIDFunction(dwEncodingType, pszFuncName, pszOID, dwFlags, pvArg, pfnEnumOIDFunc)

.. function:: CryptGetOIDFunctionValue(dwEncodingType, pszFuncName, pszOID, pwszValueName, pdwValueType, pbValueData, pcbValueData)

.. function:: CertCloseStore(hCertStore, dwFlags)

.. function:: OpenVirtualDisk(VirtualStorageType, Path, VirtualDiskAccessMask, Flags, Parameters, Handle)

.. function:: AttachVirtualDisk(VirtualDiskHandle, SecurityDescriptor, Flags, ProviderSpecificFlags, Parameters, Overlapped)

.. function:: CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)

.. function:: CryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)

.. function:: CryptProtectMemory(pDataIn, cbDataIn, dwFlags)

.. function:: CryptUnprotectMemory(pDataIn, cbDataIn, dwFlags)

.. function:: GetEnvironmentVariableA(lpName, lpBuffer, nSize)

.. function:: GetEnvironmentVariableW(lpName, lpBuffer, nSize)

.. function:: SetEnvironmentVariableA(lpName, lpValue)

.. function:: SetEnvironmentVariableW(lpName, lpValue)

.. function:: GetEnvironmentStringsA()

.. function:: GetEnvironmentStringsW()

.. function:: SetEnvironmentStringsW(NewEnvironment)

.. function:: FreeEnvironmentStringsA(penv)

.. function:: FreeEnvironmentStringsW(penv)

.. function:: EnumerateTraceGuidsEx(TraceQueryInfoClass, InBuffer, InBufferSize, OutBuffer, OutBufferSize, ReturnLength)

.. function:: QueryAllTracesA(PropertyArray, PropertyArrayCount, SessionCount)

.. function:: QueryAllTracesW(PropertyArray, PropertyArrayCount, SessionCount)

.. function:: OpenTraceA(Logfile)

.. function:: OpenTraceW(Logfile)

.. function:: StartTraceA(TraceHandle, InstanceName, Properties)

.. function:: StartTraceW(TraceHandle, InstanceName, Properties)

.. function:: StopTraceA(TraceHandle, InstanceName, Properties)

.. function:: StopTraceW(TraceHandle, InstanceName, Properties)

.. function:: ControlTraceA(TraceHandle, InstanceName, Properties, ControlCode)

.. function:: ControlTraceW(TraceHandle, InstanceName, Properties, ControlCode)

.. function:: ProcessTrace(HandleArray, HandleCount, StartTime, EndTime)

.. function:: EnableTrace(Enable, EnableFlag, EnableLevel, ControlGuid, SessionHandle)

.. function:: EnableTraceEx(ProviderId, SourceId, TraceHandle, IsEnabled, Level, MatchAnyKeyword, MatchAllKeyword, EnableProperty, EnableFilterDesc)

.. function:: EnableTraceEx2(TraceHandle, ProviderId, ControlCode, Level, MatchAnyKeyword, MatchAllKeyword, Timeout, EnableParameters)

.. function:: TraceQueryInformation(SessionHandle, InformationClass, TraceInformation, InformationLength, ReturnLength)

.. function:: TraceSetInformation(SessionHandle, InformationClass, TraceInformation, InformationLength)

.. function:: RegisterTraceGuidsW(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle)

.. function:: RegisterTraceGuidsA(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, MofImagePath, MofResourceName, RegistrationHandle)

.. function:: TraceEvent(SessionHandle, EventTrace)

.. function:: GetTraceLoggerHandle(Buffer)

.. function:: OpenEventLogA(lpUNCServerName, lpSourceName)

.. function:: OpenEventLogW(lpUNCServerName, lpSourceName)

.. function:: OpenBackupEventLogA(lpUNCServerName, lpSourceName)

.. function:: OpenBackupEventLogW(lpUNCServerName, lpSourceName)

.. function:: EvtOpenSession(LoginClass, Login, Timeout, Flags)

.. function:: ReadEventLogA(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded)

.. function:: ReadEventLogW(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded)

.. function:: GetEventLogInformation(hEventLog, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)

.. function:: GetNumberOfEventLogRecords(hEventLog, NumberOfRecords)

.. function:: CloseEventLog(hEventLog)

.. function:: EvtOpenLog(Session, Path, Flags)

.. function:: EvtQuery(Session, Path, Query, Flags)

.. function:: EvtNext(ResultSet, EventArraySize, EventArray, Timeout, Flags, Returned)

.. function:: EvtCreateRenderContext(ValuePathsCount, ValuePaths, Flags)

.. function:: EvtRender(Context, Fragment, Flags, BufferSize, Buffer, BufferUsed, PropertyCount)

.. function:: EvtClose(Object)

.. function:: EvtOpenChannelEnum(Session, Flags)

.. function:: EvtNextChannelPath(ChannelEnum, ChannelPathBufferSize, ChannelPathBuffer, ChannelPathBufferUsed)

.. function:: EvtOpenPublisherEnum(Session, Flags)

.. function:: EvtNextPublisherId(PublisherEnum, PublisherIdBufferSize, PublisherIdBuffer, PublisherIdBufferUsed)

.. function:: EvtGetLogInfo(Log, PropertyId, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)

.. function:: EvtOpenChannelConfig(Session, ChannelPath, Flags)

.. function:: EvtGetChannelConfigProperty(ChannelConfig, PropertyId, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)

.. function:: EvtOpenPublisherMetadata(Session, PublisherIdentity, LogFilePath, Locale, Flags)

.. function:: EvtOpenEventMetadataEnum(PublisherMetadata, Flags)

.. function:: EvtNextEventMetadata(EventMetadataEnum, Flags)

.. function:: EvtGetEventMetadataProperty(EventMetadata, PropertyId, Flags, EventMetadataPropertyBufferSize, EventMetadataPropertyBuffer, EventMetadataPropertyBufferUsed)

.. function:: EvtGetPublisherMetadataProperty(PublisherMetadata, PropertyId, Flags, PublisherMetadataPropertyBufferSize, PublisherMetadataPropertyBuffer, PublisherMetadataPropertyBufferUsed)

.. function:: EvtGetObjectArraySize(ObjectArray, ObjectArraySize)

.. function:: EvtGetObjectArrayProperty(ObjectArray, PropertyId, ArrayIndex, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)

.. function:: EvtFormatMessage(PublisherMetadata, Event, MessageId, ValueCount, Values, Flags, BufferSize, Buffer, BufferUsed)

.. function:: EvtSeek(ResultSet, Position, Bookmark, Timeout, Flags)

.. function:: FindFirstFileA(lpFileName, lpFindFileData)

.. function:: FindFirstFileW(lpFileName, lpFindFileData)

.. function:: FindNextFileA(hFindFile, lpFindFileData)

.. function:: FindNextFileW(hFindFile, lpFindFileData)

.. function:: FindClose(hFindFile)

.. function:: FindFirstChangeNotificationA(lpPathName, bWatchSubtree, dwNotifyFilter)

.. function:: FindFirstChangeNotificationW(lpPathName, bWatchSubtree, dwNotifyFilter)

.. function:: FindNextChangeNotification(hChangeHandle)

.. function:: FindCloseChangeNotification(hChangeHandle)

.. function:: ReadDirectoryChangesW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine)

.. function:: ReadDirectoryChangesExW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine, ReadDirectoryNotifyInformationClass)

.. function:: LockFile(hFile, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh)

.. function:: LockFileEx(hFile, dwFlags, dwReserved, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh, lpOverlapped)

.. function:: HeapAlloc(hHeap, dwFlags, dwBytes)

.. function:: InternetCheckConnectionA(lpszUrl, dwFlags, dwReserved)

.. function:: InternetCheckConnectionW(lpszUrl, dwFlags, dwReserved)

.. function:: InternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags)

.. function:: InternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags)

.. function:: InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext)

.. function:: InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext)

.. function:: InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)

.. function:: InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)

.. function:: HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)

.. function:: HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)

.. function:: InternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength)

.. function:: InternetSetOptionW(hInternet, dwOption, lpBuffer, dwBufferLength)

.. function:: InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)

.. function:: InternetReadFileExA(hFile, lpBuffersOut, dwFlags, dwContext)

.. function:: InternetReadFileExW(hFile, lpBuffersOut, dwFlags, dwContext)

.. function:: HttpQueryInfoA(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex)

.. function:: HttpQueryInfoW(hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex)

.. function:: HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)

.. function:: HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)

.. function:: WinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags)

.. function:: WinHttpCloseHandle(hInternet)

.. function:: WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved)

.. function:: WinHttpQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable)

.. function:: WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead)

.. function:: WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags)

.. function:: WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext)

.. function:: WinHttpReceiveResponse(hRequest, lpReserved)

.. function:: WinHttpAddRequestHeaders(hRequest, lpszHeaders, dwHeadersLength, dwModifiers)

.. function:: WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex)

.. function:: GetOverlappedResult(hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait)

.. function:: CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads)

.. function:: GetQueuedCompletionStatus(CompletionPort, lpNumberOfBytesTransferred, lpCompletionKey, lpOverlapped, dwMilliseconds)

.. function:: GetQueuedCompletionStatusEx(CompletionPort, lpCompletionPortEntries, ulCount, ulNumEntriesRemoved, dwMilliseconds, fAlertable)

.. function:: PostQueuedCompletionStatus(CompletionPort, dwNumberOfBytesTransferred, dwCompletionKey, lpOverlapped)

.. function:: CancelIo(hFile)

.. function:: CancelIoEx(hFile, lpOverlapped)

.. function:: CancelSynchronousIo(hThread)

.. function:: LsaOpenPolicy(SystemName, ObjectAttributes, DesiredAccess, PolicyHandle)

.. function:: LsaQueryInformationPolicy(PolicyHandle, InformationClass, Buffer)

.. function:: LsaClose(ObjectHandle)

.. function:: LsaNtStatusToWinError(Status)

.. function:: LsaLookupNames(PolicyHandle, Count, Names, ReferencedDomains, Sids)

.. function:: LsaLookupNames2(PolicyHandle, Flags, Count, Names, ReferencedDomains, Sids)

.. function:: LsaLookupSids(PolicyHandle, Count, Sids, ReferencedDomains, Names)

.. function:: LsaLookupSids2(PolicyHandle, LookupOptions, Count, Sids, ReferencedDomains, Names)

.. function:: OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName)

.. function:: OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName)

.. function:: UnmapViewOfFile(lpBaseAddress)

.. function:: NetQueryDisplayInformation(ServerName, Level, Index, EntriesRequested, PreferredMaximumLength, ReturnedEntryCount, SortedBuffer)

.. function:: NetUserEnum(servername, level, filter, bufptr, prefmaxlen, entriesread, totalentries, resume_handle)

.. function:: NetGroupEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle)

.. function:: NetGroupGetInfo(servername, groupname, level, bufptr)

.. function:: NetGroupGetUsers(servername, groupname, level, bufptr, prefmaxlen, entriesread, totalentries, ResumeHandle)

.. function:: NetLocalGroupEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)

.. function:: NetLocalGroupGetMembers(servername, localgroupname, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)

.. function:: NetLocalGroupGetInfo(servername, groupname, level, bufptr)

.. function:: NetApiBufferFree(Buffer)

.. function:: GetIpNetTable(IpNetTable, SizePointer, Order)

.. function:: GetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)

.. function:: GetExtendedUdpTable(pUdpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)

.. function:: SetTcpEntry(pTcpRow)

.. function:: DnsGetCacheDataTable(DnsEntries)

.. function:: DnsFree(pData, FreeType)

.. function:: DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved)

.. function:: DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved)

.. function:: DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle)

.. function:: GetAdaptersInfo(AdapterInfo, SizePointer)

.. function:: GetPerAdapterInfo(IfIndex, pPerAdapterInfo, pOutBufLen)

.. function:: CreateFileTransactedA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter)

.. function:: CreateFileTransactedW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, pExtendedParameter)

.. function:: CommitTransaction(TransactionHandle)

.. function:: CreateTransaction(lpTransactionAttributes, UOW, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description)

.. function:: RollbackTransaction(TransactionHandle)

.. function:: OpenTransaction(dwDesiredAccess, TransactionId)

.. function:: NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes)

.. function:: NtCreateKey(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition)

.. function:: NtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize)

.. function:: NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)

.. function:: NtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength)

.. function:: NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)

.. function:: NtDeleteValueKey(KeyHandle, ValueName)

.. function:: CreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize)

.. function:: CreateNamedPipeA(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes)

.. function:: CreateNamedPipeW(lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes)

.. function:: ConnectNamedPipe(hNamedPipe, lpOverlapped)

.. function:: SetNamedPipeHandleState(hNamedPipe, lpMode, lpMaxCollectionCount, lpCollectDataTimeout)

.. function:: PeekNamedPipe(hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage)

.. function:: CreateToolhelp32Snapshot(dwFlags, th32ProcessID)

.. function:: Thread32First(hSnapshot, lpte)

.. function:: Thread32Next(hSnapshot, lpte)

.. function:: Process32First(hSnapshot, lppe)

.. function:: Process32Next(hSnapshot, lppe)

.. function:: Process32FirstW(hSnapshot, lppe)

.. function:: Process32NextW(hSnapshot, lppe)

.. function:: GetProcAddress(hModule, lpProcName)

.. function:: LoadLibraryA(lpFileName)

.. function:: LoadLibraryW(lpFileName)

.. function:: LoadLibraryExA(lpLibFileName, hFile, dwFlags)

.. function:: LoadLibraryExW(lpLibFileName, hFile, dwFlags)

.. function:: FreeLibrary(hLibModule)

.. function:: RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)

.. function:: RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)

.. function:: RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult)

.. function:: RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult)

.. function:: RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition)

.. function:: RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition)

.. function:: RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)

.. function:: RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)

.. function:: RegCloseKey(hKey)

.. function:: RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData)

.. function:: RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData)

.. function:: RegSetKeyValueA(hKey, lpSubKey, lpValueName, dwType, lpData, cbData)

.. function:: RegSetKeyValueW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData)

.. function:: RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime)

.. function:: RegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime)

.. function:: RegGetKeySecurity(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor)

.. function:: RegQueryInfoKeyA(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime)

.. function:: RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime)

.. function:: RegDeleteKeyValueW(hKey, lpSubKey, lpValueName)

.. function:: RegDeleteKeyValueA(hKey, lpSubKey, lpValueName)

.. function:: RegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved)

.. function:: RegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved)

.. function:: RegDeleteValueA(hKey, lpValueName)

.. function:: RegDeleteValueW(hKey, lpValueName)

.. function:: RegEnumValueA(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData)

.. function:: RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData)

.. function:: RegDeleteTreeA(hKey, lpSubKey)

.. function:: RegDeleteTreeW(hKey, lpSubKey)

.. function:: RegSaveKeyA(hKey, lpFile, lpSecurityAttributes)

.. function:: RegSaveKeyW(hKey, lpFile, lpSecurityAttributes)

.. function:: RegSaveKeyExA(hKey, lpFile, lpSecurityAttributes, Flags)

.. function:: RegSaveKeyExW(hKey, lpFile, lpSecurityAttributes, Flags)

.. function:: RegLoadKeyA(hKey, lpSubKey, lpFile)

.. function:: RegLoadKeyW(hKey, lpSubKey, lpFile)

.. function:: RegUnLoadKeyA(hKey, lpSubKey)

.. function:: RegUnLoadKeyW(hKey, lpSubKey)

.. function:: IsValidSecurityDescriptor(pSecurityDescriptor)

.. function:: ConvertStringSecurityDescriptorToSecurityDescriptorA(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)

.. function:: ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)

.. function:: ConvertSecurityDescriptorToStringSecurityDescriptorA(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)

.. function:: ConvertSecurityDescriptorToStringSecurityDescriptorW(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)

.. function:: GetSecurityDescriptorControl(pSecurityDescriptor, pControl, lpdwRevision)

.. function:: GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted)

.. function:: GetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, lpbGroupDefaulted)

.. function:: GetSecurityDescriptorLength(pSecurityDescriptor)

.. function:: GetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, lpbOwnerDefaulted)

.. function:: SetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, bOwnerDefaulted)

.. function:: GetSecurityDescriptorRMControl(SecurityDescriptor, RMControl)

.. function:: GetSecurityDescriptorSacl(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted)

.. function:: GetLengthSid(pSid)

.. function:: EqualSid(pSid1, pSid2)

.. function:: CopySid(nDestinationSidLength, pDestinationSid, pSourceSid)

.. function:: GetSidIdentifierAuthority(pSid)

.. function:: GetSidLengthRequired(nSubAuthorityCount)

.. function:: GetSidSubAuthority(pSid, nSubAuthority)

.. function:: GetSidSubAuthorityCount(pSid)

.. function:: FreeSid(pSid)

.. function:: GetAce(pAcl, dwAceIndex, pAce)

.. function:: GetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass)

.. function:: MapGenericMask(AccessMask, GenericMapping)

.. function:: AccessCheck(pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus)

.. function:: GetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)

.. function:: GetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)

.. function:: GetSecurityInfo(handle, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor)

.. function:: SetSecurityInfo(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl)

.. function:: SetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl)

.. function:: SetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl)

.. function:: GetStringConditionFromBinary(BinaryAceCondition, BinaryAceConditionSize, Reserved1, StringAceCondition)

.. function:: AddAccessAllowedAce(pAcl, dwAceRevision, AccessMask, pSid)

.. function:: SetSecurityDescriptorDacl(pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted)

.. function:: InitializeAcl(pAcl, nAclLength, dwAclRevision)

.. function:: InitializeSecurityDescriptor(pSecurityDescriptor, dwRevision)

.. function:: SetAclInformation(pAcl, pAclInformation, nAclInformationLength, dwAclInformationClass)

.. function:: AddAccessAllowedAceEx(pAcl, dwAceRevision, AceFlags, AccessMask, pSid)

.. function:: AddAccessDeniedAce(pAcl, dwAceRevision, AccessMask, pSid)

.. function:: AddAccessDeniedAceEx(pAcl, dwAceRevision, AceFlags, AccessMask, pSid)

.. function:: BuildSecurityDescriptorW(pOwner, pGroup, cCountOfAccessEntries, pListOfAccessEntries, cCountOfAuditEntries, pListOfAuditEntries, pOldSD, pSizeNewSD, pNewSD)

.. function:: MakeAbsoluteSD(pSelfRelativeSecurityDescriptor, pAbsoluteSecurityDescriptor, lpdwAbsoluteSecurityDescriptorSize, pDacl, lpdwDaclSize, pSacl, lpdwSaclSize, pOwner, lpdwOwnerSize, pPrimaryGroup, lpdwPrimaryGroupSize)

.. function:: MakeSelfRelativeSD(pAbsoluteSecurityDescriptor, pSelfRelativeSecurityDescriptor, lpdwBufferLength)

.. function:: OpenSCManagerA(lpMachineName, lpDatabaseName, dwDesiredAccess)

.. function:: OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess)

.. function:: CloseServiceHandle(hSCObject)

.. function:: EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)

.. function:: EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)

.. function:: StartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors)

.. function:: StartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors)

.. function:: OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess)

.. function:: OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess)

.. function:: QueryServiceStatus(hService, lpServiceStatus)

.. function:: QueryServiceStatusEx(hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)

.. function:: ChangeServiceConfig2A(hService, dwInfoLevel, lpInfo)

.. function:: ChangeServiceConfig2W(hService, dwInfoLevel, lpInfo)

.. function:: ChangeServiceConfigA(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName)

.. function:: ChangeServiceConfigW(hService, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword, lpDisplayName)

.. function:: QueryServiceConfig2A(hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)

.. function:: QueryServiceConfig2W(hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded)

.. function:: QueryServiceConfigA(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded)

.. function:: QueryServiceConfigW(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded)

.. function:: QueryServiceDynamicInformation(hServiceStatus, dwInfoLevel, ppDynamicInfo)

.. function:: GetServiceDisplayNameA(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer)

.. function:: GetServiceDisplayNameW(hSCManager, lpServiceName, lpDisplayName, lpcchBuffer)

.. function:: GetServiceKeyNameA(hSCManager, lpDisplayName, lpServiceName, lpcchBuffer)

.. function:: GetServiceKeyNameW(hSCManager, lpDisplayName, lpServiceName, lpcchBuffer)

.. function:: EnumDependentServicesA(hService, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned)

.. function:: EnumDependentServicesW(hService, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned)

.. function:: ControlService(hService, dwControl, lpServiceStatus)

.. function:: ControlServiceExA(hService, dwControl, dwInfoLevel, pControlParams)

.. function:: ControlServiceExW(hService, dwControl, dwInfoLevel, pControlParams)

.. function:: CreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword)

.. function:: CreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword)

.. function:: DeleteService(hService)

.. function:: StartServiceCtrlDispatcherA(lpServiceStartTable)

.. function:: StartServiceCtrlDispatcherW(lpServiceStartTable)

.. function:: SetupDiClassNameFromGuidA(ClassGuid, ClassName, ClassNameSize, RequiredSize)

.. function:: SetupDiClassNameFromGuidW(ClassGuid, ClassName, ClassNameSize, RequiredSize)

.. function:: SetupDiClassNameFromGuidExA(ClassGuid, ClassName, ClassNameSize, RequiredSize, MachineName, Reserved)

.. function:: SetupDiClassNameFromGuidExW(ClassGuid, ClassName, ClassNameSize, RequiredSize, MachineName, Reserved)

.. function:: SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent, Flags)

.. function:: SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags)

.. function:: SetupDiDeleteDeviceInfo(DeviceInfoSet, DeviceInfoData)

.. function:: SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData)

.. function:: SetupDiDestroyDeviceInfoList(DeviceInfoSet)

.. function:: SetupDiEnumDeviceInterfaces(DeviceInfoSet, DeviceInfoData, InterfaceClassGuid, MemberIndex, DeviceInterfaceData)

.. function:: SetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize)

.. function:: SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize)

.. function:: ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)

.. function:: ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)

.. function:: SHGetPathFromIDListA(pidl, pszPath)

.. function:: SHGetPathFromIDListW(pidl, pszPath)

.. function:: SHFileOperationA(lpFileOp)

.. function:: StrStrIW(pszFirst, pszSrch)

.. function:: StrStrIA(pszFirst, pszSrch)

.. function:: IsOS(dwOS)

.. function:: SymLoadModuleExA(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)

.. function:: SymLoadModuleExW(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)

.. function:: SymFromAddr(hProcess, Address, Displacement, Symbol)

.. function:: SymFromAddrW(hProcess, Address, Displacement, Symbol)

.. function:: SymGetModuleInfo64(hProcess, dwAddr, ModuleInfo)

.. function:: SymGetModuleInfoW64(hProcess, qwAddr, ModuleInfo)

.. function:: SymInitialize(hProcess, UserSearchPath, fInvadeProcess)

.. function:: SymInitializeW(hProcess, UserSearchPath, fInvadeProcess)

.. function:: SymFromName(hProcess, Name, Symbol)

.. function:: SymFromNameW(hProcess, Name, Symbol)

.. function:: SymLoadModuleEx(hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags)

.. function:: SymSetOptions(SymOptions)

.. function:: SymGetOptions()

.. function:: SymEnumSymbols(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext)

.. function:: SymEnumSymbolsEx(hProcess, BaseOfDll, Mask, EnumSymbolsCallback, UserContext, Options)

.. function:: SymEnumTypes(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)

.. function:: SymEnumTypesByName(hProcess, BaseOfDll, mask, EnumSymbolsCallback, UserContext)

.. function:: SymEnumTypesByNameW(hProcess, BaseOfDll, mask, EnumSymbolsCallback, UserContext)

.. function:: SymEnumerateModules64(hProcess, EnumModulesCallback, UserContext)

.. function:: SymEnumerateModulesW64(hProcess, EnumModulesCallback, UserContext)

.. function:: SymNext(hProcess, si)

.. function:: SymNextW(hProcess, siw)

.. function:: SymPrev(hProcess, si)

.. function:: SymPrevW(hProcess, siw)

.. function:: SymSetContext(hProcess, StackFrame, Context)

.. function:: SymSetExtendedOption(option, value)

.. function:: SymSrvGetFileIndexes(File, Id, Val1, Val2, Flags)

.. function:: SymSrvGetFileIndexesW(File, Id, Val1, Val2, Flags)

.. function:: SymSrvGetFileIndexInfo(File, Info, Flags)

.. function:: SymSrvGetFileIndexInfoW(File, Info, Flags)

.. function:: SymSrvGetFileIndexString(hProcess, SrvPath, File, Index, Size, Flags)

.. function:: SymSrvGetFileIndexStringW(hProcess, SrvPath, File, Index, Size, Flags)

.. function:: SymUnDName(sym, UnDecName, UnDecNameLength)

.. function:: SymUnDName64(sym, UnDecName, UnDecNameLength)

.. function:: SymUnloadModule(hProcess, BaseOfDll)

.. function:: SymUnloadModule64(hProcess, BaseOfDll)

.. function:: UnDecorateSymbolName(name, outputString, maxStringLength, flags)

.. function:: UnDecorateSymbolNameW(name, outputString, maxStringLength, flags)

.. function:: SymCleanup(hProcess)

.. function:: SymEnumProcesses(EnumProcessesCallback, UserContext)

.. function:: SymEnumSymbolsForAddr(hProcess, Address, EnumSymbolsCallback, UserContext)

.. function:: SymEnumSymbolsForAddrW(hProcess, Address, EnumSymbolsCallback, UserContext)

.. function:: SymGetTypeFromName(hProcess, BaseOfDll, Name, Symbol)

.. function:: SymGetTypeFromNameW(hProcess, BaseOfDll, Name, Symbol)

.. function:: SymGetTypeInfo(hProcess, ModBase, TypeId, GetType, pInfo)

.. function:: SymSearch(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options)

.. function:: SymSearchW(hProcess, BaseOfDll, Index, SymTag, Mask, Address, EnumSymbolsCallback, UserContext, Options)

.. function:: SymFunctionTableAccess(hProcess, AddrBase)

.. function:: SymFunctionTableAccess64(hProcess, AddrBase)

.. function:: SymGetModuleBase(hProcess, dwAddr)

.. function:: SymGetModuleBase64(hProcess, qwAddr)

.. function:: SymRefreshModuleList(hProcess)

.. function:: SymRegisterCallback(hProcess, CallbackFunction, UserContext)

.. function:: SymRegisterCallback64(hProcess, CallbackFunction, UserContext)

.. function:: SymRegisterCallbackW64(hProcess, CallbackFunction, UserContext)

.. function:: StackWalk64(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress)

.. function:: StackWalkEx(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress, Flags)

.. function:: StackWalk(MachineType, hProcess, hThread, StackFrame, ContextRecord, ReadMemoryRoutine, FunctionTableAccessRoutine, GetModuleBaseRoutine, TranslateAddress)

.. function:: SymGetSearchPath(hProcess, SearchPath, SearchPathLength)

.. function:: SymGetSearchPathW(hProcess, SearchPath, SearchPathLength)

.. function:: SymSetSearchPath(hProcess, SearchPath)

.. function:: SymSetSearchPathW(hProcess, SearchPath)

.. function:: CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName)

.. function:: CreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName)

.. function:: CreateEventExA(lpEventAttributes, lpName, dwFlags, dwDesiredAccess)

.. function:: CreateEventExW(lpEventAttributes, lpName, dwFlags, dwDesiredAccess)

.. function:: OpenEventA(dwDesiredAccess, bInheritHandle, lpName)

.. function:: OpenEventW(dwDesiredAccess, bInheritHandle, lpName)

.. function:: NtQueryLicenseValue(Name, Type, Buffer, Length, DataLength)

.. function:: NtQueryEaFile(FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan)

.. function:: NtSetEaFile(FileHandle, IoStatusBlock, Buffer, Length)

.. function:: NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob)

.. function:: NtCreateNamedPipeFile(NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, WriteModeMessage, ReadModeMessage, NonBlocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTimeOut)

.. function:: NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength)

.. function:: NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions)

.. function:: NtCreateSymbolicLinkObject(pHandle, DesiredAccess, ObjectAttributes, DestinationName)

.. function:: NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength)

.. function:: NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength)

.. function:: NtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass)

.. function:: NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3)

.. function:: NtGetContextThread(hThread, lpContext)

.. function:: NtSetContextThread(hThread, lpContext)

.. function:: NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)

.. function:: NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)

.. function:: NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection)

.. function:: NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)

.. function:: NtQuerySystemInformationEx(SystemInformationClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength)

.. function:: NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)

.. function:: NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

.. function:: NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)

.. function:: NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes)

.. function:: NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength)

.. function:: NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes)

.. function:: NtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength)

.. function:: NtQuerySymbolicLinkObject(LinkHandle, LinkTarget, ReturnedLength)

.. function:: NtOpenSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes)

.. function:: NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)

.. function:: NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan)

.. function:: NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)

.. function:: NtEnumerateSystemEnvironmentValuesEx(InformationClass, Buffer, BufferLength)

.. function:: NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType)

.. function:: NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle)

.. function:: NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes)

.. function:: NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect)

.. function:: NtUnmapViewOfSection(ProcessHandle, BaseAddress)

.. function:: NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId)

.. function:: NtDelayExecution(Alertable, DelayInterval)

.. function:: NtTerminateProcess(ProcessHandle, ExitStatus)

.. function:: NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key)

.. function:: NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key)

.. function:: GetComputerNameExA(NameType, lpBuffer, nSize)

.. function:: GetComputerNameExW(NameType, lpBuffer, nSize)

.. function:: GetComputerNameA(lpBuffer, lpnSize)

.. function:: GetComputerNameW(lpBuffer, lpnSize)

.. function:: LookupAccountSidA(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)

.. function:: LookupAccountSidW(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)

.. function:: LookupAccountNameA(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse)

.. function:: LookupAccountNameW(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse)

.. function:: FileTimeToSystemTime(lpFileTime, lpSystemTime)

.. function:: SystemTimeToFileTime(lpSystemTime, lpFileTime)

.. function:: GetSystemTime(lpSystemTime)

.. function:: GetSystemTimes(lpIdleTime, lpKernelTime, lpUserTime)

.. function:: GetSystemTimeAsFileTime(lpSystemTimeAsFileTime)

.. function:: GetLocalTime(lpSystemTime)

.. function:: GetTickCount()

.. function:: GetTickCount64()

.. function:: TdhEnumerateProviders(pBuffer, pBufferSize)

.. function:: GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData)

.. function:: GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData)

.. function:: GetFileVersionInfoExA(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData)

.. function:: GetFileVersionInfoExW(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData)

.. function:: GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle)

.. function:: GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle)

.. function:: GetFileVersionInfoSizeExA(dwFlags, lpwstrFilename, lpdwHandle)

.. function:: GetFileVersionInfoSizeExW(dwFlags, lpwstrFilename, lpdwHandle)

.. function:: VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen)

.. function:: VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen)

.. function:: GetCursorPos(lpPoint)

.. function:: WindowFromPoint(Point)

.. function:: GetWindowRect(hWnd, lpRect)

.. function:: EnumWindows(lpEnumFunc, lParam)

.. function:: GetWindowTextA(hWnd, lpString, nMaxCount)

.. function:: GetParent(hWnd)

.. function:: GetWindowTextW(hWnd, lpString, nMaxCount)

.. function:: GetWindowModuleFileNameA(hwnd, pszFileName, cchFileNameMax)

.. function:: GetWindowModuleFileNameW(hwnd, pszFileName, cchFileNameMax)

.. function:: EnumChildWindows(hWndParent, lpEnumFunc, lParam)

.. function:: CloseWindow(hWnd)

.. function:: GetDesktopWindow()

.. function:: GetForegroundWindow()

.. function:: BringWindowToTop(hWnd)

.. function:: MoveWindow(hWnd, X, Y, nWidth, nHeight, bRepaint)

.. function:: SetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags)

.. function:: SetWindowTextA(hWnd, lpString)

.. function:: SetWindowTextW(hWnd, lpString)

.. function:: RealGetWindowClassA(hwnd, pszType, cchType)

.. function:: RealGetWindowClassW(hwnd, pszType, cchType)

.. function:: GetClassInfoExA(hinst, lpszClass, lpwcx)

.. function:: GetClassInfoExW(hinst, lpszClass, lpwcx)

.. function:: GetClassNameA(hWnd, lpClassName, nMaxCount)

.. function:: GetClassNameW(hWnd, lpClassName, nMaxCount)

.. function:: GetWindowThreadProcessId(hWnd, lpdwProcessId)

.. function:: FindWindowA(lpClassName, lpWindowName)

.. function:: FindWindowW(lpClassName, lpWindowName)

.. function:: ExitProcess(uExitCode)

.. function:: TerminateProcess(hProcess, uExitCode)

.. function:: GetLastError()

.. function:: LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle)

.. function:: GetExitCodeThread(hThread, lpExitCode)

.. function:: GetExitCodeProcess(hProcess, lpExitCode)

.. function:: SetPriorityClass(hProcess, dwPriorityClass)

.. function:: GetPriorityClass(hProcess)

.. function:: VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)

.. function:: VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)

.. function:: VirtualFree(lpAddress, dwSize, dwFreeType)

.. function:: VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType)

.. function:: VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)

.. function:: VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)

.. function:: VirtualQuery(lpAddress, lpBuffer, dwLength)

.. function:: VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength)

.. function:: QueryWorkingSet(hProcess, pv, cb)

.. function:: QueryWorkingSetEx(hProcess, pv, cb)

.. function:: GetModuleFileNameA(hModule, lpFilename, nSize)

.. function:: GetModuleFileNameW(hModule, lpFilename, nSize)

.. function:: CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)

.. function:: CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)

.. function:: CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

.. function:: CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

.. function:: CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

.. function:: CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

.. function:: GetThreadContext(hThread, lpContext)

.. function:: SetThreadContext(hThread, lpContext)

.. function:: OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId)

.. function:: OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

.. function:: CloseHandle(hObject)

.. function:: ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

.. function:: NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

.. function:: WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)

.. function:: NtWow64WriteVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)

.. function:: GetCurrentProcess()

.. function:: CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)

.. function:: CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)

.. function:: DuplicateToken(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle)

.. function:: DuplicateTokenEx(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken)

.. function:: SetThreadToken(Thread, Token)

.. function:: LookupPrivilegeValueA(lpSystemName, lpName, lpLuid)

.. function:: LookupPrivilegeValueW(lpSystemName, lpName, lpLuid)

.. function:: LookupPrivilegeNameA(lpSystemName, lpLuid, lpName, cchName)

.. function:: LookupPrivilegeNameW(lpSystemName, lpLuid, lpName, cchName)

.. function:: AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength)

.. function:: FindResourceA(hModule, lpName, lpType)

.. function:: FindResourceW(hModule, lpName, lpType)

.. function:: SizeofResource(hModule, hResInfo)

.. function:: LoadResource(hModule, hResInfo)

.. function:: LockResource(hResData)

.. function:: FreeResource(hResData)

.. function:: EnumResourceTypesA(hModule, lpEnumFunc, lParam)

.. function:: EnumResourceTypesW(hModule, lpEnumFunc, lParam)

.. function:: EnumResourceNamesA(hModule, lpType, lpEnumFunc, lParam)

.. function:: EnumResourceNamesW(hModule, lpType, lpEnumFunc, lParam)

.. function:: GetVersionExA(lpVersionInformation)

.. function:: GetVersionExW(lpVersionInformation)

.. function:: GetVersion()

.. function:: GetCurrentThread()

.. function:: GetCurrentThreadId()

.. function:: GetCurrentProcessorNumber()

.. function:: AllocConsole()

.. function:: FreeConsole()

.. function:: GetConsoleOutputCP()

.. function:: GetConsoleCP()

.. function:: GetStdHandle(nStdHandle)

.. function:: SetStdHandle(nStdHandle, hHandle)

.. function:: SetThreadAffinityMask(hThread, dwThreadAffinityMask)

.. function:: ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)

.. function:: WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)

.. function:: AddVectoredContinueHandler(FirstHandler, VectoredHandler)

.. function:: AddVectoredExceptionHandler(FirstHandler, VectoredHandler)

.. function:: TerminateThread(hThread, dwExitCode)

.. function:: ExitThread(dwExitCode)

.. function:: RemoveVectoredExceptionHandler(Handler)

.. function:: ResumeThread(hThread)

.. function:: SuspendThread(hThread)

.. function:: WaitForSingleObject(hHandle, dwMilliseconds)

.. function:: GetThreadId(Thread)

.. function:: DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)

.. function:: Wow64DisableWow64FsRedirection(OldValue)

.. function:: Wow64RevertWow64FsRedirection(OldValue)

.. function:: Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection)

.. function:: Wow64GetThreadContext(hThread, lpContext)

.. function:: SetConsoleCtrlHandler(HandlerRoutine, Add)

.. function:: GlobalAlloc(uFlags, dwBytes)

.. function:: GlobalFree(hMem)

.. function:: GlobalUnlock(hMem)

.. function:: GlobalLock(hMem)

.. function:: OpenClipboard(hWndNewOwner)

.. function:: EmptyClipboard()

.. function:: CloseClipboard()

.. function:: SetClipboardData(uFormat, hMem)

.. function:: GetClipboardData(uFormat)

.. function:: EnumClipboardFormats(format)

.. function:: GetClipboardFormatNameA(format, lpszFormatName, cchMaxCount)

.. function:: GetClipboardFormatNameW(format, lpszFormatName, cchMaxCount)

.. function:: WinVerifyTrust(hWnd, pgActionID, pWVTData)

.. function:: OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle)

.. function:: OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle)

.. function:: GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength)

.. function:: SetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength)

.. function:: CreateWellKnownSid(WellKnownSidType, DomainSid, pSid, cbSid)

.. function:: DebugBreak()

.. function:: WaitForDebugEvent(lpDebugEvent, dwMilliseconds)

.. function:: ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus)

.. function:: DebugActiveProcess(dwProcessId)

.. function:: DebugActiveProcessStop(dwProcessId)

.. function:: DebugSetProcessKillOnExit(KillOnExit)

.. function:: DebugBreakProcess(Process)

.. function:: GetProcessId(Process)

.. function:: Wow64SetThreadContext(hThread, lpContext)

.. function:: GetMappedFileNameW(hProcess, lpv, lpFilename, nSize)

.. function:: GetMappedFileNameA(hProcess, lpv, lpFilename, nSize)

.. function:: RtlInitString(DestinationString, SourceString)

.. function:: RtlInitUnicodeString(DestinationString, SourceString)

.. function:: RtlAnsiStringToUnicodeString(DestinationString, SourceString, AllocateDestinationString)

.. function:: RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize)

.. function:: RtlCompressBuffer(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, UncompressedChunkSize, FinalCompressedSize, WorkSpace)

.. function:: RtlDecompressBufferEx(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize, WorkSpace)

.. function:: RtlGetCompressionWorkSpaceSize(CompressionFormatAndEngine, CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize)

.. function:: RtlMoveMemory(Destination, Source, Length)

.. function:: lstrcmpA(lpString1, lpString2)

.. function:: lstrcmpW(lpString1, lpString2)

.. function:: CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)

.. function:: CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)

.. function:: MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap)

.. function:: GetLogicalDriveStringsA(nBufferLength, lpBuffer)

.. function:: GetLogicalDriveStringsW(nBufferLength, lpBuffer)

.. function:: GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)

.. function:: GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)

.. function:: GetVolumeNameForVolumeMountPointA(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)

.. function:: GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)

.. function:: GetDriveTypeA(lpRootPathName)

.. function:: GetDriveTypeW(lpRootPathName)

.. function:: QueryDosDeviceA(lpDeviceName, lpTargetPath, ucchMax)

.. function:: QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax)

.. function:: FindFirstVolumeA(lpszVolumeName, cchBufferLength)

.. function:: FindFirstVolumeW(lpszVolumeName, cchBufferLength)

.. function:: FindNextVolumeA(hFindVolume, lpszVolumeName, cchBufferLength)

.. function:: FindNextVolumeW(hFindVolume, lpszVolumeName, cchBufferLength)

.. function:: DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions)

.. function:: ZwDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options)

.. function:: GetModuleBaseNameA(hProcess, hModule, lpBaseName, nSize)

.. function:: GetModuleBaseNameW(hProcess, hModule, lpBaseName, nSize)

.. function:: GetProcessImageFileNameA(hProcess, lpImageFileName, nSize)

.. function:: GetProcessImageFileNameW(hProcess, lpImageFileName, nSize)

.. function:: GetSystemMetrics(nIndex)

.. function:: GetInterfaceInfo(pIfTable, dwOutBufLen)

.. function:: GetIfTable(pIfTable, pdwSize, bOrder)

.. function:: GetIpAddrTable(pIpAddrTable, pdwSize, bOrder)

.. function:: GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime)

.. function:: GetShortPathNameA(lpszLongPath, lpszShortPath, cchBuffer)

.. function:: GetShortPathNameW(lpszLongPath, lpszShortPath, cchBuffer)

.. function:: GetLongPathNameA(lpszShortPath, lpszLongPath, cchBuffer)

.. function:: GetLongPathNameW(lpszShortPath, lpszLongPath, cchBuffer)

.. function:: GetProcessDEPPolicy(hProcess, lpFlags, lpPermanent)

.. function:: ConvertStringSidToSidA(StringSid, Sid)

.. function:: ConvertStringSidToSidW(StringSid, Sid)

.. function:: ConvertSidToStringSidA(Sid, StringSid)

.. function:: ConvertSidToStringSidW(Sid, StringSid)

.. function:: LocalFree(hMem)

.. function:: InitializeProcThreadAttributeList(lpAttributeList, dwAttributeCount, dwFlags, lpSize)

.. function:: UpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize)

.. function:: DeleteProcThreadAttributeList(lpAttributeList)

.. function:: MessageBoxA(hWnd, lpText, lpCaption, uType)

.. function:: MessageBoxW(hWnd, lpText, lpCaption, uType)

.. function:: GetWindowsDirectoryA(lpBuffer, uSize)

.. function:: GetWindowsDirectoryW(lpBuffer, uSize)

.. function:: RtlGetUnloadEventTraceEx(ElementSize, ElementCount, EventTrace)

.. function:: RtlDosPathNameToNtPathName_U(DosName, NtName, PartName, RelativeName)

.. function:: ApiSetResolveToHost(Schema, FileNameIn, ParentName, Resolved, HostBinary)

.. function:: Sleep(dwMilliseconds)

.. function:: SleepEx(dwMilliseconds, bAlertable)

.. function:: GetProcessMitigationPolicy(hProcess, MitigationPolicy, lpBuffer, dwLength)

.. function:: SetProcessMitigationPolicy(MitigationPolicy, lpBuffer, dwLength)

.. function:: GetProductInfo(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType)

.. function:: GetProcessMemoryInfo(Process, ppsmemCounters, cb)

.. function:: GetModuleHandleA(lpModuleName)

.. function:: GetModuleHandleW(lpModuleName)

.. function:: RtlEqualUnicodeString(String1, String2, CaseInSensitive)

.. function:: GetFirmwareEnvironmentVariableA(lpName, lpGuid, pBuffer, nSize)

.. function:: GetFirmwareEnvironmentVariableW(lpName, lpGuid, pBuffer, nSize)

.. function:: GetFirmwareEnvironmentVariableExA(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes)

.. function:: GetFirmwareEnvironmentVariableExW(lpName, lpGuid, pBuffer, nSize, pdwAttribubutes)

.. function:: IsDebuggerPresent()

.. function:: WSAStartup(wVersionRequested, lpWSAData)

.. function:: WSACleanup()

.. function:: WSAGetLastError()

.. function:: getaddrinfo(pNodeName, pServiceName, pHints, ppResult)

.. function:: GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult)

.. function:: WSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags)

.. function:: WSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags)

.. function:: socket(af, type, protocol)

.. function:: connect(s, name, namelen)

.. function:: send(s, buf, len, flags)

.. function:: recv(s, buf, len, flags)

.. function:: shutdown(s, how)

.. function:: closesocket(s)

