``windows.winproxy`` -- Windows API
***********************************

.. module:: windows.winproxy

:mod:`windows.winproxy` tries to be a pythontic wrapper around windows API of various DLL.
It also heavily relies on :mod:`ctypes` and :mod:`windows.generated_def.winfuncs`

Here are the things to know about :mod:`windows.winproxy`
    * All of this is based on :mod:`windows.generated_def.winfuncs`
    * DLL is loaded the first time an API of it is called
    * All parameters can be passed by ordinal or keyword
    * The call will fail if an argument with default value ``NeededParamater`` have been called without another value.
    * The call will raise a subclass of :class:`WindowsError` if it fails.
    * Some functions are 'transparent proxy' it means that all parameters are mandatory

Example: ``VirtualAlloc``
"""""""""""""""""""""""""

Exemple with the function `VirtualAlloc` in :mod:`windows.winproxy`

Documentation:

.. code-block:: python

    import windows
    windows.winproxy.VirtualAlloc
    # <function VirtualAlloc at 0x02ED63F0>

    help(windows.winproxy.VirtualAlloc)
    # Help on function VirtualAlloc in module windows.winproxy:
    # VirtualAlloc(lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT(0x1000L), flProtect=PAGE_EXECUTE_READWRITE(0x40L))
    #     Errcheck:
    #     raise Kernel32Error if result is 0


Calling it

.. code-block:: python

    import windows

    # Ordinal arguments
    windows.winproxy.VirtualAlloc(0, 0x1000)
    34537472

    # Keyword arguments
    windows.winproxy.VirtualAlloc(dwSize=0x1000)
    34603008

    # NeededParameter must be provided
    windows.winproxy.VirtualAlloc()
    """
    Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
    File "windows\winproxy.py", line 264, in VirtualAlloc
        return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)
    File "windows\winproxy.py", line 130, in perform_call
        raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.func_name, param_name))
    TypeError: VirtualAlloc: Missing Mandatory parameter <dwSize>
    """

    # Error raises exception
    windows.winproxy.VirtualAlloc(dwSize=0xffffffff)
    """
    Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
    File "windows\winproxy.py", line 264, in VirtualAlloc
        return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)
    File "windows\winproxy.py", line 133, in perform_call
        return self._cprototyped(*args)
    File "windows\winproxy.py", line 59, in kernel32_error_check
        raise WinproxyError(func_name)
    windows.winproxy.error.WinproxyError: None: [Error 8] Not enough storage is available to process this command.
    """


Helper functions
""""""""""""""""

.. autofunction:: is_implemented

    Example:
        >>> windows.winproxy.is_implemented(windows.winproxy.NtWow64WriteVirtualMemory64)
        True


.. autofunction:: resolve

    Example:
        >>> hex(windows.winproxy.resolve(windows.winproxy.NtWow64WriteVirtualMemory64))
        '0x77340520'


WinproxyError
"""""""""""""

All errors raised by winproxy functions are instance of :class:`WinproxyError` (or subclasses)

.. autoclass:: WinproxyError
    :show-inheritance:

    .. attribute:: api_name

        The name of the API that raised the exception

Functions in :mod:`windows.winproxy`
""""""""""""""""""""""""""""""""""""

Transparent proxies:

* AllocConsole()
* CloseHandle(hObject)
* ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus)
* DebugActiveProcess(dwProcessId)
* DebugActiveProcessStop(dwProcessId)
* DebugBreak()
* DebugBreakProcess(Process)
* DebugSetProcessKillOnExit(KillOnExit)
* EnumWindows(lpEnumFunc, lParam)
* ExitProcess(uExitCode)
* ExitThread(dwExitCode)
* FreeConsole()
* GetComputerNameA(lpBuffer, lpnSize)
* GetComputerNameW(lpBuffer, lpnSize)
* GetCurrentProcess()
* GetCurrentProcessorNumber()
* GetCurrentThread()
* GetCurrentThreadId()
* GetDriveTypeA(lpRootPathName)
* GetDriveTypeW(lpRootPathName)
* GetExitCodeProcess(hProcess, lpExitCode)
* GetExitCodeThread(hThread, lpExitCode)
* GetLastError()
* GetLengthSid(pSid)
* GetLogicalDriveStringsA(nBufferLength, lpBuffer)
* GetLogicalDriveStringsW(nBufferLength, lpBuffer)
* GetProcAddress(hModule, lpProcName)
* GetProcessId(Process)
* GetSidSubAuthority(pSid, nSubAuthority)
* GetSidSubAuthorityCount(pSid)
* GetStdHandle(nStdHandle)
* GetSystemMetrics(nIndex)
* GetThreadId(Thread)
* GetVersionExA(lpVersionInformation)
* GetVersionExW(lpVersionInformation)
* GetVolumeNameForVolumeMountPointA(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)
* GetVolumeNameForVolumeMountPointW(lpszVolumeMountPoint, lpszVolumeName, cchBufferLength)
* GetWindowModuleFileNameA(hwnd, pszFileName, cchFileNameMax)
* GetWindowModuleFileNameW(hwnd, pszFileName, cchFileNameMax)
* GetWindowTextA(hWnd, lpString, nMaxCount)
* GetWindowTextW(hWnd, lpString, nMaxCount)
* LoadLibraryA(lpFileName)
* LoadLibraryW(lpFileName)
* LocalFree(hMem)
* QueryDosDeviceA(lpDeviceName, lpTargetPath, ucchMax)
* QueryDosDeviceW(lpDeviceName, lpTargetPath, ucchMax)
* ResumeThread(hThread)
* SetStdHandle(nStdHandle, hHandle)
* SetTcpEntry(pTcpRow)
* SuspendThread(hThread)
* TerminateProcess(hProcess, uExitCode)
* TerminateThread(hThread, dwExitCode)
* VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength)
* Wow64DisableWow64FsRedirection(OldValue)
* Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection)
* Wow64GetThreadContext(hThread, lpContext)
* Wow64RevertWow64FsRedirection(OldValue)
* lstrcmpA(lpString1, lpString2)
* lstrcmpW(lpString1, lpString2)

Functions:

* AddVectoredContinueHandler::

    AddVectoredContinueHandler(FirstHandler=1, VectoredHandler=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* AddVectoredExceptionHandler::

    AddVectoredExceptionHandler(FirstHandler=1, VectoredHandler=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* AdjustTokenPrivileges::

    AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges=False, NewState=NeededParameter, BufferLength=None, PreviousState=None, ReturnLength=None)
    Errcheck:
       raise Kernel32Error if result is 0

* AlpcGetMessageAttribute::

    AlpcGetMessageAttribute(Buffer, AttributeFlag)
    Errcheck:
       Nothing special

* AlpcInitializeMessageAttribute::

    AlpcInitializeMessageAttribute(AttributeFlags, Buffer, BufferSize, RequiredBufferSize)

* CertAddCertificateContextToStore::

    CertAddCertificateContextToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext)
    Errcheck:
       raise Kernel32Error if result is 0

* CertCompareCertificate::

    CertCompareCertificate(dwCertEncodingType, pCertId1, pCertId2)
    This function does not raise is compare has failed:
            return 0 if cert are NOT equals

    Errcheck:
       Nothing special

* CertCreateCertificateContext::

    CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded)
    Errcheck:
       raise Kernel32Error if result is 0

* CertCreateSelfSignCertificate::

    CertCreateSelfSignCertificate(hCryptProvOrNCryptKey, pSubjectIssuerBlob, dwFlags, pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions)
    Errcheck:
       raise Kernel32Error if result is 0

* CertDuplicateCertificateContext::

    CertDuplicateCertificateContext(pCertContext)
    Errcheck:
       raise Kernel32Error if result is 0

* CertEnumCTLsInStore::

    CertEnumCTLsInStore(hCertStore, pPrevCtlContext)
    Errcheck:
       raise Kernel32Error if result is 0

* CertEnumCertificateContextProperties::

    CertEnumCertificateContextProperties(pCertContext, dwPropId)
    Errcheck:
       Nothing special

* CertEnumCertificatesInStore::

    CertEnumCertificatesInStore(hCertStore, pPrevCertContext)
    Errcheck:
       raise Kernel32Error if result is 0

* CertFindCertificateInStore::

    CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext)
    Errcheck:
       raise Kernel32Error if result is 0

* CertGetCertificateChain::

    CertGetCertificateChain(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext)
    Errcheck:
       raise Kernel32Error if result is 0

* CertGetCertificateContextProperty::

    CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, pcbData)
    Errcheck:
       raise Kernel32Error if result is 0

* CertGetNameStringA::

    CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)
    Errcheck:
       raise Kernel32Error if result is 0

* CertGetNameStringW::

    CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)
    Errcheck:
       raise Kernel32Error if result is 0

* CertOpenStore::

    CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara)
    Errcheck:
       raise Kernel32Error if result is 0

* CertStrToNameA::

    CertStrToNameA(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)
    Errcheck:
       raise Kernel32Error if result is 0

* CertStrToNameW::

    CertStrToNameW(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)
    Errcheck:
       raise Kernel32Error if result is 0

* CloseServiceHandle::

    CloseServiceHandle(hSCObject)
    Errcheck:
       raise Kernel32Error if result is 0

* CoCreateInstance::

    CoCreateInstance(rclsid, pUnkOuter=None, dwClsContext=tagCLSCTX.CLSCTX_INPROC_SERVER(0x1L), riid=NeededParameter, ppv=NeededParameter)
    Errcheck:
       Nothing special

* CoInitializeEx::

    CoInitializeEx(pvReserved=None, dwCoInit=tagCOINIT.COINIT_MULTITHREADED(0x0L))
    Errcheck:
       Nothing special

* CoInitializeSecurity::

    CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3)
    Errcheck:
       Nothing special

* ConvertSidToStringSidA::

    ConvertSidToStringSidA(Sid, StringSid)
    Errcheck:
       raise Kernel32Error if result is 0

* ConvertSidToStringSidW::

    ConvertSidToStringSidW(Sid, StringSid)
    Errcheck:
       raise Kernel32Error if result is 0

* ConvertStringSidToSidA::

    ConvertStringSidToSidA(StringSid, Sid)
    Errcheck:
       raise Kernel32Error if result is 0

* ConvertStringSidToSidW::

    ConvertStringSidToSidW(StringSid, Sid)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateFileA::

    CreateFileA(lpFileName, dwDesiredAccess=GENERIC_READ(0x80000000L), dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=OPEN_EXISTING(0x3L), dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL(0x80L), hTemplateFile=None)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* CreateFileMappingA::

    CreateFileMappingA(hFile, lpFileMappingAttributes=None, flProtect=PAGE_READWRITE(0x4L), dwMaximumSizeHigh=0, dwMaximumSizeLow=NeededParameter, lpName=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateFileMappingW::

    CreateFileMappingW(hFile, lpFileMappingAttributes=None, flProtect=PAGE_READWRITE(0x4L), dwMaximumSizeHigh=0, dwMaximumSizeLow=0, lpName=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateFileW::

    CreateFileW(lpFileName, dwDesiredAccess=GENERIC_READ(0x80000000L), dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=OPEN_EXISTING(0x3L), dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL(0x80L), hTemplateFile=None)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* CreateProcessA::

    CreateProcessA(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateProcessAsUserA::

    CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateProcessAsUserW::

    CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateProcessW::

    CreateProcessW(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateRemoteThread::

    CreateRemoteThread(hProcess=NeededParameter, lpThreadAttributes=None, dwStackSize=0, lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateThread::

    CreateThread(lpThreadAttributes=None, dwStackSize=0, lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateToolhelp32Snapshot::

    CreateToolhelp32Snapshot(dwFlags, th32ProcessID=0)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateWellKnownSid::

    CreateWellKnownSid(WellKnownSidType, DomainSid=None, pSid=None, cbSid=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptAcquireCertificatePrivateKey::

    CryptAcquireCertificatePrivateKey(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptAcquireContextA::

    CryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptAcquireContextW::

    CryptAcquireContextW(phProv, pszContainer, pszProvider, dwProvType, dwFlags)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptCATAdminAcquireContext::

    CryptCATAdminAcquireContext(phCatAdmin, pgSubsystem, dwFlags)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptCATAdminCalcHashFromFileHandle::

    CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptCATAdminEnumCatalogFromHash::

    CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo)
    Errcheck:
       Nothing special

* CryptCATAdminReleaseCatalogContext::

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwFlags)
    Errcheck:
       Nothing special

* CryptCATAdminReleaseContext::

    CryptCATAdminReleaseContext(hCatAdmin, dwFlags)
    Errcheck:
       Nothing special

* CryptCATCatalogInfoFromContext::

    CryptCATCatalogInfoFromContext(hCatInfo, psCatInfo, dwFlags)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptCATEnumerateAttr::

    CryptCATEnumerateAttr(hCatalog, pCatMember, pPrevAttr)
    Errcheck:
       Nothing special

* CryptCATEnumerateCatAttr::

    CryptCATEnumerateCatAttr(hCatalog, pPrevAttr)
    Errcheck:
       Nothing special

* CryptCATEnumerateMember::

    CryptCATEnumerateMember(hCatalog, pPrevMember)
    Errcheck:
       Nothing special

* CryptDecodeObject::

    CryptDecodeObject(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptDecryptMessage::

    CryptDecryptMessage(pDecryptPara, pbEncryptedBlob, cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptDestroyKey::

    CryptDestroyKey(hKey)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptEncodeObjectEx::

    CryptEncodeObjectEx(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptEncryptMessage::

    CryptEncryptMessage(pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob, pcbEncryptedBlob)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptExportKey::

    CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptGenKey::

    CryptGenKey(hProv, Algid, dwFlags, phKey)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptMsgGetParam::

    CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, pvData, pcbData)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptQueryObject::

    CryptQueryObject(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptReleaseContext::

    CryptReleaseContext(hProv, dwFlags)
    Errcheck:
       raise Kernel32Error if result is 0

* CryptUIDlgViewContext::

    CryptUIDlgViewContext(dwContextType, pvContext, hwnd, pwszTitle, dwFlags, pvReserved)
    Errcheck:
       raise Kernel32Error if result is 0

* DeleteProcThreadAttributeList::

    DeleteProcThreadAttributeList(lpAttributeList)
    Errcheck:
       raise Kernel32Error if result is 0

* DeviceIoControl::

    DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize=None, lpOutBuffer=NeededParameter, nOutBufferSize=None, lpBytesReturned=None, lpOverlapped=None)
    Errcheck:
       raise Kernel32Error if result is 0

* DuplicateHandle::

    DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess=0, bInheritHandle=False, dwOptions=0)
    Errcheck:
       raise Kernel32Error if result is 0

* EnumServicesStatusExA::

    EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)
    Errcheck:
       raise Kernel32Error if result is 0

* EnumServicesStatusExW::

    EnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName)
    Errcheck:
       raise Kernel32Error if result is 0

* GetCursorPos::

    GetCursorPos(lpPoint)
    Errcheck:
       raise Kernel32Error if result is 0

* GetExtendedTcpTable::

    GetExtendedTcpTable(pTcpTable, pdwSize=None, bOrder=True, ulAf=NeededParameter, TableClass=_TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL(0x5L), Reserved=0)
    Errcheck:
       raise IphlpapiError if result is NOT 0

* GetFileVersionInfoA::

    GetFileVersionInfoA(lptstrFilename, dwHandle=0, dwLen=None, lpData=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* GetFileVersionInfoSizeA::

    GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetFileVersionInfoSizeW::

    GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetFileVersionInfoW::

    GetFileVersionInfoW(lptstrFilename, dwHandle=0, dwLen=None, lpData=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* GetIfTable::

    GetIfTable(pIfTable, pdwSize, bOrder=False)
    Errcheck:
       raise IphlpapiError if result is NOT 0

* GetInterfaceInfo::

    GetInterfaceInfo(pIfTable, dwOutBufLen=None)
    Errcheck:
       raise IphlpapiError if result is NOT 0

* GetIpAddrTable::

    GetIpAddrTable(pIpAddrTable, pdwSize, bOrder=False)
    Errcheck:
       raise IphlpapiError if result is NOT 0

* GetLongPathNameA::

    GetLongPathNameA(lpszShortPath, lpszLongPath, cchBuffer=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetMappedFileNameAWrapper::

    GetMappedFileNameAWrapper(hProcess, lpv, lpFilename, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetMappedFileNameAWrapper::

    GetMappedFileNameAWrapper(hProcess, lpv, lpFilename, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetMappedFileNameWWrapper::

    GetMappedFileNameWWrapper(hProcess, lpv, lpFilename, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetMappedFileNameWWrapper::

    GetMappedFileNameWWrapper(hProcess, lpv, lpFilename, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetModuleBaseNameAWrapper::

    GetModuleBaseNameAWrapper(hProcess, hModule, lpBaseName, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetModuleBaseNameAWrapper::

    GetModuleBaseNameAWrapper(hProcess, hModule, lpBaseName, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetModuleBaseNameWWrapper::

    GetModuleBaseNameWWrapper(hProcess, hModule, lpBaseName, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetModuleBaseNameWWrapper::

    GetModuleBaseNameWWrapper(hProcess, hModule, lpBaseName, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetNamedSecurityInfoA::

    GetNamedSecurityInfoA(pObjectName, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* GetNamedSecurityInfoW::

    GetNamedSecurityInfoW(pObjectName, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* GetProcessDEPPolicy::

    GetProcessDEPPolicy(hProcess, lpFlags, lpPermanent)
    Errcheck:
       raise Kernel32Error if result is 0

* GetProcessImageFileNameAWrapper::

    GetProcessImageFileNameAWrapper(hProcess, lpImageFileName, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetProcessImageFileNameAWrapper::

    GetProcessImageFileNameAWrapper(hProcess, lpImageFileName, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetProcessImageFileNameWWrapper::

    GetProcessImageFileNameWWrapper(hProcess, lpImageFileName, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetProcessImageFileNameWWrapper::

    GetProcessImageFileNameWWrapper(hProcess, lpImageFileName, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* GetProcessTimes::

    GetProcessTimes(hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime)
    Errcheck:
       raise Kernel32Error if result is 0

* GetSecurityInfo::

    GetSecurityInfo(handle, ObjectType, SecurityInfo, ppsidOwner=None, ppsidGroup=None, ppDacl=None, ppSacl=None, ppSecurityDescriptor=None)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* GetShortPathNameA::

    GetShortPathNameA(lpszLongPath, lpszShortPath, cchBuffer=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetThreadContext::

    GetThreadContext(hThread, lpContext=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetTokenInformation::

    GetTokenInformation(TokenHandle=NeededParameter, TokenInformationClass=NeededParameter, TokenInformation=None, TokenInformationLength=0, ReturnLength=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetVolumeInformationA::

    GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize)
    Errcheck:
       raise Kernel32Error if result is 0

* GetVolumeInformationW::

    GetVolumeInformationW(lpRootPathName, lpVolumeNameBuffer=None, nVolumeNameSize=0, lpVolumeSerialNumber=None, lpMaximumComponentLength=None, lpFileSystemFlags=None, lpFileSystemNameBuffer=None, nFileSystemNameSize=0)
    Errcheck:
       raise Kernel32Error if result is 0

* GetWindowRect::

    GetWindowRect(hWnd, lpRect)
    Errcheck:
       raise Kernel32Error if result is 0

* GetWindowsDirectoryA::

    GetWindowsDirectoryA(lpBuffer, uSize=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetWindowsDirectoryW::

    GetWindowsDirectoryW(lpBuffer, uSize=None)
    Errcheck:
       raise Kernel32Error if result is 0

* InitializeProcThreadAttributeList::

    InitializeProcThreadAttributeList(lpAttributeList=None, dwAttributeCount=NeededParameter, dwFlags=0, lpSize=NeededParameter)

* LdrLoadDll::

    LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle)

* LookupAccountSidA::

    LookupAccountSidA(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)
    Errcheck:
       raise Kernel32Error if result is 0

* LookupAccountSidW::

    LookupAccountSidW(lpSystemName, lpSid, lpName, cchName, lpReferencedDomainName, cchReferencedDomainName, peUse)
    Errcheck:
       raise Kernel32Error if result is 0

* LookupPrivilegeNameA::

    LookupPrivilegeNameA(lpSystemName, lpLuid, lpName, cchName)
    Errcheck:
       raise Kernel32Error if result is 0

* LookupPrivilegeNameW::

    LookupPrivilegeNameW(lpSystemName, lpLuid, lpName, cchName)
    Errcheck:
       raise Kernel32Error if result is 0

* LookupPrivilegeValueA::

    LookupPrivilegeValueA(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* LookupPrivilegeValueW::

    LookupPrivilegeValueW(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* MapViewOfFile::

    MapViewOfFile(hFileMappingObject, dwDesiredAccess=FILE_MAP_ALL_ACCESS(0xf001fL), dwFileOffsetHigh=0, dwFileOffsetLow=0, dwNumberOfBytesToMap=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* MessageBoxA::

    MessageBoxA(hWnd=0, lpText=NeededParameter, lpCaption=None, uType=0)
    Errcheck:
       raise Kernel32Error if result is 0

* MessageBoxW::

    MessageBoxW(hWnd=0, lpText=NeededParameter, lpCaption=None, uType=0)
    Errcheck:
       raise Kernel32Error if result is 0

* NtAlpcAcceptConnectPort::

    NtAlpcAcceptConnectPort(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection)

* NtAlpcConnectPort::

    NtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)

* NtAlpcConnectPortEx::

    NtAlpcConnectPortEx(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)

* NtAlpcCreatePort::

    NtAlpcCreatePort(PortHandle, ObjectAttributes, PortAttributes)

* NtAlpcCreatePortSection::

    NtAlpcCreatePortSection(PortHandle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize)

* NtAlpcCreateSectionView::

    NtAlpcCreateSectionView(PortHandle, Flags, ViewAttributes)

* NtAlpcDeletePortSection::

    NtAlpcDeletePortSection(PortHandle, Flags, SectionHandle)

* NtAlpcDeleteSectionView::

    NtAlpcDeleteSectionView(PortHandle, Flags, ViewBase)

* NtAlpcDisconnectPort::

    NtAlpcDisconnectPort(PortHandle, Flags)

* NtAlpcQueryInformation::

    NtAlpcQueryInformation(PortHandle, PortInformationClass, PortInformation, Length, ReturnLength)

* NtAlpcSendWaitReceivePort::

    NtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout)

* NtCreateFile::

    NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength)

* NtCreateSection::

    NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle)

* NtCreateThreadEx::

    NtCreateThreadEx(ThreadHandle=None, DesiredAccess=2097151, ObjectAttributes=0, ProcessHandle=NeededParameter, lpStartAddress=NeededParameter, lpParameter=NeededParameter, CreateSuspended=0, dwStackSize=0, Unknown1=0, Unknown2=0, Unknown=0)

* NtGetContextThread::

    NtGetContextThread(hThread, lpContext)

* NtMapViewOfSection::

    NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect)

* NtOpenDirectoryObject::

    NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes)

* NtOpenEvent::

    NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes)

* NtOpenSection::

    NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes)

* NtOpenSymbolicLinkObject::

    NtOpenSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes)

* NtProtectVirtualMemory::

    NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection=None)

* NtQueryDirectoryObject::

    NtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength)

* NtQueryInformationProcess::

    NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength=0, ReturnLength=None)

* NtQueryInformationThread::

    NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength=0, ReturnLength=None)

* NtQueryObject::

    NtQueryObject(Handle, ObjectInformationClass, ObjectInformation=None, ObjectInformationLength=0, ReturnLength=NeededParameter)

* NtQuerySymbolicLinkObject::

    NtQuerySymbolicLinkObject(LinkHandle, LinkTarget, ReturnedLength)

* NtQuerySystemInformation::

    NtQuerySystemInformation(SystemInformationClass, SystemInformation=None, SystemInformationLength=0, ReturnLength=NeededParameter)

* NtQueryVirtualMemory::

    NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation=NeededParameter, MemoryInformationLength=0, ReturnLength=None)

* NtReadVirtualMemory::

    NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

* NtSetContextThread::

    NtSetContextThread(hThread, lpContext)

* NtUnmapViewOfSection::

    NtUnmapViewOfSection(ProcessHandle, BaseAddress)

* NtWow64ReadVirtualMemory64::

    NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None)

* NtWow64WriteVirtualMemory64::

    NtWow64WriteVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten=None)

* OpenEventA::

    OpenEventA(dwDesiredAccess, bInheritHandle, lpName)
    Errcheck:
       raise Kernel32Error if result is 0

* OpenEventW::

    OpenEventW(dwDesiredAccess, bInheritHandle, lpName)
    Errcheck:
       raise Kernel32Error if result is 0

* OpenProcess::

    OpenProcess(dwDesiredAccess=PROCESS_ALL_ACCESS(0x1f0fffL), bInheritHandle=0, dwProcessId=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* OpenProcessToken::

    OpenProcessToken(ProcessHandle=None, DesiredAccess=NeededParameter, TokenHandle=NeededParameter)
    If ProcessHandle is None: take the current process
    Errcheck:
       raise Kernel32Error if result is 0

* OpenSCManagerA::

    OpenSCManagerA(lpMachineName=None, lpDatabaseName=None, dwDesiredAccess=SC_MANAGER_ALL_ACCESS(0xf003fL))
    Errcheck:
       raise Kernel32Error if result is 0

* OpenSCManagerW::

    OpenSCManagerW(lpMachineName=None, lpDatabaseName=None, dwDesiredAccess=SC_MANAGER_ALL_ACCESS(0xf003fL))
    Errcheck:
       raise Kernel32Error if result is 0

* OpenServiceA::

    OpenServiceA(hSCManager, lpServiceName, dwDesiredAccess)
    Errcheck:
       raise Kernel32Error if result is 0

* OpenServiceW::

    OpenServiceW(hSCManager, lpServiceName, dwDesiredAccess)
    Errcheck:
       raise Kernel32Error if result is 0

* OpenThread::

    OpenThread(dwDesiredAccess=THREAD_ALL_ACCESS(0x1f03ffL), bInheritHandle=0, dwThreadId=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* OpenThreadToken::

    OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle)
    Errcheck:
       raise Kernel32Error if result is 0

* PFXExportCertStoreEx::

    PFXExportCertStoreEx(hStore, pPFX, szPassword, pvPara, dwFlags)
    Errcheck:
       raise Kernel32Error if result is 0

* PFXImportCertStore::

    PFXImportCertStore(pPFX, szPassword, dwFlags)
    Errcheck:
       raise Kernel32Error if result is 0

* Process32First::

    Process32First(hSnapshot, lpte)
    Errcheck:
       raise Kernel32Error if result is 0

* Process32Next::

    Process32Next(hSnapshot, lpte)
    Errcheck:
       Nothing special

* QueryWorkingSetWrapper::

    QueryWorkingSetWrapper(hProcess, pv, cb)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* QueryWorkingSetExWrapper::

    QueryWorkingSetExWrapper(hProcess, pv, cb)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* QueryWorkingSetExWrapper::

    QueryWorkingSetExWrapper(hProcess, pv, cb)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* QueryWorkingSetWrapper::

    QueryWorkingSetWrapper(hProcess, pv, cb)
    Errcheck:
       raise Kernel32Error if result is 0
    Errcheck:
       raise Kernel32Error if result is 0

* ReadFile::

    ReadFile(hFile, lpBuffer, nNumberOfBytesToRead=None, lpNumberOfBytesRead=None, lpOverlapped=None)
    Errcheck:
       raise Kernel32Error if result is 0

* ReadProcessMemory::

    ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None)
    Errcheck:
       raise Kernel32Error if result is 0

* RegCloseKey::

    RegCloseKey(hKey)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegGetValueA::

    RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegGetValueW::

    RegGetValueW(hkey, lpSubKey=None, lpValue=NeededParameter, dwFlags=0, pdwType=None, pvData=None, pcbData=None)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegOpenKeyExA::

    RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegOpenKeyExW::

    RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegQueryValueExA::

    RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegQueryValueExW::

    RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RemoveVectoredExceptionHandler::

    RemoveVectoredExceptionHandler(Handler)
    Errcheck:
       raise Kernel32Error if result is 0

* RtlDecompressBuffer::

    RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize)

* RtlGetUnloadEventTraceEx::

    RtlGetUnloadEventTraceEx(ElementSize, ElementCount, EventTrace)
    Errcheck:
       Nothing special

* SetConsoleCtrlHandler::

    SetConsoleCtrlHandler(HandlerRoutine, Add)
    Errcheck:
       raise Kernel32Error if result is 0

* SetThreadAffinityMask::

    SetThreadAffinityMask(hThread=None, dwThreadAffinityMask=NeededParameter)
    If hThread is not given, it will be the current thread
    Errcheck:
       raise Kernel32Error if result is 0

* SetThreadContext::

    SetThreadContext(hThread, lpContext)
    Errcheck:
       raise Kernel32Error if result is 0

* SetTokenInformation::

    SetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength)
    Errcheck:
       raise Kernel32Error if result is 0

* ShellExecuteA::

    ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    Errcheck:
       raise Kernel32Error if result is 0

* ShellExecuteW::

    ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    Errcheck:
       raise Kernel32Error if result is 0

* StartServiceA::

    StartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors)
    Errcheck:
       raise Kernel32Error if result is 0

* StartServiceW::

    StartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors)
    Errcheck:
       raise Kernel32Error if result is 0

* Thread32First::

    Thread32First(hSnapshot, lpte)
    Set byref(lpte) if needed
    Errcheck:
       raise Kernel32Error if result is 0

* Thread32Next::

    Thread32Next(hSnapshot, lpte)
    Set byref(lpte) if needed
    Errcheck:
       Nothing special

* TpCallbackSendAlpcMessageOnCompletion::

    TpCallbackSendAlpcMessageOnCompletion(TpHandle, PortHandle, Flags, SendMessage)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* UpdateProcThreadAttribute::

    UpdateProcThreadAttribute(lpAttributeList, dwFlags=0, Attribute=NeededParameter, lpValue=NeededParameter, cbSize=NeededParameter, lpPreviousValue=None, lpReturnSize=None)
    Errcheck:
       raise Kernel32Error if result is 0

* VerQueryValueA::

    VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen)
    Errcheck:
       raise Kernel32Error if result is 0

* VerQueryValueW::

    VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen)
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualAlloc::

    VirtualAlloc(lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT(0x1000L), flProtect=PAGE_EXECUTE_READWRITE(0x40L))
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualAllocEx::

    VirtualAllocEx(hProcess, lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT(0x1000L), flProtect=PAGE_EXECUTE_READWRITE(0x40L))
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualFree::

    VirtualFree(lpAddress, dwSize=0, dwFreeType=MEM_RELEASE(0x8000L))
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualFreeEx::

    VirtualFreeEx(hProcess, lpAddress, dwSize=0, dwFreeType=MEM_RELEASE(0x8000L))
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualProtect::

    VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect=None)
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualProtectEx::

    VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect=None)
    Errcheck:
       raise Kernel32Error if result is 0

* WaitForDebugEvent::

    WaitForDebugEvent(lpDebugEvent, dwMilliseconds=INFINITE(0xffffffffL))
    Errcheck:
       raise Kernel32Error if result is 0

* WaitForSingleObject::

    WaitForSingleObject(hHandle, dwMilliseconds=INFINITE(0xffffffffL))
    Errcheck:
       raise Kernel32Error if result is NOT 0

* WinVerifyTrust::

    WinVerifyTrust(hwnd, pgActionID, pWVTData)
    Errcheck:
       Nothing special

* WindowFromPoint::

    WindowFromPoint(Point)
    Errcheck:
       raise Kernel32Error if result is 0

* Wow64SetThreadContext::

    Wow64SetThreadContext(hThread, lpContext)
    Errcheck:
       raise Kernel32Error if result is 0

* WriteFile::

    WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite=None, lpNumberOfBytesWritten=None, lpOverlapped=None)
    Errcheck:
       raise Kernel32Error if result is 0

* WriteProcessMemory::

    WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize=None, lpNumberOfBytesWritten=None)
    Computer nSize with len(lpBuffer) if not given
    Errcheck:
       raise Kernel32Error if result is 0
