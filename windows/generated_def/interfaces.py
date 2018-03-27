from winstructs import *
import functools
import ctypes


generate_IID = IID.from_raw

class COMInterface(ctypes.c_void_p):
    _functions_ = {
    }

    def __getattr__(self, name):
        if name in self._functions_:
            return functools.partial(self._functions_[name], self)
        return super(COMInterface, self).__getattribute__(name)

class IBackgroundCopyCallback(COMInterface):
    IID = generate_IID(0x97EA99C7, 0x0186, 0x4AD4, 0x8D, 0xF9, 0xC5, 0xB4, 0xE0, 0xED, 0x6B, 0x22, name="IBackgroundCopyCallback", strid="97EA99C7-0186-4AD4-8DF9-C5B4E0ED6B22")

class IBackgroundCopyError(COMInterface):
    IID = generate_IID(0x19C613A0, 0xFCB8, 0x4F28, 0x81, 0xAE, 0x89, 0x7C, 0x3D, 0x07, 0x8F, 0x81, name="IBackgroundCopyError", strid="19C613A0-FCB8-4F28-81AE-897C3D078F81")

class IBackgroundCopyFile(COMInterface):
    IID = generate_IID(0x01B7BD23, 0xFB88, 0x4A77, 0x84, 0x90, 0x58, 0x91, 0xD3, 0xE4, 0x65, 0x3A, name="IBackgroundCopyFile", strid="01B7BD23-FB88-4A77-8490-5891D3E4653A")

class IBackgroundCopyJob(COMInterface):
    IID = generate_IID(0x37668D37, 0x507E, 0x4160, 0x93, 0x16, 0x26, 0x30, 0x6D, 0x15, 0x0B, 0x12, name="IBackgroundCopyJob", strid="37668D37-507E-4160-9316-26306D150B12")

class IBackgroundCopyManager(COMInterface):
    IID = generate_IID(0x5CE34C0D, 0x0DC9, 0x4C1F, 0x89, 0x7C, 0xDA, 0xA1, 0xB7, 0x8C, 0xEE, 0x7C, name="IBackgroundCopyManager", strid="5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C")

class ICallFrame(COMInterface):
    IID = generate_IID(0xD573B4B0, 0x894E, 0x11D2, 0xB8, 0xB6, 0x00, 0xC0, 0x4F, 0xB9, 0x61, 0x8A, name="ICallFrame", strid="D573B4B0-894E-11D2-B8B6-00C04FB9618A")

class ICallFrameEvents(COMInterface):
    IID = generate_IID(0xFD5E0843, 0xFC91, 0x11D0, 0x97, 0xD7, 0x00, 0xC0, 0x4F, 0xB9, 0x61, 0x8A, name="ICallFrameEvents", strid="FD5E0843-FC91-11D0-97D7-00C04FB9618A")

class ICallFrameWalker(COMInterface):
    IID = generate_IID(0x08B23919, 0x392D, 0x11D2, 0xB8, 0xA4, 0x00, 0xC0, 0x4F, 0xB9, 0x61, 0x8A, name="ICallFrameWalker", strid="08B23919-392D-11D2-B8A4-00C04FB9618A")

class ICallInterceptor(COMInterface):
    IID = generate_IID(0x60C7CA75, 0x896D, 0x11D2, 0xB8, 0xB6, 0x00, 0xC0, 0x4F, 0xB9, 0x61, 0x8A, name="ICallInterceptor", strid="60C7CA75-896D-11D2-B8B6-00C04FB9618A")

class IDispatch(COMInterface):
    IID = generate_IID(0x00020400, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IDispatch", strid="00020400-0000-0000-C000-000000000046")

class IEnumBackgroundCopyFiles(COMInterface):
    IID = generate_IID(0xCA51E165, 0xC365, 0x424C, 0x8D, 0x41, 0x24, 0xAA, 0xA4, 0xFF, 0x3C, 0x40, name="IEnumBackgroundCopyFiles", strid="CA51E165-C365-424C-8D41-24AAA4FF3C40")

class IEnumBackgroundCopyJobs(COMInterface):
    IID = generate_IID(0x1AF4F612, 0x3B71, 0x466F, 0x8F, 0x58, 0x7B, 0x6F, 0x73, 0xAC, 0x57, 0xAD, name="IEnumBackgroundCopyJobs", strid="1AF4F612-3B71-466F-8F58-7B6F73AC57AD")

class IEnumVARIANT(COMInterface):
    IID = generate_IID(0x00020404, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IEnumVARIANT", strid="00020404-0000-0000-C000-000000000046")

class IEnumWbemClassObject(COMInterface):
    IID = generate_IID(0x027947E1, 0xD731, 0x11CE, 0xA3, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, name="IEnumWbemClassObject", strid="027947E1-D731-11CE-A357-000000000001")

class INetFwPolicy2(COMInterface):
    IID = generate_IID(0x98325047, 0xC671, 0x4174, 0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86, name="INetFwPolicy2", strid="98325047-C671-4174-8D81-DEFCD3F03186")

class INetFwRules(COMInterface):
    IID = generate_IID(0x9C4C6277, 0x5027, 0x441E, 0xAF, 0xAE, 0xCA, 0x1F, 0x54, 0x2D, 0xA0, 0x09, name="INetFwRules", strid="9C4C6277-5027-441E-AFAE-CA1F542DA009")

class INetFwRule(COMInterface):
    IID = generate_IID(0xAF230D27, 0xBABA, 0x4E42, 0xAC, 0xED, 0xF5, 0x24, 0xF2, 0x2C, 0xFC, 0xE2, name="INetFwRule", strid="AF230D27-BABA-4E42-ACED-F524F22CFCE2")

class INetFwServiceRestriction(COMInterface):
    IID = generate_IID(0x8267BBE3, 0xF890, 0x491C, 0xB7, 0xB6, 0x2D, 0xB1, 0xEF, 0x0E, 0x5D, 0x2B, name="INetFwServiceRestriction", strid="8267BBE3-F890-491C-B7B6-2DB1EF0E5D2B")

class IPersistFile(COMInterface):
    IID = generate_IID(0x0000010B, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IPersistFile", strid="0000010B-0000-0000-C000-000000000046")

class IShellLinkA(COMInterface):
    IID = generate_IID(0x000214EE, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IShellLinkA", strid="000214EE-0000-0000-C000-000000000046")

class IShellLinkW(COMInterface):
    IID = generate_IID(0x000214F9, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IShellLinkW", strid="000214F9-0000-0000-C000-000000000046")

class IUnknown(COMInterface):
    IID = generate_IID(0x00000000, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IUnknown", strid="00000000-0000-0000-C000-000000000046")

class IWbemCallResult(COMInterface):
    IID = generate_IID(0x44ACA675, 0xE8FC, 0x11D0, 0xA0, 0x7C, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20, name="IWbemCallResult", strid="44ACA675-E8FC-11D0-A07C-00C04FB68820")

class IWbemClassObject(COMInterface):
    IID = generate_IID(0xDC12A681, 0x737F, 0x11CF, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, name="IWbemClassObject", strid="DC12A681-737F-11CF-884D-00AA004B2E24")

class IWbemContext(COMInterface):
    IID = generate_IID(0x44ACA674, 0xE8FC, 0x11D0, 0xA0, 0x7C, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20, name="IWbemContext", strid="44ACA674-E8FC-11D0-A07C-00C04FB68820")

class IWbemLocator(COMInterface):
    IID = generate_IID(0xDC12A687, 0x737F, 0x11CF, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, name="IWbemLocator", strid="DC12A687-737F-11CF-884D-00AA004B2E24")

class IWbemObjectSink(COMInterface):
    IID = generate_IID(0x7C857801, 0x7381, 0x11CF, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, name="IWbemObjectSink", strid="7C857801-7381-11CF-884D-00AA004B2E24")

class IWbemQualifierSet(COMInterface):
    IID = generate_IID(0xDC12A680, 0x737F, 0x11CF, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, name="IWbemQualifierSet", strid="DC12A680-737F-11CF-884D-00AA004B2E24")

class IWbemServices(COMInterface):
    IID = generate_IID(0x9556DC99, 0x828C, 0x11CF, 0xA3, 0x7E, 0x00, 0xAA, 0x00, 0x32, 0x40, 0xC7, name="IWbemServices", strid="9556DC99-828C-11CF-A37E-00AA003240C7")

IBackgroundCopyCallback._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # JobTransferred -> pJob:*IBackgroundCopyJob
        "JobTransferred": ctypes.WINFUNCTYPE(HRESULT, IBackgroundCopyJob)(3, "JobTransferred"),
        # JobError -> pJob:*IBackgroundCopyJob, pError:*IBackgroundCopyError
        "JobError": ctypes.WINFUNCTYPE(HRESULT, IBackgroundCopyJob, IBackgroundCopyError)(4, "JobError"),
        # JobModification -> pJob:*IBackgroundCopyJob, dwReserved:DWORD
        "JobModification": ctypes.WINFUNCTYPE(HRESULT, IBackgroundCopyJob, DWORD)(5, "JobModification"),
    }

IBackgroundCopyError._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetError -> pContext:*BG_ERROR_CONTEXT, pCode:*HRESULT
        "GetError": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_ERROR_CONTEXT), POINTER(HRESULT))(3, "GetError"),
        # GetFile -> pVal:**IBackgroundCopyFile
        "GetFile": ctypes.WINFUNCTYPE(HRESULT, POINTER(IBackgroundCopyFile))(4, "GetFile"),
        # GetErrorDescription -> LanguageId:DWORD, pErrorDescription:*LPWSTR
        "GetErrorDescription": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(LPWSTR))(5, "GetErrorDescription"),
        # GetErrorContextDescription -> LanguageId:DWORD, pContextDescription:*LPWSTR
        "GetErrorContextDescription": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(LPWSTR))(6, "GetErrorContextDescription"),
        # GetProtocol -> pProtocol:*LPWSTR
        "GetProtocol": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR))(7, "GetProtocol"),
    }

IBackgroundCopyFile._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetRemoteName -> pVal:*LPWSTR
        "GetRemoteName": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR))(3, "GetRemoteName"),
        # GetLocalName -> pVal:*LPWSTR
        "GetLocalName": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR))(4, "GetLocalName"),
        # GetProgress -> pVal:*BG_FILE_PROGRESS
        "GetProgress": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_FILE_PROGRESS))(5, "GetProgress"),
    }

IBackgroundCopyJob._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # AddFileSet -> cFileCount:ULONG, pFileSet:*BG_FILE_INFO
        "AddFileSet": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(BG_FILE_INFO))(3, "AddFileSet"),
        # AddFile -> RemoteUrl:LPCWSTR, LocalName:LPCWSTR
        "AddFile": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LPCWSTR)(4, "AddFile"),
        # EnumFiles -> pEnum:**IEnumBackgroundCopyFiles
        "EnumFiles": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumBackgroundCopyFiles))(5, "EnumFiles"),
        # Suspend -> 
        "Suspend": ctypes.WINFUNCTYPE(HRESULT)(6, "Suspend"),
        # Resume -> 
        "Resume": ctypes.WINFUNCTYPE(HRESULT)(7, "Resume"),
        # Cancel -> 
        "Cancel": ctypes.WINFUNCTYPE(HRESULT)(8, "Cancel"),
        # Complete -> 
        "Complete": ctypes.WINFUNCTYPE(HRESULT)(9, "Complete"),
        # GetId -> pVal:*GUID
        "GetId": ctypes.WINFUNCTYPE(HRESULT, POINTER(GUID))(10, "GetId"),
        # GetType -> pVal:*BG_JOB_TYPE
        "GetType": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_JOB_TYPE))(11, "GetType"),
        # GetProgress -> pVal:*BG_JOB_PROGRESS
        "GetProgress": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_JOB_PROGRESS))(12, "GetProgress"),
        # GetTimes -> pVal:*BG_JOB_TIMES
        "GetTimes": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_JOB_TIMES))(13, "GetTimes"),
        # GetState -> pVal:*BG_JOB_STATE
        "GetState": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_JOB_STATE))(14, "GetState"),
        # GetError -> ppError:**IBackgroundCopyError
        "GetError": ctypes.WINFUNCTYPE(HRESULT, POINTER(IBackgroundCopyError))(15, "GetError"),
        # GetOwner -> pVal:*LPWSTR
        "GetOwner": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR))(16, "GetOwner"),
        # SetDisplayName -> Val:LPCWSTR
        "SetDisplayName": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(17, "SetDisplayName"),
        # GetDisplayName -> pVal:*LPWSTR
        "GetDisplayName": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR))(18, "GetDisplayName"),
        # SetDescription -> Val:LPCWSTR
        "SetDescription": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(19, "SetDescription"),
        # GetDescription -> pVal:*LPWSTR
        "GetDescription": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR))(20, "GetDescription"),
        # SetPriority -> Val:BG_JOB_PRIORITY
        "SetPriority": ctypes.WINFUNCTYPE(HRESULT, BG_JOB_PRIORITY)(21, "SetPriority"),
        # GetPriority -> pVal:*BG_JOB_PRIORITY
        "GetPriority": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_JOB_PRIORITY))(22, "GetPriority"),
        # SetNotifyFlags -> Val:ULONG
        "SetNotifyFlags": ctypes.WINFUNCTYPE(HRESULT, ULONG)(23, "SetNotifyFlags"),
        # GetNotifyFlags -> pVal:*ULONG
        "GetNotifyFlags": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG))(24, "GetNotifyFlags"),
        # SetNotifyInterface -> Val:*IUnknown
        "SetNotifyInterface": ctypes.WINFUNCTYPE(HRESULT, IUnknown)(25, "SetNotifyInterface"),
        # GetNotifyInterface -> pVal:**IUnknown
        "GetNotifyInterface": ctypes.WINFUNCTYPE(HRESULT, POINTER(IUnknown))(26, "GetNotifyInterface"),
        # SetMinimumRetryDelay -> Seconds:ULONG
        "SetMinimumRetryDelay": ctypes.WINFUNCTYPE(HRESULT, ULONG)(27, "SetMinimumRetryDelay"),
        # GetMinimumRetryDelay -> Seconds:*ULONG
        "GetMinimumRetryDelay": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG))(28, "GetMinimumRetryDelay"),
        # SetNoProgressTimeout -> Seconds:ULONG
        "SetNoProgressTimeout": ctypes.WINFUNCTYPE(HRESULT, ULONG)(29, "SetNoProgressTimeout"),
        # GetNoProgressTimeout -> Seconds:*ULONG
        "GetNoProgressTimeout": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG))(30, "GetNoProgressTimeout"),
        # GetErrorCount -> Errors:*ULONG
        "GetErrorCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG))(31, "GetErrorCount"),
        # SetProxySettings -> ProxyUsage:BG_JOB_PROXY_USAGE, ProxyList:*WCHAR, ProxyBypassList:*WCHAR
        "SetProxySettings": ctypes.WINFUNCTYPE(HRESULT, BG_JOB_PROXY_USAGE, POINTER(WCHAR), POINTER(WCHAR))(32, "SetProxySettings"),
        # GetProxySettings -> pProxyUsage:*BG_JOB_PROXY_USAGE, pProxyList:*LPWSTR, pProxyBypassList:*LPWSTR
        "GetProxySettings": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_JOB_PROXY_USAGE), POINTER(LPWSTR), POINTER(LPWSTR))(33, "GetProxySettings"),
        # TakeOwnership -> 
        "TakeOwnership": ctypes.WINFUNCTYPE(HRESULT)(34, "TakeOwnership"),
    }

IBackgroundCopyManager._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # CreateJob -> DisplayName:LPCWSTR, Type:BG_JOB_TYPE, pJobId:*GUID, ppJob:**IBackgroundCopyJob
        "CreateJob": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, BG_JOB_TYPE, POINTER(GUID), POINTER(IBackgroundCopyJob))(3, "CreateJob"),
        # GetJob -> jobID:REFGUID, ppJob:**IBackgroundCopyJob
        "GetJob": ctypes.WINFUNCTYPE(HRESULT, REFGUID, POINTER(IBackgroundCopyJob))(4, "GetJob"),
        # EnumJobs -> dwFlags:DWORD, ppEnum:**IEnumBackgroundCopyJobs
        "EnumJobs": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(IEnumBackgroundCopyJobs))(5, "EnumJobs"),
        # GetErrorDescription -> hResult:HRESULT, LanguageId:DWORD, pErrorDescription:*LPWSTR
        "GetErrorDescription": ctypes.WINFUNCTYPE(HRESULT, HRESULT, DWORD, POINTER(LPWSTR))(6, "GetErrorDescription"),
    }

ICallFrame._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetInfo -> pInfo:*CALLFRAMEINFO
        "GetInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(CALLFRAMEINFO))(3, "GetInfo"),
        # GetIIDAndMethod -> pIID:*IID, piMethod:*ULONG
        "GetIIDAndMethod": ctypes.WINFUNCTYPE(HRESULT, POINTER(IID), POINTER(ULONG))(4, "GetIIDAndMethod"),
        # GetNames -> pwszInterface:*LPWSTR, pwszMethod:*LPWSTR
        "GetNames": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR), POINTER(LPWSTR))(5, "GetNames"),
        # GetStackLocation -> 
        "GetStackLocation": ctypes.WINFUNCTYPE(PVOID)(6, "GetStackLocation"),
        # SetStackLocation -> pvStack:PVOID
        "SetStackLocation": ctypes.WINFUNCTYPE(VOID, PVOID)(7, "SetStackLocation"),
        # SetReturnValue -> hr:HRESULT
        "SetReturnValue": ctypes.WINFUNCTYPE(VOID, HRESULT)(8, "SetReturnValue"),
        # GetReturnValue -> 
        "GetReturnValue": ctypes.WINFUNCTYPE(HRESULT)(9, "GetReturnValue"),
        # GetParamInfo -> iparam:ULONG, pInfo:*CALLFRAMEPARAMINFO
        "GetParamInfo": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(CALLFRAMEPARAMINFO))(10, "GetParamInfo"),
        # SetParam -> iparam:ULONG, pvar:*VARIANT
        "SetParam": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(VARIANT))(11, "SetParam"),
        # GetParam -> iparam:ULONG, pvar:*VARIANT
        "GetParam": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(VARIANT))(12, "GetParam"),
        # Copy -> copyControl:CALLFRAME_COPY, pWalker:*ICallFrameWalker, ppFrame:**ICallFrame
        "Copy": ctypes.WINFUNCTYPE(HRESULT, CALLFRAME_COPY, ICallFrameWalker, POINTER(ICallFrame))(13, "Copy"),
        # Free -> pframeArgsDest:*ICallFrame, pWalkerDestFree:*ICallFrameWalker, pWalkerCopy:*ICallFrameWalker, freeFlags:DWORD, pWalkerFree:*ICallFrameWalker, nullFlags:DWORD
        "Free": ctypes.WINFUNCTYPE(HRESULT, ICallFrame, ICallFrameWalker, ICallFrameWalker, DWORD, ICallFrameWalker, DWORD)(14, "Free"),
        # FreeParam -> iparam:ULONG, freeFlags:DWORD, pWalkerFree:*ICallFrameWalker, nullFlags:DWORD
        "FreeParam": ctypes.WINFUNCTYPE(HRESULT, ULONG, DWORD, ICallFrameWalker, DWORD)(15, "FreeParam"),
        # WalkFrame -> walkWhat:DWORD, pWalker:*ICallFrameWalker
        "WalkFrame": ctypes.WINFUNCTYPE(HRESULT, DWORD, ICallFrameWalker)(16, "WalkFrame"),
        # GetMarshalSizeMax -> pmshlContext:*CALLFRAME_MARSHALCONTEXT, mshlflags:MSHLFLAGS, pcbBufferNeeded:*ULONG
        "GetMarshalSizeMax": ctypes.WINFUNCTYPE(HRESULT, POINTER(CALLFRAME_MARSHALCONTEXT), MSHLFLAGS, POINTER(ULONG))(17, "GetMarshalSizeMax"),
        # Marshal -> pmshlContext:*CALLFRAME_MARSHALCONTEXT, mshlflags:MSHLFLAGS, pBuffer:PVOID, cbBuffer:ULONG, pcbBufferUsed:*ULONG, pdataRep:*RPCOLEDATAREP, prpcFlags:*ULONG
        "Marshal": ctypes.WINFUNCTYPE(HRESULT, POINTER(CALLFRAME_MARSHALCONTEXT), MSHLFLAGS, PVOID, ULONG, POINTER(ULONG), POINTER(RPCOLEDATAREP), POINTER(ULONG))(18, "Marshal"),
        # Unmarshal -> pBuffer:PVOID, cbBuffer:ULONG, dataRep:RPCOLEDATAREP, pcontext:*CALLFRAME_MARSHALCONTEXT, pcbUnmarshalled:*ULONG
        "Unmarshal": ctypes.WINFUNCTYPE(HRESULT, PVOID, ULONG, RPCOLEDATAREP, POINTER(CALLFRAME_MARSHALCONTEXT), POINTER(ULONG))(19, "Unmarshal"),
        # ReleaseMarshalData -> pBuffer:PVOID, cbBuffer:ULONG, ibFirstRelease:ULONG, dataRep:RPCOLEDATAREP, pcontext:*CALLFRAME_MARSHALCONTEXT
        "ReleaseMarshalData": ctypes.WINFUNCTYPE(HRESULT, PVOID, ULONG, ULONG, RPCOLEDATAREP, POINTER(CALLFRAME_MARSHALCONTEXT))(20, "ReleaseMarshalData"),
        # Invoke -> pvReceiver:*void
        "Invoke": ctypes.CFUNCTYPE(HRESULT, PVOID)(21, "Invoke"),
    }

ICallFrameEvents._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # OnCall -> pFrame:*ICallFrame
        "OnCall": ctypes.WINFUNCTYPE(HRESULT, ICallFrame)(3, "OnCall"),
    }

ICallFrameWalker._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # OnWalkInterface -> iid:REFIID, ppvInterface:*PVOID, fIn:BOOL, fOut:BOOL
        "OnWalkInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID), BOOL, BOOL)(3, "OnWalkInterface"),
    }

ICallInterceptor._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # CallIndirect -> phrReturn:*HRESULT, iMethod:ULONG, pvArgs:*void, cbArgs:*ULONG
        "CallIndirect": ctypes.WINFUNCTYPE(HRESULT, POINTER(HRESULT), ULONG, PVOID, POINTER(ULONG))(3, "CallIndirect"),
        # GetMethodInfo -> iMethod:ULONG, pInfo:*CALLFRAMEINFO, pwszMethod:*LPWSTR
        "GetMethodInfo": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(CALLFRAMEINFO), POINTER(LPWSTR))(4, "GetMethodInfo"),
        # GetStackSize -> iMethod:ULONG, cbArgs:*ULONG
        "GetStackSize": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(ULONG))(5, "GetStackSize"),
        # GetIID -> piid:*IID, pfDerivesFromIDispatch:*BOOL, pcMethod:*ULONG, pwszInterface:*LPWSTR
        "GetIID": ctypes.WINFUNCTYPE(HRESULT, POINTER(IID), POINTER(BOOL), POINTER(ULONG), POINTER(LPWSTR))(6, "GetIID"),
        # RegisterSink -> psink:*ICallFrameEvents
        "RegisterSink": ctypes.WINFUNCTYPE(HRESULT, ICallFrameEvents)(7, "RegisterSink"),
        # GetRegisteredSink -> ppsink:**ICallFrameEvents
        "GetRegisteredSink": ctypes.WINFUNCTYPE(HRESULT, POINTER(ICallFrameEvents))(8, "GetRegisteredSink"),
    }

IDispatch._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetTypeInfoCount -> pctinfo:*UINT
        "GetTypeInfoCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(UINT))(3, "GetTypeInfoCount"),
        # GetTypeInfo -> iTInfo:UINT, lcid:LCID, ppTInfo:**ITypeInfo
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(PVOID))(4, "GetTypeInfo"),
        # GetIDsOfNames -> riid:REFIID, rgszNames:*LPOLESTR, cNames:UINT, lcid:LCID, rgDispId:*DISPID
        "GetIDsOfNames": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(LPOLESTR), UINT, LCID, POINTER(DISPID))(5, "GetIDsOfNames"),
        # Invoke -> dispIdMember:DISPID, riid:REFIID, lcid:LCID, wFlags:WORD, pDispParams:*DISPPARAMS, pVarResult:*VARIANT, pExcepInfo:*EXCEPINFO, puArgErr:*UINT
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, DISPID, REFIID, LCID, WORD, POINTER(DISPPARAMS), POINTER(VARIANT), POINTER(EXCEPINFO), POINTER(UINT))(6, "Invoke"),
    }

IEnumBackgroundCopyFiles._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Next -> celt:ULONG, rgelt:**IBackgroundCopyFile, pceltFetched:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(IBackgroundCopyFile), POINTER(ULONG))(3, "Next"),
        # Skip -> celt:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, ULONG)(4, "Skip"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(5, "Reset"),
        # Clone -> ppenum:**IEnumBackgroundCopyFiles
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumBackgroundCopyFiles))(6, "Clone"),
        # GetCount -> puCount:*ULONG
        "GetCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG))(7, "GetCount"),
    }

IEnumBackgroundCopyJobs._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Next -> celt:ULONG, rgelt:**IBackgroundCopyJob, pceltFetched:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(IBackgroundCopyJob), POINTER(ULONG))(3, "Next"),
        # Skip -> celt:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, ULONG)(4, "Skip"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(5, "Reset"),
        # Clone -> ppenum:**IEnumBackgroundCopyJobs
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumBackgroundCopyJobs))(6, "Clone"),
        # GetCount -> puCount:*ULONG
        "GetCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG))(7, "GetCount"),
    }

IEnumVARIANT._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Next -> celt:ULONG, rgVar:*VARIANT, pCeltFetched:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(VARIANT), POINTER(ULONG))(3, "Next"),
        # Skip -> celt:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, ULONG)(4, "Skip"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(5, "Reset"),
        # Clone -> ppEnum:**IEnumVARIANT
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumVARIANT))(6, "Clone"),
    }

IEnumWbemClassObject._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(3, "Reset"),
        # Next -> lTimeout:LONG, uCount:ULONG, apObjects:**IWbemClassObject, puReturned:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, LONG, ULONG, POINTER(IWbemClassObject), POINTER(ULONG))(4, "Next"),
        # NextAsync -> uCount:ULONG, pSink:*IWbemObjectSink
        "NextAsync": ctypes.WINFUNCTYPE(HRESULT, ULONG, IWbemObjectSink)(5, "NextAsync"),
        # Clone -> ppEnum:**IEnumWbemClassObject
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumWbemClassObject))(6, "Clone"),
        # Skip -> lTimeout:LONG, nCount:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, LONG, ULONG)(7, "Skip"),
    }

INetFwPolicy2._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetTypeInfoCount -> pctinfo:*UINT
        "GetTypeInfoCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(UINT))(3, "GetTypeInfoCount"),
        # GetTypeInfo -> iTInfo:UINT, lcid:LCID, ppTInfo:**ITypeInfo
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(PVOID))(4, "GetTypeInfo"),
        # GetIDsOfNames -> riid:REFIID, rgszNames:*LPOLESTR, cNames:UINT, lcid:LCID, rgDispId:*DISPID
        "GetIDsOfNames": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(LPOLESTR), UINT, LCID, POINTER(DISPID))(5, "GetIDsOfNames"),
        # Invoke -> dispIdMember:DISPID, riid:REFIID, lcid:LCID, wFlags:WORD, pDispParams:*DISPPARAMS, pVarResult:*VARIANT, pExcepInfo:*EXCEPINFO, puArgErr:*UINT
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, DISPID, REFIID, LCID, WORD, POINTER(DISPPARAMS), POINTER(VARIANT), POINTER(EXCEPINFO), POINTER(UINT))(6, "Invoke"),
        # get_CurrentProfileTypes -> profileTypesBitmask:*LONG
        "get_CurrentProfileTypes": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(7, "get_CurrentProfileTypes"),
        # get_FirewallEnabled -> profileType:NET_FW_PROFILE_TYPE2, enabled:*VARIANT_BOOL
        "get_FirewallEnabled": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, POINTER(VARIANT_BOOL))(8, "get_FirewallEnabled"),
        # put_FirewallEnabled -> profileType:NET_FW_PROFILE_TYPE2, enabled:VARIANT_BOOL
        "put_FirewallEnabled": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, VARIANT_BOOL)(9, "put_FirewallEnabled"),
        # get_ExcludedInterfaces -> profileType:NET_FW_PROFILE_TYPE2, interfaces:*VARIANT
        "get_ExcludedInterfaces": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, POINTER(VARIANT))(10, "get_ExcludedInterfaces"),
        # put_ExcludedInterfaces -> profileType:NET_FW_PROFILE_TYPE2, interfaces:VARIANT
        "put_ExcludedInterfaces": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, VARIANT)(11, "put_ExcludedInterfaces"),
        # get_BlockAllInboundTraffic -> profileType:NET_FW_PROFILE_TYPE2, Block:*VARIANT_BOOL
        "get_BlockAllInboundTraffic": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, POINTER(VARIANT_BOOL))(12, "get_BlockAllInboundTraffic"),
        # put_BlockAllInboundTraffic -> profileType:NET_FW_PROFILE_TYPE2, Block:VARIANT_BOOL
        "put_BlockAllInboundTraffic": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, VARIANT_BOOL)(13, "put_BlockAllInboundTraffic"),
        # get_NotificationsDisabled -> profileType:NET_FW_PROFILE_TYPE2, disabled:*VARIANT_BOOL
        "get_NotificationsDisabled": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, POINTER(VARIANT_BOOL))(14, "get_NotificationsDisabled"),
        # put_NotificationsDisabled -> profileType:NET_FW_PROFILE_TYPE2, disabled:VARIANT_BOOL
        "put_NotificationsDisabled": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, VARIANT_BOOL)(15, "put_NotificationsDisabled"),
        # get_UnicastResponsesToMulticastBroadcastDisabled -> profileType:NET_FW_PROFILE_TYPE2, disabled:*VARIANT_BOOL
        "get_UnicastResponsesToMulticastBroadcastDisabled": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, POINTER(VARIANT_BOOL))(16, "get_UnicastResponsesToMulticastBroadcastDisabled"),
        # put_UnicastResponsesToMulticastBroadcastDisabled -> profileType:NET_FW_PROFILE_TYPE2, disabled:VARIANT_BOOL
        "put_UnicastResponsesToMulticastBroadcastDisabled": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, VARIANT_BOOL)(17, "put_UnicastResponsesToMulticastBroadcastDisabled"),
        # get_Rules -> rules:**INetFwRules
        "get_Rules": ctypes.WINFUNCTYPE(HRESULT, POINTER(INetFwRules))(18, "get_Rules"),
        # get_ServiceRestriction -> ServiceRestriction:**INetFwServiceRestriction
        "get_ServiceRestriction": ctypes.WINFUNCTYPE(HRESULT, POINTER(INetFwServiceRestriction))(19, "get_ServiceRestriction"),
        # EnableRuleGroup -> profileTypesBitmask:LONG, group:BSTR, enable:VARIANT_BOOL
        "EnableRuleGroup": ctypes.WINFUNCTYPE(HRESULT, LONG, BSTR, VARIANT_BOOL)(20, "EnableRuleGroup"),
        # IsRuleGroupEnabled -> profileTypesBitmask:LONG, group:BSTR, enabled:*VARIANT_BOOL
        "IsRuleGroupEnabled": ctypes.WINFUNCTYPE(HRESULT, LONG, BSTR, POINTER(VARIANT_BOOL))(21, "IsRuleGroupEnabled"),
        # RestoreLocalFirewallDefaults -> 
        "RestoreLocalFirewallDefaults": ctypes.WINFUNCTYPE(HRESULT)(22, "RestoreLocalFirewallDefaults"),
        # get_DefaultInboundAction -> profileType:NET_FW_PROFILE_TYPE2, action:*NET_FW_ACTION
        "get_DefaultInboundAction": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, POINTER(NET_FW_ACTION))(23, "get_DefaultInboundAction"),
        # put_DefaultInboundAction -> profileType:NET_FW_PROFILE_TYPE2, action:NET_FW_ACTION
        "put_DefaultInboundAction": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, NET_FW_ACTION)(24, "put_DefaultInboundAction"),
        # get_DefaultOutboundAction -> profileType:NET_FW_PROFILE_TYPE2, action:*NET_FW_ACTION
        "get_DefaultOutboundAction": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, POINTER(NET_FW_ACTION))(25, "get_DefaultOutboundAction"),
        # put_DefaultOutboundAction -> profileType:NET_FW_PROFILE_TYPE2, action:NET_FW_ACTION
        "put_DefaultOutboundAction": ctypes.WINFUNCTYPE(HRESULT, NET_FW_PROFILE_TYPE2, NET_FW_ACTION)(26, "put_DefaultOutboundAction"),
        # get_IsRuleGroupCurrentlyEnabled -> group:BSTR, enabled:*VARIANT_BOOL
        "get_IsRuleGroupCurrentlyEnabled": ctypes.WINFUNCTYPE(HRESULT, BSTR, POINTER(VARIANT_BOOL))(27, "get_IsRuleGroupCurrentlyEnabled"),
        # get_LocalPolicyModifyState -> modifyState:*NET_FW_MODIFY_STATE
        "get_LocalPolicyModifyState": ctypes.WINFUNCTYPE(HRESULT, POINTER(NET_FW_MODIFY_STATE))(28, "get_LocalPolicyModifyState"),
    }

INetFwRules._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetTypeInfoCount -> pctinfo:*UINT
        "GetTypeInfoCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(UINT))(3, "GetTypeInfoCount"),
        # GetTypeInfo -> iTInfo:UINT, lcid:LCID, ppTInfo:**ITypeInfo
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(PVOID))(4, "GetTypeInfo"),
        # GetIDsOfNames -> riid:REFIID, rgszNames:*LPOLESTR, cNames:UINT, lcid:LCID, rgDispId:*DISPID
        "GetIDsOfNames": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(LPOLESTR), UINT, LCID, POINTER(DISPID))(5, "GetIDsOfNames"),
        # Invoke -> dispIdMember:DISPID, riid:REFIID, lcid:LCID, wFlags:WORD, pDispParams:*DISPPARAMS, pVarResult:*VARIANT, pExcepInfo:*EXCEPINFO, puArgErr:*UINT
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, DISPID, REFIID, LCID, WORD, POINTER(DISPPARAMS), POINTER(VARIANT), POINTER(EXCEPINFO), POINTER(UINT))(6, "Invoke"),
        # get_Count -> count:*LONG
        "get_Count": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(7, "get_Count"),
        # Add -> rule:*INetFwRule
        "Add": ctypes.WINFUNCTYPE(HRESULT, INetFwRule)(8, "Add"),
        # Remove -> name:BSTR
        "Remove": ctypes.WINFUNCTYPE(HRESULT, BSTR)(9, "Remove"),
        # Item -> name:BSTR, rule:**INetFwRule
        "Item": ctypes.WINFUNCTYPE(HRESULT, BSTR, POINTER(INetFwRule))(10, "Item"),
        # get__NewEnum -> newEnum:**IUnknown
        "get__NewEnum": ctypes.WINFUNCTYPE(HRESULT, POINTER(IUnknown))(11, "get__NewEnum"),
    }

INetFwRule._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetTypeInfoCount -> pctinfo:*UINT
        "GetTypeInfoCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(UINT))(3, "GetTypeInfoCount"),
        # GetTypeInfo -> iTInfo:UINT, lcid:LCID, ppTInfo:**ITypeInfo
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(PVOID))(4, "GetTypeInfo"),
        # GetIDsOfNames -> riid:REFIID, rgszNames:*LPOLESTR, cNames:UINT, lcid:LCID, rgDispId:*DISPID
        "GetIDsOfNames": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(LPOLESTR), UINT, LCID, POINTER(DISPID))(5, "GetIDsOfNames"),
        # Invoke -> dispIdMember:DISPID, riid:REFIID, lcid:LCID, wFlags:WORD, pDispParams:*DISPPARAMS, pVarResult:*VARIANT, pExcepInfo:*EXCEPINFO, puArgErr:*UINT
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, DISPID, REFIID, LCID, WORD, POINTER(DISPPARAMS), POINTER(VARIANT), POINTER(EXCEPINFO), POINTER(UINT))(6, "Invoke"),
        # get_Name -> name:*BSTR
        "get_Name": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Name"),
        # put_Name -> name:BSTR
        "put_Name": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Name"),
        # get_Description -> desc:*BSTR
        "get_Description": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(9, "get_Description"),
        # put_Description -> desc:BSTR
        "put_Description": ctypes.WINFUNCTYPE(HRESULT, BSTR)(10, "put_Description"),
        # get_ApplicationName -> imageFileName:*BSTR
        "get_ApplicationName": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(11, "get_ApplicationName"),
        # put_ApplicationName -> imageFileName:BSTR
        "put_ApplicationName": ctypes.WINFUNCTYPE(HRESULT, BSTR)(12, "put_ApplicationName"),
        # get_ServiceName -> serviceName:*BSTR
        "get_ServiceName": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(13, "get_ServiceName"),
        # put_ServiceName -> serviceName:BSTR
        "put_ServiceName": ctypes.WINFUNCTYPE(HRESULT, BSTR)(14, "put_ServiceName"),
        # get_Protocol -> protocol:*LONG
        "get_Protocol": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(15, "get_Protocol"),
        # put_Protocol -> protocol:LONG
        "put_Protocol": ctypes.WINFUNCTYPE(HRESULT, LONG)(16, "put_Protocol"),
        # get_LocalPorts -> portNumbers:*BSTR
        "get_LocalPorts": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(17, "get_LocalPorts"),
        # put_LocalPorts -> portNumbers:BSTR
        "put_LocalPorts": ctypes.WINFUNCTYPE(HRESULT, BSTR)(18, "put_LocalPorts"),
        # get_RemotePorts -> portNumbers:*BSTR
        "get_RemotePorts": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(19, "get_RemotePorts"),
        # put_RemotePorts -> portNumbers:BSTR
        "put_RemotePorts": ctypes.WINFUNCTYPE(HRESULT, BSTR)(20, "put_RemotePorts"),
        # get_LocalAddresses -> localAddrs:*BSTR
        "get_LocalAddresses": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(21, "get_LocalAddresses"),
        # put_LocalAddresses -> localAddrs:BSTR
        "put_LocalAddresses": ctypes.WINFUNCTYPE(HRESULT, BSTR)(22, "put_LocalAddresses"),
        # get_RemoteAddresses -> remoteAddrs:*BSTR
        "get_RemoteAddresses": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(23, "get_RemoteAddresses"),
        # put_RemoteAddresses -> remoteAddrs:BSTR
        "put_RemoteAddresses": ctypes.WINFUNCTYPE(HRESULT, BSTR)(24, "put_RemoteAddresses"),
        # get_IcmpTypesAndCodes -> icmpTypesAndCodes:*BSTR
        "get_IcmpTypesAndCodes": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(25, "get_IcmpTypesAndCodes"),
        # put_IcmpTypesAndCodes -> icmpTypesAndCodes:BSTR
        "put_IcmpTypesAndCodes": ctypes.WINFUNCTYPE(HRESULT, BSTR)(26, "put_IcmpTypesAndCodes"),
        # get_Direction -> dir:*NET_FW_RULE_DIRECTION
        "get_Direction": ctypes.WINFUNCTYPE(HRESULT, POINTER(NET_FW_RULE_DIRECTION))(27, "get_Direction"),
        # put_Direction -> dir:NET_FW_RULE_DIRECTION
        "put_Direction": ctypes.WINFUNCTYPE(HRESULT, NET_FW_RULE_DIRECTION)(28, "put_Direction"),
        # get_Interfaces -> interfaces:*VARIANT
        "get_Interfaces": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT))(29, "get_Interfaces"),
        # put_Interfaces -> interfaces:VARIANT
        "put_Interfaces": ctypes.WINFUNCTYPE(HRESULT, VARIANT)(30, "put_Interfaces"),
        # get_InterfaceTypes -> interfaceTypes:*BSTR
        "get_InterfaceTypes": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(31, "get_InterfaceTypes"),
        # put_InterfaceTypes -> interfaceTypes:BSTR
        "put_InterfaceTypes": ctypes.WINFUNCTYPE(HRESULT, BSTR)(32, "put_InterfaceTypes"),
        # get_Enabled -> enabled:*VARIANT_BOOL
        "get_Enabled": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(33, "get_Enabled"),
        # put_Enabled -> enabled:VARIANT_BOOL
        "put_Enabled": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(34, "put_Enabled"),
        # get_Grouping -> context:*BSTR
        "get_Grouping": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(35, "get_Grouping"),
        # put_Grouping -> context:BSTR
        "put_Grouping": ctypes.WINFUNCTYPE(HRESULT, BSTR)(36, "put_Grouping"),
        # get_Profiles -> profileTypesBitmask:*LONG
        "get_Profiles": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(37, "get_Profiles"),
        # put_Profiles -> profileTypesBitmask:LONG
        "put_Profiles": ctypes.WINFUNCTYPE(HRESULT, LONG)(38, "put_Profiles"),
        # get_EdgeTraversal -> enabled:*VARIANT_BOOL
        "get_EdgeTraversal": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(39, "get_EdgeTraversal"),
        # put_EdgeTraversal -> enabled:VARIANT_BOOL
        "put_EdgeTraversal": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(40, "put_EdgeTraversal"),
        # get_Action -> action:*NET_FW_ACTION
        "get_Action": ctypes.WINFUNCTYPE(HRESULT, POINTER(NET_FW_ACTION))(41, "get_Action"),
        # put_Action -> action:NET_FW_ACTION
        "put_Action": ctypes.WINFUNCTYPE(HRESULT, NET_FW_ACTION)(42, "put_Action"),
    }

INetFwServiceRestriction._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetTypeInfoCount -> pctinfo:*UINT
        "GetTypeInfoCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(UINT))(3, "GetTypeInfoCount"),
        # GetTypeInfo -> iTInfo:UINT, lcid:LCID, ppTInfo:**ITypeInfo
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(PVOID))(4, "GetTypeInfo"),
        # GetIDsOfNames -> riid:REFIID, rgszNames:*LPOLESTR, cNames:UINT, lcid:LCID, rgDispId:*DISPID
        "GetIDsOfNames": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(LPOLESTR), UINT, LCID, POINTER(DISPID))(5, "GetIDsOfNames"),
        # Invoke -> dispIdMember:DISPID, riid:REFIID, lcid:LCID, wFlags:WORD, pDispParams:*DISPPARAMS, pVarResult:*VARIANT, pExcepInfo:*EXCEPINFO, puArgErr:*UINT
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, DISPID, REFIID, LCID, WORD, POINTER(DISPPARAMS), POINTER(VARIANT), POINTER(EXCEPINFO), POINTER(UINT))(6, "Invoke"),
        # RestrictService -> serviceName:BSTR, appName:BSTR, restrictService:VARIANT_BOOL, serviceSidRestricted:VARIANT_BOOL
        "RestrictService": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, VARIANT_BOOL, VARIANT_BOOL)(7, "RestrictService"),
        # ServiceRestricted -> serviceName:BSTR, appName:BSTR, serviceRestricted:*VARIANT_BOOL
        "ServiceRestricted": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, POINTER(VARIANT_BOOL))(8, "ServiceRestricted"),
        # get_Rules -> rules:**INetFwRules
        "get_Rules": ctypes.WINFUNCTYPE(HRESULT, POINTER(INetFwRules))(9, "get_Rules"),
    }

IPersistFile._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetClassID -> pClassID:*CLSID
        "GetClassID": ctypes.WINFUNCTYPE(HRESULT, POINTER(CLSID))(3, "GetClassID"),
        # IsDirty -> 
        "IsDirty": ctypes.WINFUNCTYPE(HRESULT)(4, "IsDirty"),
        # Load -> pszFileName:LPCOLESTR, dwMode:DWORD
        "Load": ctypes.WINFUNCTYPE(HRESULT, LPCOLESTR, DWORD)(5, "Load"),
        # Save -> pszFileName:LPCOLESTR, fRemember:BOOL
        "Save": ctypes.WINFUNCTYPE(HRESULT, LPCOLESTR, BOOL)(6, "Save"),
        # SaveCompleted -> pszFileName:LPCOLESTR
        "SaveCompleted": ctypes.WINFUNCTYPE(HRESULT, LPCOLESTR)(7, "SaveCompleted"),
        # GetCurFile -> ppszFileName:*LPOLESTR
        "GetCurFile": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPOLESTR))(8, "GetCurFile"),
    }

IShellLinkA._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetPath -> pszFile:LPSTR, cch:INT, pfd:*WIN32_FIND_DATAA, fFlags:DWORD
        "GetPath": ctypes.WINFUNCTYPE(HRESULT, LPSTR, INT, POINTER(WIN32_FIND_DATAA), DWORD)(3, "GetPath"),
        # GetIDList -> ppidl:*PIDLIST_ABSOLUTE
        "GetIDList": ctypes.WINFUNCTYPE(HRESULT, POINTER(PIDLIST_ABSOLUTE))(4, "GetIDList"),
        # SetIDList -> pidl:PCIDLIST_ABSOLUTE
        "SetIDList": ctypes.WINFUNCTYPE(HRESULT, PCIDLIST_ABSOLUTE)(5, "SetIDList"),
        # GetDescription -> pszName:LPSTR, cch:INT
        "GetDescription": ctypes.WINFUNCTYPE(HRESULT, LPSTR, INT)(6, "GetDescription"),
        # SetDescription -> pszName:LPCSTR
        "SetDescription": ctypes.WINFUNCTYPE(HRESULT, LPCSTR)(7, "SetDescription"),
        # GetWorkingDirectory -> pszDir:LPSTR, cch:INT
        "GetWorkingDirectory": ctypes.WINFUNCTYPE(HRESULT, LPSTR, INT)(8, "GetWorkingDirectory"),
        # SetWorkingDirectory -> pszDir:LPCSTR
        "SetWorkingDirectory": ctypes.WINFUNCTYPE(HRESULT, LPCSTR)(9, "SetWorkingDirectory"),
        # GetArguments -> pszArgs:LPSTR, cch:INT
        "GetArguments": ctypes.WINFUNCTYPE(HRESULT, LPSTR, INT)(10, "GetArguments"),
        # SetArguments -> pszArgs:LPCSTR
        "SetArguments": ctypes.WINFUNCTYPE(HRESULT, LPCSTR)(11, "SetArguments"),
        # GetHotkey -> pwHotkey:*WORD
        "GetHotkey": ctypes.WINFUNCTYPE(HRESULT, POINTER(WORD))(12, "GetHotkey"),
        # SetHotkey -> wHotkey:WORD
        "SetHotkey": ctypes.WINFUNCTYPE(HRESULT, WORD)(13, "SetHotkey"),
        # GetShowCmd -> piShowCmd:*INT
        "GetShowCmd": ctypes.WINFUNCTYPE(HRESULT, POINTER(INT))(14, "GetShowCmd"),
        # SetShowCmd -> iShowCmd:INT
        "SetShowCmd": ctypes.WINFUNCTYPE(HRESULT, INT)(15, "SetShowCmd"),
        # GetIconLocation -> pszIconPath:LPSTR, cch:INT, piIcon:*INT
        "GetIconLocation": ctypes.WINFUNCTYPE(HRESULT, LPSTR, INT, POINTER(INT))(16, "GetIconLocation"),
        # SetIconLocation -> pszIconPath:LPCSTR, iIcon:INT
        "SetIconLocation": ctypes.WINFUNCTYPE(HRESULT, LPCSTR, INT)(17, "SetIconLocation"),
        # SetRelativePath -> pszPathRel:LPCSTR, dwReserved:DWORD
        "SetRelativePath": ctypes.WINFUNCTYPE(HRESULT, LPCSTR, DWORD)(18, "SetRelativePath"),
        # Resolve -> hwnd:HWND, fFlags:DWORD
        "Resolve": ctypes.WINFUNCTYPE(HRESULT, HWND, DWORD)(19, "Resolve"),
        # SetPath -> pszFile:LPCSTR
        "SetPath": ctypes.WINFUNCTYPE(HRESULT, LPCSTR)(20, "SetPath"),
    }

IShellLinkW._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetPath -> pszFile:LPWSTR, cch:INT, pfd:*WIN32_FIND_DATAW, fFlags:DWORD
        "GetPath": ctypes.WINFUNCTYPE(HRESULT, LPWSTR, INT, POINTER(WIN32_FIND_DATAW), DWORD)(3, "GetPath"),
        # GetIDList -> ppidl:*PIDLIST_ABSOLUTE
        "GetIDList": ctypes.WINFUNCTYPE(HRESULT, POINTER(PIDLIST_ABSOLUTE))(4, "GetIDList"),
        # SetIDList -> pidl:PCIDLIST_ABSOLUTE
        "SetIDList": ctypes.WINFUNCTYPE(HRESULT, PCIDLIST_ABSOLUTE)(5, "SetIDList"),
        # GetDescription -> pszName:LPWSTR, cch:INT
        "GetDescription": ctypes.WINFUNCTYPE(HRESULT, LPWSTR, INT)(6, "GetDescription"),
        # SetDescription -> pszName:LPCWSTR
        "SetDescription": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(7, "SetDescription"),
        # GetWorkingDirectory -> pszDir:LPWSTR, cch:INT
        "GetWorkingDirectory": ctypes.WINFUNCTYPE(HRESULT, LPWSTR, INT)(8, "GetWorkingDirectory"),
        # SetWorkingDirectory -> pszDir:LPCWSTR
        "SetWorkingDirectory": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(9, "SetWorkingDirectory"),
        # GetArguments -> pszArgs:LPWSTR, cch:INT
        "GetArguments": ctypes.WINFUNCTYPE(HRESULT, LPWSTR, INT)(10, "GetArguments"),
        # SetArguments -> pszArgs:LPCWSTR
        "SetArguments": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(11, "SetArguments"),
        # GetHotkey -> pwHotkey:*WORD
        "GetHotkey": ctypes.WINFUNCTYPE(HRESULT, POINTER(WORD))(12, "GetHotkey"),
        # SetHotkey -> wHotkey:WORD
        "SetHotkey": ctypes.WINFUNCTYPE(HRESULT, WORD)(13, "SetHotkey"),
        # GetShowCmd -> piShowCmd:*INT
        "GetShowCmd": ctypes.WINFUNCTYPE(HRESULT, POINTER(INT))(14, "GetShowCmd"),
        # SetShowCmd -> iShowCmd:INT
        "SetShowCmd": ctypes.WINFUNCTYPE(HRESULT, INT)(15, "SetShowCmd"),
        # GetIconLocation -> pszIconPath:LPWSTR, cch:INT, piIcon:*INT
        "GetIconLocation": ctypes.WINFUNCTYPE(HRESULT, LPWSTR, INT, POINTER(INT))(16, "GetIconLocation"),
        # SetIconLocation -> pszIconPath:LPCWSTR, iIcon:INT
        "SetIconLocation": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, INT)(17, "SetIconLocation"),
        # SetRelativePath -> pszPathRel:LPCWSTR, dwReserved:DWORD
        "SetRelativePath": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, DWORD)(18, "SetRelativePath"),
        # Resolve -> hwnd:HWND, fFlags:DWORD
        "Resolve": ctypes.WINFUNCTYPE(HRESULT, HWND, DWORD)(19, "Resolve"),
        # SetPath -> pszFile:LPCWSTR
        "SetPath": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(20, "SetPath"),
    }

IUnknown._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
    }

IWbemCallResult._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetResultObject -> lTimeout:LONG, ppResultObject:**IWbemClassObject
        "GetResultObject": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IWbemClassObject))(3, "GetResultObject"),
        # GetResultString -> lTimeout:LONG, pstrResultString:*BSTR
        "GetResultString": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(BSTR))(4, "GetResultString"),
        # GetResultServices -> lTimeout:LONG, ppServices:**IWbemServices
        "GetResultServices": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IWbemServices))(5, "GetResultServices"),
        # GetCallStatus -> lTimeout:LONG, plStatus:*LONG
        "GetCallStatus": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(LONG))(6, "GetCallStatus"),
    }

IWbemClassObject._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetQualifierSet -> ppQualSet:**IWbemQualifierSet
        "GetQualifierSet": ctypes.WINFUNCTYPE(HRESULT, POINTER(IWbemQualifierSet))(3, "GetQualifierSet"),
        # Get -> wszName:LPCWSTR, lFlags:LONG, pVal:*VARIANT, pType:*CIMTYPE, plFlavor:*LONG
        "Get": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LONG, POINTER(VARIANT), POINTER(CIMTYPE), POINTER(LONG))(4, "Get"),
        # Put -> wszName:LPCWSTR, lFlags:LONG, pVal:*VARIANT, Type:CIMTYPE
        "Put": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LONG, POINTER(VARIANT), CIMTYPE)(5, "Put"),
        # Delete -> wszName:LPCWSTR
        "Delete": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(6, "Delete"),
        # GetNames -> wszQualifierName:LPCWSTR, lFlags:LONG, pQualifierVal:*VARIANT, pNames:**SAFEARRAY
        "GetNames": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LONG, POINTER(VARIANT), POINTER(POINTER(SAFEARRAY)))(7, "GetNames"),
        # BeginEnumeration -> lEnumFlags:LONG
        "BeginEnumeration": ctypes.WINFUNCTYPE(HRESULT, LONG)(8, "BeginEnumeration"),
        # Next -> lFlags:LONG, strName:*BSTR, pVal:*VARIANT, pType:*CIMTYPE, plFlavor:*LONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(BSTR), POINTER(VARIANT), POINTER(CIMTYPE), POINTER(LONG))(9, "Next"),
        # EndEnumeration -> 
        "EndEnumeration": ctypes.WINFUNCTYPE(HRESULT)(10, "EndEnumeration"),
        # GetPropertyQualifierSet -> wszProperty:LPCWSTR, ppQualSet:**IWbemQualifierSet
        "GetPropertyQualifierSet": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, POINTER(IWbemQualifierSet))(11, "GetPropertyQualifierSet"),
        # Clone -> ppCopy:**IWbemClassObject
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IWbemClassObject))(12, "Clone"),
        # GetObjectText -> lFlags:LONG, pstrObjectText:*BSTR
        "GetObjectText": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(BSTR))(13, "GetObjectText"),
        # SpawnDerivedClass -> lFlags:LONG, ppNewClass:**IWbemClassObject
        "SpawnDerivedClass": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IWbemClassObject))(14, "SpawnDerivedClass"),
        # SpawnInstance -> lFlags:LONG, ppNewInstance:**IWbemClassObject
        "SpawnInstance": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IWbemClassObject))(15, "SpawnInstance"),
        # CompareTo -> lFlags:LONG, pCompareTo:*IWbemClassObject
        "CompareTo": ctypes.WINFUNCTYPE(HRESULT, LONG, IWbemClassObject)(16, "CompareTo"),
        # GetPropertyOrigin -> wszName:LPCWSTR, pstrClassName:*BSTR
        "GetPropertyOrigin": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, POINTER(BSTR))(17, "GetPropertyOrigin"),
        # InheritsFrom -> strAncestor:LPCWSTR
        "InheritsFrom": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(18, "InheritsFrom"),
        # GetMethod -> wszName:LPCWSTR, lFlags:LONG, ppInSignature:**IWbemClassObject, ppOutSignature:**IWbemClassObject
        "GetMethod": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LONG, POINTER(IWbemClassObject), POINTER(IWbemClassObject))(19, "GetMethod"),
        # PutMethod -> wszName:LPCWSTR, lFlags:LONG, pInSignature:*IWbemClassObject, pOutSignature:*IWbemClassObject
        "PutMethod": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LONG, IWbemClassObject, IWbemClassObject)(20, "PutMethod"),
        # DeleteMethod -> wszName:LPCWSTR
        "DeleteMethod": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(21, "DeleteMethod"),
        # BeginMethodEnumeration -> lEnumFlags:LONG
        "BeginMethodEnumeration": ctypes.WINFUNCTYPE(HRESULT, LONG)(22, "BeginMethodEnumeration"),
        # NextMethod -> lFlags:LONG, pstrName:*BSTR, ppInSignature:**IWbemClassObject, ppOutSignature:**IWbemClassObject
        "NextMethod": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(BSTR), POINTER(IWbemClassObject), POINTER(IWbemClassObject))(23, "NextMethod"),
        # EndMethodEnumeration -> 
        "EndMethodEnumeration": ctypes.WINFUNCTYPE(HRESULT)(24, "EndMethodEnumeration"),
        # GetMethodQualifierSet -> wszMethod:LPCWSTR, ppQualSet:**IWbemQualifierSet
        "GetMethodQualifierSet": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, POINTER(IWbemQualifierSet))(25, "GetMethodQualifierSet"),
        # GetMethodOrigin -> wszMethodName:LPCWSTR, pstrClassName:*BSTR
        "GetMethodOrigin": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, POINTER(BSTR))(26, "GetMethodOrigin"),
    }

IWbemContext._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Clone -> ppNewCopy:**IWbemContext
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IWbemContext))(3, "Clone"),
        # GetNames -> lFlags:LONG, pNames:**SAFEARRAY
        "GetNames": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(POINTER(SAFEARRAY)))(4, "GetNames"),
        # BeginEnumeration -> lFlags:LONG
        "BeginEnumeration": ctypes.WINFUNCTYPE(HRESULT, LONG)(5, "BeginEnumeration"),
        # Next -> lFlags:LONG, pstrName:*BSTR, pValue:*VARIANT
        "Next": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(BSTR), POINTER(VARIANT))(6, "Next"),
        # EndEnumeration -> 
        "EndEnumeration": ctypes.WINFUNCTYPE(HRESULT)(7, "EndEnumeration"),
        # SetValue -> wszName:LPCWSTR, lFlags:LONG, pValue:*VARIANT
        "SetValue": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LONG, POINTER(VARIANT))(8, "SetValue"),
        # GetValue -> wszName:LPCWSTR, lFlags:LONG, pValue:*VARIANT
        "GetValue": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LONG, POINTER(VARIANT))(9, "GetValue"),
        # DeleteValue -> wszName:LPCWSTR, lFlags:LONG
        "DeleteValue": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LONG)(10, "DeleteValue"),
        # DeleteAll -> 
        "DeleteAll": ctypes.WINFUNCTYPE(HRESULT)(11, "DeleteAll"),
    }

IWbemLocator._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # ConnectServer -> strNetworkResource:BSTR, strUser:BSTR, strPassword:BSTR, strLocale:BSTR, lSecurityFlags:LONG, strAuthority:BSTR, pCtx:*IWbemContext, ppNamespace:**IWbemServices
        "ConnectServer": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, BSTR, BSTR, LONG, BSTR, IWbemContext, POINTER(IWbemServices))(3, "ConnectServer"),
    }

IWbemObjectSink._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Indicate -> lObjectCount:LONG, apObjArray:**IWbemClassObject
        "Indicate": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IWbemClassObject))(3, "Indicate"),
        # SetStatus -> lFlags:LONG, hResult:HRESULT, strParam:BSTR, pObjParam:*IWbemClassObject
        "SetStatus": ctypes.WINFUNCTYPE(HRESULT, LONG, HRESULT, BSTR, IWbemClassObject)(4, "SetStatus"),
    }

IWbemQualifierSet._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Get -> wszName:LPCWSTR, lFlags:LONG, pVal:*VARIANT, plFlavor:*LONG
        "Get": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LONG, POINTER(VARIANT), POINTER(LONG))(3, "Get"),
        # Put -> wszName:LPCWSTR, pVal:*VARIANT, lFlavor:LONG
        "Put": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, POINTER(VARIANT), LONG)(4, "Put"),
        # Delete -> wszName:LPCWSTR
        "Delete": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(5, "Delete"),
        # GetNames -> lFlags:LONG, pNames:**SAFEARRAY
        "GetNames": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(POINTER(SAFEARRAY)))(6, "GetNames"),
        # BeginEnumeration -> lFlags:LONG
        "BeginEnumeration": ctypes.WINFUNCTYPE(HRESULT, LONG)(7, "BeginEnumeration"),
        # Next -> lFlags:LONG, pstrName:*BSTR, pVal:*VARIANT, plFlavor:*LONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(BSTR), POINTER(VARIANT), POINTER(LONG))(8, "Next"),
        # EndEnumeration -> 
        "EndEnumeration": ctypes.WINFUNCTYPE(HRESULT)(9, "EndEnumeration"),
    }

IWbemServices._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # OpenNamespace -> strNamespace:BSTR, lFlags:LONG, pCtx:*IWbemContext, ppWorkingNamespace:**IWbemServices, ppResult:**IWbemCallResult
        "OpenNamespace": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, POINTER(IWbemServices), POINTER(IWbemCallResult))(3, "OpenNamespace"),
        # CancelAsyncCall -> pSink:*IWbemObjectSink
        "CancelAsyncCall": ctypes.WINFUNCTYPE(HRESULT, IWbemObjectSink)(4, "CancelAsyncCall"),
        # QueryObjectSink -> lFlags:LONG, ppResponseHandler:**IWbemObjectSink
        "QueryObjectSink": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IWbemObjectSink))(5, "QueryObjectSink"),
        # GetObject -> strObjectPath:BSTR, lFlags:LONG, pCtx:*IWbemContext, ppObject:**IWbemClassObject, ppCallResult:**IWbemCallResult
        "GetObject": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, POINTER(IWbemClassObject), POINTER(IWbemCallResult))(6, "GetObject"),
        # GetObjectAsync -> strObjectPath:BSTR, lFlags:LONG, pCtx:*IWbemContext, pResponseHandler:*IWbemObjectSink
        "GetObjectAsync": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, IWbemObjectSink)(7, "GetObjectAsync"),
        # PutClass -> pObject:*IWbemClassObject, lFlags:LONG, pCtx:*IWbemContext, ppCallResult:**IWbemCallResult
        "PutClass": ctypes.WINFUNCTYPE(HRESULT, IWbemClassObject, LONG, IWbemContext, POINTER(IWbemCallResult))(8, "PutClass"),
        # PutClassAsync -> pObject:*IWbemClassObject, lFlags:LONG, pCtx:*IWbemContext, pResponseHandler:*IWbemObjectSink
        "PutClassAsync": ctypes.WINFUNCTYPE(HRESULT, IWbemClassObject, LONG, IWbemContext, IWbemObjectSink)(9, "PutClassAsync"),
        # DeleteClass -> strClass:BSTR, lFlags:LONG, pCtx:*IWbemContext, ppCallResult:**IWbemCallResult
        "DeleteClass": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, POINTER(IWbemCallResult))(10, "DeleteClass"),
        # DeleteClassAsync -> strClass:BSTR, lFlags:LONG, pCtx:*IWbemContext, pResponseHandler:*IWbemObjectSink
        "DeleteClassAsync": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, IWbemObjectSink)(11, "DeleteClassAsync"),
        # CreateClassEnum -> strSuperclass:BSTR, lFlags:LONG, pCtx:*IWbemContext, ppEnum:**IEnumWbemClassObject
        "CreateClassEnum": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, POINTER(IEnumWbemClassObject))(12, "CreateClassEnum"),
        # CreateClassEnumAsync -> strSuperclass:BSTR, lFlags:LONG, pCtx:*IWbemContext, pResponseHandler:*IWbemObjectSink
        "CreateClassEnumAsync": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, IWbemObjectSink)(13, "CreateClassEnumAsync"),
        # PutInstance -> pInst:*IWbemClassObject, lFlags:LONG, pCtx:*IWbemContext, ppCallResult:**IWbemCallResult
        "PutInstance": ctypes.WINFUNCTYPE(HRESULT, IWbemClassObject, LONG, IWbemContext, POINTER(IWbemCallResult))(14, "PutInstance"),
        # PutInstanceAsync -> pInst:*IWbemClassObject, lFlags:LONG, pCtx:*IWbemContext, pResponseHandler:*IWbemObjectSink
        "PutInstanceAsync": ctypes.WINFUNCTYPE(HRESULT, IWbemClassObject, LONG, IWbemContext, IWbemObjectSink)(15, "PutInstanceAsync"),
        # DeleteInstance -> strObjectPath:BSTR, lFlags:LONG, pCtx:*IWbemContext, ppCallResult:**IWbemCallResult
        "DeleteInstance": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, POINTER(IWbemCallResult))(16, "DeleteInstance"),
        # DeleteInstanceAsync -> strObjectPath:BSTR, lFlags:LONG, pCtx:*IWbemContext, pResponseHandler:*IWbemObjectSink
        "DeleteInstanceAsync": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, IWbemObjectSink)(17, "DeleteInstanceAsync"),
        # CreateInstanceEnum -> strFilter:BSTR, lFlags:LONG, pCtx:*IWbemContext, ppEnum:**IEnumWbemClassObject
        "CreateInstanceEnum": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, POINTER(IEnumWbemClassObject))(18, "CreateInstanceEnum"),
        # CreateInstanceEnumAsync -> strFilter:BSTR, lFlags:LONG, pCtx:*IWbemContext, pResponseHandler:*IWbemObjectSink
        "CreateInstanceEnumAsync": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG, IWbemContext, IWbemObjectSink)(19, "CreateInstanceEnumAsync"),
        # ExecQuery -> strQueryLanguage:BSTR, strQuery:BSTR, lFlags:LONG, pCtx:*IWbemContext, ppEnum:**IEnumWbemClassObject
        "ExecQuery": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, LONG, IWbemContext, POINTER(IEnumWbemClassObject))(20, "ExecQuery"),
        # ExecQueryAsync -> strQueryLanguage:BSTR, strQuery:BSTR, lFlags:LONG, pCtx:*IWbemContext, pResponseHandler:*IWbemObjectSink
        "ExecQueryAsync": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, LONG, IWbemContext, IWbemObjectSink)(21, "ExecQueryAsync"),
        # ExecNotificationQuery -> strQueryLanguage:BSTR, strQuery:BSTR, lFlags:LONG, pCtx:*IWbemContext, ppEnum:**IEnumWbemClassObject
        "ExecNotificationQuery": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, LONG, IWbemContext, POINTER(IEnumWbemClassObject))(22, "ExecNotificationQuery"),
        # ExecNotificationQueryAsync -> strQueryLanguage:BSTR, strQuery:BSTR, lFlags:LONG, pCtx:*IWbemContext, pResponseHandler:*IWbemObjectSink
        "ExecNotificationQueryAsync": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, LONG, IWbemContext, IWbemObjectSink)(23, "ExecNotificationQueryAsync"),
        # ExecMethod -> strObjectPath:BSTR, strMethodName:BSTR, lFlags:LONG, pCtx:*IWbemContext, pInParams:*IWbemClassObject, ppOutParams:**IWbemClassObject, ppCallResult:**IWbemCallResult
        "ExecMethod": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, LONG, IWbemContext, IWbemClassObject, POINTER(IWbemClassObject), POINTER(IWbemCallResult))(24, "ExecMethod"),
        # ExecMethodAsync -> strObjectPath:BSTR, strMethodName:BSTR, lFlags:LONG, pCtx:*IWbemContext, pInParams:*IWbemClassObject, pResponseHandler:*IWbemObjectSink
        "ExecMethodAsync": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, LONG, IWbemContext, IWbemClassObject, IWbemObjectSink)(25, "ExecMethodAsync"),
    }

