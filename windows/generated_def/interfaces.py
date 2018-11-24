from winstructs import *
import functools
import ctypes


generate_IID = IID.from_raw


class COMHRESULT(HRESULT):
    _type_ = HRESULT._type_
    def _check_retval_(self):
        # We CAN NOT try to adapt the self.value and transform it with flags
        # here, we need to do it with the errcheck
        # So we have the peer-interface callback system on errcheck :)
        return self.value # The value will be send to errcheck :)

class COMInterface(ctypes.c_void_p):
    _functions_ = {
    }

    # So COMInterface completely bypass the HRESULT
    # return value check on restype by setting the restype to COMHRESULT
    # But we add the 'errcheck' callbakc capacity for all COMInterface and subclasses
    # So the default implem of the callbakc must have the same behavior as
    # standard HRESULT restype.
    # This is why default errcheck callback call ctypes._check_HRESULT
    def _default_errcheck(self, result, func, args):
        ctypes._check_HRESULT(result)
        return args

    def __getattr__(self, name):
        if name in self._functions_:
            winfunc = self._functions_[name]
            # Hacking the HRESULT _check_retval_ and
            # letting COMInterface.errcheck do the work of validating / raising
            winfunc.restype = COMHRESULT
            effective_errcheck = getattr(self, "errcheck", self._default_errcheck)
            winfunc.errcheck = effective_errcheck
            return functools.partial(winfunc, self)
        return super(COMInterface, self).__getattribute__(name)

    def __repr__(self):
        description = "<NULL>" if not self.value else ""
        return "<{0}{1} at {2:#x}>".format(type(self).__name__, description, id(self))

    # Simplified API for QueryInterface for interface embeding there IID
    def query(self, interfacetype):
        interface = interfacetype()
        self.QueryInterface(interface.IID, interface)
        return interface









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

class IAction(COMInterface):
    IID = generate_IID(0xBAE54997, 0x48B1, 0x4CBE, 0x99, 0x65, 0xD6, 0xBE, 0x26, 0x3E, 0xBE, 0xA4, name="IAction", strid="BAE54997-48B1-4CBE-9965-D6BE263EBEA4")

class IActionCollection(COMInterface):
    IID = generate_IID(0x02820E19, 0x7B98, 0x4ED2, 0xB2, 0xE8, 0xFD, 0xCC, 0xCE, 0xFF, 0x61, 0x9B, name="IActionCollection", strid="02820E19-7B98-4ED2-B2E8-FDCCCEFF619B")

class IComHandlerAction(COMInterface):
    IID = generate_IID(0x6D2FD252, 0x75C5, 0x4F66, 0x90, 0xBA, 0x2A, 0x7D, 0x8C, 0xC3, 0x03, 0x9F, name="IComHandlerAction", strid="6D2FD252-75C5-4F66-90BA-2A7D8CC3039F")

class IEmailAction(COMInterface):
    IID = generate_IID(0x10F62C64, 0x7E16, 0x4314, 0xA0, 0xC2, 0x0C, 0x36, 0x83, 0xF9, 0x9D, 0x40, name="IEmailAction", strid="10F62C64-7E16-4314-A0C2-0C3683F99D40")

class IExecAction(COMInterface):
    IID = generate_IID(0x4C3D624D, 0xFD6B, 0x49A3, 0xB9, 0xB7, 0x09, 0xCB, 0x3C, 0xD3, 0xF0, 0x47, name="IExecAction", strid="4C3D624D-FD6B-49A3-B9B7-09CB3CD3F047")

class IIdleSettings(COMInterface):
    IID = generate_IID(0x84594461, 0x0053, 0x4342, 0xA8, 0xFD, 0x08, 0x8F, 0xAB, 0xF1, 0x1F, 0x32, name="IIdleSettings", strid="84594461-0053-4342-A8FD-088FABF11F32")

class INetworkSettings(COMInterface):
    IID = generate_IID(0x9F7DEA84, 0xC30B, 0x4245, 0x80, 0xB6, 0x00, 0xE9, 0xF6, 0x46, 0xF1, 0xB4, name="INetworkSettings", strid="9F7DEA84-C30B-4245-80B6-00E9F646F1B4")

class IPrincipal(COMInterface):
    IID = generate_IID(0xD98D51E5, 0xC9B4, 0x496A, 0xA9, 0xC1, 0x18, 0x98, 0x02, 0x61, 0xCF, 0x0F, name="IPrincipal", strid="D98D51E5-C9B4-496A-A9C1-18980261CF0F")

class IRegisteredTask(COMInterface):
    IID = generate_IID(0x9C86F320, 0xDEE3, 0x4DD1, 0xB9, 0x72, 0xA3, 0x03, 0xF2, 0x6B, 0x06, 0x1E, name="IRegisteredTask", strid="9C86F320-DEE3-4DD1-B972-A303F26B061E")

class IRegisteredTaskCollection(COMInterface):
    IID = generate_IID(0x86627EB4, 0x42A7, 0x41E4, 0xA4, 0xD9, 0xAC, 0x33, 0xA7, 0x2F, 0x2D, 0x52, name="IRegisteredTaskCollection", strid="86627EB4-42A7-41E4-A4D9-AC33A72F2D52")

class IRegistrationInfo(COMInterface):
    IID = generate_IID(0x416D8B73, 0xCB41, 0x4EA1, 0x80, 0x5C, 0x9B, 0xE9, 0xA5, 0xAC, 0x4A, 0x74, name="IRegistrationInfo", strid="416D8B73-CB41-4EA1-805C-9BE9A5AC4A74")

class IRepetitionPattern(COMInterface):
    IID = generate_IID(0x7FB9ACF1, 0x26BE, 0x400E, 0x85, 0xB5, 0x29, 0x4B, 0x9C, 0x75, 0xDF, 0xD6, name="IRepetitionPattern", strid="7FB9ACF1-26BE-400E-85B5-294B9C75DFD6")

class IRunningTask(COMInterface):
    IID = generate_IID(0x653758FB, 0x7B9A, 0x4F1E, 0xA4, 0x71, 0xBE, 0xEB, 0x8E, 0x9B, 0x83, 0x4E, name="IRunningTask", strid="653758FB-7B9A-4F1E-A471-BEEB8E9B834E")

class IRunningTaskCollection(COMInterface):
    IID = generate_IID(0x6A67614B, 0x6828, 0x4FEC, 0xAA, 0x54, 0x6D, 0x52, 0xE8, 0xF1, 0xF2, 0xDB, name="IRunningTaskCollection", strid="6A67614B-6828-4FEC-AA54-6D52E8F1F2DB")

class IShowMessageAction(COMInterface):
    IID = generate_IID(0x505E9E68, 0xAF89, 0x46B8, 0xA3, 0x0F, 0x56, 0x16, 0x2A, 0x83, 0xD5, 0x37, name="IShowMessageAction", strid="505E9E68-AF89-46B8-A30F-56162A83D537")

class ITaskDefinition(COMInterface):
    IID = generate_IID(0xF5BC8FC5, 0x536D, 0x4F77, 0xB8, 0x52, 0xFB, 0xC1, 0x35, 0x6F, 0xDE, 0xB6, name="ITaskDefinition", strid="F5BC8FC5-536D-4F77-B852-FBC1356FDEB6")

class ITaskFolder(COMInterface):
    IID = generate_IID(0x8CFAC062, 0xA080, 0x4C15, 0x9A, 0x88, 0xAA, 0x7C, 0x2A, 0xF8, 0x0D, 0xFC, name="ITaskFolder", strid="8CFAC062-A080-4C15-9A88-AA7C2AF80DFC")

class ITaskFolderCollection(COMInterface):
    IID = generate_IID(0x79184A66, 0x8664, 0x423F, 0x97, 0xF1, 0x63, 0x73, 0x56, 0xA5, 0xD8, 0x12, name="ITaskFolderCollection", strid="79184A66-8664-423F-97F1-637356A5D812")

class ITaskNamedValueCollection(COMInterface):
    IID = generate_IID(0xB4EF826B, 0x63C3, 0x46E4, 0xA5, 0x04, 0xEF, 0x69, 0xE4, 0xF7, 0xEA, 0x4D, name="ITaskNamedValueCollection", strid="B4EF826B-63C3-46E4-A504-EF69E4F7EA4D")

class ITaskNamedValuePair(COMInterface):
    IID = generate_IID(0x39038068, 0x2B46, 0x4AFD, 0x86, 0x62, 0x7B, 0xB6, 0xF8, 0x68, 0xD2, 0x21, name="ITaskNamedValuePair", strid="39038068-2B46-4AFD-8662-7BB6F868D221")

class ITaskService(COMInterface):
    IID = generate_IID(0x2FABA4C7, 0x4DA9, 0x4013, 0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85, name="ITaskService", strid="2FABA4C7-4DA9-4013-9697-20CC3FD40F85")

class ITaskSettings(COMInterface):
    IID = generate_IID(0x8FD4711D, 0x2D02, 0x4C8C, 0x87, 0xE3, 0xEF, 0xF6, 0x99, 0xDE, 0x12, 0x7E, name="ITaskSettings", strid="8FD4711D-2D02-4C8C-87E3-EFF699DE127E")

class ITrigger(COMInterface):
    IID = generate_IID(0x09941815, 0xEA89, 0x4B5B, 0x89, 0xE0, 0x2A, 0x77, 0x38, 0x01, 0xFA, 0xC3, name="ITrigger", strid="09941815-EA89-4B5B-89E0-2A773801FAC3")

class ITriggerCollection(COMInterface):
    IID = generate_IID(0x85DF5081, 0x1B24, 0x4F32, 0x87, 0x8A, 0xD9, 0xD1, 0x4D, 0xF4, 0xCB, 0x77, name="ITriggerCollection", strid="85DF5081-1B24-4F32-878A-D9D14DF4CB77")

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

IAction._functions_ = {
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
        # get_Id -> pId:*BSTR
        "get_Id": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Id"),
        # put_Id -> Id:BSTR
        "put_Id": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Id"),
        # get_Type -> pType:*TASK_ACTION_TYPE
        "get_Type": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_ACTION_TYPE))(9, "get_Type"),
    }

IActionCollection._functions_ = {
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
        # get_Count -> pCount:*LONG
        "get_Count": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(7, "get_Count"),
        # get_Item -> index:LONG, ppAction:**IAction
        "get_Item": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IAction))(8, "get_Item"),
        # get__NewEnum -> ppEnum:**IUnknown
        "get__NewEnum": ctypes.WINFUNCTYPE(HRESULT, POINTER(IUnknown))(9, "get__NewEnum"),
        # get_XmlText -> pText:*BSTR
        "get_XmlText": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(10, "get_XmlText"),
        # put_XmlText -> text:BSTR
        "put_XmlText": ctypes.WINFUNCTYPE(HRESULT, BSTR)(11, "put_XmlText"),
        # Create -> type:TASK_ACTION_TYPE, ppAction:**IAction
        "Create": ctypes.WINFUNCTYPE(HRESULT, TASK_ACTION_TYPE, POINTER(IAction))(12, "Create"),
        # Remove -> index:VARIANT
        "Remove": ctypes.WINFUNCTYPE(HRESULT, VARIANT)(13, "Remove"),
        # Clear -> 
        "Clear": ctypes.WINFUNCTYPE(HRESULT)(14, "Clear"),
        # get_Context -> pContext:*BSTR
        "get_Context": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(15, "get_Context"),
        # put_Context -> context:BSTR
        "put_Context": ctypes.WINFUNCTYPE(HRESULT, BSTR)(16, "put_Context"),
    }

IComHandlerAction._functions_ = {
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
        # get_Id -> pId:*BSTR
        "get_Id": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Id"),
        # put_Id -> Id:BSTR
        "put_Id": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Id"),
        # get_Type -> pType:*TASK_ACTION_TYPE
        "get_Type": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_ACTION_TYPE))(9, "get_Type"),
        # get_ClassId -> pClsid:*BSTR
        "get_ClassId": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(10, "get_ClassId"),
        # put_ClassId -> clsid:BSTR
        "put_ClassId": ctypes.WINFUNCTYPE(HRESULT, BSTR)(11, "put_ClassId"),
        # get_Data -> pData:*BSTR
        "get_Data": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(12, "get_Data"),
        # put_Data -> data:BSTR
        "put_Data": ctypes.WINFUNCTYPE(HRESULT, BSTR)(13, "put_Data"),
    }

IEmailAction._functions_ = {
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
        # get_Id -> pId:*BSTR
        "get_Id": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Id"),
        # put_Id -> Id:BSTR
        "put_Id": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Id"),
        # get_Type -> pType:*TASK_ACTION_TYPE
        "get_Type": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_ACTION_TYPE))(9, "get_Type"),
        # get_Server -> pServer:*BSTR
        "get_Server": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(10, "get_Server"),
        # put_Server -> server:BSTR
        "put_Server": ctypes.WINFUNCTYPE(HRESULT, BSTR)(11, "put_Server"),
        # get_Subject -> pSubject:*BSTR
        "get_Subject": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(12, "get_Subject"),
        # put_Subject -> subject:BSTR
        "put_Subject": ctypes.WINFUNCTYPE(HRESULT, BSTR)(13, "put_Subject"),
        # get_To -> pTo:*BSTR
        "get_To": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(14, "get_To"),
        # put_To -> to:BSTR
        "put_To": ctypes.WINFUNCTYPE(HRESULT, BSTR)(15, "put_To"),
        # get_Cc -> pCc:*BSTR
        "get_Cc": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(16, "get_Cc"),
        # put_Cc -> cc:BSTR
        "put_Cc": ctypes.WINFUNCTYPE(HRESULT, BSTR)(17, "put_Cc"),
        # get_Bcc -> pBcc:*BSTR
        "get_Bcc": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(18, "get_Bcc"),
        # put_Bcc -> bcc:BSTR
        "put_Bcc": ctypes.WINFUNCTYPE(HRESULT, BSTR)(19, "put_Bcc"),
        # get_ReplyTo -> pReplyTo:*BSTR
        "get_ReplyTo": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(20, "get_ReplyTo"),
        # put_ReplyTo -> replyTo:BSTR
        "put_ReplyTo": ctypes.WINFUNCTYPE(HRESULT, BSTR)(21, "put_ReplyTo"),
        # get_From -> pFrom:*BSTR
        "get_From": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(22, "get_From"),
        # put_From -> from:BSTR
        "put_From": ctypes.WINFUNCTYPE(HRESULT, BSTR)(23, "put_From"),
        # get_HeaderFields -> ppHeaderFields:**ITaskNamedValueCollection
        "get_HeaderFields": ctypes.WINFUNCTYPE(HRESULT, POINTER(ITaskNamedValueCollection))(24, "get_HeaderFields"),
        # put_HeaderFields -> pHeaderFields:*ITaskNamedValueCollection
        "put_HeaderFields": ctypes.WINFUNCTYPE(HRESULT, ITaskNamedValueCollection)(25, "put_HeaderFields"),
        # get_Body -> pBody:*BSTR
        "get_Body": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(26, "get_Body"),
        # put_Body -> body:BSTR
        "put_Body": ctypes.WINFUNCTYPE(HRESULT, BSTR)(27, "put_Body"),
        # get_Attachments -> pAttachements:**SAFEARRAY
        "get_Attachments": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(SAFEARRAY)))(28, "get_Attachments"),
        # put_Attachments -> pAttachements:*SAFEARRAY
        "put_Attachments": ctypes.WINFUNCTYPE(HRESULT, POINTER(SAFEARRAY))(29, "put_Attachments"),
    }

IExecAction._functions_ = {
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
        # get_Id -> pId:*BSTR
        "get_Id": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Id"),
        # put_Id -> Id:BSTR
        "put_Id": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Id"),
        # get_Type -> pType:*TASK_ACTION_TYPE
        "get_Type": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_ACTION_TYPE))(9, "get_Type"),
        # get_Path -> pPath:*BSTR
        "get_Path": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(10, "get_Path"),
        # put_Path -> path:BSTR
        "put_Path": ctypes.WINFUNCTYPE(HRESULT, BSTR)(11, "put_Path"),
        # get_Arguments -> pArgument:*BSTR
        "get_Arguments": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(12, "get_Arguments"),
        # put_Arguments -> argument:BSTR
        "put_Arguments": ctypes.WINFUNCTYPE(HRESULT, BSTR)(13, "put_Arguments"),
        # get_WorkingDirectory -> pWorkingDirectory:*BSTR
        "get_WorkingDirectory": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(14, "get_WorkingDirectory"),
        # put_WorkingDirectory -> workingDirectory:BSTR
        "put_WorkingDirectory": ctypes.WINFUNCTYPE(HRESULT, BSTR)(15, "put_WorkingDirectory"),
    }

IIdleSettings._functions_ = {
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
        # get_IdleDuration -> pDelay:*BSTR
        "get_IdleDuration": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_IdleDuration"),
        # put_IdleDuration -> delay:BSTR
        "put_IdleDuration": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_IdleDuration"),
        # get_WaitTimeout -> pTimeout:*BSTR
        "get_WaitTimeout": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(9, "get_WaitTimeout"),
        # put_WaitTimeout -> timeout:BSTR
        "put_WaitTimeout": ctypes.WINFUNCTYPE(HRESULT, BSTR)(10, "put_WaitTimeout"),
        # get_StopOnIdleEnd -> pStop:*VARIANT_BOOL
        "get_StopOnIdleEnd": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(11, "get_StopOnIdleEnd"),
        # put_StopOnIdleEnd -> stop:VARIANT_BOOL
        "put_StopOnIdleEnd": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(12, "put_StopOnIdleEnd"),
        # get_RestartOnIdle -> pRestart:*VARIANT_BOOL
        "get_RestartOnIdle": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(13, "get_RestartOnIdle"),
        # put_RestartOnIdle -> restart:VARIANT_BOOL
        "put_RestartOnIdle": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(14, "put_RestartOnIdle"),
    }

INetworkSettings._functions_ = {
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
        # get_Name -> pName:*BSTR
        "get_Name": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Name"),
        # put_Name -> name:BSTR
        "put_Name": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Name"),
        # get_Id -> pId:*BSTR
        "get_Id": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(9, "get_Id"),
        # put_Id -> id:BSTR
        "put_Id": ctypes.WINFUNCTYPE(HRESULT, BSTR)(10, "put_Id"),
    }

IPrincipal._functions_ = {
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
        # get_Id -> pId:*BSTR
        "get_Id": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Id"),
        # put_Id -> Id:BSTR
        "put_Id": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Id"),
        # get_DisplayName -> pName:*BSTR
        "get_DisplayName": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(9, "get_DisplayName"),
        # put_DisplayName -> name:BSTR
        "put_DisplayName": ctypes.WINFUNCTYPE(HRESULT, BSTR)(10, "put_DisplayName"),
        # get_UserId -> pUser:*BSTR
        "get_UserId": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(11, "get_UserId"),
        # put_UserId -> user:BSTR
        "put_UserId": ctypes.WINFUNCTYPE(HRESULT, BSTR)(12, "put_UserId"),
        # get_LogonType -> pLogon:*TASK_LOGON_TYPE
        "get_LogonType": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_LOGON_TYPE))(13, "get_LogonType"),
        # put_LogonType -> logon:TASK_LOGON_TYPE
        "put_LogonType": ctypes.WINFUNCTYPE(HRESULT, TASK_LOGON_TYPE)(14, "put_LogonType"),
        # get_GroupId -> pGroup:*BSTR
        "get_GroupId": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(15, "get_GroupId"),
        # put_GroupId -> group:BSTR
        "put_GroupId": ctypes.WINFUNCTYPE(HRESULT, BSTR)(16, "put_GroupId"),
        # get_RunLevel -> pRunLevel:*TASK_RUNLEVEL_TYPE
        "get_RunLevel": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_RUNLEVEL_TYPE))(17, "get_RunLevel"),
        # put_RunLevel -> runLevel:TASK_RUNLEVEL_TYPE
        "put_RunLevel": ctypes.WINFUNCTYPE(HRESULT, TASK_RUNLEVEL_TYPE)(18, "put_RunLevel"),
    }

IRegisteredTask._functions_ = {
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
        # get_Name -> pName:*BSTR
        "get_Name": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Name"),
        # get_Path -> pPath:*BSTR
        "get_Path": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(8, "get_Path"),
        # get_State -> pState:*TASK_STATE
        "get_State": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_STATE))(9, "get_State"),
        # get_Enabled -> pEnabled:*VARIANT_BOOL
        "get_Enabled": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(10, "get_Enabled"),
        # put_Enabled -> enabled:VARIANT_BOOL
        "put_Enabled": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(11, "put_Enabled"),
        # Run -> params:VARIANT, ppRunningTask:**IRunningTask
        "Run": ctypes.WINFUNCTYPE(HRESULT, VARIANT, POINTER(IRunningTask))(12, "Run"),
        # RunEx -> params:VARIANT, flags:LONG, sessionID:LONG, user:BSTR, ppRunningTask:**IRunningTask
        "RunEx": ctypes.WINFUNCTYPE(HRESULT, VARIANT, LONG, LONG, BSTR, POINTER(IRunningTask))(13, "RunEx"),
        # GetInstances -> flags:LONG, ppRunningTasks:**IRunningTaskCollection
        "GetInstances": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IRunningTaskCollection))(14, "GetInstances"),
        # get_LastRunTime -> pLastRunTime:*DATE
        "get_LastRunTime": ctypes.WINFUNCTYPE(HRESULT, POINTER(DATE))(15, "get_LastRunTime"),
        # get_LastTaskResult -> pLastTaskResult:*LONG
        "get_LastTaskResult": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(16, "get_LastTaskResult"),
        # get_NumberOfMissedRuns -> pNumberOfMissedRuns:*LONG
        "get_NumberOfMissedRuns": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(17, "get_NumberOfMissedRuns"),
        # get_NextRunTime -> pNextRunTime:*DATE
        "get_NextRunTime": ctypes.WINFUNCTYPE(HRESULT, POINTER(DATE))(18, "get_NextRunTime"),
        # get_Definition -> ppDefinition:**ITaskDefinition
        "get_Definition": ctypes.WINFUNCTYPE(HRESULT, POINTER(ITaskDefinition))(19, "get_Definition"),
        # get_Xml -> pXml:*BSTR
        "get_Xml": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(20, "get_Xml"),
        # GetSecurityDescriptor -> securityInformation:LONG, pSddl:*BSTR
        "GetSecurityDescriptor": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(BSTR))(21, "GetSecurityDescriptor"),
        # SetSecurityDescriptor -> sddl:BSTR, flags:LONG
        "SetSecurityDescriptor": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG)(22, "SetSecurityDescriptor"),
        # Stop -> flags:LONG
        "Stop": ctypes.WINFUNCTYPE(HRESULT, LONG)(23, "Stop"),
        # GetRunTimes -> pstStart:LPSYSTEMTIME, pstEnd:LPSYSTEMTIME, pCount:*DWORD, pRunTimes:*LPSYSTEMTIME
        "GetRunTimes": ctypes.WINFUNCTYPE(HRESULT, LPSYSTEMTIME, LPSYSTEMTIME, POINTER(DWORD), POINTER(LPSYSTEMTIME))(24, "GetRunTimes"),
    }

IRegisteredTaskCollection._functions_ = {
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
        # get_Count -> pCount:*LONG
        "get_Count": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(7, "get_Count"),
        # get_Item -> index:VARIANT, ppRegisteredTask:**IRegisteredTask
        "get_Item": ctypes.WINFUNCTYPE(HRESULT, VARIANT, POINTER(IRegisteredTask))(8, "get_Item"),
        # get__NewEnum -> ppEnum:**IUnknown
        "get__NewEnum": ctypes.WINFUNCTYPE(HRESULT, POINTER(IUnknown))(9, "get__NewEnum"),
    }

IRegistrationInfo._functions_ = {
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
        # get_Description -> pDescription:*BSTR
        "get_Description": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Description"),
        # put_Description -> description:BSTR
        "put_Description": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Description"),
        # get_Author -> pAuthor:*BSTR
        "get_Author": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(9, "get_Author"),
        # put_Author -> author:BSTR
        "put_Author": ctypes.WINFUNCTYPE(HRESULT, BSTR)(10, "put_Author"),
        # get_Version -> pVersion:*BSTR
        "get_Version": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(11, "get_Version"),
        # put_Version -> version:BSTR
        "put_Version": ctypes.WINFUNCTYPE(HRESULT, BSTR)(12, "put_Version"),
        # get_Date -> pDate:*BSTR
        "get_Date": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(13, "get_Date"),
        # put_Date -> date:BSTR
        "put_Date": ctypes.WINFUNCTYPE(HRESULT, BSTR)(14, "put_Date"),
        # get_Documentation -> pDocumentation:*BSTR
        "get_Documentation": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(15, "get_Documentation"),
        # put_Documentation -> documentation:BSTR
        "put_Documentation": ctypes.WINFUNCTYPE(HRESULT, BSTR)(16, "put_Documentation"),
        # get_XmlText -> pText:*BSTR
        "get_XmlText": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(17, "get_XmlText"),
        # put_XmlText -> text:BSTR
        "put_XmlText": ctypes.WINFUNCTYPE(HRESULT, BSTR)(18, "put_XmlText"),
        # get_URI -> pUri:*BSTR
        "get_URI": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(19, "get_URI"),
        # put_URI -> uri:BSTR
        "put_URI": ctypes.WINFUNCTYPE(HRESULT, BSTR)(20, "put_URI"),
        # get_SecurityDescriptor -> pSddl:*VARIANT
        "get_SecurityDescriptor": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT))(21, "get_SecurityDescriptor"),
        # put_SecurityDescriptor -> sddl:VARIANT
        "put_SecurityDescriptor": ctypes.WINFUNCTYPE(HRESULT, VARIANT)(22, "put_SecurityDescriptor"),
        # get_Source -> pSource:*BSTR
        "get_Source": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(23, "get_Source"),
        # put_Source -> source:BSTR
        "put_Source": ctypes.WINFUNCTYPE(HRESULT, BSTR)(24, "put_Source"),
    }

IRepetitionPattern._functions_ = {
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
        # get_Interval -> pInterval:*BSTR
        "get_Interval": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Interval"),
        # put_Interval -> interval:BSTR
        "put_Interval": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Interval"),
        # get_Duration -> pDuration:*BSTR
        "get_Duration": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(9, "get_Duration"),
        # put_Duration -> duration:BSTR
        "put_Duration": ctypes.WINFUNCTYPE(HRESULT, BSTR)(10, "put_Duration"),
        # get_StopAtDurationEnd -> pStop:*VARIANT_BOOL
        "get_StopAtDurationEnd": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(11, "get_StopAtDurationEnd"),
        # put_StopAtDurationEnd -> stop:VARIANT_BOOL
        "put_StopAtDurationEnd": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(12, "put_StopAtDurationEnd"),
    }

IRunningTask._functions_ = {
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
        # get_Name -> pName:*BSTR
        "get_Name": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Name"),
        # get_InstanceGuid -> pGuid:*BSTR
        "get_InstanceGuid": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(8, "get_InstanceGuid"),
        # get_Path -> pPath:*BSTR
        "get_Path": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(9, "get_Path"),
        # get_State -> pState:*TASK_STATE
        "get_State": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_STATE))(10, "get_State"),
        # get_CurrentAction -> pName:*BSTR
        "get_CurrentAction": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(11, "get_CurrentAction"),
        # Stop -> 
        "Stop": ctypes.WINFUNCTYPE(HRESULT)(12, "Stop"),
        # Refresh -> 
        "Refresh": ctypes.WINFUNCTYPE(HRESULT)(13, "Refresh"),
        # get_EnginePID -> pPID:*DWORD
        "get_EnginePID": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(14, "get_EnginePID"),
    }

IRunningTaskCollection._functions_ = {
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
        # get_Count -> pCount:*LONG
        "get_Count": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(7, "get_Count"),
        # get_Item -> index:VARIANT, ppRunningTask:**IRunningTask
        "get_Item": ctypes.WINFUNCTYPE(HRESULT, VARIANT, POINTER(IRunningTask))(8, "get_Item"),
        # get__NewEnum -> ppEnum:**IUnknown
        "get__NewEnum": ctypes.WINFUNCTYPE(HRESULT, POINTER(IUnknown))(9, "get__NewEnum"),
    }

IShowMessageAction._functions_ = {
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
        # get_Id -> pId:*BSTR
        "get_Id": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Id"),
        # put_Id -> Id:BSTR
        "put_Id": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Id"),
        # get_Type -> pType:*TASK_ACTION_TYPE
        "get_Type": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_ACTION_TYPE))(9, "get_Type"),
        # get_Title -> pTitle:*BSTR
        "get_Title": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(10, "get_Title"),
        # put_Title -> title:BSTR
        "put_Title": ctypes.WINFUNCTYPE(HRESULT, BSTR)(11, "put_Title"),
        # get_MessageBody -> pMessageBody:*BSTR
        "get_MessageBody": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(12, "get_MessageBody"),
        # put_MessageBody -> messageBody:BSTR
        "put_MessageBody": ctypes.WINFUNCTYPE(HRESULT, BSTR)(13, "put_MessageBody"),
    }

ITaskDefinition._functions_ = {
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
        # get_RegistrationInfo -> ppRegistrationInfo:**IRegistrationInfo
        "get_RegistrationInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(IRegistrationInfo))(7, "get_RegistrationInfo"),
        # put_RegistrationInfo -> pRegistrationInfo:*IRegistrationInfo
        "put_RegistrationInfo": ctypes.WINFUNCTYPE(HRESULT, IRegistrationInfo)(8, "put_RegistrationInfo"),
        # get_Triggers -> ppTriggers:**ITriggerCollection
        "get_Triggers": ctypes.WINFUNCTYPE(HRESULT, POINTER(ITriggerCollection))(9, "get_Triggers"),
        # put_Triggers -> pTriggers:*ITriggerCollection
        "put_Triggers": ctypes.WINFUNCTYPE(HRESULT, ITriggerCollection)(10, "put_Triggers"),
        # get_Settings -> ppSettings:**ITaskSettings
        "get_Settings": ctypes.WINFUNCTYPE(HRESULT, POINTER(ITaskSettings))(11, "get_Settings"),
        # put_Settings -> pSettings:*ITaskSettings
        "put_Settings": ctypes.WINFUNCTYPE(HRESULT, ITaskSettings)(12, "put_Settings"),
        # get_Data -> pData:*BSTR
        "get_Data": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(13, "get_Data"),
        # put_Data -> data:BSTR
        "put_Data": ctypes.WINFUNCTYPE(HRESULT, BSTR)(14, "put_Data"),
        # get_Principal -> ppPrincipal:**IPrincipal
        "get_Principal": ctypes.WINFUNCTYPE(HRESULT, POINTER(IPrincipal))(15, "get_Principal"),
        # put_Principal -> pPrincipal:*IPrincipal
        "put_Principal": ctypes.WINFUNCTYPE(HRESULT, IPrincipal)(16, "put_Principal"),
        # get_Actions -> ppActions:**IActionCollection
        "get_Actions": ctypes.WINFUNCTYPE(HRESULT, POINTER(IActionCollection))(17, "get_Actions"),
        # put_Actions -> pActions:*IActionCollection
        "put_Actions": ctypes.WINFUNCTYPE(HRESULT, IActionCollection)(18, "put_Actions"),
        # get_XmlText -> pXml:*BSTR
        "get_XmlText": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(19, "get_XmlText"),
        # put_XmlText -> xml:BSTR
        "put_XmlText": ctypes.WINFUNCTYPE(HRESULT, BSTR)(20, "put_XmlText"),
    }

ITaskFolder._functions_ = {
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
        # get_Name -> pName:*BSTR
        "get_Name": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Name"),
        # get_Path -> pPath:*BSTR
        "get_Path": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(8, "get_Path"),
        # GetFolder -> path:BSTR, ppFolder:**ITaskFolder
        "GetFolder": ctypes.WINFUNCTYPE(HRESULT, BSTR, POINTER(ITaskFolder))(9, "GetFolder"),
        # GetFolders -> flags:LONG, ppFolders:**ITaskFolderCollection
        "GetFolders": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(ITaskFolderCollection))(10, "GetFolders"),
        # CreateFolder -> subFolderName:BSTR, sddl:VARIANT, ppFolder:**ITaskFolder
        "CreateFolder": ctypes.WINFUNCTYPE(HRESULT, BSTR, VARIANT, POINTER(ITaskFolder))(11, "CreateFolder"),
        # DeleteFolder -> subFolderName:BSTR, flags:LONG
        "DeleteFolder": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG)(12, "DeleteFolder"),
        # GetTask -> path:BSTR, ppTask:**IRegisteredTask
        "GetTask": ctypes.WINFUNCTYPE(HRESULT, BSTR, POINTER(IRegisteredTask))(13, "GetTask"),
        # GetTasks -> flags:LONG, ppTasks:**IRegisteredTaskCollection
        "GetTasks": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IRegisteredTaskCollection))(14, "GetTasks"),
        # DeleteTask -> name:BSTR, flags:LONG
        "DeleteTask": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG)(15, "DeleteTask"),
        # RegisterTask -> path:BSTR, xmlText:BSTR, flags:LONG, userId:VARIANT, password:VARIANT, logonType:TASK_LOGON_TYPE, sddl:VARIANT, ppTask:**IRegisteredTask
        "RegisterTask": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, LONG, VARIANT, VARIANT, TASK_LOGON_TYPE, VARIANT, POINTER(IRegisteredTask))(16, "RegisterTask"),
        # RegisterTaskDefinition -> path:BSTR, pDefinition:*ITaskDefinition, flags:LONG, userId:VARIANT, password:VARIANT, logonType:TASK_LOGON_TYPE, sddl:VARIANT, ppTask:**IRegisteredTask
        "RegisterTaskDefinition": ctypes.WINFUNCTYPE(HRESULT, BSTR, ITaskDefinition, LONG, VARIANT, VARIANT, TASK_LOGON_TYPE, VARIANT, POINTER(IRegisteredTask))(17, "RegisterTaskDefinition"),
        # GetSecurityDescriptor -> securityInformation:LONG, pSddl:*BSTR
        "GetSecurityDescriptor": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(BSTR))(18, "GetSecurityDescriptor"),
        # SetSecurityDescriptor -> sddl:BSTR, flags:LONG
        "SetSecurityDescriptor": ctypes.WINFUNCTYPE(HRESULT, BSTR, LONG)(19, "SetSecurityDescriptor"),
    }

ITaskFolderCollection._functions_ = {
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
        # get_Count -> pCount:*LONG
        "get_Count": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(7, "get_Count"),
        # get_Item -> index:VARIANT, ppFolder:**ITaskFolder
        "get_Item": ctypes.WINFUNCTYPE(HRESULT, VARIANT, POINTER(ITaskFolder))(8, "get_Item"),
        # get__NewEnum -> ppEnum:**IUnknown
        "get__NewEnum": ctypes.WINFUNCTYPE(HRESULT, POINTER(IUnknown))(9, "get__NewEnum"),
    }

ITaskNamedValueCollection._functions_ = {
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
        # get_Count -> pCount:*LONG
        "get_Count": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(7, "get_Count"),
        # get_Item -> index:LONG, ppPair:**ITaskNamedValuePair
        "get_Item": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(ITaskNamedValuePair))(8, "get_Item"),
        # get__NewEnum -> ppEnum:**IUnknown
        "get__NewEnum": ctypes.WINFUNCTYPE(HRESULT, POINTER(IUnknown))(9, "get__NewEnum"),
        # Create -> name:BSTR, value:BSTR, ppPair:**ITaskNamedValuePair
        "Create": ctypes.WINFUNCTYPE(HRESULT, BSTR, BSTR, POINTER(ITaskNamedValuePair))(10, "Create"),
        # Remove -> index:LONG
        "Remove": ctypes.WINFUNCTYPE(HRESULT, LONG)(11, "Remove"),
        # Clear -> 
        "Clear": ctypes.WINFUNCTYPE(HRESULT)(12, "Clear"),
    }

ITaskNamedValuePair._functions_ = {
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
        # get_Name -> pName:*BSTR
        "get_Name": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(7, "get_Name"),
        # put_Name -> name:BSTR
        "put_Name": ctypes.WINFUNCTYPE(HRESULT, BSTR)(8, "put_Name"),
        # get_Value -> pValue:*BSTR
        "get_Value": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(9, "get_Value"),
        # put_Value -> value:BSTR
        "put_Value": ctypes.WINFUNCTYPE(HRESULT, BSTR)(10, "put_Value"),
    }

ITaskService._functions_ = {
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
        # GetFolder -> path:BSTR, ppFolder:**ITaskFolder
        "GetFolder": ctypes.WINFUNCTYPE(HRESULT, BSTR, POINTER(ITaskFolder))(7, "GetFolder"),
        # GetRunningTasks -> flags:LONG, ppRunningTasks:**IRunningTaskCollection
        "GetRunningTasks": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(IRunningTaskCollection))(8, "GetRunningTasks"),
        # NewTask -> flags:DWORD, ppDefinition:**ITaskDefinition
        "NewTask": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(ITaskDefinition))(9, "NewTask"),
        # Connect -> serverName:VARIANT, user:VARIANT, domain:VARIANT, password:VARIANT
        "Connect": ctypes.WINFUNCTYPE(HRESULT, VARIANT, VARIANT, VARIANT, VARIANT)(10, "Connect"),
        # get_Connected -> pConnected:*VARIANT_BOOL
        "get_Connected": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(11, "get_Connected"),
        # get_TargetServer -> pServer:*BSTR
        "get_TargetServer": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(12, "get_TargetServer"),
        # get_ConnectedUser -> pUser:*BSTR
        "get_ConnectedUser": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(13, "get_ConnectedUser"),
        # get_ConnectedDomain -> pDomain:*BSTR
        "get_ConnectedDomain": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(14, "get_ConnectedDomain"),
        # get_HighestVersion -> pVersion:*DWORD
        "get_HighestVersion": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(15, "get_HighestVersion"),
    }

ITaskSettings._functions_ = {
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
        # get_AllowDemandStart -> pAllowDemandStart:*VARIANT_BOOL
        "get_AllowDemandStart": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(7, "get_AllowDemandStart"),
        # put_AllowDemandStart -> allowDemandStart:VARIANT_BOOL
        "put_AllowDemandStart": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(8, "put_AllowDemandStart"),
        # get_RestartInterval -> pRestartInterval:*BSTR
        "get_RestartInterval": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(9, "get_RestartInterval"),
        # put_RestartInterval -> restartInterval:BSTR
        "put_RestartInterval": ctypes.WINFUNCTYPE(HRESULT, BSTR)(10, "put_RestartInterval"),
        # get_RestartCount -> pRestartCount:*INT
        "get_RestartCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(INT))(11, "get_RestartCount"),
        # put_RestartCount -> restartCount:INT
        "put_RestartCount": ctypes.WINFUNCTYPE(HRESULT, INT)(12, "put_RestartCount"),
        # get_MultipleInstances -> pPolicy:*TASK_INSTANCES_POLICY
        "get_MultipleInstances": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_INSTANCES_POLICY))(13, "get_MultipleInstances"),
        # put_MultipleInstances -> policy:TASK_INSTANCES_POLICY
        "put_MultipleInstances": ctypes.WINFUNCTYPE(HRESULT, TASK_INSTANCES_POLICY)(14, "put_MultipleInstances"),
        # get_StopIfGoingOnBatteries -> pStopIfOnBatteries:*VARIANT_BOOL
        "get_StopIfGoingOnBatteries": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(15, "get_StopIfGoingOnBatteries"),
        # put_StopIfGoingOnBatteries -> stopIfOnBatteries:VARIANT_BOOL
        "put_StopIfGoingOnBatteries": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(16, "put_StopIfGoingOnBatteries"),
        # get_DisallowStartIfOnBatteries -> pDisallowStart:*VARIANT_BOOL
        "get_DisallowStartIfOnBatteries": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(17, "get_DisallowStartIfOnBatteries"),
        # put_DisallowStartIfOnBatteries -> disallowStart:VARIANT_BOOL
        "put_DisallowStartIfOnBatteries": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(18, "put_DisallowStartIfOnBatteries"),
        # get_AllowHardTerminate -> pAllowHardTerminate:*VARIANT_BOOL
        "get_AllowHardTerminate": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(19, "get_AllowHardTerminate"),
        # put_AllowHardTerminate -> allowHardTerminate:VARIANT_BOOL
        "put_AllowHardTerminate": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(20, "put_AllowHardTerminate"),
        # get_StartWhenAvailable -> pStartWhenAvailable:*VARIANT_BOOL
        "get_StartWhenAvailable": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(21, "get_StartWhenAvailable"),
        # put_StartWhenAvailable -> startWhenAvailable:VARIANT_BOOL
        "put_StartWhenAvailable": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(22, "put_StartWhenAvailable"),
        # get_XmlText -> pText:*BSTR
        "get_XmlText": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(23, "get_XmlText"),
        # put_XmlText -> text:BSTR
        "put_XmlText": ctypes.WINFUNCTYPE(HRESULT, BSTR)(24, "put_XmlText"),
        # get_RunOnlyIfNetworkAvailable -> pRunOnlyIfNetworkAvailable:*VARIANT_BOOL
        "get_RunOnlyIfNetworkAvailable": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(25, "get_RunOnlyIfNetworkAvailable"),
        # put_RunOnlyIfNetworkAvailable -> runOnlyIfNetworkAvailable:VARIANT_BOOL
        "put_RunOnlyIfNetworkAvailable": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(26, "put_RunOnlyIfNetworkAvailable"),
        # get_ExecutionTimeLimit -> pExecutionTimeLimit:*BSTR
        "get_ExecutionTimeLimit": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(27, "get_ExecutionTimeLimit"),
        # put_ExecutionTimeLimit -> executionTimeLimit:BSTR
        "put_ExecutionTimeLimit": ctypes.WINFUNCTYPE(HRESULT, BSTR)(28, "put_ExecutionTimeLimit"),
        # get_Enabled -> pEnabled:*VARIANT_BOOL
        "get_Enabled": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(29, "get_Enabled"),
        # put_Enabled -> enabled:VARIANT_BOOL
        "put_Enabled": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(30, "put_Enabled"),
        # get_DeleteExpiredTaskAfter -> pExpirationDelay:*BSTR
        "get_DeleteExpiredTaskAfter": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(31, "get_DeleteExpiredTaskAfter"),
        # put_DeleteExpiredTaskAfter -> expirationDelay:BSTR
        "put_DeleteExpiredTaskAfter": ctypes.WINFUNCTYPE(HRESULT, BSTR)(32, "put_DeleteExpiredTaskAfter"),
        # get_Priority -> pPriority:*INT
        "get_Priority": ctypes.WINFUNCTYPE(HRESULT, POINTER(INT))(33, "get_Priority"),
        # put_Priority -> priority:INT
        "put_Priority": ctypes.WINFUNCTYPE(HRESULT, INT)(34, "put_Priority"),
        # get_Compatibility -> pCompatLevel:*TASK_COMPATIBILITY
        "get_Compatibility": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_COMPATIBILITY))(35, "get_Compatibility"),
        # put_Compatibility -> compatLevel:TASK_COMPATIBILITY
        "put_Compatibility": ctypes.WINFUNCTYPE(HRESULT, TASK_COMPATIBILITY)(36, "put_Compatibility"),
        # get_Hidden -> pHidden:*VARIANT_BOOL
        "get_Hidden": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(37, "get_Hidden"),
        # put_Hidden -> hidden:VARIANT_BOOL
        "put_Hidden": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(38, "put_Hidden"),
        # get_IdleSettings -> ppIdleSettings:**IIdleSettings
        "get_IdleSettings": ctypes.WINFUNCTYPE(HRESULT, POINTER(IIdleSettings))(39, "get_IdleSettings"),
        # put_IdleSettings -> pIdleSettings:*IIdleSettings
        "put_IdleSettings": ctypes.WINFUNCTYPE(HRESULT, IIdleSettings)(40, "put_IdleSettings"),
        # get_RunOnlyIfIdle -> pRunOnlyIfIdle:*VARIANT_BOOL
        "get_RunOnlyIfIdle": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(41, "get_RunOnlyIfIdle"),
        # put_RunOnlyIfIdle -> runOnlyIfIdle:VARIANT_BOOL
        "put_RunOnlyIfIdle": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(42, "put_RunOnlyIfIdle"),
        # get_WakeToRun -> pWake:*VARIANT_BOOL
        "get_WakeToRun": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(43, "get_WakeToRun"),
        # put_WakeToRun -> wake:VARIANT_BOOL
        "put_WakeToRun": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(44, "put_WakeToRun"),
        # get_NetworkSettings -> ppNetworkSettings:**INetworkSettings
        "get_NetworkSettings": ctypes.WINFUNCTYPE(HRESULT, POINTER(INetworkSettings))(45, "get_NetworkSettings"),
        # put_NetworkSettings -> pNetworkSettings:*INetworkSettings
        "put_NetworkSettings": ctypes.WINFUNCTYPE(HRESULT, INetworkSettings)(46, "put_NetworkSettings"),
    }

ITrigger._functions_ = {
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
        # get_Type -> pType:*TASK_TRIGGER_TYPE2
        "get_Type": ctypes.WINFUNCTYPE(HRESULT, POINTER(TASK_TRIGGER_TYPE2))(7, "get_Type"),
        # get_Id -> pId:*BSTR
        "get_Id": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(8, "get_Id"),
        # put_Id -> id:BSTR
        "put_Id": ctypes.WINFUNCTYPE(HRESULT, BSTR)(9, "put_Id"),
        # get_Repetition -> ppRepeat:**IRepetitionPattern
        "get_Repetition": ctypes.WINFUNCTYPE(HRESULT, POINTER(IRepetitionPattern))(10, "get_Repetition"),
        # put_Repetition -> pRepeat:*IRepetitionPattern
        "put_Repetition": ctypes.WINFUNCTYPE(HRESULT, IRepetitionPattern)(11, "put_Repetition"),
        # get_ExecutionTimeLimit -> pTimeLimit:*BSTR
        "get_ExecutionTimeLimit": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(12, "get_ExecutionTimeLimit"),
        # put_ExecutionTimeLimit -> timelimit:BSTR
        "put_ExecutionTimeLimit": ctypes.WINFUNCTYPE(HRESULT, BSTR)(13, "put_ExecutionTimeLimit"),
        # get_StartBoundary -> pStart:*BSTR
        "get_StartBoundary": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(14, "get_StartBoundary"),
        # put_StartBoundary -> start:BSTR
        "put_StartBoundary": ctypes.WINFUNCTYPE(HRESULT, BSTR)(15, "put_StartBoundary"),
        # get_EndBoundary -> pEnd:*BSTR
        "get_EndBoundary": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(16, "get_EndBoundary"),
        # put_EndBoundary -> end:BSTR
        "put_EndBoundary": ctypes.WINFUNCTYPE(HRESULT, BSTR)(17, "put_EndBoundary"),
        # get_Enabled -> pEnabled:*VARIANT_BOOL
        "get_Enabled": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(18, "get_Enabled"),
        # put_Enabled -> enabled:VARIANT_BOOL
        "put_Enabled": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(19, "put_Enabled"),
    }

ITriggerCollection._functions_ = {
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
        # get_Count -> pCount:*LONG
        "get_Count": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(7, "get_Count"),
        # get_Item -> index:LONG, ppTrigger:**ITrigger
        "get_Item": ctypes.WINFUNCTYPE(HRESULT, LONG, POINTER(ITrigger))(8, "get_Item"),
        # get__NewEnum -> ppEnum:**IUnknown
        "get__NewEnum": ctypes.WINFUNCTYPE(HRESULT, POINTER(IUnknown))(9, "get__NewEnum"),
        # Create -> type:TASK_TRIGGER_TYPE2, ppTrigger:**ITrigger
        "Create": ctypes.WINFUNCTYPE(HRESULT, TASK_TRIGGER_TYPE2, POINTER(ITrigger))(10, "Create"),
        # Remove -> index:VARIANT
        "Remove": ctypes.WINFUNCTYPE(HRESULT, VARIANT)(11, "Remove"),
        # Clear -> 
        "Clear": ctypes.WINFUNCTYPE(HRESULT)(12, "Clear"),
    }

