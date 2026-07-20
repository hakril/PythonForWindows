from .winstructs import *
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
    # But we add the 'errcheck' callback capacity for all COMInterface and subclasses
    # So the default implem of the callback must have the same behavior as
    # standard HRESULT restype.
    # This is why default errcheck callback call ctypes._check_HRESULT
    def _default_errcheck(self, result, func, args):
        ctypes._check_HRESULT(result)
        return args

    errcheck = _default_errcheck

    def __getattr__(self, name):
        if name in self._functions_:
            winfunc = self._functions_[name]
            # Hacking the HRESULT _check_retval_ and
            # letting COMInterface.errcheck do the work of validating / raising
            winfunc.restype = COMHRESULT
            winfunc.errcheck = self.errcheck
            return functools.partial(winfunc, self)
        return super(COMInterface, self).__getattribute__(name)

    def __repr__(self):
        description = "<NULL>" if not self.value else ""
        return "<{0}{1} at {2:#x}>".format(type(self).__name__, description, id(self))

    # use the context protocol to allow Release() in exit
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if bool(self):
            self.Release()

    # Simplified API for QueryInterface for interface embeding their IID
    # Or for string/Obj
    def query(self, interface, target=None):
        if isinstance(interface, str): # We have a GUID
            interface_iid = IID.from_string(interface)
            if target is None:
                target = IUnknown()
        elif issubclass(interface, COMInterface): # We have a PFW COM interface
            interface_iid = interface.IID
            if target is None:
                target = interface() # Use an instance of the ComInterface as target of the QueryInterface
        else:
            # We have something else (A gdef.GUID probably)
            interface_iid = interface
            if target is None:
                target = IUnknown()
        self.QueryInterface(interface_iid, target)
        return target

    def marshal(self, target_iid=None, destination=MSHCTX_NOSHAREDMEM, flags=MSHLFLAGS_NORMAL):
        if target_iid is None:
            target_iid = self.IID
        mystream = windows.com.MemoryIStream.create()
        windows.winproxy.CoMarshalInterface(mystream, target_iid, self, destination, 0, flags)
        mystream.seek(0)
        buffer = mystream.read(0xffffffff) # Todo: release stuff
        return buffer








class IUnknown(COMInterface):
    IID = generate_IID(0x00000000, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IUnknown", strid="00000000-0000-0000-C000-000000000046")

class ICallFactory(IUnknown):
    IID = generate_IID(0x1C733A30, 0x2A1C, 0x11CE, 0xAD, 0xE5, 0x00, 0xAA, 0x00, 0x44, 0x77, 0x3D, name="ICallFactory", strid="1C733A30-2A1C-11CE-ADE5-00AA0044773D")

class ICallFrame(IUnknown):
    IID = generate_IID(0xD573B4B0, 0x894E, 0x11D2, 0xB8, 0xB6, 0x00, 0xC0, 0x4F, 0xB9, 0x61, 0x8A, name="ICallFrame", strid="D573B4B0-894E-11D2-B8B6-00C04FB9618A")

class ICallFrameEvents(IUnknown):
    IID = generate_IID(0xFD5E0843, 0xFC91, 0x11D0, 0x97, 0xD7, 0x00, 0xC0, 0x4F, 0xB9, 0x61, 0x8A, name="ICallFrameEvents", strid="FD5E0843-FC91-11D0-97D7-00C04FB9618A")

class ICallFrameWalker(IUnknown):
    IID = generate_IID(0x08B23919, 0x392D, 0x11D2, 0xB8, 0xA4, 0x00, 0xC0, 0x4F, 0xB9, 0x61, 0x8A, name="ICallFrameWalker", strid="08B23919-392D-11D2-B8A4-00C04FB9618A")

class ICallInterceptor(IUnknown):
    IID = generate_IID(0x60C7CA75, 0x896D, 0x11D2, 0xB8, 0xB6, 0x00, 0xC0, 0x4F, 0xB9, 0x61, 0x8A, name="ICallInterceptor", strid="60C7CA75-896D-11D2-B8B6-00C04FB9618A")

class IClassFactory(IUnknown):
    IID = generate_IID(0x00000001, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IClassFactory", strid="00000001-0000-0000-C000-000000000046")

class IClientSecurity(IUnknown):
    IID = generate_IID(0x0000013D, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IClientSecurity", strid="0000013D-0000-0000-C000-000000000046")

class IComCatalog(IUnknown):
    IID = generate_IID(0x000001E0, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IComCatalog", strid="000001E0-0000-0000-C000-000000000046")

class IDispatch(IUnknown):
    IID = generate_IID(0x00020400, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IDispatch", strid="00020400-0000-0000-C000-000000000046")

class IEnumVARIANT(IUnknown):
    IID = generate_IID(0x00020404, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IEnumVARIANT", strid="00020404-0000-0000-C000-000000000046")

class IInternalUnknown(IUnknown):
    IID = generate_IID(0x00000021, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IInternalUnknown", strid="00000021-0000-0000-C000-000000000046")

class IMarshal(IUnknown):
    IID = generate_IID(0x00000003, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IMarshal", strid="00000003-0000-0000-C000-000000000046")

class IMoniker(IUnknown):
    IID = generate_IID(0x0000000F, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IMoniker", strid="0000000F-0000-0000-C000-000000000046")

class INetFwPolicy2(IUnknown):
    IID = generate_IID(0x98325047, 0xC671, 0x4174, 0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86, name="INetFwPolicy2", strid="98325047-C671-4174-8D81-DEFCD3F03186")

class INetFwRule(IUnknown):
    IID = generate_IID(0xAF230D27, 0xBABA, 0x4E42, 0xAC, 0xED, 0xF5, 0x24, 0xF2, 0x2C, 0xFC, 0xE2, name="INetFwRule", strid="AF230D27-BABA-4E42-ACED-F524F22CFCE2")

class INetFwRules(IUnknown):
    IID = generate_IID(0x9C4C6277, 0x5027, 0x441E, 0xAF, 0xAE, 0xCA, 0x1F, 0x54, 0x2D, 0xA0, 0x09, name="INetFwRules", strid="9C4C6277-5027-441E-AFAE-CA1F542DA009")

class INetFwServiceRestriction(IUnknown):
    IID = generate_IID(0x8267BBE3, 0xF890, 0x491C, 0xB7, 0xB6, 0x2D, 0xB1, 0xEF, 0x0E, 0x5D, 0x2B, name="INetFwServiceRestriction", strid="8267BBE3-F890-491C-B7B6-2DB1EF0E5D2B")

class IObjContext(IUnknown):
    IID = generate_IID(0x000001C6, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IObjContext", strid="000001C6-0000-0000-C000-000000000046")

class IPersist(IUnknown):
    IID = generate_IID(0x0000010C, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IPersist", strid="0000010C-0000-0000-C000-000000000046")

class IPersistFile(IUnknown):
    IID = generate_IID(0x0000010B, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IPersistFile", strid="0000010B-0000-0000-C000-000000000046")

class IRemUnknown(IUnknown):
    IID = generate_IID(0x00000131, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IRemUnknown", strid="00000131-0000-0000-C000-000000000046")

class IShellLinkA(IUnknown):
    IID = generate_IID(0x000214EE, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IShellLinkA", strid="000214EE-0000-0000-C000-000000000046")

class IShellLinkW(IUnknown):
    IID = generate_IID(0x000214F9, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IShellLinkW", strid="000214F9-0000-0000-C000-000000000046")

class IStdIdentity(IUnknown):
    IID = generate_IID(0x0000001b, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IStdIdentity", strid="0000001b-0000-0000-c000-000000000046")

class IStorage(IUnknown):
    IID = generate_IID(0x0000000B, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IStorage", strid="0000000B-0000-0000-C000-000000000046")

class IStream(IUnknown):
    IID = generate_IID(0x0000000C, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IStream", strid="0000000C-0000-0000-C000-000000000046")

OLD_IStream = IStream
class IStream(OLD_IStream):

    def read(self, size):
        buffer = (CHAR * size)()
        size_read = ULONG()
        self.Read(buffer, size, size_read)
        return buffer[:size_read.value]


    def write(self, data):
        assert isinstance(data, bytes), "IStream.write() only accept bytes but {0} was passed".format(type(data))
        written = ULONG()
        self.Write(data, len(data), written)
        return written.value

    def seek(self, position, origin=STREAM_SEEK_SET):
        newpos = ULARGE_INTEGER()
        self.Seek(position, origin, newpos)
        return newpos.value




class ITypeComp(IUnknown):
    IID = generate_IID(0x00020403, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="ITypeComp", strid="00020403-0000-0000-C000-000000000046")

class ITypeInfo(IUnknown):
    IID = generate_IID(0x00020401, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="ITypeInfo", strid="00020401-0000-0000-C000-000000000046")

class ITypeLib(IUnknown):
    IID = generate_IID(0x00020402, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="ITypeLib", strid="00020402-0000-0000-C000-000000000046")

class IBackgroundCopyCallback(IUnknown):
    IID = generate_IID(0x97EA99C7, 0x0186, 0x4AD4, 0x8D, 0xF9, 0xC5, 0xB4, 0xE0, 0xED, 0x6B, 0x22, name="IBackgroundCopyCallback", strid="97EA99C7-0186-4AD4-8DF9-C5B4E0ED6B22")

class IBackgroundCopyError(IUnknown):
    IID = generate_IID(0x19C613A0, 0xFCB8, 0x4F28, 0x81, 0xAE, 0x89, 0x7C, 0x3D, 0x07, 0x8F, 0x81, name="IBackgroundCopyError", strid="19C613A0-FCB8-4F28-81AE-897C3D078F81")

class IBackgroundCopyFile(IUnknown):
    IID = generate_IID(0x01B7BD23, 0xFB88, 0x4A77, 0x84, 0x90, 0x58, 0x91, 0xD3, 0xE4, 0x65, 0x3A, name="IBackgroundCopyFile", strid="01B7BD23-FB88-4A77-8490-5891D3E4653A")

class IBackgroundCopyFile2(IBackgroundCopyFile):
    IID = generate_IID(0x83E81B93, 0x0873, 0x474D, 0x8A, 0x8C, 0xF2, 0x01, 0x8B, 0x1A, 0x93, 0x9C, name="IBackgroundCopyFile2", strid="83E81B93-0873-474D-8A8C-F2018B1A939C")

class IBackgroundCopyFile3(IBackgroundCopyFile2):
    IID = generate_IID(0x659CDEAA, 0x489E, 0x11D9, 0xA9, 0xCD, 0x00, 0x0D, 0x56, 0x96, 0x52, 0x51, name="IBackgroundCopyFile3", strid="659CDEAA-489E-11D9-A9CD-000D56965251")

class IBackgroundCopyJob(IUnknown):
    IID = generate_IID(0x37668D37, 0x507E, 0x4160, 0x93, 0x16, 0x26, 0x30, 0x6D, 0x15, 0x0B, 0x12, name="IBackgroundCopyJob", strid="37668D37-507E-4160-9316-26306D150B12")

class IBackgroundCopyJob2(IBackgroundCopyJob):
    IID = generate_IID(0x54B50739, 0x686F, 0x45EB, 0x9D, 0xFF, 0xD6, 0xA9, 0xA0, 0xFA, 0xA9, 0xAF, name="IBackgroundCopyJob2", strid="54B50739-686F-45EB-9DFF-D6A9A0FAA9AF")

class IBackgroundCopyManager(IUnknown):
    IID = generate_IID(0x5CE34C0D, 0x0DC9, 0x4C1F, 0x89, 0x7C, 0xDA, 0xA1, 0xB7, 0x8C, 0xEE, 0x7C, name="IBackgroundCopyManager", strid="5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C")

class IEnumBackgroundCopyFiles(IUnknown):
    IID = generate_IID(0xCA51E165, 0xC365, 0x424C, 0x8D, 0x41, 0x24, 0xAA, 0xA4, 0xFF, 0x3C, 0x40, name="IEnumBackgroundCopyFiles", strid="CA51E165-C365-424C-8D41-24AAA4FF3C40")

class IEnumBackgroundCopyJobs(IUnknown):
    IID = generate_IID(0x1AF4F612, 0x3B71, 0x466F, 0x8F, 0x58, 0x7B, 0x6F, 0x73, 0xAC, 0x57, 0xAD, name="IEnumBackgroundCopyJobs", strid="1AF4F612-3B71-466F-8F58-7B6F73AC57AD")

class IActivationProperties(IUnknown):
    IID = generate_IID(0x000001AF, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IActivationProperties", strid="000001AF-0000-0000-C000-000000000046")

class IActivationPropertiesOut(IUnknown):
    IID = generate_IID(0x000001A3, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IActivationPropertiesOut", strid="000001A3-0000-0000-C000-000000000046")

class IActivationPropertiesIn(IUnknown):
    IID = generate_IID(0x000001A2, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IActivationPropertiesIn", strid="000001A2-0000-0000-C000-000000000046")

class IActivationStageInfo(IUnknown):
    IID = generate_IID(0x000001A8, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IActivationStageInfo", strid="000001A8-0000-0000-C000-000000000046")

class IClassClassicInfo(IUnknown):
    IID = generate_IID(0x000001E2, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IClassClassicInfo", strid="000001E2-0000-0000-C000-000000000046")

class IComClassInfo(IUnknown):
    IID = generate_IID(0x000001E1, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IComClassInfo", strid="000001E1-0000-0000-C000-000000000046")

class IContext(IUnknown):
    IID = generate_IID(0x000001C0, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IContext", strid="000001C0-0000-0000-C000-000000000046")

class IEnumContextProps(IUnknown):
    IID = generate_IID(0x000001C1, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IEnumContextProps", strid="000001C1-0000-0000-C000-000000000046")

class IEnumSTATSTG(IUnknown):
    IID = generate_IID(0x0000000D, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IEnumSTATSTG", strid="0000000D-0000-0000-C000-000000000046")

class IInitActivationPropertiesIn(IUnknown):
    IID = generate_IID(0x000001A1, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IInitActivationPropertiesIn", strid="000001A1-0000-0000-C000-000000000046")

class IOpaqueDataInfo(IUnknown):
    IID = generate_IID(0x000001A9, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IOpaqueDataInfo", strid="000001A9-0000-0000-C000-000000000046")

class IPrivActivationPropertiesIn(IUnknown):
    IID = generate_IID(0x000001B5, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IPrivActivationPropertiesIn", strid="000001B5-0000-0000-C000-000000000046")

class IPrivActivationPropertiesOut(IUnknown):
    IID = generate_IID(0x000001B0, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IPrivActivationPropertiesOut", strid="000001B0-0000-0000-C000-000000000046")

class IScmReplyInfo(IUnknown):
    IID = generate_IID(0x000001B6, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IScmReplyInfo", strid="000001B6-0000-0000-C000-000000000046")

class IScmRequestInfo(IUnknown):
    IID = generate_IID(0x000001AA, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IScmRequestInfo", strid="000001AA-0000-0000-C000-000000000046")

class IStandardActivator(IUnknown):
    IID = generate_IID(0x000001B8, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IStandardActivator", strid="000001B8-0000-0000-C000-000000000046")

class ISystemActivator(IUnknown):
    IID = generate_IID(0x000001A0, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="ISystemActivator", strid="000001A0-0000-0000-C000-000000000046")

class IBindCtx(IUnknown):
    IID = generate_IID(0x0000000E, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IBindCtx", strid="0000000E-0000-0000-C000-000000000046")

class IEnumExplorerCommand(IUnknown):
    IID = generate_IID(0xA88826F8, 0x186F, 0x4987, 0xAA, 0xDE, 0xEA, 0x0C, 0xEF, 0x8F, 0xBF, 0xE8, name="IEnumExplorerCommand", strid="A88826F8-186F-4987-AADE-EA0CEF8FBFE8")

class IEnumMoniker(IUnknown):
    IID = generate_IID(0x00000102, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IEnumMoniker", strid="00000102-0000-0000-C000-000000000046")

class IEnumShellItems(IUnknown):
    IID = generate_IID(0x70629033, 0xE363, 0x4A28, 0xA5, 0x67, 0x0D, 0xB7, 0x80, 0x06, 0xE6, 0xD7, name="IEnumShellItems", strid="70629033-E363-4A28-A567-0DB78006E6D7")

class IEnumString(IUnknown):
    IID = generate_IID(0x00000101, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IEnumString", strid="00000101-0000-0000-C000-000000000046")

class IExplorerCommand(IUnknown):
    IID = generate_IID(0xA08CE4D0, 0xFA25, 0x44AB, 0xB5, 0x7C, 0xC7, 0xB1, 0xC3, 0x23, 0xE0, 0xB9, name="IExplorerCommand", strid="A08CE4D0-FA25-44AB-B57C-C7B1C323E0B9")

class IRunningObjectTable(IUnknown):
    IID = generate_IID(0x00000010, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IRunningObjectTable", strid="00000010-0000-0000-C000-000000000046")

class IShellItem(IUnknown):
    IID = generate_IID(0x43826D1E, 0xE718, 0x42EE, 0xBC, 0x55, 0xA1, 0xE2, 0x61, 0xC3, 0x7B, 0xFE, name="IShellItem", strid="43826D1E-E718-42EE-BC55-A1E261C37BFE")

class IShellItemArray(IUnknown):
    IID = generate_IID(0x787F8E92, 0x9837, 0x4011, 0x9F, 0x83, 0x7D, 0xE5, 0x93, 0xBD, 0xC0, 0x02, name="IShellItemArray", strid="787F8E92-9837-4011-9F83-7DE593BDC002")

class IProxyManager(IUnknown):
    IID = generate_IID(0x00000008, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IProxyManager", strid="00000008-0000-0000-c000-000000000046")

class IProxyServerIdentity(IUnknown):
    IID = generate_IID(0x5524fe34, 0x8da7, 0x40a8, 0x81, 0x65, 0xe8, 0xb3, 0x7a, 0x8b, 0x4a, 0x4b, name="IProxyServerIdentity", strid="5524fe34-8da7-40a8-8165-e8b37a8b4a4b")

class IApplicationActivationManager(IUnknown):
    IID = generate_IID(0x2E941141, 0x7F97, 0x4756, 0xBA, 0x1D, 0x9D, 0xEC, 0xDE, 0x89, 0x4A, 0x3D, name="IApplicationActivationManager", strid="2E941141-7F97-4756-BA1D-9DECDE894A3D")

class IPackageDebugSettings(IUnknown):
    IID = generate_IID(0xF27C3930, 0x8029, 0x4AD1, 0x94, 0xE3, 0x3D, 0xBA, 0x41, 0x78, 0x10, 0xC1, name="IPackageDebugSettings", strid="F27C3930-8029-4AD1-94E3-3DBA417810C1")

class IPackageExecutionStateChangeNotification(IUnknown):
    IID = generate_IID(0x1BB12A62, 0x2AD8, 0x432B, 0x8C, 0xCF, 0x0C, 0x2C, 0x52, 0xAF, 0xCD, 0x5B, name="IPackageExecutionStateChangeNotification", strid="1BB12A62-2AD8-432B-8CCF-0C2C52AFCD5B")

class IChannelHook(IUnknown):
    IID = generate_IID(0x1008C4A0, 0x7613, 0x11CF, 0x9A, 0xF1, 0x00, 0x20, 0xAF, 0x6E, 0x72, 0xF4, name="IChannelHook", strid="1008C4A0-7613-11CF-9AF1-0020AF6E72F4")

class IRpcChannelBuffer(IUnknown):
    IID = generate_IID(0xD5F56B60, 0x593B, 0x101A, 0xB5, 0x69, 0x08, 0x00, 0x2B, 0x2D, 0xBF, 0x7A, name="IRpcChannelBuffer", strid="D5F56B60-593B-101A-B569-08002B2DBF7A")

class IRpcHelper(IUnknown):
    IID = generate_IID(0x00000149, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IRpcHelper", strid="00000149-0000-0000-C000-000000000046")

class IRpcOptions(IUnknown):
    IID = generate_IID(0x00000144, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, name="IRpcOptions", strid="00000144-0000-0000-C000-000000000046")

class IRpcStubBuffer(IUnknown):
    IID = generate_IID(0xD5F56AFC, 0x593B, 0x101A, 0xB5, 0x69, 0x08, 0x00, 0x2B, 0x2D, 0xBF, 0x7A, name="IRpcStubBuffer", strid="D5F56AFC-593B-101A-B569-08002B2DBF7A")

class IAction(IUnknown):
    IID = generate_IID(0xBAE54997, 0x48B1, 0x4CBE, 0x99, 0x65, 0xD6, 0xBE, 0x26, 0x3E, 0xBE, 0xA4, name="IAction", strid="BAE54997-48B1-4CBE-9965-D6BE263EBEA4")

class IActionCollection(IUnknown):
    IID = generate_IID(0x02820E19, 0x7B98, 0x4ED2, 0xB2, 0xE8, 0xFD, 0xCC, 0xCE, 0xFF, 0x61, 0x9B, name="IActionCollection", strid="02820E19-7B98-4ED2-B2E8-FDCCCEFF619B")

class IComHandlerAction(IUnknown):
    IID = generate_IID(0x6D2FD252, 0x75C5, 0x4F66, 0x90, 0xBA, 0x2A, 0x7D, 0x8C, 0xC3, 0x03, 0x9F, name="IComHandlerAction", strid="6D2FD252-75C5-4F66-90BA-2A7D8CC3039F")

class IEmailAction(IUnknown):
    IID = generate_IID(0x10F62C64, 0x7E16, 0x4314, 0xA0, 0xC2, 0x0C, 0x36, 0x83, 0xF9, 0x9D, 0x40, name="IEmailAction", strid="10F62C64-7E16-4314-A0C2-0C3683F99D40")

class IExecAction(IUnknown):
    IID = generate_IID(0x4C3D624D, 0xFD6B, 0x49A3, 0xB9, 0xB7, 0x09, 0xCB, 0x3C, 0xD3, 0xF0, 0x47, name="IExecAction", strid="4C3D624D-FD6B-49A3-B9B7-09CB3CD3F047")

class IIdleSettings(IUnknown):
    IID = generate_IID(0x84594461, 0x0053, 0x4342, 0xA8, 0xFD, 0x08, 0x8F, 0xAB, 0xF1, 0x1F, 0x32, name="IIdleSettings", strid="84594461-0053-4342-A8FD-088FABF11F32")

class INetworkSettings(IUnknown):
    IID = generate_IID(0x9F7DEA84, 0xC30B, 0x4245, 0x80, 0xB6, 0x00, 0xE9, 0xF6, 0x46, 0xF1, 0xB4, name="INetworkSettings", strid="9F7DEA84-C30B-4245-80B6-00E9F646F1B4")

class IPrincipal(IUnknown):
    IID = generate_IID(0xD98D51E5, 0xC9B4, 0x496A, 0xA9, 0xC1, 0x18, 0x98, 0x02, 0x61, 0xCF, 0x0F, name="IPrincipal", strid="D98D51E5-C9B4-496A-A9C1-18980261CF0F")

class IRegisteredTask(IUnknown):
    IID = generate_IID(0x9C86F320, 0xDEE3, 0x4DD1, 0xB9, 0x72, 0xA3, 0x03, 0xF2, 0x6B, 0x06, 0x1E, name="IRegisteredTask", strid="9C86F320-DEE3-4DD1-B972-A303F26B061E")

class IRegisteredTaskCollection(IUnknown):
    IID = generate_IID(0x86627EB4, 0x42A7, 0x41E4, 0xA4, 0xD9, 0xAC, 0x33, 0xA7, 0x2F, 0x2D, 0x52, name="IRegisteredTaskCollection", strid="86627EB4-42A7-41E4-A4D9-AC33A72F2D52")

class IRegistrationInfo(IUnknown):
    IID = generate_IID(0x416D8B73, 0xCB41, 0x4EA1, 0x80, 0x5C, 0x9B, 0xE9, 0xA5, 0xAC, 0x4A, 0x74, name="IRegistrationInfo", strid="416D8B73-CB41-4EA1-805C-9BE9A5AC4A74")

class IRepetitionPattern(IUnknown):
    IID = generate_IID(0x7FB9ACF1, 0x26BE, 0x400E, 0x85, 0xB5, 0x29, 0x4B, 0x9C, 0x75, 0xDF, 0xD6, name="IRepetitionPattern", strid="7FB9ACF1-26BE-400E-85B5-294B9C75DFD6")

class IRunningTask(IUnknown):
    IID = generate_IID(0x653758FB, 0x7B9A, 0x4F1E, 0xA4, 0x71, 0xBE, 0xEB, 0x8E, 0x9B, 0x83, 0x4E, name="IRunningTask", strid="653758FB-7B9A-4F1E-A471-BEEB8E9B834E")

class IRunningTaskCollection(IUnknown):
    IID = generate_IID(0x6A67614B, 0x6828, 0x4FEC, 0xAA, 0x54, 0x6D, 0x52, 0xE8, 0xF1, 0xF2, 0xDB, name="IRunningTaskCollection", strid="6A67614B-6828-4FEC-AA54-6D52E8F1F2DB")

class IShowMessageAction(IUnknown):
    IID = generate_IID(0x505E9E68, 0xAF89, 0x46B8, 0xA3, 0x0F, 0x56, 0x16, 0x2A, 0x83, 0xD5, 0x37, name="IShowMessageAction", strid="505E9E68-AF89-46B8-A30F-56162A83D537")

class ITaskDefinition(IUnknown):
    IID = generate_IID(0xF5BC8FC5, 0x536D, 0x4F77, 0xB8, 0x52, 0xFB, 0xC1, 0x35, 0x6F, 0xDE, 0xB6, name="ITaskDefinition", strid="F5BC8FC5-536D-4F77-B852-FBC1356FDEB6")

class ITaskFolder(IUnknown):
    IID = generate_IID(0x8CFAC062, 0xA080, 0x4C15, 0x9A, 0x88, 0xAA, 0x7C, 0x2A, 0xF8, 0x0D, 0xFC, name="ITaskFolder", strid="8CFAC062-A080-4C15-9A88-AA7C2AF80DFC")

class ITaskFolderCollection(IUnknown):
    IID = generate_IID(0x79184A66, 0x8664, 0x423F, 0x97, 0xF1, 0x63, 0x73, 0x56, 0xA5, 0xD8, 0x12, name="ITaskFolderCollection", strid="79184A66-8664-423F-97F1-637356A5D812")

class ITaskNamedValueCollection(IUnknown):
    IID = generate_IID(0xB4EF826B, 0x63C3, 0x46E4, 0xA5, 0x04, 0xEF, 0x69, 0xE4, 0xF7, 0xEA, 0x4D, name="ITaskNamedValueCollection", strid="B4EF826B-63C3-46E4-A504-EF69E4F7EA4D")

class ITaskNamedValuePair(IUnknown):
    IID = generate_IID(0x39038068, 0x2B46, 0x4AFD, 0x86, 0x62, 0x7B, 0xB6, 0xF8, 0x68, 0xD2, 0x21, name="ITaskNamedValuePair", strid="39038068-2B46-4AFD-8662-7BB6F868D221")

class ITaskService(IUnknown):
    IID = generate_IID(0x2FABA4C7, 0x4DA9, 0x4013, 0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85, name="ITaskService", strid="2FABA4C7-4DA9-4013-9697-20CC3FD40F85")

class ITaskSettings(IUnknown):
    IID = generate_IID(0x8FD4711D, 0x2D02, 0x4C8C, 0x87, 0xE3, 0xEF, 0xF6, 0x99, 0xDE, 0x12, 0x7E, name="ITaskSettings", strid="8FD4711D-2D02-4C8C-87E3-EFF699DE127E")

class ITrigger(IUnknown):
    IID = generate_IID(0x09941815, 0xEA89, 0x4B5B, 0x89, 0xE0, 0x2A, 0x77, 0x38, 0x01, 0xFA, 0xC3, name="ITrigger", strid="09941815-EA89-4B5B-89E0-2A773801FAC3")

class ITriggerCollection(IUnknown):
    IID = generate_IID(0x85DF5081, 0x1B24, 0x4F32, 0x87, 0x8A, 0xD9, 0xD1, 0x4D, 0xF4, 0xCB, 0x77, name="ITriggerCollection", strid="85DF5081-1B24-4F32-878A-D9D14DF4CB77")

class IWebBrowser2(IUnknown):
    IID = generate_IID(0xD30C1661, 0xCDAF, 0x11D0, 0x8A, 0x3E, 0x00, 0xC0, 0x4F, 0xC9, 0xE2, 0x6E, name="IWebBrowser2", strid="D30C1661-CDAF-11D0-8A3E-00C04FC9E26E")

class IEnumWbemClassObject(IUnknown):
    IID = generate_IID(0x027947E1, 0xD731, 0x11CE, 0xA3, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, name="IEnumWbemClassObject", strid="027947E1-D731-11CE-A357-000000000001")

class IWbemCallResult(IUnknown):
    IID = generate_IID(0x44ACA675, 0xE8FC, 0x11D0, 0xA0, 0x7C, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20, name="IWbemCallResult", strid="44ACA675-E8FC-11D0-A07C-00C04FB68820")

class IWbemClassObject(IUnknown):
    IID = generate_IID(0xDC12A681, 0x737F, 0x11CF, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, name="IWbemClassObject", strid="DC12A681-737F-11CF-884D-00AA004B2E24")

class IWbemContext(IUnknown):
    IID = generate_IID(0x44ACA674, 0xE8FC, 0x11D0, 0xA0, 0x7C, 0x00, 0xC0, 0x4F, 0xB6, 0x88, 0x20, name="IWbemContext", strid="44ACA674-E8FC-11D0-A07C-00C04FB68820")

class IWbemLocator(IUnknown):
    IID = generate_IID(0xDC12A687, 0x737F, 0x11CF, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, name="IWbemLocator", strid="DC12A687-737F-11CF-884D-00AA004B2E24")

class IWbemObjectSink(IUnknown):
    IID = generate_IID(0x7C857801, 0x7381, 0x11CF, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, name="IWbemObjectSink", strid="7C857801-7381-11CF-884D-00AA004B2E24")

class IWbemObjectTextSrc(IUnknown):
    IID = generate_IID(0xBFBF883A, 0xCAD7, 0x11D3, 0xA1, 0x1B, 0x00, 0x10, 0x5A, 0x1F, 0x51, 0x5A, name="IWbemObjectTextSrc", strid="BFBF883A-CAD7-11D3-A11B-00105A1F515A")

class IWbemQualifierSet(IUnknown):
    IID = generate_IID(0xDC12A680, 0x737F, 0x11CF, 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24, name="IWbemQualifierSet", strid="DC12A680-737F-11CF-884D-00AA004B2E24")

class IWbemServices(IUnknown):
    IID = generate_IID(0x0EFA6E54, 0xF313, 0x405D, 0xB5, 0xD8, 0x83, 0x0A, 0x91, 0x4F, 0x64, 0x96, name="IWbemServices", strid="0EFA6E54-F313-405D-B5D8-830A914F6496")

# class IUnknownImplem(windows.com.COMImplementation):
#     IMPLEMENT = IUnknown
#
IUnknown._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
    }

# class ICallFactoryImplem(windows.com.COMImplementation):
#     IMPLEMENT = ICallFactory
#
#     def CreateCall(self, This, riid, pCtrlUnk, riid2, ppv):
#         print('ICallFactory.CreateCall')
#         return E_NOTIMPL
#
ICallFactory._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # CreateCall -> riid:REFIID, pCtrlUnk:*IUnknown, riid2:REFIID, ppv:**IUnknown
        "CreateCall": ctypes.WINFUNCTYPE(HRESULT, REFIID, IUnknown, REFIID, POINTER(IUnknown))(3, "CreateCall"),
    }

# class ICallFrameImplem(windows.com.COMImplementation):
#     IMPLEMENT = ICallFrame
#
#     def GetInfo(self, This, pInfo):
#         print('ICallFrame.GetInfo')
#         return E_NOTIMPL
#
#     def GetIIDAndMethod(self, This, pIID, piMethod):
#         print('ICallFrame.GetIIDAndMethod')
#         return E_NOTIMPL
#
#     def GetNames(self, This, pwszInterface, pwszMethod):
#         print('ICallFrame.GetNames')
#         return E_NOTIMPL
#
#     def GetStackLocation(self, This):
#         print('ICallFrame.GetStackLocation')
#         return E_NOTIMPL
#
#     def SetStackLocation(self, This, pvStack):
#         print('ICallFrame.SetStackLocation')
#         return E_NOTIMPL
#
#     def SetReturnValue(self, This, hr):
#         print('ICallFrame.SetReturnValue')
#         return E_NOTIMPL
#
#     def GetReturnValue(self, This):
#         print('ICallFrame.GetReturnValue')
#         return E_NOTIMPL
#
#     def GetParamInfo(self, This, iparam, pInfo):
#         print('ICallFrame.GetParamInfo')
#         return E_NOTIMPL
#
#     def SetParam(self, This, iparam, pvar):
#         print('ICallFrame.SetParam')
#         return E_NOTIMPL
#
#     def GetParam(self, This, iparam, pvar):
#         print('ICallFrame.GetParam')
#         return E_NOTIMPL
#
#     def Copy(self, This, copyControl, pWalker, ppFrame):
#         print('ICallFrame.Copy')
#         return E_NOTIMPL
#
#     def Free(self, This, pframeArgsDest, pWalkerDestFree, pWalkerCopy, freeFlags, pWalkerFree, nullFlags):
#         print('ICallFrame.Free')
#         return E_NOTIMPL
#
#     def FreeParam(self, This, iparam, freeFlags, pWalkerFree, nullFlags):
#         print('ICallFrame.FreeParam')
#         return E_NOTIMPL
#
#     def WalkFrame(self, This, walkWhat, pWalker):
#         print('ICallFrame.WalkFrame')
#         return E_NOTIMPL
#
#     def GetMarshalSizeMax(self, This, pmshlContext, mshlflags, pcbBufferNeeded):
#         print('ICallFrame.GetMarshalSizeMax')
#         return E_NOTIMPL
#
#     def Marshal(self, This, pmshlContext, mshlflags, pBuffer, cbBuffer, pcbBufferUsed, pdataRep, prpcFlags):
#         print('ICallFrame.Marshal')
#         return E_NOTIMPL
#
#     def Unmarshal(self, This, pBuffer, cbBuffer, dataRep, pcontext, pcbUnmarshalled):
#         print('ICallFrame.Unmarshal')
#         return E_NOTIMPL
#
#     def ReleaseMarshalData(self, This, pBuffer, cbBuffer, ibFirstRelease, dataRep, pcontext):
#         print('ICallFrame.ReleaseMarshalData')
#         return E_NOTIMPL
#
#     def Invoke(self, This, pvReceiver):
#         print('ICallFrame.Invoke')
#         return E_NOTIMPL
#
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

# class ICallFrameEventsImplem(windows.com.COMImplementation):
#     IMPLEMENT = ICallFrameEvents
#
#     def OnCall(self, This, pFrame):
#         print('ICallFrameEvents.OnCall')
#         return E_NOTIMPL
#
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

# class ICallFrameWalkerImplem(windows.com.COMImplementation):
#     IMPLEMENT = ICallFrameWalker
#
#     def OnWalkInterface(self, This, iid, ppvInterface, fIn, fOut):
#         print('ICallFrameWalker.OnWalkInterface')
#         return E_NOTIMPL
#
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

# class ICallInterceptorImplem(windows.com.COMImplementation):
#     IMPLEMENT = ICallInterceptor
#
#     def CallIndirect(self, This, phrReturn, iMethod, pvArgs, cbArgs):
#         print('ICallInterceptor.CallIndirect')
#         return E_NOTIMPL
#
#     def GetMethodInfo(self, This, iMethod, pInfo, pwszMethod):
#         print('ICallInterceptor.GetMethodInfo')
#         return E_NOTIMPL
#
#     def GetStackSize(self, This, iMethod, cbArgs):
#         print('ICallInterceptor.GetStackSize')
#         return E_NOTIMPL
#
#     def GetIID(self, This, piid, pfDerivesFromIDispatch, pcMethod, pwszInterface):
#         print('ICallInterceptor.GetIID')
#         return E_NOTIMPL
#
#     def RegisterSink(self, This, psink):
#         print('ICallInterceptor.RegisterSink')
#         return E_NOTIMPL
#
#     def GetRegisteredSink(self, This, ppsink):
#         print('ICallInterceptor.GetRegisteredSink')
#         return E_NOTIMPL
#
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

# class IClassFactoryImplem(windows.com.COMImplementation):
#     IMPLEMENT = IClassFactory
#
#     def CreateInstance(self, This, pUnkOuter, riid, ppvObject):
#         print('IClassFactory.CreateInstance')
#         return E_NOTIMPL
#
#     def LockServer(self, This, fLock):
#         print('IClassFactory.LockServer')
#         return E_NOTIMPL
#
IClassFactory._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # CreateInstance -> pUnkOuter:*IUnknown, riid:REFIID, ppvObject:**void
        "CreateInstance": ctypes.WINFUNCTYPE(HRESULT, IUnknown, REFIID, POINTER(PVOID))(3, "CreateInstance"),
        # LockServer -> fLock:BOOL
        "LockServer": ctypes.WINFUNCTYPE(HRESULT, BOOL)(4, "LockServer"),
    }

# class IClientSecurityImplem(windows.com.COMImplementation):
#     IMPLEMENT = IClientSecurity
#
#     def QueryBlanket(self, This, pProxy, pAuthnSvc, pAuthzSvc, pServerPrincName, pAuthnLevel, pImpLevel, pAuthInfo, pCapabilites):
#         print('IClientSecurity.QueryBlanket')
#         return E_NOTIMPL
#
#     def SetBlanket(self, This, pProxy, dwAuthnSvc, dwAuthzSvc, pServerPrincName, dwAuthnLevel, dwImpLevel, pAuthInfo, dwCapabilities):
#         print('IClientSecurity.SetBlanket')
#         return E_NOTIMPL
#
#     def CopyProxy(self, This, pProxy, ppCopy):
#         print('IClientSecurity.CopyProxy')
#         return E_NOTIMPL
#
IClientSecurity._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # QueryBlanket -> pProxy:*IUnknown, pAuthnSvc:*DWORD, pAuthzSvc:*DWORD, pServerPrincName:**OLECHAR, pAuthnLevel:*DWORD, pImpLevel:*DWORD, pAuthInfo:**void, pCapabilites:*DWORD
        "QueryBlanket": ctypes.WINFUNCTYPE(HRESULT, IUnknown, POINTER(DWORD), POINTER(DWORD), POINTER(POINTER(OLECHAR)), POINTER(DWORD), POINTER(DWORD), POINTER(PVOID), POINTER(DWORD))(3, "QueryBlanket"),
        # SetBlanket -> pProxy:*IUnknown, dwAuthnSvc:DWORD, dwAuthzSvc:DWORD, pServerPrincName:*OLECHAR, dwAuthnLevel:DWORD, dwImpLevel:DWORD, pAuthInfo:*void, dwCapabilities:DWORD
        "SetBlanket": ctypes.WINFUNCTYPE(HRESULT, IUnknown, DWORD, DWORD, POINTER(OLECHAR), DWORD, DWORD, PVOID, DWORD)(4, "SetBlanket"),
        # CopyProxy -> pProxy:*IUnknown, ppCopy:**IUnknown
        "CopyProxy": ctypes.WINFUNCTYPE(HRESULT, IUnknown, POINTER(IUnknown))(5, "CopyProxy"),
    }

# class IComCatalogImplem(windows.com.COMImplementation):
#     IMPLEMENT = IComCatalog
#
#     def GetClassInfo(self, This, guidConfiguredClsid, riid, ppv):
#         print('IComCatalog.GetClassInfo')
#         return E_NOTIMPL
#
#     def GetApplicationInfo(self, This, guidApplId, riid, ppv):
#         print('IComCatalog.GetApplicationInfo')
#         return E_NOTIMPL
#
#     def GetProcessInfo(self, This, guidProcess, riid, ppv):
#         print('IComCatalog.GetProcessInfo')
#         return E_NOTIMPL
#
#     def GetServerGroupInfo(self, This, guidServerGroup, riid, ppv):
#         print('IComCatalog.GetServerGroupInfo')
#         return E_NOTIMPL
#
#     def GetRetQueueInfo(self, This, wszFormatName, riid, ppv):
#         print('IComCatalog.GetRetQueueInfo')
#         return E_NOTIMPL
#
#     def GetApplicationInfoForExe(self, This, pwszExeName, riid, ppv):
#         print('IComCatalog.GetApplicationInfoForExe')
#         return E_NOTIMPL
#
#     def GetTypeLibrary(self, This, guidTypeLib, riid, ppv):
#         print('IComCatalog.GetTypeLibrary')
#         return E_NOTIMPL
#
#     def GetInterfaceInfo(self, This, iidInterface, riid, ppv):
#         print('IComCatalog.GetInterfaceInfo')
#         return E_NOTIMPL
#
#     def FlushCache(self, This):
#         print('IComCatalog.FlushCache')
#         return E_NOTIMPL
#
#     def GetClassInfoFromProgId(self, This, pwszProgID, riid, ppv):
#         print('IComCatalog.GetClassInfoFromProgId')
#         return E_NOTIMPL
#
IComCatalog._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetClassInfo -> guidConfiguredClsid:REFGUID, riid:REFIID, ppv:**void
        "GetClassInfo": ctypes.WINFUNCTYPE(HRESULT, REFGUID, REFIID, POINTER(PVOID))(3, "GetClassInfo"),
        # GetApplicationInfo -> guidApplId:REFGUID, riid:REFIID, ppv:**void
        "GetApplicationInfo": ctypes.WINFUNCTYPE(HRESULT, REFGUID, REFIID, POINTER(PVOID))(4, "GetApplicationInfo"),
        # GetProcessInfo -> guidProcess:REFGUID, riid:REFIID, ppv:**void
        "GetProcessInfo": ctypes.WINFUNCTYPE(HRESULT, REFGUID, REFIID, POINTER(PVOID))(5, "GetProcessInfo"),
        # GetServerGroupInfo -> guidServerGroup:REFGUID, riid:REFIID, ppv:**void
        "GetServerGroupInfo": ctypes.WINFUNCTYPE(HRESULT, REFGUID, REFIID, POINTER(PVOID))(6, "GetServerGroupInfo"),
        # GetRetQueueInfo -> wszFormatName:*WCHAR, riid:REFIID, ppv:**void
        "GetRetQueueInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(WCHAR), REFIID, POINTER(PVOID))(7, "GetRetQueueInfo"),
        # GetApplicationInfoForExe -> pwszExeName:*WCHAR, riid:REFIID, ppv:**void
        "GetApplicationInfoForExe": ctypes.WINFUNCTYPE(HRESULT, POINTER(WCHAR), REFIID, POINTER(PVOID))(8, "GetApplicationInfoForExe"),
        # GetTypeLibrary -> guidTypeLib:REFGUID, riid:REFIID, ppv:**void
        "GetTypeLibrary": ctypes.WINFUNCTYPE(HRESULT, REFGUID, REFIID, POINTER(PVOID))(9, "GetTypeLibrary"),
        # GetInterfaceInfo -> iidInterface:REFIID, riid:REFIID, ppv:**void
        "GetInterfaceInfo": ctypes.WINFUNCTYPE(HRESULT, REFIID, REFIID, POINTER(PVOID))(10, "GetInterfaceInfo"),
        # FlushCache -> 
        "FlushCache": ctypes.WINFUNCTYPE(HRESULT)(11, "FlushCache"),
        # GetClassInfoFromProgId -> pwszProgID:*WCHAR, riid:REFIID, ppv:**void
        "GetClassInfoFromProgId": ctypes.WINFUNCTYPE(HRESULT, POINTER(WCHAR), REFIID, POINTER(PVOID))(12, "GetClassInfoFromProgId"),
    }

# class IDispatchImplem(windows.com.COMImplementation):
#     IMPLEMENT = IDispatch
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IDispatch.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IDispatch.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IDispatch.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IDispatch.Invoke')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
        # GetIDsOfNames -> riid:REFIID, rgszNames:*LPOLESTR, cNames:UINT, lcid:LCID, rgDispId:*DISPID
        "GetIDsOfNames": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(LPOLESTR), UINT, LCID, POINTER(DISPID))(5, "GetIDsOfNames"),
        # Invoke -> dispIdMember:DISPID, riid:REFIID, lcid:LCID, wFlags:WORD, pDispParams:*DISPPARAMS, pVarResult:*VARIANT, pExcepInfo:*EXCEPINFO, puArgErr:*UINT
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, DISPID, REFIID, LCID, WORD, POINTER(DISPPARAMS), POINTER(VARIANT), POINTER(EXCEPINFO), POINTER(UINT))(6, "Invoke"),
    }

# class IEnumVARIANTImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumVARIANT
#
#     def Next(self, This, celt, rgVar, pCeltFetched):
#         print('IEnumVARIANT.Next')
#         return E_NOTIMPL
#
#     def Skip(self, This, celt):
#         print('IEnumVARIANT.Skip')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IEnumVARIANT.Reset')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppEnum):
#         print('IEnumVARIANT.Clone')
#         return E_NOTIMPL
#
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

# class IInternalUnknownImplem(windows.com.COMImplementation):
#     IMPLEMENT = IInternalUnknown
#
#     def QueryInternalInterface(self, This, riid, ppv):
#         print('IInternalUnknown.QueryInternalInterface')
#         return E_NOTIMPL
#
IInternalUnknown._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # QueryInternalInterface -> riid:REFIID, ppv:**void
        "QueryInternalInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(3, "QueryInternalInterface"),
    }

# class IMarshalImplem(windows.com.COMImplementation):
#     IMPLEMENT = IMarshal
#
#     def GetUnmarshalClass(self, This, riid, pv, dwDestContext, pvDestContext, mshlflags, pCid):
#         print('IMarshal.GetUnmarshalClass')
#         return E_NOTIMPL
#
#     def GetMarshalSizeMax(self, This, riid, pv, dwDestContext, pvDestContext, mshlflags, pSize):
#         print('IMarshal.GetMarshalSizeMax')
#         return E_NOTIMPL
#
#     def MarshalInterface(self, This, pStm, riid, pv, dwDestContext, pvDestContext, mshlflags):
#         print('IMarshal.MarshalInterface')
#         return E_NOTIMPL
#
#     def UnmarshalInterface(self, This, pStm, riid, ppv):
#         print('IMarshal.UnmarshalInterface')
#         return E_NOTIMPL
#
#     def ReleaseMarshalData(self, This, pStm):
#         print('IMarshal.ReleaseMarshalData')
#         return E_NOTIMPL
#
#     def DisconnectObject(self, This, dwReserved):
#         print('IMarshal.DisconnectObject')
#         return E_NOTIMPL
#
IMarshal._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetUnmarshalClass -> riid:REFIID, pv:*void, dwDestContext:DWORD, pvDestContext:*void, mshlflags:DWORD, pCid:*CLSID
        "GetUnmarshalClass": ctypes.WINFUNCTYPE(HRESULT, REFIID, PVOID, DWORD, PVOID, DWORD, POINTER(CLSID))(3, "GetUnmarshalClass"),
        # GetMarshalSizeMax -> riid:REFIID, pv:*void, dwDestContext:DWORD, pvDestContext:*void, mshlflags:DWORD, pSize:*DWORD
        "GetMarshalSizeMax": ctypes.WINFUNCTYPE(HRESULT, REFIID, PVOID, DWORD, PVOID, DWORD, POINTER(DWORD))(4, "GetMarshalSizeMax"),
        # MarshalInterface -> pStm:*IStream, riid:REFIID, pv:*void, dwDestContext:DWORD, pvDestContext:*void, mshlflags:DWORD
        "MarshalInterface": ctypes.WINFUNCTYPE(HRESULT, IStream, REFIID, PVOID, DWORD, PVOID, DWORD)(5, "MarshalInterface"),
        # UnmarshalInterface -> pStm:*IStream, riid:REFIID, ppv:**void
        "UnmarshalInterface": ctypes.WINFUNCTYPE(HRESULT, IStream, REFIID, POINTER(PVOID))(6, "UnmarshalInterface"),
        # ReleaseMarshalData -> pStm:*IStream
        "ReleaseMarshalData": ctypes.WINFUNCTYPE(HRESULT, IStream)(7, "ReleaseMarshalData"),
        # DisconnectObject -> dwReserved:DWORD
        "DisconnectObject": ctypes.WINFUNCTYPE(HRESULT, DWORD)(8, "DisconnectObject"),
    }

# class IMonikerImplem(windows.com.COMImplementation):
#     IMPLEMENT = IMoniker
#
#     def GetClassID(self, This, pClassID):
#         print('IMoniker.GetClassID')
#         return E_NOTIMPL
#
#     def IsDirty(self, This):
#         print('IMoniker.IsDirty')
#         return E_NOTIMPL
#
#     def Load(self, This, pStm):
#         print('IMoniker.Load')
#         return E_NOTIMPL
#
#     def Save(self, This, pStm, fClearDirty):
#         print('IMoniker.Save')
#         return E_NOTIMPL
#
#     def GetSizeMax(self, This, pcbSize):
#         print('IMoniker.GetSizeMax')
#         return E_NOTIMPL
#
#     def BindToObject(self, This, pbc, pmkToLeft, riidResult, ppvResult):
#         print('IMoniker.BindToObject')
#         return E_NOTIMPL
#
#     def BindToStorage(self, This, pbc, pmkToLeft, riid, ppvObj):
#         print('IMoniker.BindToStorage')
#         return E_NOTIMPL
#
#     def Reduce(self, This, pbc, dwReduceHowFar, ppmkToLeft, ppmkReduced):
#         print('IMoniker.Reduce')
#         return E_NOTIMPL
#
#     def ComposeWith(self, This, pmkRight, fOnlyIfNotGeneric, ppmkComposite):
#         print('IMoniker.ComposeWith')
#         return E_NOTIMPL
#
#     def Enum(self, This, fForward, ppenumMoniker):
#         print('IMoniker.Enum')
#         return E_NOTIMPL
#
#     def IsEqual(self, This, pmkOtherMoniker):
#         print('IMoniker.IsEqual')
#         return E_NOTIMPL
#
#     def Hash(self, This, pdwHash):
#         print('IMoniker.Hash')
#         return E_NOTIMPL
#
#     def IsRunning(self, This, pbc, pmkToLeft, pmkNewlyRunning):
#         print('IMoniker.IsRunning')
#         return E_NOTIMPL
#
#     def GetTimeOfLastChange(self, This, pbc, pmkToLeft, pFileTime):
#         print('IMoniker.GetTimeOfLastChange')
#         return E_NOTIMPL
#
#     def Inverse(self, This, ppmk):
#         print('IMoniker.Inverse')
#         return E_NOTIMPL
#
#     def CommonPrefixWith(self, This, pmkOther, ppmkPrefix):
#         print('IMoniker.CommonPrefixWith')
#         return E_NOTIMPL
#
#     def RelativePathTo(self, This, pmkOther, ppmkRelPath):
#         print('IMoniker.RelativePathTo')
#         return E_NOTIMPL
#
#     def GetDisplayName(self, This, pbc, pmkToLeft, ppszDisplayName):
#         print('IMoniker.GetDisplayName')
#         return E_NOTIMPL
#
#     def ParseDisplayName(self, This, pbc, pmkToLeft, pszDisplayName, pchEaten, ppmkOut):
#         print('IMoniker.ParseDisplayName')
#         return E_NOTIMPL
#
#     def IsSystemMoniker(self, This, pdwMksys):
#         print('IMoniker.IsSystemMoniker')
#         return E_NOTIMPL
#
IMoniker._functions_ = {
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
        # Load -> pStm:*IStream
        "Load": ctypes.WINFUNCTYPE(HRESULT, IStream)(5, "Load"),
        # Save -> pStm:*IStream, fClearDirty:BOOL
        "Save": ctypes.WINFUNCTYPE(HRESULT, IStream, BOOL)(6, "Save"),
        # GetSizeMax -> pcbSize:*ULARGE_INTEGER
        "GetSizeMax": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULARGE_INTEGER))(7, "GetSizeMax"),
        # BindToObject -> pbc:*IBindCtx, pmkToLeft:*IMoniker, riidResult:REFIID, ppvResult:**void
        "BindToObject": ctypes.WINFUNCTYPE(HRESULT, IBindCtx, IMoniker, REFIID, POINTER(PVOID))(8, "BindToObject"),
        # BindToStorage -> pbc:*IBindCtx, pmkToLeft:*IMoniker, riid:REFIID, ppvObj:**void
        "BindToStorage": ctypes.WINFUNCTYPE(HRESULT, IBindCtx, IMoniker, REFIID, POINTER(PVOID))(9, "BindToStorage"),
        # Reduce -> pbc:*IBindCtx, dwReduceHowFar:DWORD, ppmkToLeft:**IMoniker, ppmkReduced:**IMoniker
        "Reduce": ctypes.WINFUNCTYPE(HRESULT, IBindCtx, DWORD, POINTER(IMoniker), POINTER(IMoniker))(10, "Reduce"),
        # ComposeWith -> pmkRight:*IMoniker, fOnlyIfNotGeneric:BOOL, ppmkComposite:**IMoniker
        "ComposeWith": ctypes.WINFUNCTYPE(HRESULT, IMoniker, BOOL, POINTER(IMoniker))(11, "ComposeWith"),
        # Enum -> fForward:BOOL, ppenumMoniker:**IEnumMoniker
        "Enum": ctypes.WINFUNCTYPE(HRESULT, BOOL, POINTER(IEnumMoniker))(12, "Enum"),
        # IsEqual -> pmkOtherMoniker:*IMoniker
        "IsEqual": ctypes.WINFUNCTYPE(HRESULT, IMoniker)(13, "IsEqual"),
        # Hash -> pdwHash:*DWORD
        "Hash": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(14, "Hash"),
        # IsRunning -> pbc:*IBindCtx, pmkToLeft:*IMoniker, pmkNewlyRunning:*IMoniker
        "IsRunning": ctypes.WINFUNCTYPE(HRESULT, IBindCtx, IMoniker, IMoniker)(15, "IsRunning"),
        # GetTimeOfLastChange -> pbc:*IBindCtx, pmkToLeft:*IMoniker, pFileTime:*FILETIME
        "GetTimeOfLastChange": ctypes.WINFUNCTYPE(HRESULT, IBindCtx, IMoniker, POINTER(FILETIME))(16, "GetTimeOfLastChange"),
        # Inverse -> ppmk:**IMoniker
        "Inverse": ctypes.WINFUNCTYPE(HRESULT, POINTER(IMoniker))(17, "Inverse"),
        # CommonPrefixWith -> pmkOther:*IMoniker, ppmkPrefix:**IMoniker
        "CommonPrefixWith": ctypes.WINFUNCTYPE(HRESULT, IMoniker, POINTER(IMoniker))(18, "CommonPrefixWith"),
        # RelativePathTo -> pmkOther:*IMoniker, ppmkRelPath:**IMoniker
        "RelativePathTo": ctypes.WINFUNCTYPE(HRESULT, IMoniker, POINTER(IMoniker))(19, "RelativePathTo"),
        # GetDisplayName -> pbc:*IBindCtx, pmkToLeft:*IMoniker, ppszDisplayName:*LPOLESTR
        "GetDisplayName": ctypes.WINFUNCTYPE(HRESULT, IBindCtx, IMoniker, POINTER(LPOLESTR))(20, "GetDisplayName"),
        # ParseDisplayName -> pbc:*IBindCtx, pmkToLeft:*IMoniker, pszDisplayName:LPOLESTR, pchEaten:*ULONG, ppmkOut:**IMoniker
        "ParseDisplayName": ctypes.WINFUNCTYPE(HRESULT, IBindCtx, IMoniker, LPOLESTR, POINTER(ULONG), POINTER(IMoniker))(21, "ParseDisplayName"),
        # IsSystemMoniker -> pdwMksys:*DWORD
        "IsSystemMoniker": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(22, "IsSystemMoniker"),
    }

# class INetFwPolicy2Implem(windows.com.COMImplementation):
#     IMPLEMENT = INetFwPolicy2
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('INetFwPolicy2.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('INetFwPolicy2.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('INetFwPolicy2.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('INetFwPolicy2.Invoke')
#         return E_NOTIMPL
#
#     def get_CurrentProfileTypes(self, This, profileTypesBitmask):
#         print('INetFwPolicy2.get_CurrentProfileTypes')
#         return E_NOTIMPL
#
#     def get_FirewallEnabled(self, This, profileType, enabled):
#         print('INetFwPolicy2.get_FirewallEnabled')
#         return E_NOTIMPL
#
#     def put_FirewallEnabled(self, This, profileType, enabled):
#         print('INetFwPolicy2.put_FirewallEnabled')
#         return E_NOTIMPL
#
#     def get_ExcludedInterfaces(self, This, profileType, interfaces):
#         print('INetFwPolicy2.get_ExcludedInterfaces')
#         return E_NOTIMPL
#
#     def put_ExcludedInterfaces(self, This, profileType, interfaces):
#         print('INetFwPolicy2.put_ExcludedInterfaces')
#         return E_NOTIMPL
#
#     def get_BlockAllInboundTraffic(self, This, profileType, Block):
#         print('INetFwPolicy2.get_BlockAllInboundTraffic')
#         return E_NOTIMPL
#
#     def put_BlockAllInboundTraffic(self, This, profileType, Block):
#         print('INetFwPolicy2.put_BlockAllInboundTraffic')
#         return E_NOTIMPL
#
#     def get_NotificationsDisabled(self, This, profileType, disabled):
#         print('INetFwPolicy2.get_NotificationsDisabled')
#         return E_NOTIMPL
#
#     def put_NotificationsDisabled(self, This, profileType, disabled):
#         print('INetFwPolicy2.put_NotificationsDisabled')
#         return E_NOTIMPL
#
#     def get_UnicastResponsesToMulticastBroadcastDisabled(self, This, profileType, disabled):
#         print('INetFwPolicy2.get_UnicastResponsesToMulticastBroadcastDisabled')
#         return E_NOTIMPL
#
#     def put_UnicastResponsesToMulticastBroadcastDisabled(self, This, profileType, disabled):
#         print('INetFwPolicy2.put_UnicastResponsesToMulticastBroadcastDisabled')
#         return E_NOTIMPL
#
#     def get_Rules(self, This, rules):
#         print('INetFwPolicy2.get_Rules')
#         return E_NOTIMPL
#
#     def get_ServiceRestriction(self, This, ServiceRestriction):
#         print('INetFwPolicy2.get_ServiceRestriction')
#         return E_NOTIMPL
#
#     def EnableRuleGroup(self, This, profileTypesBitmask, group, enable):
#         print('INetFwPolicy2.EnableRuleGroup')
#         return E_NOTIMPL
#
#     def IsRuleGroupEnabled(self, This, profileTypesBitmask, group, enabled):
#         print('INetFwPolicy2.IsRuleGroupEnabled')
#         return E_NOTIMPL
#
#     def RestoreLocalFirewallDefaults(self, This):
#         print('INetFwPolicy2.RestoreLocalFirewallDefaults')
#         return E_NOTIMPL
#
#     def get_DefaultInboundAction(self, This, profileType, action):
#         print('INetFwPolicy2.get_DefaultInboundAction')
#         return E_NOTIMPL
#
#     def put_DefaultInboundAction(self, This, profileType, action):
#         print('INetFwPolicy2.put_DefaultInboundAction')
#         return E_NOTIMPL
#
#     def get_DefaultOutboundAction(self, This, profileType, action):
#         print('INetFwPolicy2.get_DefaultOutboundAction')
#         return E_NOTIMPL
#
#     def put_DefaultOutboundAction(self, This, profileType, action):
#         print('INetFwPolicy2.put_DefaultOutboundAction')
#         return E_NOTIMPL
#
#     def get_IsRuleGroupCurrentlyEnabled(self, This, group, enabled):
#         print('INetFwPolicy2.get_IsRuleGroupCurrentlyEnabled')
#         return E_NOTIMPL
#
#     def get_LocalPolicyModifyState(self, This, modifyState):
#         print('INetFwPolicy2.get_LocalPolicyModifyState')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class INetFwRuleImplem(windows.com.COMImplementation):
#     IMPLEMENT = INetFwRule
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('INetFwRule.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('INetFwRule.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('INetFwRule.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('INetFwRule.Invoke')
#         return E_NOTIMPL
#
#     def get_Name(self, This, name):
#         print('INetFwRule.get_Name')
#         return E_NOTIMPL
#
#     def put_Name(self, This, name):
#         print('INetFwRule.put_Name')
#         return E_NOTIMPL
#
#     def get_Description(self, This, desc):
#         print('INetFwRule.get_Description')
#         return E_NOTIMPL
#
#     def put_Description(self, This, desc):
#         print('INetFwRule.put_Description')
#         return E_NOTIMPL
#
#     def get_ApplicationName(self, This, imageFileName):
#         print('INetFwRule.get_ApplicationName')
#         return E_NOTIMPL
#
#     def put_ApplicationName(self, This, imageFileName):
#         print('INetFwRule.put_ApplicationName')
#         return E_NOTIMPL
#
#     def get_ServiceName(self, This, serviceName):
#         print('INetFwRule.get_ServiceName')
#         return E_NOTIMPL
#
#     def put_ServiceName(self, This, serviceName):
#         print('INetFwRule.put_ServiceName')
#         return E_NOTIMPL
#
#     def get_Protocol(self, This, protocol):
#         print('INetFwRule.get_Protocol')
#         return E_NOTIMPL
#
#     def put_Protocol(self, This, protocol):
#         print('INetFwRule.put_Protocol')
#         return E_NOTIMPL
#
#     def get_LocalPorts(self, This, portNumbers):
#         print('INetFwRule.get_LocalPorts')
#         return E_NOTIMPL
#
#     def put_LocalPorts(self, This, portNumbers):
#         print('INetFwRule.put_LocalPorts')
#         return E_NOTIMPL
#
#     def get_RemotePorts(self, This, portNumbers):
#         print('INetFwRule.get_RemotePorts')
#         return E_NOTIMPL
#
#     def put_RemotePorts(self, This, portNumbers):
#         print('INetFwRule.put_RemotePorts')
#         return E_NOTIMPL
#
#     def get_LocalAddresses(self, This, localAddrs):
#         print('INetFwRule.get_LocalAddresses')
#         return E_NOTIMPL
#
#     def put_LocalAddresses(self, This, localAddrs):
#         print('INetFwRule.put_LocalAddresses')
#         return E_NOTIMPL
#
#     def get_RemoteAddresses(self, This, remoteAddrs):
#         print('INetFwRule.get_RemoteAddresses')
#         return E_NOTIMPL
#
#     def put_RemoteAddresses(self, This, remoteAddrs):
#         print('INetFwRule.put_RemoteAddresses')
#         return E_NOTIMPL
#
#     def get_IcmpTypesAndCodes(self, This, icmpTypesAndCodes):
#         print('INetFwRule.get_IcmpTypesAndCodes')
#         return E_NOTIMPL
#
#     def put_IcmpTypesAndCodes(self, This, icmpTypesAndCodes):
#         print('INetFwRule.put_IcmpTypesAndCodes')
#         return E_NOTIMPL
#
#     def get_Direction(self, This, dir):
#         print('INetFwRule.get_Direction')
#         return E_NOTIMPL
#
#     def put_Direction(self, This, dir):
#         print('INetFwRule.put_Direction')
#         return E_NOTIMPL
#
#     def get_Interfaces(self, This, interfaces):
#         print('INetFwRule.get_Interfaces')
#         return E_NOTIMPL
#
#     def put_Interfaces(self, This, interfaces):
#         print('INetFwRule.put_Interfaces')
#         return E_NOTIMPL
#
#     def get_InterfaceTypes(self, This, interfaceTypes):
#         print('INetFwRule.get_InterfaceTypes')
#         return E_NOTIMPL
#
#     def put_InterfaceTypes(self, This, interfaceTypes):
#         print('INetFwRule.put_InterfaceTypes')
#         return E_NOTIMPL
#
#     def get_Enabled(self, This, enabled):
#         print('INetFwRule.get_Enabled')
#         return E_NOTIMPL
#
#     def put_Enabled(self, This, enabled):
#         print('INetFwRule.put_Enabled')
#         return E_NOTIMPL
#
#     def get_Grouping(self, This, context):
#         print('INetFwRule.get_Grouping')
#         return E_NOTIMPL
#
#     def put_Grouping(self, This, context):
#         print('INetFwRule.put_Grouping')
#         return E_NOTIMPL
#
#     def get_Profiles(self, This, profileTypesBitmask):
#         print('INetFwRule.get_Profiles')
#         return E_NOTIMPL
#
#     def put_Profiles(self, This, profileTypesBitmask):
#         print('INetFwRule.put_Profiles')
#         return E_NOTIMPL
#
#     def get_EdgeTraversal(self, This, enabled):
#         print('INetFwRule.get_EdgeTraversal')
#         return E_NOTIMPL
#
#     def put_EdgeTraversal(self, This, enabled):
#         print('INetFwRule.put_EdgeTraversal')
#         return E_NOTIMPL
#
#     def get_Action(self, This, action):
#         print('INetFwRule.get_Action')
#         return E_NOTIMPL
#
#     def put_Action(self, This, action):
#         print('INetFwRule.put_Action')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class INetFwRulesImplem(windows.com.COMImplementation):
#     IMPLEMENT = INetFwRules
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('INetFwRules.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('INetFwRules.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('INetFwRules.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('INetFwRules.Invoke')
#         return E_NOTIMPL
#
#     def get_Count(self, This, count):
#         print('INetFwRules.get_Count')
#         return E_NOTIMPL
#
#     def Add(self, This, rule):
#         print('INetFwRules.Add')
#         return E_NOTIMPL
#
#     def Remove(self, This, name):
#         print('INetFwRules.Remove')
#         return E_NOTIMPL
#
#     def Item(self, This, name, rule):
#         print('INetFwRules.Item')
#         return E_NOTIMPL
#
#     def get__NewEnum(self, This, newEnum):
#         print('INetFwRules.get__NewEnum')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class INetFwServiceRestrictionImplem(windows.com.COMImplementation):
#     IMPLEMENT = INetFwServiceRestriction
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('INetFwServiceRestriction.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('INetFwServiceRestriction.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('INetFwServiceRestriction.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('INetFwServiceRestriction.Invoke')
#         return E_NOTIMPL
#
#     def RestrictService(self, This, serviceName, appName, restrictService, serviceSidRestricted):
#         print('INetFwServiceRestriction.RestrictService')
#         return E_NOTIMPL
#
#     def ServiceRestricted(self, This, serviceName, appName, serviceRestricted):
#         print('INetFwServiceRestriction.ServiceRestricted')
#         return E_NOTIMPL
#
#     def get_Rules(self, This, rules):
#         print('INetFwServiceRestriction.get_Rules')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IObjContextImplem(windows.com.COMImplementation):
#     IMPLEMENT = IObjContext
#
#     def SetProperty(self, This, rpolicyId, flags, pUnk):
#         print('IObjContext.SetProperty')
#         return E_NOTIMPL
#
#     def RemoveProperty(self, This, rPolicyId):
#         print('IObjContext.RemoveProperty')
#         return E_NOTIMPL
#
#     def GetProperty(self, This, rGuid, pFlags, ppUnk):
#         print('IObjContext.GetProperty')
#         return E_NOTIMPL
#
#     def EnumContextProps(self, This, ppEnumContextProps):
#         print('IObjContext.EnumContextProps')
#         return E_NOTIMPL
#
#     def Reserved1(self, This):
#         print('IObjContext.Reserved1')
#         return E_NOTIMPL
#
#     def Reserved2(self, This):
#         print('IObjContext.Reserved2')
#         return E_NOTIMPL
#
#     def Reserved3(self, This):
#         print('IObjContext.Reserved3')
#         return E_NOTIMPL
#
#     def Reserved4(self, This):
#         print('IObjContext.Reserved4')
#         return E_NOTIMPL
#
#     def Reserved5(self, This):
#         print('IObjContext.Reserved5')
#         return E_NOTIMPL
#
#     def Reserved6(self, This):
#         print('IObjContext.Reserved6')
#         return E_NOTIMPL
#
#     def Reserved7(self, This):
#         print('IObjContext.Reserved7')
#         return E_NOTIMPL
#
IObjContext._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # SetProperty -> rpolicyId:REFGUID, flags:CPFLAGS, pUnk:*IUnknown
        "SetProperty": ctypes.WINFUNCTYPE(HRESULT, REFGUID, CPFLAGS, IUnknown)(3, "SetProperty"),
        # RemoveProperty -> rPolicyId:REFGUID
        "RemoveProperty": ctypes.WINFUNCTYPE(HRESULT, REFGUID)(4, "RemoveProperty"),
        # GetProperty -> rGuid:REFGUID, pFlags:*CPFLAGS, ppUnk:**IUnknown
        "GetProperty": ctypes.WINFUNCTYPE(HRESULT, REFGUID, POINTER(CPFLAGS), POINTER(IUnknown))(5, "GetProperty"),
        # EnumContextProps -> ppEnumContextProps:**IEnumContextProps
        "EnumContextProps": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumContextProps))(6, "EnumContextProps"),
        # Reserved1 -> 
        "Reserved1": ctypes.WINFUNCTYPE(PVOID)(7, "Reserved1"),
        # Reserved2 -> 
        "Reserved2": ctypes.WINFUNCTYPE(PVOID)(8, "Reserved2"),
        # Reserved3 -> 
        "Reserved3": ctypes.WINFUNCTYPE(PVOID)(9, "Reserved3"),
        # Reserved4 -> 
        "Reserved4": ctypes.WINFUNCTYPE(PVOID)(10, "Reserved4"),
        # Reserved5 -> 
        "Reserved5": ctypes.WINFUNCTYPE(PVOID)(11, "Reserved5"),
        # Reserved6 -> 
        "Reserved6": ctypes.WINFUNCTYPE(PVOID)(12, "Reserved6"),
        # Reserved7 -> 
        "Reserved7": ctypes.WINFUNCTYPE(PVOID)(13, "Reserved7"),
    }

# class IPersistImplem(windows.com.COMImplementation):
#     IMPLEMENT = IPersist
#
#     def GetClassID(self, This, pClassID):
#         print('IPersist.GetClassID')
#         return E_NOTIMPL
#
IPersist._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetClassID -> pClassID:*CLSID
        "GetClassID": ctypes.WINFUNCTYPE(HRESULT, POINTER(CLSID))(3, "GetClassID"),
    }

# class IPersistFileImplem(windows.com.COMImplementation):
#     IMPLEMENT = IPersistFile
#
#     def GetClassID(self, This, pClassID):
#         print('IPersistFile.GetClassID')
#         return E_NOTIMPL
#
#     def IsDirty(self, This):
#         print('IPersistFile.IsDirty')
#         return E_NOTIMPL
#
#     def Load(self, This, pszFileName, dwMode):
#         print('IPersistFile.Load')
#         return E_NOTIMPL
#
#     def Save(self, This, pszFileName, fRemember):
#         print('IPersistFile.Save')
#         return E_NOTIMPL
#
#     def SaveCompleted(self, This, pszFileName):
#         print('IPersistFile.SaveCompleted')
#         return E_NOTIMPL
#
#     def GetCurFile(self, This, ppszFileName):
#         print('IPersistFile.GetCurFile')
#         return E_NOTIMPL
#
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

# class IRemUnknownImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRemUnknown
#
#     def RemQueryInterface(self, This, ripid, cRefs, cIids, iids, ppQIResults):
#         print('IRemUnknown.RemQueryInterface')
#         return E_NOTIMPL
#
#     def RemAddRef(self, This, cInterfaceRefs, InterfaceRefs, pResults):
#         print('IRemUnknown.RemAddRef')
#         return E_NOTIMPL
#
#     def RemRelease(self, This, cInterfaceRefs, InterfaceRefs):
#         print('IRemUnknown.RemRelease')
#         return E_NOTIMPL
#
IRemUnknown._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # RemQueryInterface -> ripid:REFIPID, cRefs:ULONG, cIids:USHORT, iids:*IID, ppQIResults:**REMQIRESULT
        "RemQueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIPID, ULONG, USHORT, POINTER(IID), POINTER(POINTER(REMQIRESULT)))(3, "RemQueryInterface"),
        # RemAddRef -> cInterfaceRefs:USHORT, InterfaceRefs:*REMINTERFACEREF, pResults:*HRESULT
        "RemAddRef": ctypes.WINFUNCTYPE(HRESULT, USHORT, POINTER(REMINTERFACEREF), POINTER(HRESULT))(4, "RemAddRef"),
        # RemRelease -> cInterfaceRefs:USHORT, InterfaceRefs:*REMINTERFACEREF
        "RemRelease": ctypes.WINFUNCTYPE(HRESULT, USHORT, POINTER(REMINTERFACEREF))(5, "RemRelease"),
    }

# class IShellLinkAImplem(windows.com.COMImplementation):
#     IMPLEMENT = IShellLinkA
#
#     def GetPath(self, This, pszFile, cch, pfd, fFlags):
#         print('IShellLinkA.GetPath')
#         return E_NOTIMPL
#
#     def GetIDList(self, This, ppidl):
#         print('IShellLinkA.GetIDList')
#         return E_NOTIMPL
#
#     def SetIDList(self, This, pidl):
#         print('IShellLinkA.SetIDList')
#         return E_NOTIMPL
#
#     def GetDescription(self, This, pszName, cch):
#         print('IShellLinkA.GetDescription')
#         return E_NOTIMPL
#
#     def SetDescription(self, This, pszName):
#         print('IShellLinkA.SetDescription')
#         return E_NOTIMPL
#
#     def GetWorkingDirectory(self, This, pszDir, cch):
#         print('IShellLinkA.GetWorkingDirectory')
#         return E_NOTIMPL
#
#     def SetWorkingDirectory(self, This, pszDir):
#         print('IShellLinkA.SetWorkingDirectory')
#         return E_NOTIMPL
#
#     def GetArguments(self, This, pszArgs, cch):
#         print('IShellLinkA.GetArguments')
#         return E_NOTIMPL
#
#     def SetArguments(self, This, pszArgs):
#         print('IShellLinkA.SetArguments')
#         return E_NOTIMPL
#
#     def GetHotkey(self, This, pwHotkey):
#         print('IShellLinkA.GetHotkey')
#         return E_NOTIMPL
#
#     def SetHotkey(self, This, wHotkey):
#         print('IShellLinkA.SetHotkey')
#         return E_NOTIMPL
#
#     def GetShowCmd(self, This, piShowCmd):
#         print('IShellLinkA.GetShowCmd')
#         return E_NOTIMPL
#
#     def SetShowCmd(self, This, iShowCmd):
#         print('IShellLinkA.SetShowCmd')
#         return E_NOTIMPL
#
#     def GetIconLocation(self, This, pszIconPath, cch, piIcon):
#         print('IShellLinkA.GetIconLocation')
#         return E_NOTIMPL
#
#     def SetIconLocation(self, This, pszIconPath, iIcon):
#         print('IShellLinkA.SetIconLocation')
#         return E_NOTIMPL
#
#     def SetRelativePath(self, This, pszPathRel, dwReserved):
#         print('IShellLinkA.SetRelativePath')
#         return E_NOTIMPL
#
#     def Resolve(self, This, hwnd, fFlags):
#         print('IShellLinkA.Resolve')
#         return E_NOTIMPL
#
#     def SetPath(self, This, pszFile):
#         print('IShellLinkA.SetPath')
#         return E_NOTIMPL
#
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

# class IShellLinkWImplem(windows.com.COMImplementation):
#     IMPLEMENT = IShellLinkW
#
#     def GetPath(self, This, pszFile, cch, pfd, fFlags):
#         print('IShellLinkW.GetPath')
#         return E_NOTIMPL
#
#     def GetIDList(self, This, ppidl):
#         print('IShellLinkW.GetIDList')
#         return E_NOTIMPL
#
#     def SetIDList(self, This, pidl):
#         print('IShellLinkW.SetIDList')
#         return E_NOTIMPL
#
#     def GetDescription(self, This, pszName, cch):
#         print('IShellLinkW.GetDescription')
#         return E_NOTIMPL
#
#     def SetDescription(self, This, pszName):
#         print('IShellLinkW.SetDescription')
#         return E_NOTIMPL
#
#     def GetWorkingDirectory(self, This, pszDir, cch):
#         print('IShellLinkW.GetWorkingDirectory')
#         return E_NOTIMPL
#
#     def SetWorkingDirectory(self, This, pszDir):
#         print('IShellLinkW.SetWorkingDirectory')
#         return E_NOTIMPL
#
#     def GetArguments(self, This, pszArgs, cch):
#         print('IShellLinkW.GetArguments')
#         return E_NOTIMPL
#
#     def SetArguments(self, This, pszArgs):
#         print('IShellLinkW.SetArguments')
#         return E_NOTIMPL
#
#     def GetHotkey(self, This, pwHotkey):
#         print('IShellLinkW.GetHotkey')
#         return E_NOTIMPL
#
#     def SetHotkey(self, This, wHotkey):
#         print('IShellLinkW.SetHotkey')
#         return E_NOTIMPL
#
#     def GetShowCmd(self, This, piShowCmd):
#         print('IShellLinkW.GetShowCmd')
#         return E_NOTIMPL
#
#     def SetShowCmd(self, This, iShowCmd):
#         print('IShellLinkW.SetShowCmd')
#         return E_NOTIMPL
#
#     def GetIconLocation(self, This, pszIconPath, cch, piIcon):
#         print('IShellLinkW.GetIconLocation')
#         return E_NOTIMPL
#
#     def SetIconLocation(self, This, pszIconPath, iIcon):
#         print('IShellLinkW.SetIconLocation')
#         return E_NOTIMPL
#
#     def SetRelativePath(self, This, pszPathRel, dwReserved):
#         print('IShellLinkW.SetRelativePath')
#         return E_NOTIMPL
#
#     def Resolve(self, This, hwnd, fFlags):
#         print('IShellLinkW.Resolve')
#         return E_NOTIMPL
#
#     def SetPath(self, This, pszFile):
#         print('IShellLinkW.SetPath')
#         return E_NOTIMPL
#
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

# class IStdIdentityImplem(windows.com.COMImplementation):
#     IMPLEMENT = IStdIdentity
#
IStdIdentity._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
    }

# class IStorageImplem(windows.com.COMImplementation):
#     IMPLEMENT = IStorage
#
#     def CreateStream(self, This, pwcsName, grfMode, reserved1, reserved2, ppstm):
#         print('IStorage.CreateStream')
#         return E_NOTIMPL
#
#     def OpenStream(self, This, pwcsName, reserved1, grfMode, reserved2, ppstm):
#         print('IStorage.OpenStream')
#         return E_NOTIMPL
#
#     def CreateStorage(self, This, pwcsName, grfMode, reserved1, reserved2, ppstg):
#         print('IStorage.CreateStorage')
#         return E_NOTIMPL
#
#     def OpenStorage(self, This, pwcsName, pstgPriority, grfMode, snbExclude, reserved, ppstg):
#         print('IStorage.OpenStorage')
#         return E_NOTIMPL
#
#     def CopyTo(self, This, ciidExclude, rgiidExclude, snbExclude, pstgDest):
#         print('IStorage.CopyTo')
#         return E_NOTIMPL
#
#     def MoveElementTo(self, This, pwcsName, pstgDest, pwcsNewName, grfFlags):
#         print('IStorage.MoveElementTo')
#         return E_NOTIMPL
#
#     def Commit(self, This, grfCommitFlags):
#         print('IStorage.Commit')
#         return E_NOTIMPL
#
#     def Revert(self, This):
#         print('IStorage.Revert')
#         return E_NOTIMPL
#
#     def EnumElements(self, This, reserved1, reserved2, reserved3, ppenum):
#         print('IStorage.EnumElements')
#         return E_NOTIMPL
#
#     def DestroyElement(self, This, pwcsName):
#         print('IStorage.DestroyElement')
#         return E_NOTIMPL
#
#     def RenameElement(self, This, pwcsOldName, pwcsNewName):
#         print('IStorage.RenameElement')
#         return E_NOTIMPL
#
#     def SetElementTimes(self, This, pwcsName, pctime, patime, pmtime):
#         print('IStorage.SetElementTimes')
#         return E_NOTIMPL
#
#     def SetClass(self, This, clsid):
#         print('IStorage.SetClass')
#         return E_NOTIMPL
#
#     def SetStateBits(self, This, grfStateBits, grfMask):
#         print('IStorage.SetStateBits')
#         return E_NOTIMPL
#
#     def Stat(self, This, pstatstg, grfStatFlag):
#         print('IStorage.Stat')
#         return E_NOTIMPL
#
IStorage._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # CreateStream -> pwcsName:*OLECHAR, grfMode:DWORD, reserved1:DWORD, reserved2:DWORD, ppstm:**IStream
        "CreateStream": ctypes.WINFUNCTYPE(HRESULT, POINTER(OLECHAR), DWORD, DWORD, DWORD, POINTER(IStream))(3, "CreateStream"),
        # OpenStream -> pwcsName:*OLECHAR, reserved1:*void, grfMode:DWORD, reserved2:DWORD, ppstm:**IStream
        "OpenStream": ctypes.WINFUNCTYPE(HRESULT, POINTER(OLECHAR), PVOID, DWORD, DWORD, POINTER(IStream))(4, "OpenStream"),
        # CreateStorage -> pwcsName:*OLECHAR, grfMode:DWORD, reserved1:DWORD, reserved2:DWORD, ppstg:**IStorage
        "CreateStorage": ctypes.WINFUNCTYPE(HRESULT, POINTER(OLECHAR), DWORD, DWORD, DWORD, POINTER(IStorage))(5, "CreateStorage"),
        # OpenStorage -> pwcsName:*OLECHAR, pstgPriority:*IStorage, grfMode:DWORD, snbExclude:SNB, reserved:DWORD, ppstg:**IStorage
        "OpenStorage": ctypes.WINFUNCTYPE(HRESULT, POINTER(OLECHAR), IStorage, DWORD, SNB, DWORD, POINTER(IStorage))(6, "OpenStorage"),
        # CopyTo -> ciidExclude:DWORD, rgiidExclude:*IID, snbExclude:SNB, pstgDest:*IStorage
        "CopyTo": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(IID), SNB, IStorage)(7, "CopyTo"),
        # MoveElementTo -> pwcsName:*OLECHAR, pstgDest:*IStorage, pwcsNewName:*OLECHAR, grfFlags:DWORD
        "MoveElementTo": ctypes.WINFUNCTYPE(HRESULT, POINTER(OLECHAR), IStorage, POINTER(OLECHAR), DWORD)(8, "MoveElementTo"),
        # Commit -> grfCommitFlags:DWORD
        "Commit": ctypes.WINFUNCTYPE(HRESULT, DWORD)(9, "Commit"),
        # Revert -> 
        "Revert": ctypes.WINFUNCTYPE(HRESULT)(10, "Revert"),
        # EnumElements -> reserved1:DWORD, reserved2:*void, reserved3:DWORD, ppenum:**IEnumSTATSTG
        "EnumElements": ctypes.WINFUNCTYPE(HRESULT, DWORD, PVOID, DWORD, POINTER(IEnumSTATSTG))(11, "EnumElements"),
        # DestroyElement -> pwcsName:*OLECHAR
        "DestroyElement": ctypes.WINFUNCTYPE(HRESULT, POINTER(OLECHAR))(12, "DestroyElement"),
        # RenameElement -> pwcsOldName:*OLECHAR, pwcsNewName:*OLECHAR
        "RenameElement": ctypes.WINFUNCTYPE(HRESULT, POINTER(OLECHAR), POINTER(OLECHAR))(13, "RenameElement"),
        # SetElementTimes -> pwcsName:*OLECHAR, pctime:*FILETIME, patime:*FILETIME, pmtime:*FILETIME
        "SetElementTimes": ctypes.WINFUNCTYPE(HRESULT, POINTER(OLECHAR), POINTER(FILETIME), POINTER(FILETIME), POINTER(FILETIME))(14, "SetElementTimes"),
        # SetClass -> clsid:REFCLSID
        "SetClass": ctypes.WINFUNCTYPE(HRESULT, REFCLSID)(15, "SetClass"),
        # SetStateBits -> grfStateBits:DWORD, grfMask:DWORD
        "SetStateBits": ctypes.WINFUNCTYPE(HRESULT, DWORD, DWORD)(16, "SetStateBits"),
        # Stat -> pstatstg:*STATSTG, grfStatFlag:DWORD
        "Stat": ctypes.WINFUNCTYPE(HRESULT, POINTER(STATSTG), DWORD)(17, "Stat"),
    }

# class IStreamImplem(windows.com.COMImplementation):
#     IMPLEMENT = IStream
#
#     def Read(self, This, pv, cb, pcbRead):
#         print('IStream.Read')
#         return E_NOTIMPL
#
#     def Write(self, This, pv, cb, pcbWritten):
#         print('IStream.Write')
#         return E_NOTIMPL
#
#     def Seek(self, This, dlibMove, dwOrigin, plibNewPosition):
#         print('IStream.Seek')
#         return E_NOTIMPL
#
#     def SetSize(self, This, libNewSize):
#         print('IStream.SetSize')
#         return E_NOTIMPL
#
#     def CopyTo(self, This, pstm, cb, pcbRead, pcbWritten):
#         print('IStream.CopyTo')
#         return E_NOTIMPL
#
#     def Commit(self, This, grfCommitFlags):
#         print('IStream.Commit')
#         return E_NOTIMPL
#
#     def Revert(self, This):
#         print('IStream.Revert')
#         return E_NOTIMPL
#
#     def LockRegion(self, This, libOffset, cb, dwLockType):
#         print('IStream.LockRegion')
#         return E_NOTIMPL
#
#     def UnlockRegion(self, This, libOffset, cb, dwLockType):
#         print('IStream.UnlockRegion')
#         return E_NOTIMPL
#
#     def Stat(self, This, pstatstg, grfStatFlag):
#         print('IStream.Stat')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppstm):
#         print('IStream.Clone')
#         return E_NOTIMPL
#
IStream._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Read -> pv:*void, cb:ULONG, pcbRead:*ULONG
        "Read": ctypes.WINFUNCTYPE(HRESULT, PVOID, ULONG, POINTER(ULONG))(3, "Read"),
        # Write -> pv:*void, cb:ULONG, pcbWritten:*ULONG
        "Write": ctypes.WINFUNCTYPE(HRESULT, PVOID, ULONG, POINTER(ULONG))(4, "Write"),
        # Seek -> dlibMove:LARGE_INTEGER, dwOrigin:DWORD, plibNewPosition:*ULARGE_INTEGER
        "Seek": ctypes.WINFUNCTYPE(HRESULT, LARGE_INTEGER, DWORD, POINTER(ULARGE_INTEGER))(5, "Seek"),
        # SetSize -> libNewSize:ULARGE_INTEGER
        "SetSize": ctypes.WINFUNCTYPE(HRESULT, ULARGE_INTEGER)(6, "SetSize"),
        # CopyTo -> pstm:*IStream, cb:ULARGE_INTEGER, pcbRead:*ULARGE_INTEGER, pcbWritten:*ULARGE_INTEGER
        "CopyTo": ctypes.WINFUNCTYPE(HRESULT, IStream, ULARGE_INTEGER, POINTER(ULARGE_INTEGER), POINTER(ULARGE_INTEGER))(7, "CopyTo"),
        # Commit -> grfCommitFlags:DWORD
        "Commit": ctypes.WINFUNCTYPE(HRESULT, DWORD)(8, "Commit"),
        # Revert -> 
        "Revert": ctypes.WINFUNCTYPE(HRESULT)(9, "Revert"),
        # LockRegion -> libOffset:ULARGE_INTEGER, cb:ULARGE_INTEGER, dwLockType:DWORD
        "LockRegion": ctypes.WINFUNCTYPE(HRESULT, ULARGE_INTEGER, ULARGE_INTEGER, DWORD)(10, "LockRegion"),
        # UnlockRegion -> libOffset:ULARGE_INTEGER, cb:ULARGE_INTEGER, dwLockType:DWORD
        "UnlockRegion": ctypes.WINFUNCTYPE(HRESULT, ULARGE_INTEGER, ULARGE_INTEGER, DWORD)(11, "UnlockRegion"),
        # Stat -> pstatstg:*STATSTG, grfStatFlag:DWORD
        "Stat": ctypes.WINFUNCTYPE(HRESULT, POINTER(STATSTG), DWORD)(12, "Stat"),
        # Clone -> ppstm:**IStream
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IStream))(13, "Clone"),
    }

# class ITypeCompImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITypeComp
#
#     def Bind(self, This, szName, lHashVal, wFlags, ppTInfo, pDescKind, pBindPtr):
#         print('ITypeComp.Bind')
#         return E_NOTIMPL
#
#     def BindType(self, This, szName, lHashVal, ppTInfo, ppTComp):
#         print('ITypeComp.BindType')
#         return E_NOTIMPL
#
ITypeComp._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:*PVOID
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Bind -> szName:LPOLESTR, lHashVal:ULONG, wFlags:WORD, ppTInfo:**ITypeInfo, pDescKind:*DESCKIND, pBindPtr:*BINDPTR
        "Bind": ctypes.WINFUNCTYPE(HRESULT, LPOLESTR, ULONG, WORD, POINTER(ITypeInfo), POINTER(DESCKIND), POINTER(BINDPTR))(3, "Bind"),
        # BindType -> szName:LPOLESTR, lHashVal:ULONG, ppTInfo:**ITypeInfo, ppTComp:**ITypeComp
        "BindType": ctypes.WINFUNCTYPE(HRESULT, LPOLESTR, ULONG, POINTER(ITypeInfo), POINTER(ITypeComp))(4, "BindType"),
    }

# class ITypeInfoImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITypeInfo
#
#     def GetTypeAttr(self, This, ppTypeAttr):
#         print('ITypeInfo.GetTypeAttr')
#         return E_NOTIMPL
#
#     def GetTypeComp(self, This, ppTComp):
#         print('ITypeInfo.GetTypeComp')
#         return E_NOTIMPL
#
#     def GetFuncDesc(self, This, index, ppFuncDesc):
#         print('ITypeInfo.GetFuncDesc')
#         return E_NOTIMPL
#
#     def GetVarDesc(self, This, index, ppVarDesc):
#         print('ITypeInfo.GetVarDesc')
#         return E_NOTIMPL
#
#     def GetNames(self, This, memid, rgBstrNames, cMaxNames, pcNames):
#         print('ITypeInfo.GetNames')
#         return E_NOTIMPL
#
#     def GetRefTypeOfImplType(self, This, index, pRefType):
#         print('ITypeInfo.GetRefTypeOfImplType')
#         return E_NOTIMPL
#
#     def GetImplTypeFlags(self, This, index, pImplTypeFlags):
#         print('ITypeInfo.GetImplTypeFlags')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, rgszNames, cNames, pMemId):
#         print('ITypeInfo.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, pvInstance, memid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITypeInfo.Invoke')
#         return E_NOTIMPL
#
#     def GetDocumentation(self, This, memid, pBstrName, pBstrDocString, pdwHelpContext, pBstrHelpFile):
#         print('ITypeInfo.GetDocumentation')
#         return E_NOTIMPL
#
#     def GetDllEntry(self, This, memid, invKind, pBstrDllName, pBstrName, pwOrdinal):
#         print('ITypeInfo.GetDllEntry')
#         return E_NOTIMPL
#
#     def GetRefTypeInfo(self, This, hRefType, ppTInfo):
#         print('ITypeInfo.GetRefTypeInfo')
#         return E_NOTIMPL
#
#     def AddressOfMember(self, This, memid, invKind, ppv):
#         print('ITypeInfo.AddressOfMember')
#         return E_NOTIMPL
#
#     def CreateInstance(self, This, pUnkOuter, riid, ppvObj):
#         print('ITypeInfo.CreateInstance')
#         return E_NOTIMPL
#
#     def GetMops(self, This, memid, pBstrMops):
#         print('ITypeInfo.GetMops')
#         return E_NOTIMPL
#
#     def GetContainingTypeLib(self, This, ppTLib, pIndex):
#         print('ITypeInfo.GetContainingTypeLib')
#         return E_NOTIMPL
#
#     def ReleaseTypeAttr(self, This, pTypeAttr):
#         print('ITypeInfo.ReleaseTypeAttr')
#         return E_NOTIMPL
#
#     def ReleaseFuncDesc(self, This, pFuncDesc):
#         print('ITypeInfo.ReleaseFuncDesc')
#         return E_NOTIMPL
#
#     def ReleaseVarDesc(self, This, pVarDesc):
#         print('ITypeInfo.ReleaseVarDesc')
#         return E_NOTIMPL
#
ITypeInfo._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetTypeAttr -> ppTypeAttr:**TYPEATTR
        "GetTypeAttr": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(TYPEATTR)))(3, "GetTypeAttr"),
        # GetTypeComp -> ppTComp:**ITypeComp
        "GetTypeComp": ctypes.WINFUNCTYPE(HRESULT, POINTER(ITypeComp))(4, "GetTypeComp"),
        # GetFuncDesc -> index:UINT, ppFuncDesc:**FUNCDESC
        "GetFuncDesc": ctypes.WINFUNCTYPE(HRESULT, UINT, POINTER(POINTER(FUNCDESC)))(5, "GetFuncDesc"),
        # GetVarDesc -> index:UINT, ppVarDesc:**VARDESC
        "GetVarDesc": ctypes.WINFUNCTYPE(HRESULT, UINT, POINTER(POINTER(VARDESC)))(6, "GetVarDesc"),
        # GetNames -> memid:MEMBERID, rgBstrNames:*BSTR, cMaxNames:UINT, pcNames:*UINT
        "GetNames": ctypes.WINFUNCTYPE(HRESULT, MEMBERID, POINTER(BSTR), UINT, POINTER(UINT))(7, "GetNames"),
        # GetRefTypeOfImplType -> index:UINT, pRefType:*HREFTYPE
        "GetRefTypeOfImplType": ctypes.WINFUNCTYPE(HRESULT, UINT, POINTER(HREFTYPE))(8, "GetRefTypeOfImplType"),
        # GetImplTypeFlags -> index:UINT, pImplTypeFlags:*INT
        "GetImplTypeFlags": ctypes.WINFUNCTYPE(HRESULT, UINT, POINTER(INT))(9, "GetImplTypeFlags"),
        # GetIDsOfNames -> rgszNames:*LPOLESTR, cNames:UINT, pMemId:*MEMBERID
        "GetIDsOfNames": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPOLESTR), UINT, POINTER(MEMBERID))(10, "GetIDsOfNames"),
        # Invoke -> pvInstance:PVOID, memid:MEMBERID, wFlags:WORD, pDispParams:*DISPPARAMS, pVarResult:*VARIANT, pExcepInfo:*EXCEPINFO, puArgErr:*UINT
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, PVOID, MEMBERID, WORD, POINTER(DISPPARAMS), POINTER(VARIANT), POINTER(EXCEPINFO), POINTER(UINT))(11, "Invoke"),
        # GetDocumentation -> memid:MEMBERID, pBstrName:*BSTR, pBstrDocString:*BSTR, pdwHelpContext:*DWORD, pBstrHelpFile:*BSTR
        "GetDocumentation": ctypes.WINFUNCTYPE(HRESULT, MEMBERID, POINTER(BSTR), POINTER(BSTR), POINTER(DWORD), POINTER(BSTR))(12, "GetDocumentation"),
        # GetDllEntry -> memid:MEMBERID, invKind:INVOKEKIND, pBstrDllName:*BSTR, pBstrName:*BSTR, pwOrdinal:*WORD
        "GetDllEntry": ctypes.WINFUNCTYPE(HRESULT, MEMBERID, INVOKEKIND, POINTER(BSTR), POINTER(BSTR), POINTER(WORD))(13, "GetDllEntry"),
        # GetRefTypeInfo -> hRefType:HREFTYPE, ppTInfo:**ITypeInfo
        "GetRefTypeInfo": ctypes.WINFUNCTYPE(HRESULT, HREFTYPE, POINTER(ITypeInfo))(14, "GetRefTypeInfo"),
        # AddressOfMember -> memid:MEMBERID, invKind:INVOKEKIND, ppv:*PVOID
        "AddressOfMember": ctypes.WINFUNCTYPE(HRESULT, MEMBERID, INVOKEKIND, POINTER(PVOID))(15, "AddressOfMember"),
        # CreateInstance -> pUnkOuter:*IUnknown, riid:REFIID, ppvObj:*PVOID
        "CreateInstance": ctypes.WINFUNCTYPE(HRESULT, IUnknown, REFIID, POINTER(PVOID))(16, "CreateInstance"),
        # GetMops -> memid:MEMBERID, pBstrMops:*BSTR
        "GetMops": ctypes.WINFUNCTYPE(HRESULT, MEMBERID, POINTER(BSTR))(17, "GetMops"),
        # GetContainingTypeLib -> ppTLib:**ITypeLib, pIndex:*UINT
        "GetContainingTypeLib": ctypes.WINFUNCTYPE(HRESULT, POINTER(ITypeLib), POINTER(UINT))(18, "GetContainingTypeLib"),
        # ReleaseTypeAttr -> pTypeAttr:*TYPEATTR
        "ReleaseTypeAttr": ctypes.WINFUNCTYPE(DWORD, POINTER(TYPEATTR))(19, "ReleaseTypeAttr"),
        # ReleaseFuncDesc -> pFuncDesc:*FUNCDESC
        "ReleaseFuncDesc": ctypes.WINFUNCTYPE(DWORD, POINTER(FUNCDESC))(20, "ReleaseFuncDesc"),
        # ReleaseVarDesc -> pVarDesc:*VARDESC
        "ReleaseVarDesc": ctypes.WINFUNCTYPE(DWORD, POINTER(VARDESC))(21, "ReleaseVarDesc"),
    }

# class ITypeLibImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITypeLib
#
#     def GetTypeInfoCount(self, This):
#         print('ITypeLib.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, index, ppTInfo):
#         print('ITypeLib.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetTypeInfoType(self, This, index, pTKind):
#         print('ITypeLib.GetTypeInfoType')
#         return E_NOTIMPL
#
#     def GetTypeInfoOfGuid(self, This, guid, ppTinfo):
#         print('ITypeLib.GetTypeInfoOfGuid')
#         return E_NOTIMPL
#
#     def GetLibAttr(self, This, ppTLibAttr):
#         print('ITypeLib.GetLibAttr')
#         return E_NOTIMPL
#
#     def GetTypeComp(self, This, ppTComp):
#         print('ITypeLib.GetTypeComp')
#         return E_NOTIMPL
#
#     def GetDocumentation(self, This, index, pBstrName, pBstrDocString, pdwHelpContext, pBstrHelpFile):
#         print('ITypeLib.GetDocumentation')
#         return E_NOTIMPL
#
#     def IsName(self, This, szNameBuf, lHashVal, pfName):
#         print('ITypeLib.IsName')
#         return E_NOTIMPL
#
#     def FindName(self, This, szNameBuf, lHashVal, ppTInfo, rgMemId, pcFound):
#         print('ITypeLib.FindName')
#         return E_NOTIMPL
#
#     def ReleaseTLibAttr(self, This, pTLibAttr):
#         print('ITypeLib.ReleaseTLibAttr')
#         return E_NOTIMPL
#
ITypeLib._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetTypeInfoCount -> 
        "GetTypeInfoCount": ctypes.WINFUNCTYPE(UINT)(3, "GetTypeInfoCount"),
        # GetTypeInfo -> index:UINT, ppTInfo:**ITypeInfo
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, POINTER(ITypeInfo))(4, "GetTypeInfo"),
        # GetTypeInfoType -> index:UINT, pTKind:*TYPEKIND
        "GetTypeInfoType": ctypes.WINFUNCTYPE(HRESULT, UINT, POINTER(TYPEKIND))(5, "GetTypeInfoType"),
        # GetTypeInfoOfGuid -> guid:REFGUID, ppTinfo:**ITypeInfo
        "GetTypeInfoOfGuid": ctypes.WINFUNCTYPE(HRESULT, REFGUID, POINTER(ITypeInfo))(6, "GetTypeInfoOfGuid"),
        # GetLibAttr -> ppTLibAttr:**TLIBATTR
        "GetLibAttr": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(TLIBATTR)))(7, "GetLibAttr"),
        # GetTypeComp -> ppTComp:**ITypeComp
        "GetTypeComp": ctypes.WINFUNCTYPE(HRESULT, POINTER(ITypeComp))(8, "GetTypeComp"),
        # GetDocumentation -> index:INT, pBstrName:*BSTR, pBstrDocString:*BSTR, pdwHelpContext:*DWORD, pBstrHelpFile:*BSTR
        "GetDocumentation": ctypes.WINFUNCTYPE(HRESULT, INT, POINTER(BSTR), POINTER(BSTR), POINTER(DWORD), POINTER(BSTR))(9, "GetDocumentation"),
        # IsName -> szNameBuf:LPOLESTR, lHashVal:ULONG, pfName:*BOOL
        "IsName": ctypes.WINFUNCTYPE(HRESULT, LPOLESTR, ULONG, POINTER(BOOL))(10, "IsName"),
        # FindName -> szNameBuf:LPOLESTR, lHashVal:ULONG, ppTInfo:**ITypeInfo, rgMemId:*MEMBERID, pcFound:*USHORT
        "FindName": ctypes.WINFUNCTYPE(HRESULT, LPOLESTR, ULONG, POINTER(ITypeInfo), POINTER(MEMBERID), POINTER(USHORT))(11, "FindName"),
        # ReleaseTLibAttr -> pTLibAttr:*TLIBATTR
        "ReleaseTLibAttr": ctypes.WINFUNCTYPE(DWORD, POINTER(TLIBATTR))(12, "ReleaseTLibAttr"),
    }

# class IBackgroundCopyCallbackImplem(windows.com.COMImplementation):
#     IMPLEMENT = IBackgroundCopyCallback
#
#     def JobTransferred(self, This, pJob):
#         print('IBackgroundCopyCallback.JobTransferred')
#         return E_NOTIMPL
#
#     def JobError(self, This, pJob, pError):
#         print('IBackgroundCopyCallback.JobError')
#         return E_NOTIMPL
#
#     def JobModification(self, This, pJob, dwReserved):
#         print('IBackgroundCopyCallback.JobModification')
#         return E_NOTIMPL
#
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

# class IBackgroundCopyErrorImplem(windows.com.COMImplementation):
#     IMPLEMENT = IBackgroundCopyError
#
#     def GetError(self, This, pContext, pCode):
#         print('IBackgroundCopyError.GetError')
#         return E_NOTIMPL
#
#     def GetFile(self, This, pVal):
#         print('IBackgroundCopyError.GetFile')
#         return E_NOTIMPL
#
#     def GetErrorDescription(self, This, LanguageId, pErrorDescription):
#         print('IBackgroundCopyError.GetErrorDescription')
#         return E_NOTIMPL
#
#     def GetErrorContextDescription(self, This, LanguageId, pContextDescription):
#         print('IBackgroundCopyError.GetErrorContextDescription')
#         return E_NOTIMPL
#
#     def GetProtocol(self, This, pProtocol):
#         print('IBackgroundCopyError.GetProtocol')
#         return E_NOTIMPL
#
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

# class IBackgroundCopyFileImplem(windows.com.COMImplementation):
#     IMPLEMENT = IBackgroundCopyFile
#
#     def GetRemoteName(self, This, pVal):
#         print('IBackgroundCopyFile.GetRemoteName')
#         return E_NOTIMPL
#
#     def GetLocalName(self, This, pVal):
#         print('IBackgroundCopyFile.GetLocalName')
#         return E_NOTIMPL
#
#     def GetProgress(self, This, pVal):
#         print('IBackgroundCopyFile.GetProgress')
#         return E_NOTIMPL
#
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

# class IBackgroundCopyFile2Implem(windows.com.COMImplementation):
#     IMPLEMENT = IBackgroundCopyFile2
#
#     def GetRemoteName(self, This, pVal):
#         print('IBackgroundCopyFile2.GetRemoteName')
#         return E_NOTIMPL
#
#     def GetLocalName(self, This, pVal):
#         print('IBackgroundCopyFile2.GetLocalName')
#         return E_NOTIMPL
#
#     def GetProgress(self, This, pVal):
#         print('IBackgroundCopyFile2.GetProgress')
#         return E_NOTIMPL
#
#     def GetFileRanges(self, This, RangeCount, Ranges):
#         print('IBackgroundCopyFile2.GetFileRanges')
#         return E_NOTIMPL
#
#     def SetRemoteName(self, This, Val):
#         print('IBackgroundCopyFile2.SetRemoteName')
#         return E_NOTIMPL
#
IBackgroundCopyFile2._functions_ = {
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
        # GetFileRanges -> RangeCount:*DWORD, Ranges:**BG_FILE_RANGE
        "GetFileRanges": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD), POINTER(POINTER(BG_FILE_RANGE)))(6, "GetFileRanges"),
        # SetRemoteName -> Val:LPCWSTR
        "SetRemoteName": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(7, "SetRemoteName"),
    }

# class IBackgroundCopyFile3Implem(windows.com.COMImplementation):
#     IMPLEMENT = IBackgroundCopyFile3
#
#     def GetRemoteName(self, This, pVal):
#         print('IBackgroundCopyFile3.GetRemoteName')
#         return E_NOTIMPL
#
#     def GetLocalName(self, This, pVal):
#         print('IBackgroundCopyFile3.GetLocalName')
#         return E_NOTIMPL
#
#     def GetProgress(self, This, pVal):
#         print('IBackgroundCopyFile3.GetProgress')
#         return E_NOTIMPL
#
#     def GetFileRanges(self, This, RangeCount, Ranges):
#         print('IBackgroundCopyFile3.GetFileRanges')
#         return E_NOTIMPL
#
#     def SetRemoteName(self, This, Val):
#         print('IBackgroundCopyFile3.SetRemoteName')
#         return E_NOTIMPL
#
#     def GetTemporaryName(self, This, pFilename):
#         print('IBackgroundCopyFile3.GetTemporaryName')
#         return E_NOTIMPL
#
#     def SetValidationState(self, This, state):
#         print('IBackgroundCopyFile3.SetValidationState')
#         return E_NOTIMPL
#
#     def GetValidationState(self, This, pState):
#         print('IBackgroundCopyFile3.GetValidationState')
#         return E_NOTIMPL
#
#     def IsDownloadedFromPeer(self, This, pVal):
#         print('IBackgroundCopyFile3.IsDownloadedFromPeer')
#         return E_NOTIMPL
#
IBackgroundCopyFile3._functions_ = {
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
        # GetFileRanges -> RangeCount:*DWORD, Ranges:**BG_FILE_RANGE
        "GetFileRanges": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD), POINTER(POINTER(BG_FILE_RANGE)))(6, "GetFileRanges"),
        # SetRemoteName -> Val:LPCWSTR
        "SetRemoteName": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(7, "SetRemoteName"),
        # GetTemporaryName -> pFilename:*LPWSTR
        "GetTemporaryName": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR))(8, "GetTemporaryName"),
        # SetValidationState -> state:BOOL
        "SetValidationState": ctypes.WINFUNCTYPE(HRESULT, BOOL)(9, "SetValidationState"),
        # GetValidationState -> pState:*BOOL
        "GetValidationState": ctypes.WINFUNCTYPE(HRESULT, POINTER(BOOL))(10, "GetValidationState"),
        # IsDownloadedFromPeer -> pVal:*BOOL
        "IsDownloadedFromPeer": ctypes.WINFUNCTYPE(HRESULT, POINTER(BOOL))(11, "IsDownloadedFromPeer"),
    }

# class IBackgroundCopyJobImplem(windows.com.COMImplementation):
#     IMPLEMENT = IBackgroundCopyJob
#
#     def AddFileSet(self, This, cFileCount, pFileSet):
#         print('IBackgroundCopyJob.AddFileSet')
#         return E_NOTIMPL
#
#     def AddFile(self, This, RemoteUrl, LocalName):
#         print('IBackgroundCopyJob.AddFile')
#         return E_NOTIMPL
#
#     def EnumFiles(self, This, pEnum):
#         print('IBackgroundCopyJob.EnumFiles')
#         return E_NOTIMPL
#
#     def Suspend(self, This):
#         print('IBackgroundCopyJob.Suspend')
#         return E_NOTIMPL
#
#     def Resume(self, This):
#         print('IBackgroundCopyJob.Resume')
#         return E_NOTIMPL
#
#     def Cancel(self, This):
#         print('IBackgroundCopyJob.Cancel')
#         return E_NOTIMPL
#
#     def Complete(self, This):
#         print('IBackgroundCopyJob.Complete')
#         return E_NOTIMPL
#
#     def GetId(self, This, pVal):
#         print('IBackgroundCopyJob.GetId')
#         return E_NOTIMPL
#
#     def GetType(self, This, pVal):
#         print('IBackgroundCopyJob.GetType')
#         return E_NOTIMPL
#
#     def GetProgress(self, This, pVal):
#         print('IBackgroundCopyJob.GetProgress')
#         return E_NOTIMPL
#
#     def GetTimes(self, This, pVal):
#         print('IBackgroundCopyJob.GetTimes')
#         return E_NOTIMPL
#
#     def GetState(self, This, pVal):
#         print('IBackgroundCopyJob.GetState')
#         return E_NOTIMPL
#
#     def GetError(self, This, ppError):
#         print('IBackgroundCopyJob.GetError')
#         return E_NOTIMPL
#
#     def GetOwner(self, This, pVal):
#         print('IBackgroundCopyJob.GetOwner')
#         return E_NOTIMPL
#
#     def SetDisplayName(self, This, Val):
#         print('IBackgroundCopyJob.SetDisplayName')
#         return E_NOTIMPL
#
#     def GetDisplayName(self, This, pVal):
#         print('IBackgroundCopyJob.GetDisplayName')
#         return E_NOTIMPL
#
#     def SetDescription(self, This, Val):
#         print('IBackgroundCopyJob.SetDescription')
#         return E_NOTIMPL
#
#     def GetDescription(self, This, pVal):
#         print('IBackgroundCopyJob.GetDescription')
#         return E_NOTIMPL
#
#     def SetPriority(self, This, Val):
#         print('IBackgroundCopyJob.SetPriority')
#         return E_NOTIMPL
#
#     def GetPriority(self, This, pVal):
#         print('IBackgroundCopyJob.GetPriority')
#         return E_NOTIMPL
#
#     def SetNotifyFlags(self, This, Val):
#         print('IBackgroundCopyJob.SetNotifyFlags')
#         return E_NOTIMPL
#
#     def GetNotifyFlags(self, This, pVal):
#         print('IBackgroundCopyJob.GetNotifyFlags')
#         return E_NOTIMPL
#
#     def SetNotifyInterface(self, This, Val):
#         print('IBackgroundCopyJob.SetNotifyInterface')
#         return E_NOTIMPL
#
#     def GetNotifyInterface(self, This, pVal):
#         print('IBackgroundCopyJob.GetNotifyInterface')
#         return E_NOTIMPL
#
#     def SetMinimumRetryDelay(self, This, Seconds):
#         print('IBackgroundCopyJob.SetMinimumRetryDelay')
#         return E_NOTIMPL
#
#     def GetMinimumRetryDelay(self, This, Seconds):
#         print('IBackgroundCopyJob.GetMinimumRetryDelay')
#         return E_NOTIMPL
#
#     def SetNoProgressTimeout(self, This, Seconds):
#         print('IBackgroundCopyJob.SetNoProgressTimeout')
#         return E_NOTIMPL
#
#     def GetNoProgressTimeout(self, This, Seconds):
#         print('IBackgroundCopyJob.GetNoProgressTimeout')
#         return E_NOTIMPL
#
#     def GetErrorCount(self, This, Errors):
#         print('IBackgroundCopyJob.GetErrorCount')
#         return E_NOTIMPL
#
#     def SetProxySettings(self, This, ProxyUsage, ProxyList, ProxyBypassList):
#         print('IBackgroundCopyJob.SetProxySettings')
#         return E_NOTIMPL
#
#     def GetProxySettings(self, This, pProxyUsage, pProxyList, pProxyBypassList):
#         print('IBackgroundCopyJob.GetProxySettings')
#         return E_NOTIMPL
#
#     def TakeOwnership(self, This):
#         print('IBackgroundCopyJob.TakeOwnership')
#         return E_NOTIMPL
#
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

# class IBackgroundCopyJob2Implem(windows.com.COMImplementation):
#     IMPLEMENT = IBackgroundCopyJob2
#
#     def AddFileSet(self, This, cFileCount, pFileSet):
#         print('IBackgroundCopyJob2.AddFileSet')
#         return E_NOTIMPL
#
#     def AddFile(self, This, RemoteUrl, LocalName):
#         print('IBackgroundCopyJob2.AddFile')
#         return E_NOTIMPL
#
#     def EnumFiles(self, This, pEnum):
#         print('IBackgroundCopyJob2.EnumFiles')
#         return E_NOTIMPL
#
#     def Suspend(self, This):
#         print('IBackgroundCopyJob2.Suspend')
#         return E_NOTIMPL
#
#     def Resume(self, This):
#         print('IBackgroundCopyJob2.Resume')
#         return E_NOTIMPL
#
#     def Cancel(self, This):
#         print('IBackgroundCopyJob2.Cancel')
#         return E_NOTIMPL
#
#     def Complete(self, This):
#         print('IBackgroundCopyJob2.Complete')
#         return E_NOTIMPL
#
#     def GetId(self, This, pVal):
#         print('IBackgroundCopyJob2.GetId')
#         return E_NOTIMPL
#
#     def GetType(self, This, pVal):
#         print('IBackgroundCopyJob2.GetType')
#         return E_NOTIMPL
#
#     def GetProgress(self, This, pVal):
#         print('IBackgroundCopyJob2.GetProgress')
#         return E_NOTIMPL
#
#     def GetTimes(self, This, pVal):
#         print('IBackgroundCopyJob2.GetTimes')
#         return E_NOTIMPL
#
#     def GetState(self, This, pVal):
#         print('IBackgroundCopyJob2.GetState')
#         return E_NOTIMPL
#
#     def GetError(self, This, ppError):
#         print('IBackgroundCopyJob2.GetError')
#         return E_NOTIMPL
#
#     def GetOwner(self, This, pVal):
#         print('IBackgroundCopyJob2.GetOwner')
#         return E_NOTIMPL
#
#     def SetDisplayName(self, This, Val):
#         print('IBackgroundCopyJob2.SetDisplayName')
#         return E_NOTIMPL
#
#     def GetDisplayName(self, This, pVal):
#         print('IBackgroundCopyJob2.GetDisplayName')
#         return E_NOTIMPL
#
#     def SetDescription(self, This, Val):
#         print('IBackgroundCopyJob2.SetDescription')
#         return E_NOTIMPL
#
#     def GetDescription(self, This, pVal):
#         print('IBackgroundCopyJob2.GetDescription')
#         return E_NOTIMPL
#
#     def SetPriority(self, This, Val):
#         print('IBackgroundCopyJob2.SetPriority')
#         return E_NOTIMPL
#
#     def GetPriority(self, This, pVal):
#         print('IBackgroundCopyJob2.GetPriority')
#         return E_NOTIMPL
#
#     def SetNotifyFlags(self, This, Val):
#         print('IBackgroundCopyJob2.SetNotifyFlags')
#         return E_NOTIMPL
#
#     def GetNotifyFlags(self, This, pVal):
#         print('IBackgroundCopyJob2.GetNotifyFlags')
#         return E_NOTIMPL
#
#     def SetNotifyInterface(self, This, Val):
#         print('IBackgroundCopyJob2.SetNotifyInterface')
#         return E_NOTIMPL
#
#     def GetNotifyInterface(self, This, pVal):
#         print('IBackgroundCopyJob2.GetNotifyInterface')
#         return E_NOTIMPL
#
#     def SetMinimumRetryDelay(self, This, Seconds):
#         print('IBackgroundCopyJob2.SetMinimumRetryDelay')
#         return E_NOTIMPL
#
#     def GetMinimumRetryDelay(self, This, Seconds):
#         print('IBackgroundCopyJob2.GetMinimumRetryDelay')
#         return E_NOTIMPL
#
#     def SetNoProgressTimeout(self, This, Seconds):
#         print('IBackgroundCopyJob2.SetNoProgressTimeout')
#         return E_NOTIMPL
#
#     def GetNoProgressTimeout(self, This, Seconds):
#         print('IBackgroundCopyJob2.GetNoProgressTimeout')
#         return E_NOTIMPL
#
#     def GetErrorCount(self, This, Errors):
#         print('IBackgroundCopyJob2.GetErrorCount')
#         return E_NOTIMPL
#
#     def SetProxySettings(self, This, ProxyUsage, ProxyList, ProxyBypassList):
#         print('IBackgroundCopyJob2.SetProxySettings')
#         return E_NOTIMPL
#
#     def GetProxySettings(self, This, pProxyUsage, pProxyList, pProxyBypassList):
#         print('IBackgroundCopyJob2.GetProxySettings')
#         return E_NOTIMPL
#
#     def TakeOwnership(self, This):
#         print('IBackgroundCopyJob2.TakeOwnership')
#         return E_NOTIMPL
#
#     def SetNotifyCmdLine(self, This, Program, Parameters):
#         print('IBackgroundCopyJob2.SetNotifyCmdLine')
#         return E_NOTIMPL
#
#     def GetNotifyCmdLine(self, This, pProgram, pParameters):
#         print('IBackgroundCopyJob2.GetNotifyCmdLine')
#         return E_NOTIMPL
#
#     def GetReplyProgress(self, This, pProgress):
#         print('IBackgroundCopyJob2.GetReplyProgress')
#         return E_NOTIMPL
#
#     def GetReplyData(self, This, ppBuffer, pLength):
#         print('IBackgroundCopyJob2.GetReplyData')
#         return E_NOTIMPL
#
#     def SetReplyFileName(self, This, ReplyFileName):
#         print('IBackgroundCopyJob2.SetReplyFileName')
#         return E_NOTIMPL
#
#     def GetReplyFileName(self, This, pReplyFileName):
#         print('IBackgroundCopyJob2.GetReplyFileName')
#         return E_NOTIMPL
#
#     def SetCredentials(self, This, credentials):
#         print('IBackgroundCopyJob2.SetCredentials')
#         return E_NOTIMPL
#
#     def RemoveCredentials(self, This, Target, Scheme):
#         print('IBackgroundCopyJob2.RemoveCredentials')
#         return E_NOTIMPL
#
IBackgroundCopyJob2._functions_ = {
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
        # SetNotifyCmdLine -> Program:LPCWSTR, Parameters:LPCWSTR
        "SetNotifyCmdLine": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LPCWSTR)(35, "SetNotifyCmdLine"),
        # GetNotifyCmdLine -> pProgram:*LPWSTR, pParameters:*LPWSTR
        "GetNotifyCmdLine": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR), POINTER(LPWSTR))(36, "GetNotifyCmdLine"),
        # GetReplyProgress -> pProgress:*BG_JOB_REPLY_PROGRESS
        "GetReplyProgress": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_JOB_REPLY_PROGRESS))(37, "GetReplyProgress"),
        # GetReplyData -> ppBuffer:**BYTE, pLength:*UINT64
        "GetReplyData": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(BYTE)), POINTER(UINT64))(38, "GetReplyData"),
        # SetReplyFileName -> ReplyFileName:LPCWSTR
        "SetReplyFileName": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(39, "SetReplyFileName"),
        # GetReplyFileName -> pReplyFileName:*LPWSTR
        "GetReplyFileName": ctypes.WINFUNCTYPE(HRESULT, POINTER(LPWSTR))(40, "GetReplyFileName"),
        # SetCredentials -> credentials:*BG_AUTH_CREDENTIALS
        "SetCredentials": ctypes.WINFUNCTYPE(HRESULT, POINTER(BG_AUTH_CREDENTIALS))(41, "SetCredentials"),
        # RemoveCredentials -> Target:BG_AUTH_TARGET, Scheme:BG_AUTH_SCHEME
        "RemoveCredentials": ctypes.WINFUNCTYPE(HRESULT, BG_AUTH_TARGET, BG_AUTH_SCHEME)(42, "RemoveCredentials"),
    }

# class IBackgroundCopyManagerImplem(windows.com.COMImplementation):
#     IMPLEMENT = IBackgroundCopyManager
#
#     def CreateJob(self, This, DisplayName, Type, pJobId, ppJob):
#         print('IBackgroundCopyManager.CreateJob')
#         return E_NOTIMPL
#
#     def GetJob(self, This, jobID, ppJob):
#         print('IBackgroundCopyManager.GetJob')
#         return E_NOTIMPL
#
#     def EnumJobs(self, This, dwFlags, ppEnum):
#         print('IBackgroundCopyManager.EnumJobs')
#         return E_NOTIMPL
#
#     def GetErrorDescription(self, This, hResult, LanguageId, pErrorDescription):
#         print('IBackgroundCopyManager.GetErrorDescription')
#         return E_NOTIMPL
#
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

# class IEnumBackgroundCopyFilesImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumBackgroundCopyFiles
#
#     def Next(self, This, celt, rgelt, pceltFetched):
#         print('IEnumBackgroundCopyFiles.Next')
#         return E_NOTIMPL
#
#     def Skip(self, This, celt):
#         print('IEnumBackgroundCopyFiles.Skip')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IEnumBackgroundCopyFiles.Reset')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppenum):
#         print('IEnumBackgroundCopyFiles.Clone')
#         return E_NOTIMPL
#
#     def GetCount(self, This, puCount):
#         print('IEnumBackgroundCopyFiles.GetCount')
#         return E_NOTIMPL
#
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

# class IEnumBackgroundCopyJobsImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumBackgroundCopyJobs
#
#     def Next(self, This, celt, rgelt, pceltFetched):
#         print('IEnumBackgroundCopyJobs.Next')
#         return E_NOTIMPL
#
#     def Skip(self, This, celt):
#         print('IEnumBackgroundCopyJobs.Skip')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IEnumBackgroundCopyJobs.Reset')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppenum):
#         print('IEnumBackgroundCopyJobs.Clone')
#         return E_NOTIMPL
#
#     def GetCount(self, This, puCount):
#         print('IEnumBackgroundCopyJobs.GetCount')
#         return E_NOTIMPL
#
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

# class IActivationPropertiesImplem(windows.com.COMImplementation):
#     IMPLEMENT = IActivationProperties
#
#     def GetUnmarshalClass(self, This, riid, pv, dwDestContext, pvDestContext, mshlflags, pCid):
#         print('IActivationProperties.GetUnmarshalClass')
#         return E_NOTIMPL
#
#     def GetMarshalSizeMax(self, This, riid, pv, dwDestContext, pvDestContext, mshlflags, pSize):
#         print('IActivationProperties.GetMarshalSizeMax')
#         return E_NOTIMPL
#
#     def MarshalInterface(self, This, pStm, riid, pv, dwDestContext, pvDestContext, mshlflags):
#         print('IActivationProperties.MarshalInterface')
#         return E_NOTIMPL
#
#     def UnmarshalInterface(self, This, pStm, riid, ppv):
#         print('IActivationProperties.UnmarshalInterface')
#         return E_NOTIMPL
#
#     def ReleaseMarshalData(self, This, pStm):
#         print('IActivationProperties.ReleaseMarshalData')
#         return E_NOTIMPL
#
#     def DisconnectObject(self, This, dwReserved):
#         print('IActivationProperties.DisconnectObject')
#         return E_NOTIMPL
#
#     def SetDestCtx(self, This, dwDestCtx):
#         print('IActivationProperties.SetDestCtx')
#         return E_NOTIMPL
#
#     def SetMarshalFlags(self, This, dwMarshalFlags):
#         print('IActivationProperties.SetMarshalFlags')
#         return E_NOTIMPL
#
#     def SetLocalBlob(self, This, blob):
#         print('IActivationProperties.SetLocalBlob')
#         return E_NOTIMPL
#
#     def GetLocalBlob(self, This, blob):
#         print('IActivationProperties.GetLocalBlob')
#         return E_NOTIMPL
#
IActivationProperties._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetUnmarshalClass -> riid:REFIID, pv:*void, dwDestContext:DWORD, pvDestContext:*void, mshlflags:DWORD, pCid:*CLSID
        "GetUnmarshalClass": ctypes.WINFUNCTYPE(HRESULT, REFIID, PVOID, DWORD, PVOID, DWORD, POINTER(CLSID))(3, "GetUnmarshalClass"),
        # GetMarshalSizeMax -> riid:REFIID, pv:*void, dwDestContext:DWORD, pvDestContext:*void, mshlflags:DWORD, pSize:*DWORD
        "GetMarshalSizeMax": ctypes.WINFUNCTYPE(HRESULT, REFIID, PVOID, DWORD, PVOID, DWORD, POINTER(DWORD))(4, "GetMarshalSizeMax"),
        # MarshalInterface -> pStm:*IStream, riid:REFIID, pv:*void, dwDestContext:DWORD, pvDestContext:*void, mshlflags:DWORD
        "MarshalInterface": ctypes.WINFUNCTYPE(HRESULT, IStream, REFIID, PVOID, DWORD, PVOID, DWORD)(5, "MarshalInterface"),
        # UnmarshalInterface -> pStm:*IStream, riid:REFIID, ppv:**void
        "UnmarshalInterface": ctypes.WINFUNCTYPE(HRESULT, IStream, REFIID, POINTER(PVOID))(6, "UnmarshalInterface"),
        # ReleaseMarshalData -> pStm:*IStream
        "ReleaseMarshalData": ctypes.WINFUNCTYPE(HRESULT, IStream)(7, "ReleaseMarshalData"),
        # DisconnectObject -> dwReserved:DWORD
        "DisconnectObject": ctypes.WINFUNCTYPE(HRESULT, DWORD)(8, "DisconnectObject"),
        # SetDestCtx -> dwDestCtx:DWORD
        "SetDestCtx": ctypes.WINFUNCTYPE(HRESULT, DWORD)(9, "SetDestCtx"),
        # SetMarshalFlags -> dwMarshalFlags:DWORD
        "SetMarshalFlags": ctypes.WINFUNCTYPE(HRESULT, DWORD)(10, "SetMarshalFlags"),
        # SetLocalBlob -> blob:*void
        "SetLocalBlob": ctypes.WINFUNCTYPE(HRESULT, PVOID)(11, "SetLocalBlob"),
        # GetLocalBlob -> blob:**void
        "GetLocalBlob": ctypes.WINFUNCTYPE(HRESULT, POINTER(PVOID))(12, "GetLocalBlob"),
    }

# class IActivationPropertiesOutImplem(windows.com.COMImplementation):
#     IMPLEMENT = IActivationPropertiesOut
#
#     def GetActivationID(self, This, pActivationID):
#         print('IActivationPropertiesOut.GetActivationID')
#         return E_NOTIMPL
#
#     def GetObjectInterface(self, This, riid, actvflags, ppv):
#         print('IActivationPropertiesOut.GetObjectInterface')
#         return E_NOTIMPL
#
#     def GetObjectInterfaces(self, This, cIfs, actvflags, multiQi):
#         print('IActivationPropertiesOut.GetObjectInterfaces')
#         return E_NOTIMPL
#
#     def RemoveRequestedIIDs(self, This, cIfs, rgIID):
#         print('IActivationPropertiesOut.RemoveRequestedIIDs')
#         return E_NOTIMPL
#
IActivationPropertiesOut._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetActivationID -> pActivationID:*GUID
        "GetActivationID": ctypes.WINFUNCTYPE(HRESULT, POINTER(GUID))(3, "GetActivationID"),
        # GetObjectInterface -> riid:REFIID, actvflags:DWORD, ppv:**void
        "GetObjectInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, DWORD, POINTER(PVOID))(4, "GetObjectInterface"),
        # GetObjectInterfaces -> cIfs:DWORD, actvflags:DWORD, multiQi:*MULTI_QI
        "GetObjectInterfaces": ctypes.WINFUNCTYPE(HRESULT, DWORD, DWORD, POINTER(MULTI_QI))(5, "GetObjectInterfaces"),
        # RemoveRequestedIIDs -> cIfs:DWORD, rgIID:*IID
        "RemoveRequestedIIDs": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(IID))(6, "RemoveRequestedIIDs"),
    }

# class IActivationPropertiesInImplem(windows.com.COMImplementation):
#     IMPLEMENT = IActivationPropertiesIn
#
#     def GetActivationID(self, This, pActivationID):
#         print('IActivationPropertiesIn.GetActivationID')
#         return E_NOTIMPL
#
#     def GetClassInfo(self, This, riid, ppv):
#         print('IActivationPropertiesIn.GetClassInfo')
#         return E_NOTIMPL
#
#     def GetClsctx(self, This, pclsctx):
#         print('IActivationPropertiesIn.GetClsctx')
#         return E_NOTIMPL
#
#     def GetActivationFlags(self, This, pactvflags):
#         print('IActivationPropertiesIn.GetActivationFlags')
#         return E_NOTIMPL
#
#     def AddRequestedIIDs(self, This, cIfs, rgIID):
#         print('IActivationPropertiesIn.AddRequestedIIDs')
#         return E_NOTIMPL
#
#     def GetRequestedIIDs(self, This, pulCount, prgIID):
#         print('IActivationPropertiesIn.GetRequestedIIDs')
#         return E_NOTIMPL
#
#     def DelegateGetClassObject(self, This, pActPropsOut):
#         print('IActivationPropertiesIn.DelegateGetClassObject')
#         return E_NOTIMPL
#
#     def DelegateCreateInstance(self, This, pUnkOuter, pActPropsOut):
#         print('IActivationPropertiesIn.DelegateCreateInstance')
#         return E_NOTIMPL
#
#     def DelegateCIAndGetCF(self, This, pUnkOuter, pActPropsOut, ppCf):
#         print('IActivationPropertiesIn.DelegateCIAndGetCF')
#         return E_NOTIMPL
#
#     def GetReturnActivationProperties(self, This, pUnk, ppActOut):
#         print('IActivationPropertiesIn.GetReturnActivationProperties')
#         return E_NOTIMPL
#
IActivationPropertiesIn._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetActivationID -> pActivationID:*GUID
        "GetActivationID": ctypes.WINFUNCTYPE(HRESULT, POINTER(GUID))(3, "GetActivationID"),
        # GetClassInfo -> riid:REFIID, ppv:**void
        "GetClassInfo": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(4, "GetClassInfo"),
        # GetClsctx -> pclsctx:*DWORD
        "GetClsctx": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(5, "GetClsctx"),
        # GetActivationFlags -> pactvflags:*DWORD
        "GetActivationFlags": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(6, "GetActivationFlags"),
        # AddRequestedIIDs -> cIfs:DWORD, rgIID:*IID
        "AddRequestedIIDs": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(IID))(7, "AddRequestedIIDs"),
        # GetRequestedIIDs -> pulCount:*ULONG, prgIID:**IID
        "GetRequestedIIDs": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG), POINTER(POINTER(IID)))(8, "GetRequestedIIDs"),
        # DelegateGetClassObject -> pActPropsOut:**IActivationPropertiesOut
        "DelegateGetClassObject": ctypes.WINFUNCTYPE(HRESULT, POINTER(IActivationPropertiesOut))(9, "DelegateGetClassObject"),
        # DelegateCreateInstance -> pUnkOuter:*IUnknown, pActPropsOut:**IActivationPropertiesOut
        "DelegateCreateInstance": ctypes.WINFUNCTYPE(HRESULT, IUnknown, POINTER(IActivationPropertiesOut))(10, "DelegateCreateInstance"),
        # DelegateCIAndGetCF -> pUnkOuter:*IUnknown, pActPropsOut:**IActivationPropertiesOut, ppCf:**IClassFactory
        "DelegateCIAndGetCF": ctypes.WINFUNCTYPE(HRESULT, IUnknown, POINTER(IActivationPropertiesOut), POINTER(IClassFactory))(11, "DelegateCIAndGetCF"),
        # GetReturnActivationProperties -> pUnk:*IUnknown, ppActOut:**IActivationPropertiesOut
        "GetReturnActivationProperties": ctypes.WINFUNCTYPE(HRESULT, IUnknown, POINTER(IActivationPropertiesOut))(12, "GetReturnActivationProperties"),
    }

# class IActivationStageInfoImplem(windows.com.COMImplementation):
#     IMPLEMENT = IActivationStageInfo
#
#     def SetStageAndIndex(self, This, stage, index):
#         print('IActivationStageInfo.SetStageAndIndex')
#         return E_NOTIMPL
#
#     def GetStage(self, This, pstage):
#         print('IActivationStageInfo.GetStage')
#         return E_NOTIMPL
#
#     def GetIndex(self, This, pindex):
#         print('IActivationStageInfo.GetIndex')
#         return E_NOTIMPL
#
IActivationStageInfo._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # SetStageAndIndex -> stage:ACTIVATION_STAGE, index:INT
        "SetStageAndIndex": ctypes.WINFUNCTYPE(HRESULT, ACTIVATION_STAGE, INT)(3, "SetStageAndIndex"),
        # GetStage -> pstage:*ACTIVATION_STAGE
        "GetStage": ctypes.WINFUNCTYPE(HRESULT, POINTER(ACTIVATION_STAGE))(4, "GetStage"),
        # GetIndex -> pindex:*INT
        "GetIndex": ctypes.WINFUNCTYPE(HRESULT, POINTER(INT))(5, "GetIndex"),
    }

# class IClassClassicInfoImplem(windows.com.COMImplementation):
#     IMPLEMENT = IClassClassicInfo
#
#     def GetThreadingModel(self, This, pthreadmodel):
#         print('IClassClassicInfo.GetThreadingModel')
#         return E_NOTIMPL
#
#     def GetModulePath(self, This, clsctx, pwszDllName):
#         print('IClassClassicInfo.GetModulePath')
#         return E_NOTIMPL
#
#     def GetImplementedClsid(self, This, ppguidClsid):
#         print('IClassClassicInfo.GetImplementedClsid')
#         return E_NOTIMPL
#
#     def GetProcess(self, This, riid, ppv):
#         print('IClassClassicInfo.GetProcess')
#         return E_NOTIMPL
#
#     def GetRemoteServerName(self, This, pwszServerName):
#         print('IClassClassicInfo.GetRemoteServerName')
#         return E_NOTIMPL
#
#     def GetLocalServerType(self, This, pType):
#         print('IClassClassicInfo.GetLocalServerType')
#         return E_NOTIMPL
#
#     def GetSurrogateCommandLine(self, This, pwszSurrogateCommandLine):
#         print('IClassClassicInfo.GetSurrogateCommandLine')
#         return E_NOTIMPL
#
IClassClassicInfo._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetThreadingModel -> pthreadmodel:*ThreadingModel
        "GetThreadingModel": ctypes.WINFUNCTYPE(HRESULT, POINTER(ThreadingModel))(3, "GetThreadingModel"),
        # GetModulePath -> clsctx:CLSCTX, pwszDllName:**WCHAR
        "GetModulePath": ctypes.WINFUNCTYPE(HRESULT, CLSCTX, POINTER(POINTER(WCHAR)))(4, "GetModulePath"),
        # GetImplementedClsid -> ppguidClsid:**GUID
        "GetImplementedClsid": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(GUID)))(5, "GetImplementedClsid"),
        # GetProcess -> riid:REFIID, ppv:**void
        "GetProcess": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(6, "GetProcess"),
        # GetRemoteServerName -> pwszServerName:**WCHAR
        "GetRemoteServerName": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(WCHAR)))(7, "GetRemoteServerName"),
        # GetLocalServerType -> pType:*LocalServerType
        "GetLocalServerType": ctypes.WINFUNCTYPE(HRESULT, POINTER(LocalServerType))(8, "GetLocalServerType"),
        # GetSurrogateCommandLine -> pwszSurrogateCommandLine:**WCHAR
        "GetSurrogateCommandLine": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(WCHAR)))(9, "GetSurrogateCommandLine"),
    }

# class IComClassInfoImplem(windows.com.COMImplementation):
#     IMPLEMENT = IComClassInfo
#
#     def GetConfiguredClsid(self, This, ppguidClsid):
#         print('IComClassInfo.GetConfiguredClsid')
#         return E_NOTIMPL
#
#     def GetProgId(self, This, pwszProgid):
#         print('IComClassInfo.GetProgId')
#         return E_NOTIMPL
#
#     def GetClassName(self, This, pwszClassName):
#         print('IComClassInfo.GetClassName')
#         return E_NOTIMPL
#
#     def GetApplication(self, This, riid, ppv):
#         print('IComClassInfo.GetApplication')
#         return E_NOTIMPL
#
#     def GetClassContext(self, This, clsctxFilter, pclsctx):
#         print('IComClassInfo.GetClassContext')
#         return E_NOTIMPL
#
#     def GetCustomActivatorCount(self, This, activationStage, pulCount):
#         print('IComClassInfo.GetCustomActivatorCount')
#         return E_NOTIMPL
#
#     def GetCustomActivatorClsids(self, This, activationStage, prgguidClsid):
#         print('IComClassInfo.GetCustomActivatorClsids')
#         return E_NOTIMPL
#
#     def GetCustomActivators(self, This, activationStage, prgpActivator):
#         print('IComClassInfo.GetCustomActivators')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, riid, ppv):
#         print('IComClassInfo.GetTypeInfo')
#         return E_NOTIMPL
#
#     def IsComPlusConfiguredClass(self, This, pfComPlusConfiguredClass):
#         print('IComClassInfo.IsComPlusConfiguredClass')
#         return E_NOTIMPL
#
#     def MustRunInClientContext(self, This, pbMustRunInClientContext):
#         print('IComClassInfo.MustRunInClientContext')
#         return E_NOTIMPL
#
#     def GetVersionNumber(self, This, pdwVersionMS, pdwVersionLS):
#         print('IComClassInfo.GetVersionNumber')
#         return E_NOTIMPL
#
#     def Lock(self, This):
#         print('IComClassInfo.Lock')
#         return E_NOTIMPL
#
#     def Unlock(self, This):
#         print('IComClassInfo.Unlock')
#         return E_NOTIMPL
#
IComClassInfo._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetConfiguredClsid -> ppguidClsid:**GUID
        "GetConfiguredClsid": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(GUID)))(3, "GetConfiguredClsid"),
        # GetProgId -> pwszProgid:**WCHAR
        "GetProgId": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(WCHAR)))(4, "GetProgId"),
        # GetClassName -> pwszClassName:**WCHAR
        "GetClassName": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(WCHAR)))(5, "GetClassName"),
        # GetApplication -> riid:REFIID, ppv:**void
        "GetApplication": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(6, "GetApplication"),
        # GetClassContext -> clsctxFilter:CLSCTX, pclsctx:*CLSCTX
        "GetClassContext": ctypes.WINFUNCTYPE(HRESULT, CLSCTX, POINTER(CLSCTX))(7, "GetClassContext"),
        # GetCustomActivatorCount -> activationStage:ACTIVATION_STAGE, pulCount:*ULONG
        "GetCustomActivatorCount": ctypes.WINFUNCTYPE(HRESULT, ACTIVATION_STAGE, POINTER(ULONG))(8, "GetCustomActivatorCount"),
        # GetCustomActivatorClsids -> activationStage:ACTIVATION_STAGE, prgguidClsid:**GUID
        "GetCustomActivatorClsids": ctypes.WINFUNCTYPE(HRESULT, ACTIVATION_STAGE, POINTER(POINTER(GUID)))(9, "GetCustomActivatorClsids"),
        # GetCustomActivators -> activationStage:ACTIVATION_STAGE, prgpActivator:***ISystemActivator
        "GetCustomActivators": ctypes.WINFUNCTYPE(HRESULT, ACTIVATION_STAGE, POINTER(POINTER(ISystemActivator)))(10, "GetCustomActivators"),
        # GetTypeInfo -> riid:REFIID, ppv:**void
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(11, "GetTypeInfo"),
        # IsComPlusConfiguredClass -> pfComPlusConfiguredClass:*BOOL
        "IsComPlusConfiguredClass": ctypes.WINFUNCTYPE(HRESULT, POINTER(BOOL))(12, "IsComPlusConfiguredClass"),
        # MustRunInClientContext -> pbMustRunInClientContext:*BOOL
        "MustRunInClientContext": ctypes.WINFUNCTYPE(HRESULT, POINTER(BOOL))(13, "MustRunInClientContext"),
        # GetVersionNumber -> pdwVersionMS:*DWORD, pdwVersionLS:*DWORD
        "GetVersionNumber": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD), POINTER(DWORD))(14, "GetVersionNumber"),
        # Lock -> 
        "Lock": ctypes.WINFUNCTYPE(HRESULT)(15, "Lock"),
        # Unlock -> 
        "Unlock": ctypes.WINFUNCTYPE(HRESULT)(16, "Unlock"),
    }

# class IContextImplem(windows.com.COMImplementation):
#     IMPLEMENT = IContext
#
#     def SetProperty(self, This, rpolicyId, flags, pUnk):
#         print('IContext.SetProperty')
#         return E_NOTIMPL
#
#     def RemoveProperty(self, This, rPolicyId):
#         print('IContext.RemoveProperty')
#         return E_NOTIMPL
#
#     def GetProperty(self, This, rGuid, pFlags, ppUnk):
#         print('IContext.GetProperty')
#         return E_NOTIMPL
#
#     def EnumContextProps(self, This, ppEnumContextProps):
#         print('IContext.EnumContextProps')
#         return E_NOTIMPL
#
IContext._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # SetProperty -> rpolicyId:REFGUID, flags:CPFLAGS, pUnk:*IUnknown
        "SetProperty": ctypes.WINFUNCTYPE(HRESULT, REFGUID, CPFLAGS, IUnknown)(3, "SetProperty"),
        # RemoveProperty -> rPolicyId:REFGUID
        "RemoveProperty": ctypes.WINFUNCTYPE(HRESULT, REFGUID)(4, "RemoveProperty"),
        # GetProperty -> rGuid:REFGUID, pFlags:*CPFLAGS, ppUnk:**IUnknown
        "GetProperty": ctypes.WINFUNCTYPE(HRESULT, REFGUID, POINTER(CPFLAGS), POINTER(IUnknown))(5, "GetProperty"),
        # EnumContextProps -> ppEnumContextProps:**IEnumContextProps
        "EnumContextProps": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumContextProps))(6, "EnumContextProps"),
    }

# class IEnumContextPropsImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumContextProps
#
#     def Next(self, This, celt, pContextProperties, pceltFetched):
#         print('IEnumContextProps.Next')
#         return E_NOTIMPL
#
#     def Skip(self, This, celt):
#         print('IEnumContextProps.Skip')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IEnumContextProps.Reset')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppEnumContextProps):
#         print('IEnumContextProps.Clone')
#         return E_NOTIMPL
#
#     def Count(self, This, pcelt):
#         print('IEnumContextProps.Count')
#         return E_NOTIMPL
#
IEnumContextProps._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Next -> celt:ULONG, pContextProperties:*ContextProperty, pceltFetched:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(ContextProperty), POINTER(ULONG))(3, "Next"),
        # Skip -> celt:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, ULONG)(4, "Skip"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(5, "Reset"),
        # Clone -> ppEnumContextProps:**IEnumContextProps
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumContextProps))(6, "Clone"),
        # Count -> pcelt:*ULONG
        "Count": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG))(7, "Count"),
    }

# class IEnumSTATSTGImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumSTATSTG
#
#     def Next(self, This, celt, rgelt, pceltFetched):
#         print('IEnumSTATSTG.Next')
#         return E_NOTIMPL
#
#     def Skip(self, This, celt):
#         print('IEnumSTATSTG.Skip')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IEnumSTATSTG.Reset')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppenum):
#         print('IEnumSTATSTG.Clone')
#         return E_NOTIMPL
#
IEnumSTATSTG._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Next -> celt:ULONG, rgelt:*STATSTG, pceltFetched:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(STATSTG), POINTER(ULONG))(3, "Next"),
        # Skip -> celt:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, ULONG)(4, "Skip"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(5, "Reset"),
        # Clone -> ppenum:**IEnumSTATSTG
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumSTATSTG))(6, "Clone"),
    }

# class IInitActivationPropertiesInImplem(windows.com.COMImplementation):
#     IMPLEMENT = IInitActivationPropertiesIn
#
#     def SetClsctx(self, This, clsctx):
#         print('IInitActivationPropertiesIn.SetClsctx')
#         return E_NOTIMPL
#
#     def SetActivationFlags(self, This, actvflags):
#         print('IInitActivationPropertiesIn.SetActivationFlags')
#         return E_NOTIMPL
#
#     def SetClassInfo(self, This, pUnkClassInfo):
#         print('IInitActivationPropertiesIn.SetClassInfo')
#         return E_NOTIMPL
#
#     def SetContextInfo(self, This, pClientContext, pPrototypeContext):
#         print('IInitActivationPropertiesIn.SetContextInfo')
#         return E_NOTIMPL
#
#     def SetConstructFromStorage(self, This, pStorage):
#         print('IInitActivationPropertiesIn.SetConstructFromStorage')
#         return E_NOTIMPL
#
#     def SetConstructFromFile(self, This, wszFileName, dwMode):
#         print('IInitActivationPropertiesIn.SetConstructFromFile')
#         return E_NOTIMPL
#
IInitActivationPropertiesIn._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # SetClsctx -> clsctx:DWORD
        "SetClsctx": ctypes.WINFUNCTYPE(HRESULT, DWORD)(3, "SetClsctx"),
        # SetActivationFlags -> actvflags:DWORD
        "SetActivationFlags": ctypes.WINFUNCTYPE(HRESULT, DWORD)(4, "SetActivationFlags"),
        # SetClassInfo -> pUnkClassInfo:*IUnknown
        "SetClassInfo": ctypes.WINFUNCTYPE(HRESULT, IUnknown)(5, "SetClassInfo"),
        # SetContextInfo -> pClientContext:*IContext, pPrototypeContext:*IContext
        "SetContextInfo": ctypes.WINFUNCTYPE(HRESULT, IContext, IContext)(6, "SetContextInfo"),
        # SetConstructFromStorage -> pStorage:*IStorage
        "SetConstructFromStorage": ctypes.WINFUNCTYPE(HRESULT, IStorage)(7, "SetConstructFromStorage"),
        # SetConstructFromFile -> wszFileName:*WCHAR, dwMode:DWORD
        "SetConstructFromFile": ctypes.WINFUNCTYPE(HRESULT, POINTER(WCHAR), DWORD)(8, "SetConstructFromFile"),
    }

# class IOpaqueDataInfoImplem(windows.com.COMImplementation):
#     IMPLEMENT = IOpaqueDataInfo
#
#     def AddOpaqueData(self, This, pData):
#         print('IOpaqueDataInfo.AddOpaqueData')
#         return E_NOTIMPL
#
#     def GetOpaqueData(self, This, guid, pData):
#         print('IOpaqueDataInfo.GetOpaqueData')
#         return E_NOTIMPL
#
#     def DeleteOpaqueData(self, This, guid):
#         print('IOpaqueDataInfo.DeleteOpaqueData')
#         return E_NOTIMPL
#
#     def GetOpaqueDataCount(self, This, pulCount):
#         print('IOpaqueDataInfo.GetOpaqueDataCount')
#         return E_NOTIMPL
#
#     def GetAllOpaqueData(self, This, prgData):
#         print('IOpaqueDataInfo.GetAllOpaqueData')
#         return E_NOTIMPL
#
IOpaqueDataInfo._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # AddOpaqueData -> pData:*OpaqueData
        "AddOpaqueData": ctypes.WINFUNCTYPE(HRESULT, POINTER(OpaqueData))(3, "AddOpaqueData"),
        # GetOpaqueData -> guid:REFGUID, pData:**OpaqueData
        "GetOpaqueData": ctypes.WINFUNCTYPE(HRESULT, REFGUID, POINTER(POINTER(OpaqueData)))(4, "GetOpaqueData"),
        # DeleteOpaqueData -> guid:REFGUID
        "DeleteOpaqueData": ctypes.WINFUNCTYPE(HRESULT, REFGUID)(5, "DeleteOpaqueData"),
        # GetOpaqueDataCount -> pulCount:*ULONG
        "GetOpaqueDataCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG))(6, "GetOpaqueDataCount"),
        # GetAllOpaqueData -> prgData:**OpaqueData
        "GetAllOpaqueData": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(OpaqueData)))(7, "GetAllOpaqueData"),
    }

# class IPrivActivationPropertiesInImplem(windows.com.COMImplementation):
#     IMPLEMENT = IPrivActivationPropertiesIn
#
#     def GetActivationID(self, This, pActivationID):
#         print('IPrivActivationPropertiesIn.GetActivationID')
#         return E_NOTIMPL
#
#     def GetClassInfo(self, This, riid, ppv):
#         print('IPrivActivationPropertiesIn.GetClassInfo')
#         return E_NOTIMPL
#
#     def GetClsctx(self, This, pclsctx):
#         print('IPrivActivationPropertiesIn.GetClsctx')
#         return E_NOTIMPL
#
#     def GetActivationFlags(self, This, pactvflags):
#         print('IPrivActivationPropertiesIn.GetActivationFlags')
#         return E_NOTIMPL
#
#     def AddRequestedIIDs(self, This, cIfs, rgIID):
#         print('IPrivActivationPropertiesIn.AddRequestedIIDs')
#         return E_NOTIMPL
#
#     def GetRequestedIIDs(self, This, pulCount, prgIID):
#         print('IPrivActivationPropertiesIn.GetRequestedIIDs')
#         return E_NOTIMPL
#
#     def DelegateGetClassObject(self, This, pActPropsOut):
#         print('IPrivActivationPropertiesIn.DelegateGetClassObject')
#         return E_NOTIMPL
#
#     def DelegateCreateInstance(self, This, pUnkOuter, pActPropsOut):
#         print('IPrivActivationPropertiesIn.DelegateCreateInstance')
#         return E_NOTIMPL
#
#     def DelegateCIAndGetCF(self, This, pUnkOuter, pActPropsOut, ppCf):
#         print('IPrivActivationPropertiesIn.DelegateCIAndGetCF')
#         return E_NOTIMPL
#
#     def GetReturnActivationProperties(self, This, pUnk, ppActOut):
#         print('IPrivActivationPropertiesIn.GetReturnActivationProperties')
#         return E_NOTIMPL
#
#     def PrivGetReturnActivationProperties(self, This, ppActOut):
#         print('IPrivActivationPropertiesIn.PrivGetReturnActivationProperties')
#         return E_NOTIMPL
#
#     def GetCOMVersion(self, This, pVersion):
#         print('IPrivActivationPropertiesIn.GetCOMVersion')
#         return E_NOTIMPL
#
#     def GetClsid(self, This, pClsid):
#         print('IPrivActivationPropertiesIn.GetClsid')
#         return E_NOTIMPL
#
#     def GetClientToken(self, This, pHandle):
#         print('IPrivActivationPropertiesIn.GetClientToken')
#         return E_NOTIMPL
#
#     def GetDestCtx(self, This, pdwDestCtx):
#         print('IPrivActivationPropertiesIn.GetDestCtx')
#         return E_NOTIMPL
#
IPrivActivationPropertiesIn._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetActivationID -> pActivationID:*GUID
        "GetActivationID": ctypes.WINFUNCTYPE(HRESULT, POINTER(GUID))(3, "GetActivationID"),
        # GetClassInfo -> riid:REFIID, ppv:**void
        "GetClassInfo": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(4, "GetClassInfo"),
        # GetClsctx -> pclsctx:*DWORD
        "GetClsctx": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(5, "GetClsctx"),
        # GetActivationFlags -> pactvflags:*DWORD
        "GetActivationFlags": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(6, "GetActivationFlags"),
        # AddRequestedIIDs -> cIfs:DWORD, rgIID:*IID
        "AddRequestedIIDs": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(IID))(7, "AddRequestedIIDs"),
        # GetRequestedIIDs -> pulCount:*ULONG, prgIID:**IID
        "GetRequestedIIDs": ctypes.WINFUNCTYPE(HRESULT, POINTER(ULONG), POINTER(POINTER(IID)))(8, "GetRequestedIIDs"),
        # DelegateGetClassObject -> pActPropsOut:**IActivationPropertiesOut
        "DelegateGetClassObject": ctypes.WINFUNCTYPE(HRESULT, POINTER(IActivationPropertiesOut))(9, "DelegateGetClassObject"),
        # DelegateCreateInstance -> pUnkOuter:*IUnknown, pActPropsOut:**IActivationPropertiesOut
        "DelegateCreateInstance": ctypes.WINFUNCTYPE(HRESULT, IUnknown, POINTER(IActivationPropertiesOut))(10, "DelegateCreateInstance"),
        # DelegateCIAndGetCF -> pUnkOuter:*IUnknown, pActPropsOut:**IActivationPropertiesOut, ppCf:**IClassFactory
        "DelegateCIAndGetCF": ctypes.WINFUNCTYPE(HRESULT, IUnknown, POINTER(IActivationPropertiesOut), POINTER(IClassFactory))(11, "DelegateCIAndGetCF"),
        # GetReturnActivationProperties -> pUnk:*IUnknown, ppActOut:**IActivationPropertiesOut
        "GetReturnActivationProperties": ctypes.WINFUNCTYPE(HRESULT, IUnknown, POINTER(IActivationPropertiesOut))(12, "GetReturnActivationProperties"),
        # PrivGetReturnActivationProperties -> ppActOut:**IPrivActivationPropertiesOut
        "PrivGetReturnActivationProperties": ctypes.WINFUNCTYPE(HRESULT, POINTER(IPrivActivationPropertiesOut))(13, "PrivGetReturnActivationProperties"),
        # GetCOMVersion -> pVersion:*COMVERSION
        "GetCOMVersion": ctypes.WINFUNCTYPE(HRESULT, POINTER(COMVERSION))(14, "GetCOMVersion"),
        # GetClsid -> pClsid:*CLSID
        "GetClsid": ctypes.WINFUNCTYPE(HRESULT, POINTER(CLSID))(15, "GetClsid"),
        # GetClientToken -> pHandle:*HANDLE
        "GetClientToken": ctypes.WINFUNCTYPE(HRESULT, POINTER(HANDLE))(16, "GetClientToken"),
        # GetDestCtx -> pdwDestCtx:*DWORD
        "GetDestCtx": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(17, "GetDestCtx"),
    }

# class IPrivActivationPropertiesOutImplem(windows.com.COMImplementation):
#     IMPLEMENT = IPrivActivationPropertiesOut
#
#     def GetActivationID(self, This, pActivationID):
#         print('IPrivActivationPropertiesOut.GetActivationID')
#         return E_NOTIMPL
#
#     def GetObjectInterface(self, This, riid, actvflags, ppv):
#         print('IPrivActivationPropertiesOut.GetObjectInterface')
#         return E_NOTIMPL
#
#     def GetObjectInterfaces(self, This, cIfs, actvflags, multiQi):
#         print('IPrivActivationPropertiesOut.GetObjectInterfaces')
#         return E_NOTIMPL
#
#     def RemoveRequestedIIDs(self, This, cIfs, rgIID):
#         print('IPrivActivationPropertiesOut.RemoveRequestedIIDs')
#         return E_NOTIMPL
#
#     def SetObjectInterfaces(self, This, cIfs, pIID, pUnk):
#         print('IPrivActivationPropertiesOut.SetObjectInterfaces')
#         return E_NOTIMPL
#
#     def SetMarshalledResults(self, This, cIfs, pIID, pHr, pIntfData):
#         print('IPrivActivationPropertiesOut.SetMarshalledResults')
#         return E_NOTIMPL
#
#     def GetMarshalledResults(self, This, pcIfs, pIID, pHr, pIntfData):
#         print('IPrivActivationPropertiesOut.GetMarshalledResults')
#         return E_NOTIMPL
#
IPrivActivationPropertiesOut._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetActivationID -> pActivationID:*GUID
        "GetActivationID": ctypes.WINFUNCTYPE(HRESULT, POINTER(GUID))(3, "GetActivationID"),
        # GetObjectInterface -> riid:REFIID, actvflags:DWORD, ppv:**void
        "GetObjectInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, DWORD, POINTER(PVOID))(4, "GetObjectInterface"),
        # GetObjectInterfaces -> cIfs:DWORD, actvflags:DWORD, multiQi:*MULTI_QI
        "GetObjectInterfaces": ctypes.WINFUNCTYPE(HRESULT, DWORD, DWORD, POINTER(MULTI_QI))(5, "GetObjectInterfaces"),
        # RemoveRequestedIIDs -> cIfs:DWORD, rgIID:*IID
        "RemoveRequestedIIDs": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(IID))(6, "RemoveRequestedIIDs"),
        # SetObjectInterfaces -> cIfs:DWORD, pIID:*IID, pUnk:*IUnknown
        "SetObjectInterfaces": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(IID), IUnknown)(7, "SetObjectInterfaces"),
        # SetMarshalledResults -> cIfs:DWORD, pIID:*IID, pHr:*HRESULT, pIntfData:**MInterfacePointer
        "SetMarshalledResults": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(IID), POINTER(HRESULT), POINTER(POINTER(MInterfacePointer)))(8, "SetMarshalledResults"),
        # GetMarshalledResults -> pcIfs:*DWORD, pIID:**IID, pHr:**HRESULT, pIntfData:***MInterfacePointer
        "GetMarshalledResults": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD), POINTER(POINTER(IID)), POINTER(POINTER(HRESULT)), POINTER(POINTER(POINTER(MInterfacePointer))))(9, "GetMarshalledResults"),
    }

# class IScmReplyInfoImplem(windows.com.COMImplementation):
#     IMPLEMENT = IScmReplyInfo
#
#     def SetResolverInfo(self, This, pResolverInfo):
#         print('IScmReplyInfo.SetResolverInfo')
#         return E_NOTIMPL
#
#     def GetResolverInfo(self, This, ppResolverInfo):
#         print('IScmReplyInfo.GetResolverInfo')
#         return E_NOTIMPL
#
#     def SetRemoteReplyInfo(self, This, pRemoteReply):
#         print('IScmReplyInfo.SetRemoteReplyInfo')
#         return E_NOTIMPL
#
#     def GetRemoteReplyInfo(self, This, ppRemoteReply):
#         print('IScmReplyInfo.GetRemoteReplyInfo')
#         return E_NOTIMPL
#
IScmReplyInfo._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # SetResolverInfo -> pResolverInfo:*PRIV_RESOLVER_INFO
        "SetResolverInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(PRIV_RESOLVER_INFO))(3, "SetResolverInfo"),
        # GetResolverInfo -> ppResolverInfo:**PRIV_RESOLVER_INFO
        "GetResolverInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(PRIV_RESOLVER_INFO)))(4, "GetResolverInfo"),
        # SetRemoteReplyInfo -> pRemoteReply:*REMOTE_REPLY_SCM_INFO
        "SetRemoteReplyInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(REMOTE_REPLY_SCM_INFO))(5, "SetRemoteReplyInfo"),
        # GetRemoteReplyInfo -> ppRemoteReply:**REMOTE_REPLY_SCM_INFO
        "GetRemoteReplyInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(REMOTE_REPLY_SCM_INFO)))(6, "GetRemoteReplyInfo"),
    }

# class IScmRequestInfoImplem(windows.com.COMImplementation):
#     IMPLEMENT = IScmRequestInfo
#
#     def SetScmInfo(self, This, pScmInfo):
#         print('IScmRequestInfo.SetScmInfo')
#         return E_NOTIMPL
#
#     def GetScmInfo(self, This, ppScmInfo):
#         print('IScmRequestInfo.GetScmInfo')
#         return E_NOTIMPL
#
#     def SetRemoteRequestInfo(self, This, pRemoteReq):
#         print('IScmRequestInfo.SetRemoteRequestInfo')
#         return E_NOTIMPL
#
#     def GetRemoteRequestInfo(self, This, ppRemoteReq):
#         print('IScmRequestInfo.GetRemoteRequestInfo')
#         return E_NOTIMPL
#
IScmRequestInfo._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # SetScmInfo -> pScmInfo:*PRIV_SCM_INFO
        "SetScmInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(PRIV_SCM_INFO))(3, "SetScmInfo"),
        # GetScmInfo -> ppScmInfo:**PRIV_SCM_INFO
        "GetScmInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(PRIV_SCM_INFO)))(4, "GetScmInfo"),
        # SetRemoteRequestInfo -> pRemoteReq:*REMOTE_REQUEST_SCM_INFO
        "SetRemoteRequestInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(REMOTE_REQUEST_SCM_INFO))(5, "SetRemoteRequestInfo"),
        # GetRemoteRequestInfo -> ppRemoteReq:**REMOTE_REQUEST_SCM_INFO
        "GetRemoteRequestInfo": ctypes.WINFUNCTYPE(HRESULT, POINTER(POINTER(REMOTE_REQUEST_SCM_INFO)))(6, "GetRemoteRequestInfo"),
    }

# class IStandardActivatorImplem(windows.com.COMImplementation):
#     IMPLEMENT = IStandardActivator
#
#     def StandardGetClassObject(self, This, rclsid, dwClsCtx, pServerInfo, riid, ppv):
#         print('IStandardActivator.StandardGetClassObject')
#         return E_NOTIMPL
#
#     def StandardCreateInstance(self, This, Clsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults):
#         print('IStandardActivator.StandardCreateInstance')
#         return E_NOTIMPL
#
#     def StandardGetInstanceFromFile(self, This, pServerInfo, pclsidOverride, punkOuter, dwClsCtx, grfMode, pwszName, dwCount, pResults):
#         print('IStandardActivator.StandardGetInstanceFromFile')
#         return E_NOTIMPL
#
#     def StandardGetInstanceFromIStorage(self, This, pServerInfo, pclsidOverride, punkOuter, dwClsCtx, pstg, dwCount, pResults):
#         print('IStandardActivator.StandardGetInstanceFromIStorage')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IStandardActivator.Reset')
#         return E_NOTIMPL
#
IStandardActivator._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # StandardGetClassObject -> rclsid:REFCLSID, dwClsCtx:DWORD, pServerInfo:*COSERVERINFO, riid:REFIID, ppv:**void
        "StandardGetClassObject": ctypes.WINFUNCTYPE(HRESULT, REFCLSID, DWORD, POINTER(COSERVERINFO), REFIID, POINTER(PVOID))(3, "StandardGetClassObject"),
        # StandardCreateInstance -> Clsid:REFCLSID, punkOuter:*IUnknown, dwClsCtx:DWORD, pServerInfo:*COSERVERINFO, dwCount:DWORD, pResults:*MULTI_QI
        "StandardCreateInstance": ctypes.WINFUNCTYPE(HRESULT, REFCLSID, IUnknown, DWORD, POINTER(COSERVERINFO), DWORD, POINTER(MULTI_QI))(4, "StandardCreateInstance"),
        # StandardGetInstanceFromFile -> pServerInfo:*COSERVERINFO, pclsidOverride:*CLSID, punkOuter:*IUnknown, dwClsCtx:DWORD, grfMode:DWORD, pwszName:*OLECHAR, dwCount:DWORD, pResults:*MULTI_QI
        "StandardGetInstanceFromFile": ctypes.WINFUNCTYPE(HRESULT, POINTER(COSERVERINFO), POINTER(CLSID), IUnknown, DWORD, DWORD, POINTER(OLECHAR), DWORD, POINTER(MULTI_QI))(5, "StandardGetInstanceFromFile"),
        # StandardGetInstanceFromIStorage -> pServerInfo:*COSERVERINFO, pclsidOverride:*CLSID, punkOuter:*IUnknown, dwClsCtx:DWORD, pstg:*IStorage, dwCount:DWORD, pResults:*MULTI_QI
        "StandardGetInstanceFromIStorage": ctypes.WINFUNCTYPE(HRESULT, POINTER(COSERVERINFO), POINTER(CLSID), IUnknown, DWORD, IStorage, DWORD, POINTER(MULTI_QI))(6, "StandardGetInstanceFromIStorage"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(7, "Reset"),
    }

# class ISystemActivatorImplem(windows.com.COMImplementation):
#     IMPLEMENT = ISystemActivator
#
#     def GetClassObject(self, This, pActProperties, ppActProperties):
#         print('ISystemActivator.GetClassObject')
#         return E_NOTIMPL
#
#     def CreateInstance(self, This, pUnkOuter, pActProperties, ppActProperties):
#         print('ISystemActivator.CreateInstance')
#         return E_NOTIMPL
#
ISystemActivator._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetClassObject -> pActProperties:*IActivationPropertiesIn, ppActProperties:**IActivationPropertiesOut
        "GetClassObject": ctypes.WINFUNCTYPE(HRESULT, IActivationPropertiesIn, POINTER(IActivationPropertiesOut))(3, "GetClassObject"),
        # CreateInstance -> pUnkOuter:*IUnknown, pActProperties:*IActivationPropertiesIn, ppActProperties:**IActivationPropertiesOut
        "CreateInstance": ctypes.WINFUNCTYPE(HRESULT, IUnknown, IActivationPropertiesIn, POINTER(IActivationPropertiesOut))(4, "CreateInstance"),
    }

# class IBindCtxImplem(windows.com.COMImplementation):
#     IMPLEMENT = IBindCtx
#
#     def RegisterObjectBound(self, This, punk):
#         print('IBindCtx.RegisterObjectBound')
#         return E_NOTIMPL
#
#     def RevokeObjectBound(self, This, punk):
#         print('IBindCtx.RevokeObjectBound')
#         return E_NOTIMPL
#
#     def ReleaseBoundObjects(self, This):
#         print('IBindCtx.ReleaseBoundObjects')
#         return E_NOTIMPL
#
#     def SetBindOptions(self, This, pbindopts):
#         print('IBindCtx.SetBindOptions')
#         return E_NOTIMPL
#
#     def GetBindOptions(self, This, pbindopts):
#         print('IBindCtx.GetBindOptions')
#         return E_NOTIMPL
#
#     def GetRunningObjectTable(self, This, pprot):
#         print('IBindCtx.GetRunningObjectTable')
#         return E_NOTIMPL
#
#     def RegisterObjectParam(self, This, pszKey, punk):
#         print('IBindCtx.RegisterObjectParam')
#         return E_NOTIMPL
#
#     def GetObjectParam(self, This, pszKey, ppunk):
#         print('IBindCtx.GetObjectParam')
#         return E_NOTIMPL
#
#     def EnumObjectParam(self, This, ppenum):
#         print('IBindCtx.EnumObjectParam')
#         return E_NOTIMPL
#
#     def RevokeObjectParam(self, This, pszKey):
#         print('IBindCtx.RevokeObjectParam')
#         return E_NOTIMPL
#
IBindCtx._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # RegisterObjectBound -> punk:*IUnknown
        "RegisterObjectBound": ctypes.WINFUNCTYPE(HRESULT, IUnknown)(3, "RegisterObjectBound"),
        # RevokeObjectBound -> punk:*IUnknown
        "RevokeObjectBound": ctypes.WINFUNCTYPE(HRESULT, IUnknown)(4, "RevokeObjectBound"),
        # ReleaseBoundObjects -> 
        "ReleaseBoundObjects": ctypes.WINFUNCTYPE(HRESULT)(5, "ReleaseBoundObjects"),
        # SetBindOptions -> pbindopts:*BIND_OPTS
        "SetBindOptions": ctypes.WINFUNCTYPE(HRESULT, POINTER(BIND_OPTS))(6, "SetBindOptions"),
        # GetBindOptions -> pbindopts:*BIND_OPTS
        "GetBindOptions": ctypes.WINFUNCTYPE(HRESULT, POINTER(BIND_OPTS))(7, "GetBindOptions"),
        # GetRunningObjectTable -> pprot:**IRunningObjectTable
        "GetRunningObjectTable": ctypes.WINFUNCTYPE(HRESULT, POINTER(IRunningObjectTable))(8, "GetRunningObjectTable"),
        # RegisterObjectParam -> pszKey:LPOLESTR, punk:*IUnknown
        "RegisterObjectParam": ctypes.WINFUNCTYPE(HRESULT, LPOLESTR, IUnknown)(9, "RegisterObjectParam"),
        # GetObjectParam -> pszKey:LPOLESTR, ppunk:**IUnknown
        "GetObjectParam": ctypes.WINFUNCTYPE(HRESULT, LPOLESTR, POINTER(IUnknown))(10, "GetObjectParam"),
        # EnumObjectParam -> ppenum:**IEnumString
        "EnumObjectParam": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumString))(11, "EnumObjectParam"),
        # RevokeObjectParam -> pszKey:LPOLESTR
        "RevokeObjectParam": ctypes.WINFUNCTYPE(HRESULT, LPOLESTR)(12, "RevokeObjectParam"),
    }

# class IEnumExplorerCommandImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumExplorerCommand
#
#     def Next(self, This, celt, pUICommand, pceltFetched):
#         print('IEnumExplorerCommand.Next')
#         return E_NOTIMPL
#
#     def Skip(self, This, celt):
#         print('IEnumExplorerCommand.Skip')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IEnumExplorerCommand.Reset')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppenum):
#         print('IEnumExplorerCommand.Clone')
#         return E_NOTIMPL
#
IEnumExplorerCommand._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Next -> celt:ULONG, pUICommand:**IExplorerCommand, pceltFetched:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(IExplorerCommand), POINTER(ULONG))(3, "Next"),
        # Skip -> celt:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, ULONG)(4, "Skip"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(5, "Reset"),
        # Clone -> ppenum:**IEnumExplorerCommand
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumExplorerCommand))(6, "Clone"),
    }

# class IEnumMonikerImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumMoniker
#
#     def Next(self, This, celt, rgelt, pceltFetched):
#         print('IEnumMoniker.Next')
#         return E_NOTIMPL
#
#     def Skip(self, This, celt):
#         print('IEnumMoniker.Skip')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IEnumMoniker.Reset')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppenum):
#         print('IEnumMoniker.Clone')
#         return E_NOTIMPL
#
IEnumMoniker._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Next -> celt:ULONG, rgelt:**IMoniker, pceltFetched:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(IMoniker), POINTER(ULONG))(3, "Next"),
        # Skip -> celt:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, ULONG)(4, "Skip"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(5, "Reset"),
        # Clone -> ppenum:**IEnumMoniker
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumMoniker))(6, "Clone"),
    }

# class IEnumShellItemsImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumShellItems
#
#     def Next(self, This, celt, rgelt, pceltFetched):
#         print('IEnumShellItems.Next')
#         return E_NOTIMPL
#
#     def Skip(self, This, celt):
#         print('IEnumShellItems.Skip')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IEnumShellItems.Reset')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppenum):
#         print('IEnumShellItems.Clone')
#         return E_NOTIMPL
#
IEnumShellItems._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Next -> celt:ULONG, rgelt:**IShellItem, pceltFetched:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(IShellItem), POINTER(ULONG))(3, "Next"),
        # Skip -> celt:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, ULONG)(4, "Skip"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(5, "Reset"),
        # Clone -> ppenum:**IEnumShellItems
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumShellItems))(6, "Clone"),
    }

# class IEnumStringImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumString
#
#     def Next(self, This, celt, rgelt, pceltFetched):
#         print('IEnumString.Next')
#         return E_NOTIMPL
#
#     def Skip(self, This, celt):
#         print('IEnumString.Skip')
#         return E_NOTIMPL
#
#     def Reset(self, This):
#         print('IEnumString.Reset')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppenum):
#         print('IEnumString.Clone')
#         return E_NOTIMPL
#
IEnumString._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Next -> celt:ULONG, rgelt:*LPOLESTR, pceltFetched:*ULONG
        "Next": ctypes.WINFUNCTYPE(HRESULT, ULONG, POINTER(LPOLESTR), POINTER(ULONG))(3, "Next"),
        # Skip -> celt:ULONG
        "Skip": ctypes.WINFUNCTYPE(HRESULT, ULONG)(4, "Skip"),
        # Reset -> 
        "Reset": ctypes.WINFUNCTYPE(HRESULT)(5, "Reset"),
        # Clone -> ppenum:**IEnumString
        "Clone": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumString))(6, "Clone"),
    }

# class IExplorerCommandImplem(windows.com.COMImplementation):
#     IMPLEMENT = IExplorerCommand
#
#     def GetTitle(self, This, psiItemArray, ppszName):
#         print('IExplorerCommand.GetTitle')
#         return E_NOTIMPL
#
#     def GetIcon(self, This, psiItemArray, ppszIcon):
#         print('IExplorerCommand.GetIcon')
#         return E_NOTIMPL
#
#     def GetToolTip(self, This, psiItemArray, ppszInfotip):
#         print('IExplorerCommand.GetToolTip')
#         return E_NOTIMPL
#
#     def GetCanonicalName(self, This, pguidCommandName):
#         print('IExplorerCommand.GetCanonicalName')
#         return E_NOTIMPL
#
#     def GetState(self, This, psiItemArray, fOkToBeSlow, pCmdState):
#         print('IExplorerCommand.GetState')
#         return E_NOTIMPL
#
#     def Invoke(self, This, psiItemArray, pbc):
#         print('IExplorerCommand.Invoke')
#         return E_NOTIMPL
#
#     def GetFlags(self, This, pFlags):
#         print('IExplorerCommand.GetFlags')
#         return E_NOTIMPL
#
#     def EnumSubCommands(self, This, ppEnum):
#         print('IExplorerCommand.EnumSubCommands')
#         return E_NOTIMPL
#
IExplorerCommand._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetTitle -> psiItemArray:*IShellItemArray, ppszName:*LPWSTR
        "GetTitle": ctypes.WINFUNCTYPE(HRESULT, IShellItemArray, POINTER(LPWSTR))(3, "GetTitle"),
        # GetIcon -> psiItemArray:*IShellItemArray, ppszIcon:*LPWSTR
        "GetIcon": ctypes.WINFUNCTYPE(HRESULT, IShellItemArray, POINTER(LPWSTR))(4, "GetIcon"),
        # GetToolTip -> psiItemArray:*IShellItemArray, ppszInfotip:*LPWSTR
        "GetToolTip": ctypes.WINFUNCTYPE(HRESULT, IShellItemArray, POINTER(LPWSTR))(5, "GetToolTip"),
        # GetCanonicalName -> pguidCommandName:*GUID
        "GetCanonicalName": ctypes.WINFUNCTYPE(HRESULT, POINTER(GUID))(6, "GetCanonicalName"),
        # GetState -> psiItemArray:*IShellItemArray, fOkToBeSlow:BOOL, pCmdState:*EXPCMDSTATE
        "GetState": ctypes.WINFUNCTYPE(HRESULT, IShellItemArray, BOOL, POINTER(EXPCMDSTATE))(7, "GetState"),
        # Invoke -> psiItemArray:*IShellItemArray, pbc:*IBindCtx
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, IShellItemArray, IBindCtx)(8, "Invoke"),
        # GetFlags -> pFlags:*EXPCMDFLAGS
        "GetFlags": ctypes.WINFUNCTYPE(HRESULT, POINTER(EXPCMDFLAGS))(9, "GetFlags"),
        # EnumSubCommands -> ppEnum:**IEnumExplorerCommand
        "EnumSubCommands": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumExplorerCommand))(10, "EnumSubCommands"),
    }

# class IRunningObjectTableImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRunningObjectTable
#
#     def Register(self, This, grfFlags, punkObject, pmkObjectName, pdwRegister):
#         print('IRunningObjectTable.Register')
#         return E_NOTIMPL
#
#     def Revoke(self, This, dwRegister):
#         print('IRunningObjectTable.Revoke')
#         return E_NOTIMPL
#
#     def IsRunning(self, This, pmkObjectName):
#         print('IRunningObjectTable.IsRunning')
#         return E_NOTIMPL
#
#     def GetObject(self, This, pmkObjectName, ppunkObject):
#         print('IRunningObjectTable.GetObject')
#         return E_NOTIMPL
#
#     def NoteChangeTime(self, This, dwRegister, pfiletime):
#         print('IRunningObjectTable.NoteChangeTime')
#         return E_NOTIMPL
#
#     def GetTimeOfLastChange(self, This, pmkObjectName, pfiletime):
#         print('IRunningObjectTable.GetTimeOfLastChange')
#         return E_NOTIMPL
#
#     def EnumRunning(self, This, ppenumMoniker):
#         print('IRunningObjectTable.EnumRunning')
#         return E_NOTIMPL
#
IRunningObjectTable._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Register -> grfFlags:DWORD, punkObject:*IUnknown, pmkObjectName:*IMoniker, pdwRegister:*DWORD
        "Register": ctypes.WINFUNCTYPE(HRESULT, DWORD, IUnknown, IMoniker, POINTER(DWORD))(3, "Register"),
        # Revoke -> dwRegister:DWORD
        "Revoke": ctypes.WINFUNCTYPE(HRESULT, DWORD)(4, "Revoke"),
        # IsRunning -> pmkObjectName:*IMoniker
        "IsRunning": ctypes.WINFUNCTYPE(HRESULT, IMoniker)(5, "IsRunning"),
        # GetObject -> pmkObjectName:*IMoniker, ppunkObject:**IUnknown
        "GetObject": ctypes.WINFUNCTYPE(HRESULT, IMoniker, POINTER(IUnknown))(6, "GetObject"),
        # NoteChangeTime -> dwRegister:DWORD, pfiletime:*FILETIME
        "NoteChangeTime": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(FILETIME))(7, "NoteChangeTime"),
        # GetTimeOfLastChange -> pmkObjectName:*IMoniker, pfiletime:*FILETIME
        "GetTimeOfLastChange": ctypes.WINFUNCTYPE(HRESULT, IMoniker, POINTER(FILETIME))(8, "GetTimeOfLastChange"),
        # EnumRunning -> ppenumMoniker:**IEnumMoniker
        "EnumRunning": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumMoniker))(9, "EnumRunning"),
    }

# class IShellItemImplem(windows.com.COMImplementation):
#     IMPLEMENT = IShellItem
#
#     def BindToHandler(self, This, pbc, bhid, riid, ppv):
#         print('IShellItem.BindToHandler')
#         return E_NOTIMPL
#
#     def GetParent(self, This, ppsi):
#         print('IShellItem.GetParent')
#         return E_NOTIMPL
#
#     def GetDisplayName(self, This, sigdnName, ppszName):
#         print('IShellItem.GetDisplayName')
#         return E_NOTIMPL
#
#     def GetAttributes(self, This, sfgaoMask, psfgaoAttribs):
#         print('IShellItem.GetAttributes')
#         return E_NOTIMPL
#
#     def Compare(self, This, psi, hint, piOrder):
#         print('IShellItem.Compare')
#         return E_NOTIMPL
#
IShellItem._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # BindToHandler -> pbc:*IBindCtx, bhid:REFGUID, riid:REFIID, ppv:**void
        "BindToHandler": ctypes.WINFUNCTYPE(HRESULT, IBindCtx, REFGUID, REFIID, POINTER(PVOID))(3, "BindToHandler"),
        # GetParent -> ppsi:**IShellItem
        "GetParent": ctypes.WINFUNCTYPE(HRESULT, POINTER(IShellItem))(4, "GetParent"),
        # GetDisplayName -> sigdnName:SIGDN, ppszName:*LPWSTR
        "GetDisplayName": ctypes.WINFUNCTYPE(HRESULT, SIGDN, POINTER(LPWSTR))(5, "GetDisplayName"),
        # GetAttributes -> sfgaoMask:SFGAOF, psfgaoAttribs:*SFGAOF
        "GetAttributes": ctypes.WINFUNCTYPE(HRESULT, SFGAOF, POINTER(SFGAOF))(6, "GetAttributes"),
        # Compare -> psi:*IShellItem, hint:SICHINTF, piOrder:*INT
        "Compare": ctypes.WINFUNCTYPE(HRESULT, IShellItem, SICHINTF, POINTER(INT))(7, "Compare"),
    }

# class IShellItemArrayImplem(windows.com.COMImplementation):
#     IMPLEMENT = IShellItemArray
#
#     def BindToHandler(self, This, pbc, bhid, riid, ppvOut):
#         print('IShellItemArray.BindToHandler')
#         return E_NOTIMPL
#
#     def GetPropertyStore(self, This, flags, riid, ppv):
#         print('IShellItemArray.GetPropertyStore')
#         return E_NOTIMPL
#
#     def GetPropertyDescriptionList(self, This, keyType, riid, ppv):
#         print('IShellItemArray.GetPropertyDescriptionList')
#         return E_NOTIMPL
#
#     def GetAttributes(self, This, AttribFlags, sfgaoMask, psfgaoAttribs):
#         print('IShellItemArray.GetAttributes')
#         return E_NOTIMPL
#
#     def GetCount(self, This, pdwNumItems):
#         print('IShellItemArray.GetCount')
#         return E_NOTIMPL
#
#     def GetItemAt(self, This, dwIndex, ppsi):
#         print('IShellItemArray.GetItemAt')
#         return E_NOTIMPL
#
#     def EnumItems(self, This, ppenumShellItems):
#         print('IShellItemArray.EnumItems')
#         return E_NOTIMPL
#
IShellItemArray._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # BindToHandler -> pbc:*IBindCtx, bhid:REFGUID, riid:REFIID, ppvOut:**void
        "BindToHandler": ctypes.WINFUNCTYPE(HRESULT, IBindCtx, REFGUID, REFIID, POINTER(PVOID))(3, "BindToHandler"),
        # GetPropertyStore -> flags:GETPROPERTYSTOREFLAGS, riid:REFIID, ppv:**void
        "GetPropertyStore": ctypes.WINFUNCTYPE(HRESULT, GETPROPERTYSTOREFLAGS, REFIID, POINTER(PVOID))(4, "GetPropertyStore"),
        # GetPropertyDescriptionList -> keyType:REFPROPERTYKEY, riid:REFIID, ppv:**void
        "GetPropertyDescriptionList": ctypes.WINFUNCTYPE(HRESULT, REFPROPERTYKEY, REFIID, POINTER(PVOID))(5, "GetPropertyDescriptionList"),
        # GetAttributes -> AttribFlags:SIATTRIBFLAGS, sfgaoMask:SFGAOF, psfgaoAttribs:*SFGAOF
        "GetAttributes": ctypes.WINFUNCTYPE(HRESULT, SIATTRIBFLAGS, SFGAOF, POINTER(SFGAOF))(6, "GetAttributes"),
        # GetCount -> pdwNumItems:*DWORD
        "GetCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(7, "GetCount"),
        # GetItemAt -> dwIndex:DWORD, ppsi:**IShellItem
        "GetItemAt": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(IShellItem))(8, "GetItemAt"),
        # EnumItems -> ppenumShellItems:**IEnumShellItems
        "EnumItems": ctypes.WINFUNCTYPE(HRESULT, POINTER(IEnumShellItems))(9, "EnumItems"),
    }

# class IProxyManagerImplem(windows.com.COMImplementation):
#     IMPLEMENT = IProxyManager
#
#     def CreateServer(self, This, rclsid, clsctx, pv):
#         print('IProxyManager.CreateServer')
#         return E_NOTIMPL
#
#     def IsConnected(self, This):
#         print('IProxyManager.IsConnected')
#         return E_NOTIMPL
#
#     def LockConnection(self, This, fLock, fLastUnlockReleases):
#         print('IProxyManager.LockConnection')
#         return E_NOTIMPL
#
#     def Disconnect(self, This):
#         print('IProxyManager.Disconnect')
#         return E_NOTIMPL
#
#     def GetConnectionStatus(self, This):
#         print('IProxyManager.GetConnectionStatus')
#         return E_NOTIMPL
#
#     def ScalarDeletingDestructor(self, This):
#         print('IProxyManager.ScalarDeletingDestructor')
#         return E_NOTIMPL
#
#     def SetMapping(self, This):
#         print('IProxyManager.SetMapping')
#         return E_NOTIMPL
#
#     def GetMapping(self, This):
#         print('IProxyManager.GetMapping')
#         return E_NOTIMPL
#
#     def GetServerObjectContext(self, This):
#         print('IProxyManager.GetServerObjectContext')
#         return E_NOTIMPL
#
#     def GetWrapperForContex(self, This, pCtx, riid, ppv):
#         print('IProxyManager.GetWrapperForContex')
#         return E_NOTIMPL
#
IProxyManager._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # CreateServer -> rclsid:*REFCLSID, clsctx:*DWORD, pv:*PVOID
        "CreateServer": ctypes.WINFUNCTYPE(HRESULT, POINTER(REFCLSID), POINTER(DWORD), POINTER(PVOID))(3, "CreateServer"),
        # IsConnected -> 
        "IsConnected": ctypes.WINFUNCTYPE(BOOL)(4, "IsConnected"),
        # LockConnection -> fLock:BOOL, fLastUnlockReleases:BOOL
        "LockConnection": ctypes.WINFUNCTYPE(HRESULT, BOOL, BOOL)(5, "LockConnection"),
        # Disconnect -> 
        "Disconnect": ctypes.WINFUNCTYPE(HRESULT)(6, "Disconnect"),
        # GetConnectionStatus -> 
        "GetConnectionStatus": ctypes.WINFUNCTYPE(HRESULT)(7, "GetConnectionStatus"),
        # ScalarDeletingDestructor -> 
        "ScalarDeletingDestructor": ctypes.WINFUNCTYPE(HRESULT)(8, "ScalarDeletingDestructor"),
        # SetMapping -> 
        "SetMapping": ctypes.WINFUNCTYPE(HRESULT)(9, "SetMapping"),
        # GetMapping -> 
        "GetMapping": ctypes.WINFUNCTYPE(HRESULT)(10, "GetMapping"),
        # GetServerObjectContext -> 
        "GetServerObjectContext": ctypes.WINFUNCTYPE(IObjContext)(11, "GetServerObjectContext"),
        # GetWrapperForContex -> pCtx:*IObjContext, riid:*IID, ppv:**void
        "GetWrapperForContex": ctypes.WINFUNCTYPE(HRESULT, IObjContext, POINTER(IID), POINTER(PVOID))(12, "GetWrapperForContex"),
    }

# class IProxyServerIdentityImplem(windows.com.COMImplementation):
#     IMPLEMENT = IProxyServerIdentity
#
#     def GetServerProcessId(self, This, processId):
#         print('IProxyServerIdentity.GetServerProcessId')
#         return E_NOTIMPL
#
#     def GetServerProcessHandle(self, This, dwDesiredAccess, bInheritHandle, phProcess):
#         print('IProxyServerIdentity.GetServerProcessHandle')
#         return E_NOTIMPL
#
IProxyServerIdentity._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetServerProcessId -> processId:*UINT
        "GetServerProcessId": ctypes.WINFUNCTYPE(HRESULT, POINTER(UINT))(3, "GetServerProcessId"),
        # GetServerProcessHandle -> dwDesiredAccess:DWORD, bInheritHandle:INT, phProcess:*PVOID
        "GetServerProcessHandle": ctypes.WINFUNCTYPE(HRESULT, DWORD, INT, POINTER(PVOID))(4, "GetServerProcessHandle"),
    }

# class IApplicationActivationManagerImplem(windows.com.COMImplementation):
#     IMPLEMENT = IApplicationActivationManager
#
#     def ActivateApplication(self, This, appUserModelId, arguments, options, processId):
#         print('IApplicationActivationManager.ActivateApplication')
#         return E_NOTIMPL
#
#     def ActivateForFile(self, This, appUserModelId, itemArray, verb, processId):
#         print('IApplicationActivationManager.ActivateForFile')
#         return E_NOTIMPL
#
#     def ActivateForProtocol(self, This, appUserModelId, itemArray, processId):
#         print('IApplicationActivationManager.ActivateForProtocol')
#         return E_NOTIMPL
#
IApplicationActivationManager._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # ActivateApplication -> appUserModelId:LPCWSTR, arguments:LPCWSTR, options:ACTIVATEOPTIONS, processId:*DWORD
        "ActivateApplication": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LPCWSTR, ACTIVATEOPTIONS, POINTER(DWORD))(3, "ActivateApplication"),
        # ActivateForFile -> appUserModelId:LPCWSTR, itemArray:*IShellItemArray, verb:LPCWSTR, processId:*DWORD
        "ActivateForFile": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, IShellItemArray, LPCWSTR, POINTER(DWORD))(4, "ActivateForFile"),
        # ActivateForProtocol -> appUserModelId:LPCWSTR, itemArray:*IShellItemArray, processId:*DWORD
        "ActivateForProtocol": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, IShellItemArray, POINTER(DWORD))(5, "ActivateForProtocol"),
    }

# class IPackageDebugSettingsImplem(windows.com.COMImplementation):
#     IMPLEMENT = IPackageDebugSettings
#
#     def EnableDebugging(self, This, packageFullName, debuggerCommandLine, environment):
#         print('IPackageDebugSettings.EnableDebugging')
#         return E_NOTIMPL
#
#     def DisableDebugging(self, This, packageFullName):
#         print('IPackageDebugSettings.DisableDebugging')
#         return E_NOTIMPL
#
#     def Suspend(self, This, packageFullName):
#         print('IPackageDebugSettings.Suspend')
#         return E_NOTIMPL
#
#     def Resume(self, This, packageFullName):
#         print('IPackageDebugSettings.Resume')
#         return E_NOTIMPL
#
#     def TerminateAllProcesses(self, This, packageFullName):
#         print('IPackageDebugSettings.TerminateAllProcesses')
#         return E_NOTIMPL
#
#     def SetTargetSessionId(self, This, sessionId):
#         print('IPackageDebugSettings.SetTargetSessionId')
#         return E_NOTIMPL
#
#     def EnumerateBackgroundTasks(self, This, packageFullName, taskCount, taskIds, taskNames):
#         print('IPackageDebugSettings.EnumerateBackgroundTasks')
#         return E_NOTIMPL
#
#     def ActivateBackgroundTask(self, This, taskId):
#         print('IPackageDebugSettings.ActivateBackgroundTask')
#         return E_NOTIMPL
#
#     def StartServicing(self, This, packageFullName):
#         print('IPackageDebugSettings.StartServicing')
#         return E_NOTIMPL
#
#     def StopServicing(self, This, packageFullName):
#         print('IPackageDebugSettings.StopServicing')
#         return E_NOTIMPL
#
#     def StartSessionRedirection(self, This, packageFullName, sessionId):
#         print('IPackageDebugSettings.StartSessionRedirection')
#         return E_NOTIMPL
#
#     def StopSessionRedirection(self, This, packageFullName):
#         print('IPackageDebugSettings.StopSessionRedirection')
#         return E_NOTIMPL
#
#     def GetPackageExecutionState(self, This, packageFullName, packageExecutionState):
#         print('IPackageDebugSettings.GetPackageExecutionState')
#         return E_NOTIMPL
#
#     def RegisterForPackageStateChanges(self, This, packageFullName, pPackageExecutionStateChangeNotification, pdwCookie):
#         print('IPackageDebugSettings.RegisterForPackageStateChanges')
#         return E_NOTIMPL
#
#     def UnregisterForPackageStateChanges(self, This, dwCookie):
#         print('IPackageDebugSettings.UnregisterForPackageStateChanges')
#         return E_NOTIMPL
#
IPackageDebugSettings._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # EnableDebugging -> packageFullName:LPCWSTR, debuggerCommandLine:LPCWSTR, environment:PZZWSTR
        "EnableDebugging": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, LPCWSTR, PZZWSTR)(3, "EnableDebugging"),
        # DisableDebugging -> packageFullName:LPCWSTR
        "DisableDebugging": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(4, "DisableDebugging"),
        # Suspend -> packageFullName:LPCWSTR
        "Suspend": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(5, "Suspend"),
        # Resume -> packageFullName:LPCWSTR
        "Resume": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(6, "Resume"),
        # TerminateAllProcesses -> packageFullName:LPCWSTR
        "TerminateAllProcesses": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(7, "TerminateAllProcesses"),
        # SetTargetSessionId -> sessionId:ULONG
        "SetTargetSessionId": ctypes.WINFUNCTYPE(HRESULT, ULONG)(8, "SetTargetSessionId"),
        # EnumerateBackgroundTasks -> packageFullName:LPCWSTR, taskCount:*ULONG, taskIds:*LPCGUID, taskNames:**LPCWSTR
        "EnumerateBackgroundTasks": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, POINTER(ULONG), POINTER(LPCGUID), POINTER(POINTER(LPCWSTR)))(9, "EnumerateBackgroundTasks"),
        # ActivateBackgroundTask -> taskId:LPCGUID
        "ActivateBackgroundTask": ctypes.WINFUNCTYPE(HRESULT, LPCGUID)(10, "ActivateBackgroundTask"),
        # StartServicing -> packageFullName:LPCWSTR
        "StartServicing": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(11, "StartServicing"),
        # StopServicing -> packageFullName:LPCWSTR
        "StopServicing": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(12, "StopServicing"),
        # StartSessionRedirection -> packageFullName:LPCWSTR, sessionId:ULONG
        "StartSessionRedirection": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, ULONG)(13, "StartSessionRedirection"),
        # StopSessionRedirection -> packageFullName:LPCWSTR
        "StopSessionRedirection": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR)(14, "StopSessionRedirection"),
        # GetPackageExecutionState -> packageFullName:LPCWSTR, packageExecutionState:*PACKAGE_EXECUTION_STATE
        "GetPackageExecutionState": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, POINTER(PACKAGE_EXECUTION_STATE))(15, "GetPackageExecutionState"),
        # RegisterForPackageStateChanges -> packageFullName:LPCWSTR, pPackageExecutionStateChangeNotification:*IPackageExecutionStateChangeNotification, pdwCookie:*DWORD
        "RegisterForPackageStateChanges": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, IPackageExecutionStateChangeNotification, POINTER(DWORD))(16, "RegisterForPackageStateChanges"),
        # UnregisterForPackageStateChanges -> dwCookie:DWORD
        "UnregisterForPackageStateChanges": ctypes.WINFUNCTYPE(HRESULT, DWORD)(17, "UnregisterForPackageStateChanges"),
    }

# class IPackageExecutionStateChangeNotificationImplem(windows.com.COMImplementation):
#     IMPLEMENT = IPackageExecutionStateChangeNotification
#
#     def OnStateChanged(self, This, pszPackageFullName, pesNewState):
#         print('IPackageExecutionStateChangeNotification.OnStateChanged')
#         return E_NOTIMPL
#
IPackageExecutionStateChangeNotification._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # OnStateChanged -> pszPackageFullName:LPCWSTR, pesNewState:PACKAGE_EXECUTION_STATE
        "OnStateChanged": ctypes.WINFUNCTYPE(HRESULT, LPCWSTR, PACKAGE_EXECUTION_STATE)(3, "OnStateChanged"),
    }

# class IChannelHookImplem(windows.com.COMImplementation):
#     IMPLEMENT = IChannelHook
#
#     def ClientGetSize(self, This, uExtent, riid, pDataSize):
#         print('IChannelHook.ClientGetSize')
#         return E_NOTIMPL
#
#     def ClientFillBuffer(self, This, uExtent, riid, pDataSize, pDataBuffer):
#         print('IChannelHook.ClientFillBuffer')
#         return E_NOTIMPL
#
#     def ClientNotify(self, This, uExtent, riid, cbDataSize, pDataBuffer, lDataRep, hrFault):
#         print('IChannelHook.ClientNotify')
#         return E_NOTIMPL
#
#     def ServerNotify(self, This, uExtent, riid, cbDataSize, pDataBuffer, lDataRep):
#         print('IChannelHook.ServerNotify')
#         return E_NOTIMPL
#
#     def ServerGetSize(self, This, uExtent, riid, hrFault, pDataSize):
#         print('IChannelHook.ServerGetSize')
#         return E_NOTIMPL
#
#     def ServerFillBuffer(self, This, uExtent, riid, pDataSize, pDataBuffer, hrFault):
#         print('IChannelHook.ServerFillBuffer')
#         return E_NOTIMPL
#
IChannelHook._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # ClientGetSize -> uExtent:REFGUID, riid:REFIID, pDataSize:*ULONG
        "ClientGetSize": ctypes.WINFUNCTYPE(PVOID, REFGUID, REFIID, POINTER(ULONG))(3, "ClientGetSize"),
        # ClientFillBuffer -> uExtent:REFGUID, riid:REFIID, pDataSize:*ULONG, pDataBuffer:*void
        "ClientFillBuffer": ctypes.WINFUNCTYPE(PVOID, REFGUID, REFIID, POINTER(ULONG), PVOID)(4, "ClientFillBuffer"),
        # ClientNotify -> uExtent:REFGUID, riid:REFIID, cbDataSize:ULONG, pDataBuffer:*void, lDataRep:DWORD, hrFault:HRESULT
        "ClientNotify": ctypes.WINFUNCTYPE(PVOID, REFGUID, REFIID, ULONG, PVOID, DWORD, HRESULT)(5, "ClientNotify"),
        # ServerNotify -> uExtent:REFGUID, riid:REFIID, cbDataSize:ULONG, pDataBuffer:*void, lDataRep:DWORD
        "ServerNotify": ctypes.WINFUNCTYPE(PVOID, REFGUID, REFIID, ULONG, PVOID, DWORD)(6, "ServerNotify"),
        # ServerGetSize -> uExtent:REFGUID, riid:REFIID, hrFault:HRESULT, pDataSize:*ULONG
        "ServerGetSize": ctypes.WINFUNCTYPE(PVOID, REFGUID, REFIID, HRESULT, POINTER(ULONG))(7, "ServerGetSize"),
        # ServerFillBuffer -> uExtent:REFGUID, riid:REFIID, pDataSize:*ULONG, pDataBuffer:*void, hrFault:HRESULT
        "ServerFillBuffer": ctypes.WINFUNCTYPE(PVOID, REFGUID, REFIID, POINTER(ULONG), PVOID, HRESULT)(8, "ServerFillBuffer"),
    }

# class IRpcChannelBufferImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRpcChannelBuffer
#
#     def GetBuffer(self, This, pMessage, riid):
#         print('IRpcChannelBuffer.GetBuffer')
#         return E_NOTIMPL
#
#     def SendReceive(self, This, pMessage, pStatus):
#         print('IRpcChannelBuffer.SendReceive')
#         return E_NOTIMPL
#
#     def FreeBuffer(self, This, pMessage):
#         print('IRpcChannelBuffer.FreeBuffer')
#         return E_NOTIMPL
#
#     def GetDestCtx(self, This, pdwDestContext, ppvDestContext):
#         print('IRpcChannelBuffer.GetDestCtx')
#         return E_NOTIMPL
#
#     def IsConnected(self, This):
#         print('IRpcChannelBuffer.IsConnected')
#         return E_NOTIMPL
#
IRpcChannelBuffer._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetBuffer -> pMessage:*RPCOLEMESSAGE, riid:REFIID
        "GetBuffer": ctypes.WINFUNCTYPE(HRESULT, POINTER(RPCOLEMESSAGE), REFIID)(3, "GetBuffer"),
        # SendReceive -> pMessage:*RPCOLEMESSAGE, pStatus:*ULONG
        "SendReceive": ctypes.WINFUNCTYPE(HRESULT, POINTER(RPCOLEMESSAGE), POINTER(ULONG))(4, "SendReceive"),
        # FreeBuffer -> pMessage:*RPCOLEMESSAGE
        "FreeBuffer": ctypes.WINFUNCTYPE(HRESULT, POINTER(RPCOLEMESSAGE))(5, "FreeBuffer"),
        # GetDestCtx -> pdwDestContext:*DWORD, ppvDestContext:**void
        "GetDestCtx": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD), POINTER(PVOID))(6, "GetDestCtx"),
        # IsConnected -> 
        "IsConnected": ctypes.WINFUNCTYPE(HRESULT)(7, "IsConnected"),
    }

# class IRpcHelperImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRpcHelper
#
#     def GetDCOMProtocolVersion(self, This, pComVersion):
#         print('IRpcHelper.GetDCOMProtocolVersion')
#         return E_NOTIMPL
#
#     def GetIIDFromOBJREF(self, This, pObjRef, piid):
#         print('IRpcHelper.GetIIDFromOBJREF')
#         return E_NOTIMPL
#
IRpcHelper._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetDCOMProtocolVersion -> pComVersion:*DWORD
        "GetDCOMProtocolVersion": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(3, "GetDCOMProtocolVersion"),
        # GetIIDFromOBJREF -> pObjRef:*void, piid:**IID
        "GetIIDFromOBJREF": ctypes.WINFUNCTYPE(HRESULT, PVOID, POINTER(POINTER(IID)))(4, "GetIIDFromOBJREF"),
    }

# class IRpcOptionsImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRpcOptions
#
#     def Set(self, This, pPrx, dwProperty, dwValue):
#         print('IRpcOptions.Set')
#         return E_NOTIMPL
#
#     def Query(self, This, pPrx, dwProperty, pdwValue):
#         print('IRpcOptions.Query')
#         return E_NOTIMPL
#
IRpcOptions._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Set -> pPrx:*IUnknown, dwProperty:DWORD, dwValue:ULONG_PTR
        "Set": ctypes.WINFUNCTYPE(HRESULT, IUnknown, DWORD, ULONG_PTR)(3, "Set"),
        # Query -> pPrx:*IUnknown, dwProperty:DWORD, pdwValue:*ULONG_PTR
        "Query": ctypes.WINFUNCTYPE(HRESULT, IUnknown, DWORD, POINTER(ULONG_PTR))(4, "Query"),
    }

# class IRpcStubBufferImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRpcStubBuffer
#
#     def Connect(self, This, pUnkServer):
#         print('IRpcStubBuffer.Connect')
#         return E_NOTIMPL
#
#     def Disconnect(self, This):
#         print('IRpcStubBuffer.Disconnect')
#         return E_NOTIMPL
#
#     def Invoke(self, This, _prpcmsg, _pRpcChannelBuffer):
#         print('IRpcStubBuffer.Invoke')
#         return E_NOTIMPL
#
#     def IsIIDSupported(self, This, riid):
#         print('IRpcStubBuffer.IsIIDSupported')
#         return E_NOTIMPL
#
#     def CountRefs(self, This):
#         print('IRpcStubBuffer.CountRefs')
#         return E_NOTIMPL
#
#     def DebugServerQueryInterface(self, This, ppv):
#         print('IRpcStubBuffer.DebugServerQueryInterface')
#         return E_NOTIMPL
#
#     def DebugServerRelease(self, This, pv):
#         print('IRpcStubBuffer.DebugServerRelease')
#         return E_NOTIMPL
#
IRpcStubBuffer._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:*PVOID
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # Connect -> pUnkServer:*IUnknown
        "Connect": ctypes.WINFUNCTYPE(HRESULT, IUnknown)(3, "Connect"),
        # Disconnect -> 
        "Disconnect": ctypes.WINFUNCTYPE(PVOID)(4, "Disconnect"),
        # Invoke -> _prpcmsg:*RPCOLEMESSAGE, _pRpcChannelBuffer:*IRpcChannelBuffer
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, POINTER(RPCOLEMESSAGE), IRpcChannelBuffer)(5, "Invoke"),
        # IsIIDSupported -> riid:REFIID
        "IsIIDSupported": ctypes.WINFUNCTYPE(PVOID, REFIID)(6, "IsIIDSupported"),
        # CountRefs -> 
        "CountRefs": ctypes.WINFUNCTYPE(ULONG)(7, "CountRefs"),
        # DebugServerQueryInterface -> ppv:*PVOID
        "DebugServerQueryInterface": ctypes.WINFUNCTYPE(HRESULT, POINTER(PVOID))(8, "DebugServerQueryInterface"),
        # DebugServerRelease -> pv:PVOID
        "DebugServerRelease": ctypes.WINFUNCTYPE(PVOID, PVOID)(9, "DebugServerRelease"),
    }

# class IActionImplem(windows.com.COMImplementation):
#     IMPLEMENT = IAction
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IAction.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IAction.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IAction.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IAction.Invoke')
#         return E_NOTIMPL
#
#     def get_Id(self, This, pId):
#         print('IAction.get_Id')
#         return E_NOTIMPL
#
#     def put_Id(self, This, Id):
#         print('IAction.put_Id')
#         return E_NOTIMPL
#
#     def get_Type(self, This, pType):
#         print('IAction.get_Type')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IActionCollectionImplem(windows.com.COMImplementation):
#     IMPLEMENT = IActionCollection
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IActionCollection.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IActionCollection.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IActionCollection.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IActionCollection.Invoke')
#         return E_NOTIMPL
#
#     def get_Count(self, This, pCount):
#         print('IActionCollection.get_Count')
#         return E_NOTIMPL
#
#     def get_Item(self, This, index, ppAction):
#         print('IActionCollection.get_Item')
#         return E_NOTIMPL
#
#     def get__NewEnum(self, This, ppEnum):
#         print('IActionCollection.get__NewEnum')
#         return E_NOTIMPL
#
#     def get_XmlText(self, This, pText):
#         print('IActionCollection.get_XmlText')
#         return E_NOTIMPL
#
#     def put_XmlText(self, This, text):
#         print('IActionCollection.put_XmlText')
#         return E_NOTIMPL
#
#     def Create(self, This, type, ppAction):
#         print('IActionCollection.Create')
#         return E_NOTIMPL
#
#     def Remove(self, This, index):
#         print('IActionCollection.Remove')
#         return E_NOTIMPL
#
#     def Clear(self, This):
#         print('IActionCollection.Clear')
#         return E_NOTIMPL
#
#     def get_Context(self, This, pContext):
#         print('IActionCollection.get_Context')
#         return E_NOTIMPL
#
#     def put_Context(self, This, context):
#         print('IActionCollection.put_Context')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IComHandlerActionImplem(windows.com.COMImplementation):
#     IMPLEMENT = IComHandlerAction
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IComHandlerAction.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IComHandlerAction.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IComHandlerAction.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IComHandlerAction.Invoke')
#         return E_NOTIMPL
#
#     def get_Id(self, This, pId):
#         print('IComHandlerAction.get_Id')
#         return E_NOTIMPL
#
#     def put_Id(self, This, Id):
#         print('IComHandlerAction.put_Id')
#         return E_NOTIMPL
#
#     def get_Type(self, This, pType):
#         print('IComHandlerAction.get_Type')
#         return E_NOTIMPL
#
#     def get_ClassId(self, This, pClsid):
#         print('IComHandlerAction.get_ClassId')
#         return E_NOTIMPL
#
#     def put_ClassId(self, This, clsid):
#         print('IComHandlerAction.put_ClassId')
#         return E_NOTIMPL
#
#     def get_Data(self, This, pData):
#         print('IComHandlerAction.get_Data')
#         return E_NOTIMPL
#
#     def put_Data(self, This, data):
#         print('IComHandlerAction.put_Data')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IEmailActionImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEmailAction
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IEmailAction.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IEmailAction.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IEmailAction.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IEmailAction.Invoke')
#         return E_NOTIMPL
#
#     def get_Id(self, This, pId):
#         print('IEmailAction.get_Id')
#         return E_NOTIMPL
#
#     def put_Id(self, This, Id):
#         print('IEmailAction.put_Id')
#         return E_NOTIMPL
#
#     def get_Type(self, This, pType):
#         print('IEmailAction.get_Type')
#         return E_NOTIMPL
#
#     def get_Server(self, This, pServer):
#         print('IEmailAction.get_Server')
#         return E_NOTIMPL
#
#     def put_Server(self, This, server):
#         print('IEmailAction.put_Server')
#         return E_NOTIMPL
#
#     def get_Subject(self, This, pSubject):
#         print('IEmailAction.get_Subject')
#         return E_NOTIMPL
#
#     def put_Subject(self, This, subject):
#         print('IEmailAction.put_Subject')
#         return E_NOTIMPL
#
#     def get_To(self, This, pTo):
#         print('IEmailAction.get_To')
#         return E_NOTIMPL
#
#     def put_To(self, This, to):
#         print('IEmailAction.put_To')
#         return E_NOTIMPL
#
#     def get_Cc(self, This, pCc):
#         print('IEmailAction.get_Cc')
#         return E_NOTIMPL
#
#     def put_Cc(self, This, cc):
#         print('IEmailAction.put_Cc')
#         return E_NOTIMPL
#
#     def get_Bcc(self, This, pBcc):
#         print('IEmailAction.get_Bcc')
#         return E_NOTIMPL
#
#     def put_Bcc(self, This, bcc):
#         print('IEmailAction.put_Bcc')
#         return E_NOTIMPL
#
#     def get_ReplyTo(self, This, pReplyTo):
#         print('IEmailAction.get_ReplyTo')
#         return E_NOTIMPL
#
#     def put_ReplyTo(self, This, replyTo):
#         print('IEmailAction.put_ReplyTo')
#         return E_NOTIMPL
#
#     def get_From(self, This, pFrom):
#         print('IEmailAction.get_From')
#         return E_NOTIMPL
#
#     def put_From(self, This, from):
#         print('IEmailAction.put_From')
#         return E_NOTIMPL
#
#     def get_HeaderFields(self, This, ppHeaderFields):
#         print('IEmailAction.get_HeaderFields')
#         return E_NOTIMPL
#
#     def put_HeaderFields(self, This, pHeaderFields):
#         print('IEmailAction.put_HeaderFields')
#         return E_NOTIMPL
#
#     def get_Body(self, This, pBody):
#         print('IEmailAction.get_Body')
#         return E_NOTIMPL
#
#     def put_Body(self, This, body):
#         print('IEmailAction.put_Body')
#         return E_NOTIMPL
#
#     def get_Attachments(self, This, pAttachements):
#         print('IEmailAction.get_Attachments')
#         return E_NOTIMPL
#
#     def put_Attachments(self, This, pAttachements):
#         print('IEmailAction.put_Attachments')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IExecActionImplem(windows.com.COMImplementation):
#     IMPLEMENT = IExecAction
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IExecAction.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IExecAction.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IExecAction.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IExecAction.Invoke')
#         return E_NOTIMPL
#
#     def get_Id(self, This, pId):
#         print('IExecAction.get_Id')
#         return E_NOTIMPL
#
#     def put_Id(self, This, Id):
#         print('IExecAction.put_Id')
#         return E_NOTIMPL
#
#     def get_Type(self, This, pType):
#         print('IExecAction.get_Type')
#         return E_NOTIMPL
#
#     def get_Path(self, This, pPath):
#         print('IExecAction.get_Path')
#         return E_NOTIMPL
#
#     def put_Path(self, This, path):
#         print('IExecAction.put_Path')
#         return E_NOTIMPL
#
#     def get_Arguments(self, This, pArgument):
#         print('IExecAction.get_Arguments')
#         return E_NOTIMPL
#
#     def put_Arguments(self, This, argument):
#         print('IExecAction.put_Arguments')
#         return E_NOTIMPL
#
#     def get_WorkingDirectory(self, This, pWorkingDirectory):
#         print('IExecAction.get_WorkingDirectory')
#         return E_NOTIMPL
#
#     def put_WorkingDirectory(self, This, workingDirectory):
#         print('IExecAction.put_WorkingDirectory')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IIdleSettingsImplem(windows.com.COMImplementation):
#     IMPLEMENT = IIdleSettings
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IIdleSettings.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IIdleSettings.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IIdleSettings.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IIdleSettings.Invoke')
#         return E_NOTIMPL
#
#     def get_IdleDuration(self, This, pDelay):
#         print('IIdleSettings.get_IdleDuration')
#         return E_NOTIMPL
#
#     def put_IdleDuration(self, This, delay):
#         print('IIdleSettings.put_IdleDuration')
#         return E_NOTIMPL
#
#     def get_WaitTimeout(self, This, pTimeout):
#         print('IIdleSettings.get_WaitTimeout')
#         return E_NOTIMPL
#
#     def put_WaitTimeout(self, This, timeout):
#         print('IIdleSettings.put_WaitTimeout')
#         return E_NOTIMPL
#
#     def get_StopOnIdleEnd(self, This, pStop):
#         print('IIdleSettings.get_StopOnIdleEnd')
#         return E_NOTIMPL
#
#     def put_StopOnIdleEnd(self, This, stop):
#         print('IIdleSettings.put_StopOnIdleEnd')
#         return E_NOTIMPL
#
#     def get_RestartOnIdle(self, This, pRestart):
#         print('IIdleSettings.get_RestartOnIdle')
#         return E_NOTIMPL
#
#     def put_RestartOnIdle(self, This, restart):
#         print('IIdleSettings.put_RestartOnIdle')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class INetworkSettingsImplem(windows.com.COMImplementation):
#     IMPLEMENT = INetworkSettings
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('INetworkSettings.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('INetworkSettings.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('INetworkSettings.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('INetworkSettings.Invoke')
#         return E_NOTIMPL
#
#     def get_Name(self, This, pName):
#         print('INetworkSettings.get_Name')
#         return E_NOTIMPL
#
#     def put_Name(self, This, name):
#         print('INetworkSettings.put_Name')
#         return E_NOTIMPL
#
#     def get_Id(self, This, pId):
#         print('INetworkSettings.get_Id')
#         return E_NOTIMPL
#
#     def put_Id(self, This, id):
#         print('INetworkSettings.put_Id')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IPrincipalImplem(windows.com.COMImplementation):
#     IMPLEMENT = IPrincipal
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IPrincipal.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IPrincipal.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IPrincipal.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IPrincipal.Invoke')
#         return E_NOTIMPL
#
#     def get_Id(self, This, pId):
#         print('IPrincipal.get_Id')
#         return E_NOTIMPL
#
#     def put_Id(self, This, Id):
#         print('IPrincipal.put_Id')
#         return E_NOTIMPL
#
#     def get_DisplayName(self, This, pName):
#         print('IPrincipal.get_DisplayName')
#         return E_NOTIMPL
#
#     def put_DisplayName(self, This, name):
#         print('IPrincipal.put_DisplayName')
#         return E_NOTIMPL
#
#     def get_UserId(self, This, pUser):
#         print('IPrincipal.get_UserId')
#         return E_NOTIMPL
#
#     def put_UserId(self, This, user):
#         print('IPrincipal.put_UserId')
#         return E_NOTIMPL
#
#     def get_LogonType(self, This, pLogon):
#         print('IPrincipal.get_LogonType')
#         return E_NOTIMPL
#
#     def put_LogonType(self, This, logon):
#         print('IPrincipal.put_LogonType')
#         return E_NOTIMPL
#
#     def get_GroupId(self, This, pGroup):
#         print('IPrincipal.get_GroupId')
#         return E_NOTIMPL
#
#     def put_GroupId(self, This, group):
#         print('IPrincipal.put_GroupId')
#         return E_NOTIMPL
#
#     def get_RunLevel(self, This, pRunLevel):
#         print('IPrincipal.get_RunLevel')
#         return E_NOTIMPL
#
#     def put_RunLevel(self, This, runLevel):
#         print('IPrincipal.put_RunLevel')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IRegisteredTaskImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRegisteredTask
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IRegisteredTask.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IRegisteredTask.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IRegisteredTask.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IRegisteredTask.Invoke')
#         return E_NOTIMPL
#
#     def get_Name(self, This, pName):
#         print('IRegisteredTask.get_Name')
#         return E_NOTIMPL
#
#     def get_Path(self, This, pPath):
#         print('IRegisteredTask.get_Path')
#         return E_NOTIMPL
#
#     def get_State(self, This, pState):
#         print('IRegisteredTask.get_State')
#         return E_NOTIMPL
#
#     def get_Enabled(self, This, pEnabled):
#         print('IRegisteredTask.get_Enabled')
#         return E_NOTIMPL
#
#     def put_Enabled(self, This, enabled):
#         print('IRegisteredTask.put_Enabled')
#         return E_NOTIMPL
#
#     def Run(self, This, params, ppRunningTask):
#         print('IRegisteredTask.Run')
#         return E_NOTIMPL
#
#     def RunEx(self, This, params, flags, sessionID, user, ppRunningTask):
#         print('IRegisteredTask.RunEx')
#         return E_NOTIMPL
#
#     def GetInstances(self, This, flags, ppRunningTasks):
#         print('IRegisteredTask.GetInstances')
#         return E_NOTIMPL
#
#     def get_LastRunTime(self, This, pLastRunTime):
#         print('IRegisteredTask.get_LastRunTime')
#         return E_NOTIMPL
#
#     def get_LastTaskResult(self, This, pLastTaskResult):
#         print('IRegisteredTask.get_LastTaskResult')
#         return E_NOTIMPL
#
#     def get_NumberOfMissedRuns(self, This, pNumberOfMissedRuns):
#         print('IRegisteredTask.get_NumberOfMissedRuns')
#         return E_NOTIMPL
#
#     def get_NextRunTime(self, This, pNextRunTime):
#         print('IRegisteredTask.get_NextRunTime')
#         return E_NOTIMPL
#
#     def get_Definition(self, This, ppDefinition):
#         print('IRegisteredTask.get_Definition')
#         return E_NOTIMPL
#
#     def get_Xml(self, This, pXml):
#         print('IRegisteredTask.get_Xml')
#         return E_NOTIMPL
#
#     def GetSecurityDescriptor(self, This, securityInformation, pSddl):
#         print('IRegisteredTask.GetSecurityDescriptor')
#         return E_NOTIMPL
#
#     def SetSecurityDescriptor(self, This, sddl, flags):
#         print('IRegisteredTask.SetSecurityDescriptor')
#         return E_NOTIMPL
#
#     def Stop(self, This, flags):
#         print('IRegisteredTask.Stop')
#         return E_NOTIMPL
#
#     def GetRunTimes(self, This, pstStart, pstEnd, pCount, pRunTimes):
#         print('IRegisteredTask.GetRunTimes')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IRegisteredTaskCollectionImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRegisteredTaskCollection
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IRegisteredTaskCollection.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IRegisteredTaskCollection.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IRegisteredTaskCollection.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IRegisteredTaskCollection.Invoke')
#         return E_NOTIMPL
#
#     def get_Count(self, This, pCount):
#         print('IRegisteredTaskCollection.get_Count')
#         return E_NOTIMPL
#
#     def get_Item(self, This, index, ppRegisteredTask):
#         print('IRegisteredTaskCollection.get_Item')
#         return E_NOTIMPL
#
#     def get__NewEnum(self, This, ppEnum):
#         print('IRegisteredTaskCollection.get__NewEnum')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IRegistrationInfoImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRegistrationInfo
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IRegistrationInfo.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IRegistrationInfo.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IRegistrationInfo.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IRegistrationInfo.Invoke')
#         return E_NOTIMPL
#
#     def get_Description(self, This, pDescription):
#         print('IRegistrationInfo.get_Description')
#         return E_NOTIMPL
#
#     def put_Description(self, This, description):
#         print('IRegistrationInfo.put_Description')
#         return E_NOTIMPL
#
#     def get_Author(self, This, pAuthor):
#         print('IRegistrationInfo.get_Author')
#         return E_NOTIMPL
#
#     def put_Author(self, This, author):
#         print('IRegistrationInfo.put_Author')
#         return E_NOTIMPL
#
#     def get_Version(self, This, pVersion):
#         print('IRegistrationInfo.get_Version')
#         return E_NOTIMPL
#
#     def put_Version(self, This, version):
#         print('IRegistrationInfo.put_Version')
#         return E_NOTIMPL
#
#     def get_Date(self, This, pDate):
#         print('IRegistrationInfo.get_Date')
#         return E_NOTIMPL
#
#     def put_Date(self, This, date):
#         print('IRegistrationInfo.put_Date')
#         return E_NOTIMPL
#
#     def get_Documentation(self, This, pDocumentation):
#         print('IRegistrationInfo.get_Documentation')
#         return E_NOTIMPL
#
#     def put_Documentation(self, This, documentation):
#         print('IRegistrationInfo.put_Documentation')
#         return E_NOTIMPL
#
#     def get_XmlText(self, This, pText):
#         print('IRegistrationInfo.get_XmlText')
#         return E_NOTIMPL
#
#     def put_XmlText(self, This, text):
#         print('IRegistrationInfo.put_XmlText')
#         return E_NOTIMPL
#
#     def get_URI(self, This, pUri):
#         print('IRegistrationInfo.get_URI')
#         return E_NOTIMPL
#
#     def put_URI(self, This, uri):
#         print('IRegistrationInfo.put_URI')
#         return E_NOTIMPL
#
#     def get_SecurityDescriptor(self, This, pSddl):
#         print('IRegistrationInfo.get_SecurityDescriptor')
#         return E_NOTIMPL
#
#     def put_SecurityDescriptor(self, This, sddl):
#         print('IRegistrationInfo.put_SecurityDescriptor')
#         return E_NOTIMPL
#
#     def get_Source(self, This, pSource):
#         print('IRegistrationInfo.get_Source')
#         return E_NOTIMPL
#
#     def put_Source(self, This, source):
#         print('IRegistrationInfo.put_Source')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IRepetitionPatternImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRepetitionPattern
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IRepetitionPattern.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IRepetitionPattern.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IRepetitionPattern.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IRepetitionPattern.Invoke')
#         return E_NOTIMPL
#
#     def get_Interval(self, This, pInterval):
#         print('IRepetitionPattern.get_Interval')
#         return E_NOTIMPL
#
#     def put_Interval(self, This, interval):
#         print('IRepetitionPattern.put_Interval')
#         return E_NOTIMPL
#
#     def get_Duration(self, This, pDuration):
#         print('IRepetitionPattern.get_Duration')
#         return E_NOTIMPL
#
#     def put_Duration(self, This, duration):
#         print('IRepetitionPattern.put_Duration')
#         return E_NOTIMPL
#
#     def get_StopAtDurationEnd(self, This, pStop):
#         print('IRepetitionPattern.get_StopAtDurationEnd')
#         return E_NOTIMPL
#
#     def put_StopAtDurationEnd(self, This, stop):
#         print('IRepetitionPattern.put_StopAtDurationEnd')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IRunningTaskImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRunningTask
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IRunningTask.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IRunningTask.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IRunningTask.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IRunningTask.Invoke')
#         return E_NOTIMPL
#
#     def get_Name(self, This, pName):
#         print('IRunningTask.get_Name')
#         return E_NOTIMPL
#
#     def get_InstanceGuid(self, This, pGuid):
#         print('IRunningTask.get_InstanceGuid')
#         return E_NOTIMPL
#
#     def get_Path(self, This, pPath):
#         print('IRunningTask.get_Path')
#         return E_NOTIMPL
#
#     def get_State(self, This, pState):
#         print('IRunningTask.get_State')
#         return E_NOTIMPL
#
#     def get_CurrentAction(self, This, pName):
#         print('IRunningTask.get_CurrentAction')
#         return E_NOTIMPL
#
#     def Stop(self, This):
#         print('IRunningTask.Stop')
#         return E_NOTIMPL
#
#     def Refresh(self, This):
#         print('IRunningTask.Refresh')
#         return E_NOTIMPL
#
#     def get_EnginePID(self, This, pPID):
#         print('IRunningTask.get_EnginePID')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IRunningTaskCollectionImplem(windows.com.COMImplementation):
#     IMPLEMENT = IRunningTaskCollection
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IRunningTaskCollection.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IRunningTaskCollection.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IRunningTaskCollection.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IRunningTaskCollection.Invoke')
#         return E_NOTIMPL
#
#     def get_Count(self, This, pCount):
#         print('IRunningTaskCollection.get_Count')
#         return E_NOTIMPL
#
#     def get_Item(self, This, index, ppRunningTask):
#         print('IRunningTaskCollection.get_Item')
#         return E_NOTIMPL
#
#     def get__NewEnum(self, This, ppEnum):
#         print('IRunningTaskCollection.get__NewEnum')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IShowMessageActionImplem(windows.com.COMImplementation):
#     IMPLEMENT = IShowMessageAction
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IShowMessageAction.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IShowMessageAction.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IShowMessageAction.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IShowMessageAction.Invoke')
#         return E_NOTIMPL
#
#     def get_Id(self, This, pId):
#         print('IShowMessageAction.get_Id')
#         return E_NOTIMPL
#
#     def put_Id(self, This, Id):
#         print('IShowMessageAction.put_Id')
#         return E_NOTIMPL
#
#     def get_Type(self, This, pType):
#         print('IShowMessageAction.get_Type')
#         return E_NOTIMPL
#
#     def get_Title(self, This, pTitle):
#         print('IShowMessageAction.get_Title')
#         return E_NOTIMPL
#
#     def put_Title(self, This, title):
#         print('IShowMessageAction.put_Title')
#         return E_NOTIMPL
#
#     def get_MessageBody(self, This, pMessageBody):
#         print('IShowMessageAction.get_MessageBody')
#         return E_NOTIMPL
#
#     def put_MessageBody(self, This, messageBody):
#         print('IShowMessageAction.put_MessageBody')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class ITaskDefinitionImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITaskDefinition
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('ITaskDefinition.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('ITaskDefinition.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('ITaskDefinition.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITaskDefinition.Invoke')
#         return E_NOTIMPL
#
#     def get_RegistrationInfo(self, This, ppRegistrationInfo):
#         print('ITaskDefinition.get_RegistrationInfo')
#         return E_NOTIMPL
#
#     def put_RegistrationInfo(self, This, pRegistrationInfo):
#         print('ITaskDefinition.put_RegistrationInfo')
#         return E_NOTIMPL
#
#     def get_Triggers(self, This, ppTriggers):
#         print('ITaskDefinition.get_Triggers')
#         return E_NOTIMPL
#
#     def put_Triggers(self, This, pTriggers):
#         print('ITaskDefinition.put_Triggers')
#         return E_NOTIMPL
#
#     def get_Settings(self, This, ppSettings):
#         print('ITaskDefinition.get_Settings')
#         return E_NOTIMPL
#
#     def put_Settings(self, This, pSettings):
#         print('ITaskDefinition.put_Settings')
#         return E_NOTIMPL
#
#     def get_Data(self, This, pData):
#         print('ITaskDefinition.get_Data')
#         return E_NOTIMPL
#
#     def put_Data(self, This, data):
#         print('ITaskDefinition.put_Data')
#         return E_NOTIMPL
#
#     def get_Principal(self, This, ppPrincipal):
#         print('ITaskDefinition.get_Principal')
#         return E_NOTIMPL
#
#     def put_Principal(self, This, pPrincipal):
#         print('ITaskDefinition.put_Principal')
#         return E_NOTIMPL
#
#     def get_Actions(self, This, ppActions):
#         print('ITaskDefinition.get_Actions')
#         return E_NOTIMPL
#
#     def put_Actions(self, This, pActions):
#         print('ITaskDefinition.put_Actions')
#         return E_NOTIMPL
#
#     def get_XmlText(self, This, pXml):
#         print('ITaskDefinition.get_XmlText')
#         return E_NOTIMPL
#
#     def put_XmlText(self, This, xml):
#         print('ITaskDefinition.put_XmlText')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class ITaskFolderImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITaskFolder
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('ITaskFolder.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('ITaskFolder.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('ITaskFolder.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITaskFolder.Invoke')
#         return E_NOTIMPL
#
#     def get_Name(self, This, pName):
#         print('ITaskFolder.get_Name')
#         return E_NOTIMPL
#
#     def get_Path(self, This, pPath):
#         print('ITaskFolder.get_Path')
#         return E_NOTIMPL
#
#     def GetFolder(self, This, path, ppFolder):
#         print('ITaskFolder.GetFolder')
#         return E_NOTIMPL
#
#     def GetFolders(self, This, flags, ppFolders):
#         print('ITaskFolder.GetFolders')
#         return E_NOTIMPL
#
#     def CreateFolder(self, This, subFolderName, sddl, ppFolder):
#         print('ITaskFolder.CreateFolder')
#         return E_NOTIMPL
#
#     def DeleteFolder(self, This, subFolderName, flags):
#         print('ITaskFolder.DeleteFolder')
#         return E_NOTIMPL
#
#     def GetTask(self, This, path, ppTask):
#         print('ITaskFolder.GetTask')
#         return E_NOTIMPL
#
#     def GetTasks(self, This, flags, ppTasks):
#         print('ITaskFolder.GetTasks')
#         return E_NOTIMPL
#
#     def DeleteTask(self, This, name, flags):
#         print('ITaskFolder.DeleteTask')
#         return E_NOTIMPL
#
#     def RegisterTask(self, This, path, xmlText, flags, userId, password, logonType, sddl, ppTask):
#         print('ITaskFolder.RegisterTask')
#         return E_NOTIMPL
#
#     def RegisterTaskDefinition(self, This, path, pDefinition, flags, userId, password, logonType, sddl, ppTask):
#         print('ITaskFolder.RegisterTaskDefinition')
#         return E_NOTIMPL
#
#     def GetSecurityDescriptor(self, This, securityInformation, pSddl):
#         print('ITaskFolder.GetSecurityDescriptor')
#         return E_NOTIMPL
#
#     def SetSecurityDescriptor(self, This, sddl, flags):
#         print('ITaskFolder.SetSecurityDescriptor')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class ITaskFolderCollectionImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITaskFolderCollection
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('ITaskFolderCollection.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('ITaskFolderCollection.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('ITaskFolderCollection.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITaskFolderCollection.Invoke')
#         return E_NOTIMPL
#
#     def get_Count(self, This, pCount):
#         print('ITaskFolderCollection.get_Count')
#         return E_NOTIMPL
#
#     def get_Item(self, This, index, ppFolder):
#         print('ITaskFolderCollection.get_Item')
#         return E_NOTIMPL
#
#     def get__NewEnum(self, This, ppEnum):
#         print('ITaskFolderCollection.get__NewEnum')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class ITaskNamedValueCollectionImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITaskNamedValueCollection
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('ITaskNamedValueCollection.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('ITaskNamedValueCollection.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('ITaskNamedValueCollection.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITaskNamedValueCollection.Invoke')
#         return E_NOTIMPL
#
#     def get_Count(self, This, pCount):
#         print('ITaskNamedValueCollection.get_Count')
#         return E_NOTIMPL
#
#     def get_Item(self, This, index, ppPair):
#         print('ITaskNamedValueCollection.get_Item')
#         return E_NOTIMPL
#
#     def get__NewEnum(self, This, ppEnum):
#         print('ITaskNamedValueCollection.get__NewEnum')
#         return E_NOTIMPL
#
#     def Create(self, This, name, value, ppPair):
#         print('ITaskNamedValueCollection.Create')
#         return E_NOTIMPL
#
#     def Remove(self, This, index):
#         print('ITaskNamedValueCollection.Remove')
#         return E_NOTIMPL
#
#     def Clear(self, This):
#         print('ITaskNamedValueCollection.Clear')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class ITaskNamedValuePairImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITaskNamedValuePair
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('ITaskNamedValuePair.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('ITaskNamedValuePair.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('ITaskNamedValuePair.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITaskNamedValuePair.Invoke')
#         return E_NOTIMPL
#
#     def get_Name(self, This, pName):
#         print('ITaskNamedValuePair.get_Name')
#         return E_NOTIMPL
#
#     def put_Name(self, This, name):
#         print('ITaskNamedValuePair.put_Name')
#         return E_NOTIMPL
#
#     def get_Value(self, This, pValue):
#         print('ITaskNamedValuePair.get_Value')
#         return E_NOTIMPL
#
#     def put_Value(self, This, value):
#         print('ITaskNamedValuePair.put_Value')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class ITaskServiceImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITaskService
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('ITaskService.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('ITaskService.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('ITaskService.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITaskService.Invoke')
#         return E_NOTIMPL
#
#     def GetFolder(self, This, path, ppFolder):
#         print('ITaskService.GetFolder')
#         return E_NOTIMPL
#
#     def GetRunningTasks(self, This, flags, ppRunningTasks):
#         print('ITaskService.GetRunningTasks')
#         return E_NOTIMPL
#
#     def NewTask(self, This, flags, ppDefinition):
#         print('ITaskService.NewTask')
#         return E_NOTIMPL
#
#     def Connect(self, This, serverName, user, domain, password):
#         print('ITaskService.Connect')
#         return E_NOTIMPL
#
#     def get_Connected(self, This, pConnected):
#         print('ITaskService.get_Connected')
#         return E_NOTIMPL
#
#     def get_TargetServer(self, This, pServer):
#         print('ITaskService.get_TargetServer')
#         return E_NOTIMPL
#
#     def get_ConnectedUser(self, This, pUser):
#         print('ITaskService.get_ConnectedUser')
#         return E_NOTIMPL
#
#     def get_ConnectedDomain(self, This, pDomain):
#         print('ITaskService.get_ConnectedDomain')
#         return E_NOTIMPL
#
#     def get_HighestVersion(self, This, pVersion):
#         print('ITaskService.get_HighestVersion')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class ITaskSettingsImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITaskSettings
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('ITaskSettings.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('ITaskSettings.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('ITaskSettings.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITaskSettings.Invoke')
#         return E_NOTIMPL
#
#     def get_AllowDemandStart(self, This, pAllowDemandStart):
#         print('ITaskSettings.get_AllowDemandStart')
#         return E_NOTIMPL
#
#     def put_AllowDemandStart(self, This, allowDemandStart):
#         print('ITaskSettings.put_AllowDemandStart')
#         return E_NOTIMPL
#
#     def get_RestartInterval(self, This, pRestartInterval):
#         print('ITaskSettings.get_RestartInterval')
#         return E_NOTIMPL
#
#     def put_RestartInterval(self, This, restartInterval):
#         print('ITaskSettings.put_RestartInterval')
#         return E_NOTIMPL
#
#     def get_RestartCount(self, This, pRestartCount):
#         print('ITaskSettings.get_RestartCount')
#         return E_NOTIMPL
#
#     def put_RestartCount(self, This, restartCount):
#         print('ITaskSettings.put_RestartCount')
#         return E_NOTIMPL
#
#     def get_MultipleInstances(self, This, pPolicy):
#         print('ITaskSettings.get_MultipleInstances')
#         return E_NOTIMPL
#
#     def put_MultipleInstances(self, This, policy):
#         print('ITaskSettings.put_MultipleInstances')
#         return E_NOTIMPL
#
#     def get_StopIfGoingOnBatteries(self, This, pStopIfOnBatteries):
#         print('ITaskSettings.get_StopIfGoingOnBatteries')
#         return E_NOTIMPL
#
#     def put_StopIfGoingOnBatteries(self, This, stopIfOnBatteries):
#         print('ITaskSettings.put_StopIfGoingOnBatteries')
#         return E_NOTIMPL
#
#     def get_DisallowStartIfOnBatteries(self, This, pDisallowStart):
#         print('ITaskSettings.get_DisallowStartIfOnBatteries')
#         return E_NOTIMPL
#
#     def put_DisallowStartIfOnBatteries(self, This, disallowStart):
#         print('ITaskSettings.put_DisallowStartIfOnBatteries')
#         return E_NOTIMPL
#
#     def get_AllowHardTerminate(self, This, pAllowHardTerminate):
#         print('ITaskSettings.get_AllowHardTerminate')
#         return E_NOTIMPL
#
#     def put_AllowHardTerminate(self, This, allowHardTerminate):
#         print('ITaskSettings.put_AllowHardTerminate')
#         return E_NOTIMPL
#
#     def get_StartWhenAvailable(self, This, pStartWhenAvailable):
#         print('ITaskSettings.get_StartWhenAvailable')
#         return E_NOTIMPL
#
#     def put_StartWhenAvailable(self, This, startWhenAvailable):
#         print('ITaskSettings.put_StartWhenAvailable')
#         return E_NOTIMPL
#
#     def get_XmlText(self, This, pText):
#         print('ITaskSettings.get_XmlText')
#         return E_NOTIMPL
#
#     def put_XmlText(self, This, text):
#         print('ITaskSettings.put_XmlText')
#         return E_NOTIMPL
#
#     def get_RunOnlyIfNetworkAvailable(self, This, pRunOnlyIfNetworkAvailable):
#         print('ITaskSettings.get_RunOnlyIfNetworkAvailable')
#         return E_NOTIMPL
#
#     def put_RunOnlyIfNetworkAvailable(self, This, runOnlyIfNetworkAvailable):
#         print('ITaskSettings.put_RunOnlyIfNetworkAvailable')
#         return E_NOTIMPL
#
#     def get_ExecutionTimeLimit(self, This, pExecutionTimeLimit):
#         print('ITaskSettings.get_ExecutionTimeLimit')
#         return E_NOTIMPL
#
#     def put_ExecutionTimeLimit(self, This, executionTimeLimit):
#         print('ITaskSettings.put_ExecutionTimeLimit')
#         return E_NOTIMPL
#
#     def get_Enabled(self, This, pEnabled):
#         print('ITaskSettings.get_Enabled')
#         return E_NOTIMPL
#
#     def put_Enabled(self, This, enabled):
#         print('ITaskSettings.put_Enabled')
#         return E_NOTIMPL
#
#     def get_DeleteExpiredTaskAfter(self, This, pExpirationDelay):
#         print('ITaskSettings.get_DeleteExpiredTaskAfter')
#         return E_NOTIMPL
#
#     def put_DeleteExpiredTaskAfter(self, This, expirationDelay):
#         print('ITaskSettings.put_DeleteExpiredTaskAfter')
#         return E_NOTIMPL
#
#     def get_Priority(self, This, pPriority):
#         print('ITaskSettings.get_Priority')
#         return E_NOTIMPL
#
#     def put_Priority(self, This, priority):
#         print('ITaskSettings.put_Priority')
#         return E_NOTIMPL
#
#     def get_Compatibility(self, This, pCompatLevel):
#         print('ITaskSettings.get_Compatibility')
#         return E_NOTIMPL
#
#     def put_Compatibility(self, This, compatLevel):
#         print('ITaskSettings.put_Compatibility')
#         return E_NOTIMPL
#
#     def get_Hidden(self, This, pHidden):
#         print('ITaskSettings.get_Hidden')
#         return E_NOTIMPL
#
#     def put_Hidden(self, This, hidden):
#         print('ITaskSettings.put_Hidden')
#         return E_NOTIMPL
#
#     def get_IdleSettings(self, This, ppIdleSettings):
#         print('ITaskSettings.get_IdleSettings')
#         return E_NOTIMPL
#
#     def put_IdleSettings(self, This, pIdleSettings):
#         print('ITaskSettings.put_IdleSettings')
#         return E_NOTIMPL
#
#     def get_RunOnlyIfIdle(self, This, pRunOnlyIfIdle):
#         print('ITaskSettings.get_RunOnlyIfIdle')
#         return E_NOTIMPL
#
#     def put_RunOnlyIfIdle(self, This, runOnlyIfIdle):
#         print('ITaskSettings.put_RunOnlyIfIdle')
#         return E_NOTIMPL
#
#     def get_WakeToRun(self, This, pWake):
#         print('ITaskSettings.get_WakeToRun')
#         return E_NOTIMPL
#
#     def put_WakeToRun(self, This, wake):
#         print('ITaskSettings.put_WakeToRun')
#         return E_NOTIMPL
#
#     def get_NetworkSettings(self, This, ppNetworkSettings):
#         print('ITaskSettings.get_NetworkSettings')
#         return E_NOTIMPL
#
#     def put_NetworkSettings(self, This, pNetworkSettings):
#         print('ITaskSettings.put_NetworkSettings')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class ITriggerImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITrigger
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('ITrigger.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('ITrigger.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('ITrigger.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITrigger.Invoke')
#         return E_NOTIMPL
#
#     def get_Type(self, This, pType):
#         print('ITrigger.get_Type')
#         return E_NOTIMPL
#
#     def get_Id(self, This, pId):
#         print('ITrigger.get_Id')
#         return E_NOTIMPL
#
#     def put_Id(self, This, id):
#         print('ITrigger.put_Id')
#         return E_NOTIMPL
#
#     def get_Repetition(self, This, ppRepeat):
#         print('ITrigger.get_Repetition')
#         return E_NOTIMPL
#
#     def put_Repetition(self, This, pRepeat):
#         print('ITrigger.put_Repetition')
#         return E_NOTIMPL
#
#     def get_ExecutionTimeLimit(self, This, pTimeLimit):
#         print('ITrigger.get_ExecutionTimeLimit')
#         return E_NOTIMPL
#
#     def put_ExecutionTimeLimit(self, This, timelimit):
#         print('ITrigger.put_ExecutionTimeLimit')
#         return E_NOTIMPL
#
#     def get_StartBoundary(self, This, pStart):
#         print('ITrigger.get_StartBoundary')
#         return E_NOTIMPL
#
#     def put_StartBoundary(self, This, start):
#         print('ITrigger.put_StartBoundary')
#         return E_NOTIMPL
#
#     def get_EndBoundary(self, This, pEnd):
#         print('ITrigger.get_EndBoundary')
#         return E_NOTIMPL
#
#     def put_EndBoundary(self, This, end):
#         print('ITrigger.put_EndBoundary')
#         return E_NOTIMPL
#
#     def get_Enabled(self, This, pEnabled):
#         print('ITrigger.get_Enabled')
#         return E_NOTIMPL
#
#     def put_Enabled(self, This, enabled):
#         print('ITrigger.put_Enabled')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class ITriggerCollectionImplem(windows.com.COMImplementation):
#     IMPLEMENT = ITriggerCollection
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('ITriggerCollection.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('ITriggerCollection.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('ITriggerCollection.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('ITriggerCollection.Invoke')
#         return E_NOTIMPL
#
#     def get_Count(self, This, pCount):
#         print('ITriggerCollection.get_Count')
#         return E_NOTIMPL
#
#     def get_Item(self, This, index, ppTrigger):
#         print('ITriggerCollection.get_Item')
#         return E_NOTIMPL
#
#     def get__NewEnum(self, This, ppEnum):
#         print('ITriggerCollection.get__NewEnum')
#         return E_NOTIMPL
#
#     def Create(self, This, type, ppTrigger):
#         print('ITriggerCollection.Create')
#         return E_NOTIMPL
#
#     def Remove(self, This, index):
#         print('ITriggerCollection.Remove')
#         return E_NOTIMPL
#
#     def Clear(self, This):
#         print('ITriggerCollection.Clear')
#         return E_NOTIMPL
#
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
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
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

# class IWebBrowser2Implem(windows.com.COMImplementation):
#     IMPLEMENT = IWebBrowser2
#
#     def GetTypeInfoCount(self, This, pctinfo):
#         print('IWebBrowser2.GetTypeInfoCount')
#         return E_NOTIMPL
#
#     def GetTypeInfo(self, This, iTInfo, lcid, ppTInfo):
#         print('IWebBrowser2.GetTypeInfo')
#         return E_NOTIMPL
#
#     def GetIDsOfNames(self, This, riid, rgszNames, cNames, lcid, rgDispId):
#         print('IWebBrowser2.GetIDsOfNames')
#         return E_NOTIMPL
#
#     def Invoke(self, This, dispIdMember, riid, lcid, wFlags, pDispParams, pVarResult, pExcepInfo, puArgErr):
#         print('IWebBrowser2.Invoke')
#         return E_NOTIMPL
#
#     def GoBack(self, This):
#         print('IWebBrowser2.GoBack')
#         return E_NOTIMPL
#
#     def GoForward(self, This):
#         print('IWebBrowser2.GoForward')
#         return E_NOTIMPL
#
#     def GoHome(self, This):
#         print('IWebBrowser2.GoHome')
#         return E_NOTIMPL
#
#     def GoSearch(self, This):
#         print('IWebBrowser2.GoSearch')
#         return E_NOTIMPL
#
#     def Navigate(self, This, URL, Flags, TargetFrameName, PostData, Headers):
#         print('IWebBrowser2.Navigate')
#         return E_NOTIMPL
#
#     def Refresh(self, This):
#         print('IWebBrowser2.Refresh')
#         return E_NOTIMPL
#
#     def Refresh2(self, This, Level):
#         print('IWebBrowser2.Refresh2')
#         return E_NOTIMPL
#
#     def Stop(self, This):
#         print('IWebBrowser2.Stop')
#         return E_NOTIMPL
#
#     def get_Application(self, This, ppDisp):
#         print('IWebBrowser2.get_Application')
#         return E_NOTIMPL
#
#     def get_Parent(self, This, ppDisp):
#         print('IWebBrowser2.get_Parent')
#         return E_NOTIMPL
#
#     def get_Container(self, This, ppDisp):
#         print('IWebBrowser2.get_Container')
#         return E_NOTIMPL
#
#     def get_Document(self, This, ppDisp):
#         print('IWebBrowser2.get_Document')
#         return E_NOTIMPL
#
#     def get_TopLevelContainer(self, This, pBool):
#         print('IWebBrowser2.get_TopLevelContainer')
#         return E_NOTIMPL
#
#     def get_Type(self, This, Type):
#         print('IWebBrowser2.get_Type')
#         return E_NOTIMPL
#
#     def get_Left(self, This, pl):
#         print('IWebBrowser2.get_Left')
#         return E_NOTIMPL
#
#     def put_Left(self, This, Left):
#         print('IWebBrowser2.put_Left')
#         return E_NOTIMPL
#
#     def get_Top(self, This, pl):
#         print('IWebBrowser2.get_Top')
#         return E_NOTIMPL
#
#     def put_Top(self, This, Top):
#         print('IWebBrowser2.put_Top')
#         return E_NOTIMPL
#
#     def get_Width(self, This, pl):
#         print('IWebBrowser2.get_Width')
#         return E_NOTIMPL
#
#     def put_Width(self, This, Width):
#         print('IWebBrowser2.put_Width')
#         return E_NOTIMPL
#
#     def get_Height(self, This, pl):
#         print('IWebBrowser2.get_Height')
#         return E_NOTIMPL
#
#     def put_Height(self, This, Height):
#         print('IWebBrowser2.put_Height')
#         return E_NOTIMPL
#
#     def get_LocationName(self, This, LocationName):
#         print('IWebBrowser2.get_LocationName')
#         return E_NOTIMPL
#
#     def get_LocationURL(self, This, LocationURL):
#         print('IWebBrowser2.get_LocationURL')
#         return E_NOTIMPL
#
#     def get_Busy(self, This, pBool):
#         print('IWebBrowser2.get_Busy')
#         return E_NOTIMPL
#
#     def Quit(self, This):
#         print('IWebBrowser2.Quit')
#         return E_NOTIMPL
#
#     def ClientToWindow(self, This, pcx, pcy):
#         print('IWebBrowser2.ClientToWindow')
#         return E_NOTIMPL
#
#     def PutProperty(self, This, Property, vtValue):
#         print('IWebBrowser2.PutProperty')
#         return E_NOTIMPL
#
#     def GetProperty(self, This, Property, pvtValue):
#         print('IWebBrowser2.GetProperty')
#         return E_NOTIMPL
#
#     def get_Name(self, This, Name):
#         print('IWebBrowser2.get_Name')
#         return E_NOTIMPL
#
#     def get_HWND(self, This, pHWND):
#         print('IWebBrowser2.get_HWND')
#         return E_NOTIMPL
#
#     def get_FullName(self, This, FullName):
#         print('IWebBrowser2.get_FullName')
#         return E_NOTIMPL
#
#     def get_Path(self, This, Path):
#         print('IWebBrowser2.get_Path')
#         return E_NOTIMPL
#
#     def get_Visible(self, This, pBool):
#         print('IWebBrowser2.get_Visible')
#         return E_NOTIMPL
#
#     def put_Visible(self, This, Value):
#         print('IWebBrowser2.put_Visible')
#         return E_NOTIMPL
#
#     def get_StatusBar(self, This, pBool):
#         print('IWebBrowser2.get_StatusBar')
#         return E_NOTIMPL
#
#     def put_StatusBar(self, This, Value):
#         print('IWebBrowser2.put_StatusBar')
#         return E_NOTIMPL
#
#     def get_StatusText(self, This, StatusText):
#         print('IWebBrowser2.get_StatusText')
#         return E_NOTIMPL
#
#     def put_StatusText(self, This, StatusText):
#         print('IWebBrowser2.put_StatusText')
#         return E_NOTIMPL
#
#     def get_ToolBar(self, This, Value):
#         print('IWebBrowser2.get_ToolBar')
#         return E_NOTIMPL
#
#     def put_ToolBar(self, This, Value):
#         print('IWebBrowser2.put_ToolBar')
#         return E_NOTIMPL
#
#     def get_MenuBar(self, This, Value):
#         print('IWebBrowser2.get_MenuBar')
#         return E_NOTIMPL
#
#     def put_MenuBar(self, This, Value):
#         print('IWebBrowser2.put_MenuBar')
#         return E_NOTIMPL
#
#     def get_FullScreen(self, This, pbFullScreen):
#         print('IWebBrowser2.get_FullScreen')
#         return E_NOTIMPL
#
#     def put_FullScreen(self, This, bFullScreen):
#         print('IWebBrowser2.put_FullScreen')
#         return E_NOTIMPL
#
#     def Navigate2(self, This, URL, Flags, TargetFrameName, PostData, Headers):
#         print('IWebBrowser2.Navigate2')
#         return E_NOTIMPL
#
#     def QueryStatusWB(self, This, cmdID, pcmdf):
#         print('IWebBrowser2.QueryStatusWB')
#         return E_NOTIMPL
#
#     def ExecWB(self, This, cmdID, cmdexecopt, pvaIn, pvaOut):
#         print('IWebBrowser2.ExecWB')
#         return E_NOTIMPL
#
#     def ShowBrowserBar(self, This, pvaClsid, pvarShow, pvarSize):
#         print('IWebBrowser2.ShowBrowserBar')
#         return E_NOTIMPL
#
#     def get_ReadyState(self, This, plReadyState):
#         print('IWebBrowser2.get_ReadyState')
#         return E_NOTIMPL
#
#     def get_Offline(self, This, pbOffline):
#         print('IWebBrowser2.get_Offline')
#         return E_NOTIMPL
#
#     def put_Offline(self, This, bOffline):
#         print('IWebBrowser2.put_Offline')
#         return E_NOTIMPL
#
#     def get_Silent(self, This, pbSilent):
#         print('IWebBrowser2.get_Silent')
#         return E_NOTIMPL
#
#     def put_Silent(self, This, bSilent):
#         print('IWebBrowser2.put_Silent')
#         return E_NOTIMPL
#
#     def get_RegisterAsBrowser(self, This, pbRegister):
#         print('IWebBrowser2.get_RegisterAsBrowser')
#         return E_NOTIMPL
#
#     def put_RegisterAsBrowser(self, This, bRegister):
#         print('IWebBrowser2.put_RegisterAsBrowser')
#         return E_NOTIMPL
#
#     def get_RegisterAsDropTarget(self, This, pbRegister):
#         print('IWebBrowser2.get_RegisterAsDropTarget')
#         return E_NOTIMPL
#
#     def put_RegisterAsDropTarget(self, This, bRegister):
#         print('IWebBrowser2.put_RegisterAsDropTarget')
#         return E_NOTIMPL
#
#     def get_TheaterMode(self, This, pbRegister):
#         print('IWebBrowser2.get_TheaterMode')
#         return E_NOTIMPL
#
#     def put_TheaterMode(self, This, bRegister):
#         print('IWebBrowser2.put_TheaterMode')
#         return E_NOTIMPL
#
#     def get_AddressBar(self, This, Value):
#         print('IWebBrowser2.get_AddressBar')
#         return E_NOTIMPL
#
#     def put_AddressBar(self, This, Value):
#         print('IWebBrowser2.put_AddressBar')
#         return E_NOTIMPL
#
#     def get_Resizable(self, This, Value):
#         print('IWebBrowser2.get_Resizable')
#         return E_NOTIMPL
#
#     def put_Resizable(self, This, Value):
#         print('IWebBrowser2.put_Resizable')
#         return E_NOTIMPL
#
IWebBrowser2._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetTypeInfoCount -> pctinfo:*UINT
        "GetTypeInfoCount": ctypes.WINFUNCTYPE(HRESULT, POINTER(UINT))(3, "GetTypeInfoCount"),
        # GetTypeInfo -> iTInfo:UINT, lcid:LCID, ppTInfo:**ITypeInfo
        "GetTypeInfo": ctypes.WINFUNCTYPE(HRESULT, UINT, LCID, POINTER(ITypeInfo))(4, "GetTypeInfo"),
        # GetIDsOfNames -> riid:REFIID, rgszNames:*LPOLESTR, cNames:UINT, lcid:LCID, rgDispId:*DISPID
        "GetIDsOfNames": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(LPOLESTR), UINT, LCID, POINTER(DISPID))(5, "GetIDsOfNames"),
        # Invoke -> dispIdMember:DISPID, riid:REFIID, lcid:LCID, wFlags:WORD, pDispParams:*DISPPARAMS, pVarResult:*VARIANT, pExcepInfo:*EXCEPINFO, puArgErr:*UINT
        "Invoke": ctypes.WINFUNCTYPE(HRESULT, DISPID, REFIID, LCID, WORD, POINTER(DISPPARAMS), POINTER(VARIANT), POINTER(EXCEPINFO), POINTER(UINT))(6, "Invoke"),
        # GoBack -> 
        "GoBack": ctypes.WINFUNCTYPE(HRESULT)(7, "GoBack"),
        # GoForward -> 
        "GoForward": ctypes.WINFUNCTYPE(HRESULT)(8, "GoForward"),
        # GoHome -> 
        "GoHome": ctypes.WINFUNCTYPE(HRESULT)(9, "GoHome"),
        # GoSearch -> 
        "GoSearch": ctypes.WINFUNCTYPE(HRESULT)(10, "GoSearch"),
        # Navigate -> URL:BSTR, Flags:*VARIANT, TargetFrameName:*VARIANT, PostData:*VARIANT, Headers:*VARIANT
        "Navigate": ctypes.WINFUNCTYPE(HRESULT, BSTR, POINTER(VARIANT), POINTER(VARIANT), POINTER(VARIANT), POINTER(VARIANT))(11, "Navigate"),
        # Refresh -> 
        "Refresh": ctypes.WINFUNCTYPE(HRESULT)(12, "Refresh"),
        # Refresh2 -> Level:*VARIANT
        "Refresh2": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT))(13, "Refresh2"),
        # Stop -> 
        "Stop": ctypes.WINFUNCTYPE(HRESULT)(14, "Stop"),
        # get_Application -> ppDisp:**IDispatch
        "get_Application": ctypes.WINFUNCTYPE(HRESULT, POINTER(IDispatch))(15, "get_Application"),
        # get_Parent -> ppDisp:**IDispatch
        "get_Parent": ctypes.WINFUNCTYPE(HRESULT, POINTER(IDispatch))(16, "get_Parent"),
        # get_Container -> ppDisp:**IDispatch
        "get_Container": ctypes.WINFUNCTYPE(HRESULT, POINTER(IDispatch))(17, "get_Container"),
        # get_Document -> ppDisp:**IDispatch
        "get_Document": ctypes.WINFUNCTYPE(HRESULT, POINTER(IDispatch))(18, "get_Document"),
        # get_TopLevelContainer -> pBool:*VARIANT_BOOL
        "get_TopLevelContainer": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(19, "get_TopLevelContainer"),
        # get_Type -> Type:*BSTR
        "get_Type": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(20, "get_Type"),
        # get_Left -> pl:*LONG
        "get_Left": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(21, "get_Left"),
        # put_Left -> Left:LONG
        "put_Left": ctypes.WINFUNCTYPE(HRESULT, LONG)(22, "put_Left"),
        # get_Top -> pl:*LONG
        "get_Top": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(23, "get_Top"),
        # put_Top -> Top:LONG
        "put_Top": ctypes.WINFUNCTYPE(HRESULT, LONG)(24, "put_Top"),
        # get_Width -> pl:*LONG
        "get_Width": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(25, "get_Width"),
        # put_Width -> Width:LONG
        "put_Width": ctypes.WINFUNCTYPE(HRESULT, LONG)(26, "put_Width"),
        # get_Height -> pl:*LONG
        "get_Height": ctypes.WINFUNCTYPE(HRESULT, POINTER(LONG))(27, "get_Height"),
        # put_Height -> Height:LONG
        "put_Height": ctypes.WINFUNCTYPE(HRESULT, LONG)(28, "put_Height"),
        # get_LocationName -> LocationName:*BSTR
        "get_LocationName": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(29, "get_LocationName"),
        # get_LocationURL -> LocationURL:*BSTR
        "get_LocationURL": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(30, "get_LocationURL"),
        # get_Busy -> pBool:*VARIANT_BOOL
        "get_Busy": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(31, "get_Busy"),
        # Quit -> 
        "Quit": ctypes.WINFUNCTYPE(HRESULT)(32, "Quit"),
        # ClientToWindow -> pcx:*INT, pcy:*INT
        "ClientToWindow": ctypes.WINFUNCTYPE(HRESULT, POINTER(INT), POINTER(INT))(33, "ClientToWindow"),
        # PutProperty -> Property:BSTR, vtValue:VARIANT
        "PutProperty": ctypes.WINFUNCTYPE(HRESULT, BSTR, VARIANT)(34, "PutProperty"),
        # GetProperty -> Property:BSTR, pvtValue:*VARIANT
        "GetProperty": ctypes.WINFUNCTYPE(HRESULT, BSTR, POINTER(VARIANT))(35, "GetProperty"),
        # get_Name -> Name:*BSTR
        "get_Name": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(36, "get_Name"),
        # get_HWND -> pHWND:*PVOID
        "get_HWND": ctypes.WINFUNCTYPE(HRESULT, POINTER(PVOID))(37, "get_HWND"),
        # get_FullName -> FullName:*BSTR
        "get_FullName": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(38, "get_FullName"),
        # get_Path -> Path:*BSTR
        "get_Path": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(39, "get_Path"),
        # get_Visible -> pBool:*VARIANT_BOOL
        "get_Visible": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(40, "get_Visible"),
        # put_Visible -> Value:VARIANT_BOOL
        "put_Visible": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(41, "put_Visible"),
        # get_StatusBar -> pBool:*VARIANT_BOOL
        "get_StatusBar": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(42, "get_StatusBar"),
        # put_StatusBar -> Value:VARIANT_BOOL
        "put_StatusBar": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(43, "put_StatusBar"),
        # get_StatusText -> StatusText:*BSTR
        "get_StatusText": ctypes.WINFUNCTYPE(HRESULT, POINTER(BSTR))(44, "get_StatusText"),
        # put_StatusText -> StatusText:BSTR
        "put_StatusText": ctypes.WINFUNCTYPE(HRESULT, BSTR)(45, "put_StatusText"),
        # get_ToolBar -> Value:*INT
        "get_ToolBar": ctypes.WINFUNCTYPE(HRESULT, POINTER(INT))(46, "get_ToolBar"),
        # put_ToolBar -> Value:INT
        "put_ToolBar": ctypes.WINFUNCTYPE(HRESULT, INT)(47, "put_ToolBar"),
        # get_MenuBar -> Value:*VARIANT_BOOL
        "get_MenuBar": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(48, "get_MenuBar"),
        # put_MenuBar -> Value:VARIANT_BOOL
        "put_MenuBar": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(49, "put_MenuBar"),
        # get_FullScreen -> pbFullScreen:*VARIANT_BOOL
        "get_FullScreen": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(50, "get_FullScreen"),
        # put_FullScreen -> bFullScreen:VARIANT_BOOL
        "put_FullScreen": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(51, "put_FullScreen"),
        # Navigate2 -> URL:*VARIANT, Flags:*VARIANT, TargetFrameName:*VARIANT, PostData:*VARIANT, Headers:*VARIANT
        "Navigate2": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT), POINTER(VARIANT), POINTER(VARIANT), POINTER(VARIANT), POINTER(VARIANT))(52, "Navigate2"),
        # QueryStatusWB -> cmdID:DWORD, pcmdf:*DWORD
        "QueryStatusWB": ctypes.WINFUNCTYPE(HRESULT, DWORD, POINTER(DWORD))(53, "QueryStatusWB"),
        # ExecWB -> cmdID:DWORD, cmdexecopt:DWORD, pvaIn:*VARIANT, pvaOut:*VARIANT
        "ExecWB": ctypes.WINFUNCTYPE(HRESULT, DWORD, DWORD, POINTER(VARIANT), POINTER(VARIANT))(54, "ExecWB"),
        # ShowBrowserBar -> pvaClsid:*VARIANT, pvarShow:*VARIANT, pvarSize:*VARIANT
        "ShowBrowserBar": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT), POINTER(VARIANT), POINTER(VARIANT))(55, "ShowBrowserBar"),
        # get_ReadyState -> plReadyState:*DWORD
        "get_ReadyState": ctypes.WINFUNCTYPE(HRESULT, POINTER(DWORD))(56, "get_ReadyState"),
        # get_Offline -> pbOffline:*VARIANT_BOOL
        "get_Offline": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(57, "get_Offline"),
        # put_Offline -> bOffline:VARIANT_BOOL
        "put_Offline": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(58, "put_Offline"),
        # get_Silent -> pbSilent:*VARIANT_BOOL
        "get_Silent": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(59, "get_Silent"),
        # put_Silent -> bSilent:VARIANT_BOOL
        "put_Silent": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(60, "put_Silent"),
        # get_RegisterAsBrowser -> pbRegister:*VARIANT_BOOL
        "get_RegisterAsBrowser": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(61, "get_RegisterAsBrowser"),
        # put_RegisterAsBrowser -> bRegister:VARIANT_BOOL
        "put_RegisterAsBrowser": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(62, "put_RegisterAsBrowser"),
        # get_RegisterAsDropTarget -> pbRegister:*VARIANT_BOOL
        "get_RegisterAsDropTarget": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(63, "get_RegisterAsDropTarget"),
        # put_RegisterAsDropTarget -> bRegister:VARIANT_BOOL
        "put_RegisterAsDropTarget": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(64, "put_RegisterAsDropTarget"),
        # get_TheaterMode -> pbRegister:*VARIANT_BOOL
        "get_TheaterMode": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(65, "get_TheaterMode"),
        # put_TheaterMode -> bRegister:VARIANT_BOOL
        "put_TheaterMode": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(66, "put_TheaterMode"),
        # get_AddressBar -> Value:*VARIANT_BOOL
        "get_AddressBar": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(67, "get_AddressBar"),
        # put_AddressBar -> Value:VARIANT_BOOL
        "put_AddressBar": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(68, "put_AddressBar"),
        # get_Resizable -> Value:*VARIANT_BOOL
        "get_Resizable": ctypes.WINFUNCTYPE(HRESULT, POINTER(VARIANT_BOOL))(69, "get_Resizable"),
        # put_Resizable -> Value:VARIANT_BOOL
        "put_Resizable": ctypes.WINFUNCTYPE(HRESULT, VARIANT_BOOL)(70, "put_Resizable"),
    }

# class IEnumWbemClassObjectImplem(windows.com.COMImplementation):
#     IMPLEMENT = IEnumWbemClassObject
#
#     def Reset(self, This):
#         print('IEnumWbemClassObject.Reset')
#         return E_NOTIMPL
#
#     def Next(self, This, lTimeout, uCount, apObjects, puReturned):
#         print('IEnumWbemClassObject.Next')
#         return E_NOTIMPL
#
#     def NextAsync(self, This, uCount, pSink):
#         print('IEnumWbemClassObject.NextAsync')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppEnum):
#         print('IEnumWbemClassObject.Clone')
#         return E_NOTIMPL
#
#     def Skip(self, This, lTimeout, nCount):
#         print('IEnumWbemClassObject.Skip')
#         return E_NOTIMPL
#
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

# class IWbemCallResultImplem(windows.com.COMImplementation):
#     IMPLEMENT = IWbemCallResult
#
#     def GetResultObject(self, This, lTimeout, ppResultObject):
#         print('IWbemCallResult.GetResultObject')
#         return E_NOTIMPL
#
#     def GetResultString(self, This, lTimeout, pstrResultString):
#         print('IWbemCallResult.GetResultString')
#         return E_NOTIMPL
#
#     def GetResultServices(self, This, lTimeout, ppServices):
#         print('IWbemCallResult.GetResultServices')
#         return E_NOTIMPL
#
#     def GetCallStatus(self, This, lTimeout, plStatus):
#         print('IWbemCallResult.GetCallStatus')
#         return E_NOTIMPL
#
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

# class IWbemClassObjectImplem(windows.com.COMImplementation):
#     IMPLEMENT = IWbemClassObject
#
#     def GetQualifierSet(self, This, ppQualSet):
#         print('IWbemClassObject.GetQualifierSet')
#         return E_NOTIMPL
#
#     def Get(self, This, wszName, lFlags, pVal, pType, plFlavor):
#         print('IWbemClassObject.Get')
#         return E_NOTIMPL
#
#     def Put(self, This, wszName, lFlags, pVal, Type):
#         print('IWbemClassObject.Put')
#         return E_NOTIMPL
#
#     def Delete(self, This, wszName):
#         print('IWbemClassObject.Delete')
#         return E_NOTIMPL
#
#     def GetNames(self, This, wszQualifierName, lFlags, pQualifierVal, pNames):
#         print('IWbemClassObject.GetNames')
#         return E_NOTIMPL
#
#     def BeginEnumeration(self, This, lEnumFlags):
#         print('IWbemClassObject.BeginEnumeration')
#         return E_NOTIMPL
#
#     def Next(self, This, lFlags, strName, pVal, pType, plFlavor):
#         print('IWbemClassObject.Next')
#         return E_NOTIMPL
#
#     def EndEnumeration(self, This):
#         print('IWbemClassObject.EndEnumeration')
#         return E_NOTIMPL
#
#     def GetPropertyQualifierSet(self, This, wszProperty, ppQualSet):
#         print('IWbemClassObject.GetPropertyQualifierSet')
#         return E_NOTIMPL
#
#     def Clone(self, This, ppCopy):
#         print('IWbemClassObject.Clone')
#         return E_NOTIMPL
#
#     def GetObjectText(self, This, lFlags, pstrObjectText):
#         print('IWbemClassObject.GetObjectText')
#         return E_NOTIMPL
#
#     def SpawnDerivedClass(self, This, lFlags, ppNewClass):
#         print('IWbemClassObject.SpawnDerivedClass')
#         return E_NOTIMPL
#
#     def SpawnInstance(self, This, lFlags, ppNewInstance):
#         print('IWbemClassObject.SpawnInstance')
#         return E_NOTIMPL
#
#     def CompareTo(self, This, lFlags, pCompareTo):
#         print('IWbemClassObject.CompareTo')
#         return E_NOTIMPL
#
#     def GetPropertyOrigin(self, This, wszName, pstrClassName):
#         print('IWbemClassObject.GetPropertyOrigin')
#         return E_NOTIMPL
#
#     def InheritsFrom(self, This, strAncestor):
#         print('IWbemClassObject.InheritsFrom')
#         return E_NOTIMPL
#
#     def GetMethod(self, This, wszName, lFlags, ppInSignature, ppOutSignature):
#         print('IWbemClassObject.GetMethod')
#         return E_NOTIMPL
#
#     def PutMethod(self, This, wszName, lFlags, pInSignature, pOutSignature):
#         print('IWbemClassObject.PutMethod')
#         return E_NOTIMPL
#
#     def DeleteMethod(self, This, wszName):
#         print('IWbemClassObject.DeleteMethod')
#         return E_NOTIMPL
#
#     def BeginMethodEnumeration(self, This, lEnumFlags):
#         print('IWbemClassObject.BeginMethodEnumeration')
#         return E_NOTIMPL
#
#     def NextMethod(self, This, lFlags, pstrName, ppInSignature, ppOutSignature):
#         print('IWbemClassObject.NextMethod')
#         return E_NOTIMPL
#
#     def EndMethodEnumeration(self, This):
#         print('IWbemClassObject.EndMethodEnumeration')
#         return E_NOTIMPL
#
#     def GetMethodQualifierSet(self, This, wszMethod, ppQualSet):
#         print('IWbemClassObject.GetMethodQualifierSet')
#         return E_NOTIMPL
#
#     def GetMethodOrigin(self, This, wszMethodName, pstrClassName):
#         print('IWbemClassObject.GetMethodOrigin')
#         return E_NOTIMPL
#
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

# class IWbemContextImplem(windows.com.COMImplementation):
#     IMPLEMENT = IWbemContext
#
#     def Clone(self, This, ppNewCopy):
#         print('IWbemContext.Clone')
#         return E_NOTIMPL
#
#     def GetNames(self, This, lFlags, pNames):
#         print('IWbemContext.GetNames')
#         return E_NOTIMPL
#
#     def BeginEnumeration(self, This, lFlags):
#         print('IWbemContext.BeginEnumeration')
#         return E_NOTIMPL
#
#     def Next(self, This, lFlags, pstrName, pValue):
#         print('IWbemContext.Next')
#         return E_NOTIMPL
#
#     def EndEnumeration(self, This):
#         print('IWbemContext.EndEnumeration')
#         return E_NOTIMPL
#
#     def SetValue(self, This, wszName, lFlags, pValue):
#         print('IWbemContext.SetValue')
#         return E_NOTIMPL
#
#     def GetValue(self, This, wszName, lFlags, pValue):
#         print('IWbemContext.GetValue')
#         return E_NOTIMPL
#
#     def DeleteValue(self, This, wszName, lFlags):
#         print('IWbemContext.DeleteValue')
#         return E_NOTIMPL
#
#     def DeleteAll(self, This):
#         print('IWbemContext.DeleteAll')
#         return E_NOTIMPL
#
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

# class IWbemLocatorImplem(windows.com.COMImplementation):
#     IMPLEMENT = IWbemLocator
#
#     def ConnectServer(self, This, strNetworkResource, strUser, strPassword, strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace):
#         print('IWbemLocator.ConnectServer')
#         return E_NOTIMPL
#
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

# class IWbemObjectSinkImplem(windows.com.COMImplementation):
#     IMPLEMENT = IWbemObjectSink
#
#     def Indicate(self, This, lObjectCount, apObjArray):
#         print('IWbemObjectSink.Indicate')
#         return E_NOTIMPL
#
#     def SetStatus(self, This, lFlags, hResult, strParam, pObjParam):
#         print('IWbemObjectSink.SetStatus')
#         return E_NOTIMPL
#
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

# class IWbemObjectTextSrcImplem(windows.com.COMImplementation):
#     IMPLEMENT = IWbemObjectTextSrc
#
#     def GetText(self, This, lFlags, pObj, uObjTextFormat, pCtx, strText):
#         print('IWbemObjectTextSrc.GetText')
#         return E_NOTIMPL
#
#     def CreateFromText(self, This, lFlags, strText, uObjTextFormat, pCtx, pNewObj):
#         print('IWbemObjectTextSrc.CreateFromText')
#         return E_NOTIMPL
#
IWbemObjectTextSrc._functions_ = {
        # QueryInterface -> riid:REFIID, ppvObject:**void
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, REFIID, POINTER(PVOID))(0, "QueryInterface"),
        # AddRef -> 
        "AddRef": ctypes.WINFUNCTYPE(ULONG)(1, "AddRef"),
        # Release -> 
        "Release": ctypes.WINFUNCTYPE(ULONG)(2, "Release"),
        # GetText -> lFlags:LONG, pObj:*IWbemClassObject, uObjTextFormat:ULONG, pCtx:*IWbemContext, strText:*BSTR
        "GetText": ctypes.WINFUNCTYPE(HRESULT, LONG, IWbemClassObject, ULONG, IWbemContext, POINTER(BSTR))(3, "GetText"),
        # CreateFromText -> lFlags:LONG, strText:BSTR, uObjTextFormat:ULONG, pCtx:*IWbemContext, pNewObj:**IWbemClassObject
        "CreateFromText": ctypes.WINFUNCTYPE(HRESULT, LONG, BSTR, ULONG, IWbemContext, POINTER(IWbemClassObject))(4, "CreateFromText"),
    }

# class IWbemQualifierSetImplem(windows.com.COMImplementation):
#     IMPLEMENT = IWbemQualifierSet
#
#     def Get(self, This, wszName, lFlags, pVal, plFlavor):
#         print('IWbemQualifierSet.Get')
#         return E_NOTIMPL
#
#     def Put(self, This, wszName, pVal, lFlavor):
#         print('IWbemQualifierSet.Put')
#         return E_NOTIMPL
#
#     def Delete(self, This, wszName):
#         print('IWbemQualifierSet.Delete')
#         return E_NOTIMPL
#
#     def GetNames(self, This, lFlags, pNames):
#         print('IWbemQualifierSet.GetNames')
#         return E_NOTIMPL
#
#     def BeginEnumeration(self, This, lFlags):
#         print('IWbemQualifierSet.BeginEnumeration')
#         return E_NOTIMPL
#
#     def Next(self, This, lFlags, pstrName, pVal, plFlavor):
#         print('IWbemQualifierSet.Next')
#         return E_NOTIMPL
#
#     def EndEnumeration(self, This):
#         print('IWbemQualifierSet.EndEnumeration')
#         return E_NOTIMPL
#
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

# class IWbemServicesImplem(windows.com.COMImplementation):
#     IMPLEMENT = IWbemServices
#
#     def OpenNamespace(self, This, strNamespace, lFlags, pCtx, ppWorkingNamespace, ppResult):
#         print('IWbemServices.OpenNamespace')
#         return E_NOTIMPL
#
#     def CancelAsyncCall(self, This, pSink):
#         print('IWbemServices.CancelAsyncCall')
#         return E_NOTIMPL
#
#     def QueryObjectSink(self, This, lFlags, ppResponseHandler):
#         print('IWbemServices.QueryObjectSink')
#         return E_NOTIMPL
#
#     def GetObject(self, This, strObjectPath, lFlags, pCtx, ppObject, ppCallResult):
#         print('IWbemServices.GetObject')
#         return E_NOTIMPL
#
#     def GetObjectAsync(self, This, strObjectPath, lFlags, pCtx, pResponseHandler):
#         print('IWbemServices.GetObjectAsync')
#         return E_NOTIMPL
#
#     def PutClass(self, This, pObject, lFlags, pCtx, ppCallResult):
#         print('IWbemServices.PutClass')
#         return E_NOTIMPL
#
#     def PutClassAsync(self, This, pObject, lFlags, pCtx, pResponseHandler):
#         print('IWbemServices.PutClassAsync')
#         return E_NOTIMPL
#
#     def DeleteClass(self, This, strClass, lFlags, pCtx, ppCallResult):
#         print('IWbemServices.DeleteClass')
#         return E_NOTIMPL
#
#     def DeleteClassAsync(self, This, strClass, lFlags, pCtx, pResponseHandler):
#         print('IWbemServices.DeleteClassAsync')
#         return E_NOTIMPL
#
#     def CreateClassEnum(self, This, strSuperclass, lFlags, pCtx, ppEnum):
#         print('IWbemServices.CreateClassEnum')
#         return E_NOTIMPL
#
#     def CreateClassEnumAsync(self, This, strSuperclass, lFlags, pCtx, pResponseHandler):
#         print('IWbemServices.CreateClassEnumAsync')
#         return E_NOTIMPL
#
#     def PutInstance(self, This, pInst, lFlags, pCtx, ppCallResult):
#         print('IWbemServices.PutInstance')
#         return E_NOTIMPL
#
#     def PutInstanceAsync(self, This, pInst, lFlags, pCtx, pResponseHandler):
#         print('IWbemServices.PutInstanceAsync')
#         return E_NOTIMPL
#
#     def DeleteInstance(self, This, strObjectPath, lFlags, pCtx, ppCallResult):
#         print('IWbemServices.DeleteInstance')
#         return E_NOTIMPL
#
#     def DeleteInstanceAsync(self, This, strObjectPath, lFlags, pCtx, pResponseHandler):
#         print('IWbemServices.DeleteInstanceAsync')
#         return E_NOTIMPL
#
#     def CreateInstanceEnum(self, This, strFilter, lFlags, pCtx, ppEnum):
#         print('IWbemServices.CreateInstanceEnum')
#         return E_NOTIMPL
#
#     def CreateInstanceEnumAsync(self, This, strFilter, lFlags, pCtx, pResponseHandler):
#         print('IWbemServices.CreateInstanceEnumAsync')
#         return E_NOTIMPL
#
#     def ExecQuery(self, This, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum):
#         print('IWbemServices.ExecQuery')
#         return E_NOTIMPL
#
#     def ExecQueryAsync(self, This, strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler):
#         print('IWbemServices.ExecQueryAsync')
#         return E_NOTIMPL
#
#     def ExecNotificationQuery(self, This, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum):
#         print('IWbemServices.ExecNotificationQuery')
#         return E_NOTIMPL
#
#     def ExecNotificationQueryAsync(self, This, strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler):
#         print('IWbemServices.ExecNotificationQueryAsync')
#         return E_NOTIMPL
#
#     def ExecMethod(self, This, strObjectPath, strMethodName, lFlags, pCtx, pInParams, ppOutParams, ppCallResult):
#         print('IWbemServices.ExecMethod')
#         return E_NOTIMPL
#
#     def ExecMethodAsync(self, This, strObjectPath, strMethodName, lFlags, pCtx, pInParams, pResponseHandler):
#         print('IWbemServices.ExecMethodAsync')
#         return E_NOTIMPL
#
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

