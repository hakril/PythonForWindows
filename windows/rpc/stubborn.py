# An implementation of stubborn:
# https://blog.exatrack.com/STUBborn/
# https://github.com/ExaTrack/COM_IExaDemo/blob/master/stubborn_client.py
## Allows to retrieve a raw RPCClient on a DCOM object

import ctypes

import windows.rpc
import windows.generated_def as gdef

# Should be in windows.com ?
def stubborn_create_instance(clsid, iid):
    """Require windows.com.init()"""
    if isinstance(clsid, str):
        clsid = gdef.GUID.from_string(clsid)
    if isinstance(iid, str):
        iid = gdef.GUID.from_string(iid)

    windows.com.init()

    # Retrieve the COM Catalog to get a IComClassInfo
    comcatalog = gdef.IComCatalog()
    windows.com.create_instance("00000346-0000-0000-c000-000000000046", comcatalog)

    # Retrieve the IComClassInfo on CLSID_TARGET
    comclassinfo = gdef.IComClassInfo()
    comcatalog.GetClassInfo(clsid, gdef.IComClassInfo.IID, comclassinfo)

    # Create an ActivationPropertiesIn
    propin = gdef.IActivationPropertiesIn()
    windows.com.create_instance("00000338-0000-0000-c000-000000000046", propin)

    # Query the interfaces we need to fill the ActivationPropertiesIn
    propin_init = propin.query(gdef.IInitActivationPropertiesIn)
    propin_as_priv = propin.query(gdef.IPrivActivationPropertiesIn)
    propin_as_stage = propin.query(gdef.IActivationStageInfo)

    # Fill the ActivationPropertiesIn
    # Simple example : We directly ask for a pointer to an gdef.ITaskService.IID
    # We could ask for a IUnknown and then use RemQueryInterface
    propin.AddRequestedIIDs(1, iid)
    propin_init.SetClassInfo(ctypes.cast(comclassinfo, gdef.IUnknown))
    propin_init.SetClsctx(gdef.CLSCTX_LOCAL_SERVER)
    propin_as_stage.SetStageAndIndex(gdef.CLIENT_CONTEXT_STAGE, 0) # We are a Client activator

    # Make the actual CreateInstance
    propout = gdef.IActivationPropertiesOut()
    remiunknown = gdef.IUnknown()
    propin_as_priv.DelegateCreateInstance(remiunknown, propout)

    # Query the interfaces we need to from the ActivationPropertiesOut
    propout_as_priv = propout.query(gdef.IPrivActivationPropertiesOut)
    propout_as_scmreply = propout.query(gdef.IScmReplyInfo)

    # TODO: a real analysis of which combase version change this structure ?
    # 6.1.7601.17514 -> 10.0.19041.4894 -> PPRIV_RESOLVER_INFO_LEGACY
    # 10.0.22000.65 -> 10.0.26100.2454 -> PPRIV_RESOLVER_INFO (Windows 11 & +)
    rpiv_infoptr = gdef.PPRIV_RESOLVER_INFO() # Structure may change on older windows and be PPRIV_RESOLVER_INFO_LEGACY
    propout_as_scmreply.GetResolverInfo(rpiv_infoptr)

    resolver_info = rpiv_infoptr[0]
    # resolver_info.OxidInfo.containerVersion.version is part of OxidInfo.ipidRemUnknown on PPRIV_RESOLVER_INFO_LEGACY
    # And this part of ipidRemUnknown is a PID
    # So a good value to check for > 3 :)
    # Bad alignemetn of containerVersion -> its an older version
    if resolver_info.OxidInfo.containerVersion.version > 3:
        dcomversionstruct = resolver_info.OxidInfo.dcomVersion
        # If 5,7 -> good alignement of dcomversion so we know its PRIV_RESOLVER_INFO_17763
        dcomversion = (dcomversionstruct.MajorVersion, dcomversionstruct.MinorVersion)
        if dcomversion == (5, 7):
            resolver_info = ctypes.cast(rpiv_infoptr, gdef.PPRIV_RESOLVER_INFO_17763)[0]
        else:
            # Bad alignement for everythin -> Legacy
            resolver_info = ctypes.cast(rpiv_infoptr, gdef.PPRIV_RESOLVER_INFO_LEGACY)[0]

    try:
        psa = resolver_info.OxidInfo.psa[0] # Retrieve the bidings to our COM server
    except ValueError as e:
        # Seen case of NULL DEREF
        # Embed more value to the except for better debugging
        e.stubborn_info = {
            "resolver_info.OxidInfo.containerVersion.version": resolver_info.OxidInfo.containerVersion.version,
            "dcomversion": (dcomversionstruct.MajorVersion, dcomversionstruct.MinorVersion),
            "resolver_info": resolver_info,
        }
        raise

    # print("psa.bidings: {0}".format(psa.bidings))
    # ipidRemUnknown = resolver_info.OxidInfo.ipidRemUnknown # Useful for IRemQueryInterface

    # Retrieve info about the IPID from GetMarshalledResults
    nb_interface = gdef.DWORD()
    iids = gdef.LPGUID()
    results = ctypes.POINTER(gdef.HRESULT)()
    interfaces = ctypes.pointer(gdef.PMInterfacePointer())
    propout_as_priv.GetMarshalledResults(nb_interface, iids, results, interfaces)

    objref = interfaces[0][0].objref

    # Parse the RPC biding and connect to the related ALPC Port
    target_alpc_endpoint = psa.bidings[0]
    assert target_alpc_endpoint.startswith("ncalrpc:[")
    target_alpc_server = "\\RPC Control\\" + target_alpc_endpoint[len("ncalrpc:["):-1]
    # Does not works on Windows XP at this point -> ALPC did not exists back then
    # I won't implement a LRPC Client :')
    client = windows.rpc.RPCClient(target_alpc_server)

    # RPC: Bind to the IID on ou server
    iid = client.bind(iid, (0, 0))
    return client, objref.std.ipid