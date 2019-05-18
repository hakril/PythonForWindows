import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import no_error_check

# IMPORTANT:
# Functions that returns HRESULT (like CoInitializeEx) will raise if HRESULT is an error
# even if there is no error check on the return value

class Ole32Proxy(ApiProxy):
    APIDLL = "ole32"
    default_error_check = staticmethod(no_error_check)


@Ole32Proxy()
def CoInitializeEx(pvReserved=None, dwCoInit=gdef.COINIT_MULTITHREADED):
    return CoInitializeEx.ctypes_function(pvReserved, dwCoInit)


@Ole32Proxy()
def CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3):
    return CoInitializeSecurity.ctypes_function(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3)


@Ole32Proxy()
def CoCreateInstance(rclsid, pUnkOuter=None, dwClsContext=gdef.CLSCTX_INPROC_SERVER, riid=NeededParameter, ppv=NeededParameter):
    return CoCreateInstance.ctypes_function(rclsid, pUnkOuter, dwClsContext, riid, ppv)

@Ole32Proxy()
def CoCreateInstanceEx(rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults):
    return CoCreateInstanceEx.ctypes_function(rclsid, punkOuter, dwClsCtx, pServerInfo, dwCount, pResults)


@Ole32Proxy()
def CoGetClassObject(rclsid, dwClsContext, pvReserved, riid, ppv):
    return CoGetClassObject.ctypes_function(rclsid, dwClsContext, pvReserved, riid, ppv)

@Ole32Proxy()
def CoGetInterceptor(iidIntercepted, punkOuter, iid, ppv):
    return CoGetInterceptor.ctypes_function(iidIntercepted, punkOuter, iid, ppv)

@Ole32Proxy()
def CLSIDFromProgID(lpszProgID, lpclsid):
    return CLSIDFromProgID.ctypes_function(lpszProgID, lpclsid)

@Ole32Proxy()
def CoTaskMemFree(pv):
    return CoTaskMemFree.ctypes_function(pv)