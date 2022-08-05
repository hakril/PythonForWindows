import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import no_error_check, fail_on_zero, succeed_on_zero

# IMPORTANT:
# Functions that returns HRESULT (like CoInitializeEx) will raise if HRESULT is an error
# even if there is no error check on the return value

class Ole32Proxy(ApiProxy):
    APIDLL = "oleaut32"
    default_error_check = staticmethod(no_error_check)


@Ole32Proxy()
def SysAllocString(psz):
   return SysAllocString.ctypes_function(psz)


@Ole32Proxy()
def SysFreeString(bstrString):
   return SysFreeString.ctypes_function(bstrString)

@Ole32Proxy(error_check=fail_on_zero)
def SafeArrayCreate(vt, cDims, rgsabound):
   return SafeArrayCreate.ctypes_function(vt, cDims, rgsabound)


@Ole32Proxy(error_check=succeed_on_zero)
def SafeArrayDestroy(psa):
   return SafeArrayDestroy.ctypes_function(psa)


@Ole32Proxy(error_check=succeed_on_zero)
def SafeArrayPutElement(psa, rgIndices, pv):
   return SafeArrayPutElement.ctypes_function(psa, rgIndices, pv)


@Ole32Proxy(error_check=succeed_on_zero)
def SafeArrayGetElement(psa, rgIndices, pv):
   return SafeArrayGetElement.ctypes_function(psa, rgIndices, pv)

