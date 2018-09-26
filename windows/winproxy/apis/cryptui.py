import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero

class CryptUIProxy(ApiProxy):
    APIDLL = "cryptui"
    default_error_check = staticmethod(fail_on_zero)


@CryptUIProxy()
def CryptUIDlgViewContext(dwContextType, pvContext, hwnd, pwszTitle, dwFlags, pvReserved):
    return CryptUIDlgViewContext.ctypes_function(dwContextType, pvContext, hwnd, pwszTitle, dwFlags, pvReserved)
