import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter, is_implemented
from ..error import succeed_on_zero

class OleaccProxy(ApiProxy):
    APIDLL = "Oleacc"
    default_error_check = staticmethod(succeed_on_zero)

@OleaccProxy()
def ObjectFromLresult(lResult, riid, wParam, ppvObject):
    return ObjectFromLresult.ctypes_function(lResult, riid, wParam, ppvObject)
