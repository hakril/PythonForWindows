import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import result_is_error_code

# TDH: Trace Data Helper
# https://docs.microsoft.com/en-us/windows/desktop/etw/retrieving-event-data-using-tdh

class TdhProxy(ApiProxy):
    APIDLL = "tdh"
    default_error_check = staticmethod(result_is_error_code)

@TdhProxy()
def TdhEnumerateProviders(pBuffer, pBufferSize):
    return TdhEnumerateProviders.ctypes_function(pBuffer, pBufferSize)