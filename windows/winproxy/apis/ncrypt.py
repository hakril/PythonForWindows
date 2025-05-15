
import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import no_error_check, succeed_on_zero

import windows.pycompat
from windows.pycompat import int_types

class NCryptProxy(ApiProxy):
    APIDLL = "ncrypt"
    default_error_check = staticmethod(succeed_on_zero)


@NCryptProxy()
def NCryptOpenKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, dwFlags):
   return NCryptOpenKey.ctypes_function(hProvider, phKey, pszKeyName, dwLegacyKeySpec, dwFlags)


@NCryptProxy()
def NCryptOpenStorageProvider(phProvider, pszProviderName, dwFlags):
   return NCryptOpenStorageProvider.ctypes_function(phProvider, pszProviderName, dwFlags)