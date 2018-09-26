import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import no_error_check, fail_on_zero

class WinTrustProxy(ApiProxy):
    APIDLL = "wintrust"
    default_error_check = staticmethod(fail_on_zero)


# Trust

@WinTrustProxy(error_check=no_error_check)
def WinVerifyTrust(hwnd, pgActionID, pWVTData):
    return WinVerifyTrust.ctypes_function(hwnd, pgActionID, pWVTData)

# Catalog

@WinTrustProxy()
def CryptCATAdminCalcHashFromFileHandle(hFile, pcbHash, pbHash, dwFlags):
    return CryptCATAdminCalcHashFromFileHandle.ctypes_function(hFile, pcbHash, pbHash, dwFlags)

@WinTrustProxy()
def CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, pcbHash, pbHash, dwFlags):
    return CryptCATAdminCalcHashFromFileHandle2.ctypes_function(hCatAdmin, hFile, pcbHash, pbHash, dwFlags)

@WinTrustProxy(error_check=no_error_check)
def CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo):
    return CryptCATAdminEnumCatalogFromHash.ctypes_function(hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo)

@WinTrustProxy()
def CryptCATAdminAcquireContext(phCatAdmin, pgSubsystem, dwFlags):
    return CryptCATAdminAcquireContext.ctypes_function(phCatAdmin, pgSubsystem, dwFlags)

@WinTrustProxy()
def CryptCATAdminAcquireContext2(phCatAdmin, pgSubsystem, pwszHashAlgorithm, pStrongHashPolicy, dwFlags):
    return CryptCATAdminAcquireContext2.ctypes_function(phCatAdmin, pgSubsystem, pwszHashAlgorithm, pStrongHashPolicy, dwFlags)


@WinTrustProxy()
def CryptCATCatalogInfoFromContext(hCatInfo, psCatInfo, dwFlags):
    return CryptCATCatalogInfoFromContext.ctypes_function(hCatInfo, psCatInfo, dwFlags)


@WinTrustProxy(error_check=no_error_check)
def CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwFlags):
    return CryptCATAdminReleaseCatalogContext.ctypes_function(hCatAdmin, hCatInfo, dwFlags)


@WinTrustProxy()
def CryptCATAdminReleaseContext(hCatAdmin, dwFlags):
    return CryptCATAdminReleaseContext.ctypes_function(hCatAdmin, dwFlags)


@WinTrustProxy(error_check=no_error_check)
def CryptCATEnumerateAttr(hCatalog, pCatMember, pPrevAttr):
    return CryptCATEnumerateAttr.ctypes_function(hCatalog, pCatMember, pPrevAttr)


@WinTrustProxy(error_check=no_error_check)
def CryptCATEnumerateCatAttr(hCatalog, pPrevAttr):
    return CryptCATEnumerateCatAttr.ctypes_function(hCatalog, pPrevAttr)


@WinTrustProxy(error_check=no_error_check)
def CryptCATEnumerateMember(hCatalog, pPrevMember):
    return CryptCATEnumerateMember.ctypes_function(hCatalog, pPrevMember)