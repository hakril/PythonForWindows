import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero, result_is_error_code, no_error_check

class DNSapiProxy(ApiProxy):
    APIDLL = "dnsapi"
    default_error_check = staticmethod(fail_on_zero)


@DNSapiProxy()
def DnsGetCacheDataTable(DnsEntries):
    return DnsGetCacheDataTable.ctypes_function(DnsEntries)


@DNSapiProxy(error_check=result_is_error_code)
def DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved):
    return DnsQuery_A.ctypes_function(pszName, wType, Options, pExtra, ppQueryResults, pReserved)


@DNSapiProxy(error_check=result_is_error_code)
def DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved):
    return DnsQuery_W.ctypes_function(pszName, wType, Options, pExtra, ppQueryResults, pReserved)

@DNSapiProxy(error_check=result_is_error_code)
def DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle):
    return DnsQueryEx.ctypes_function(pQueryRequest, pQueryResults, pCancelHandle)

@DNSapiProxy(error_check=no_error_check)
def DnsFree(pData, FreeType):
    return DnsFree.ctypes_function(pData, FreeType)
