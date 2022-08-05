import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import succeed_on_zero

class IphlpapiProxy(ApiProxy):
    APIDLL = "iphlpapi"
    default_error_check = staticmethod(succeed_on_zero)


@IphlpapiProxy()
def SetTcpEntry(pTcpRow):
   return SetTcpEntry.ctypes_function(pTcpRow)

@IphlpapiProxy()
def GetExtendedTcpTable(pTcpTable, pdwSize=None, bOrder=True, ulAf=NeededParameter, TableClass=gdef.TCP_TABLE_OWNER_PID_ALL, Reserved=0):
    if pdwSize is None:
        pdwSize = gdef.ULONG(ctypes.sizeof(pTcpTable))
    return GetExtendedTcpTable.ctypes_function(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved)

@IphlpapiProxy()
def GetInterfaceInfo(pIfTable, dwOutBufLen=None):
    if dwOutBufLen is None:
        dwOutBufLen = gdef.ULONG(ctypes.sizeof(pIfTable))
    return GetInterfaceInfo.ctypes_function(pIfTable, dwOutBufLen)

@IphlpapiProxy()
def GetIfTable(pIfTable, pdwSize, bOrder=False):
    return GetIfTable.ctypes_function(pIfTable, pdwSize, bOrder)

@IphlpapiProxy()
def GetIpAddrTable(pIpAddrTable, pdwSize, bOrder=False):
    return GetIpAddrTable.ctypes_function(pIpAddrTable, pdwSize, bOrder)


@IphlpapiProxy()
def GetIpNetTable(IpNetTable, SizePointer, Order):
   return GetIpNetTable.ctypes_function(IpNetTable, SizePointer, Order)

@IphlpapiProxy()
def GetAdaptersInfo(AdapterInfo, SizePointer):
    return GetAdaptersInfo.ctypes_function(AdapterInfo, SizePointer)

@IphlpapiProxy()
def GetPerAdapterInfo(IfIndex, pPerAdapterInfo, pOutBufLen):
    return GetPerAdapterInfo.ctypes_function(IfIndex, pPerAdapterInfo, pOutBufLen)