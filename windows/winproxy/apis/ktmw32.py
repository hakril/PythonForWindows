import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero

class Ktmw32Proxy(ApiProxy):
    APIDLL = "Ktmw32"
    default_error_check = staticmethod(fail_on_zero)


@Ktmw32Proxy()
def CommitTransaction(TransactionHandle):
    return CommitTransaction.ctypes_function(TransactionHandle)


@Ktmw32Proxy()
def CreateTransaction(lpTransactionAttributes, UOW, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description):
    return CreateTransaction.ctypes_function(lpTransactionAttributes, UOW, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description)


@Ktmw32Proxy()
def RollbackTransaction(TransactionHandle):
    return RollbackTransaction.ctypes_function(TransactionHandle)


@Ktmw32Proxy()
def OpenTransaction(dwDesiredAccess, TransactionId):
    return OpenTransaction.ctypes_function(dwDesiredAccess, TransactionId)
