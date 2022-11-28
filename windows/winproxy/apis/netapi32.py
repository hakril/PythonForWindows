import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import succeed_on_zero

class NetApi32Proxy(ApiProxy):
    APIDLL = "netapi32"
    default_error_check = staticmethod(succeed_on_zero)


@NetApi32Proxy()
def NetLocalGroupGetMembers(servername, localgroupname, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle):
    return NetLocalGroupGetMembers.ctypes_function(servername, localgroupname, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)

@NetApi32Proxy()
def NetQueryDisplayInformation(ServerName, Level, Index, EntriesRequested, PreferredMaximumLength, ReturnedEntryCount, SortedBuffer):
    return NetQueryDisplayInformation.ctypes_function(ServerName, Level, Index, EntriesRequested, PreferredMaximumLength, ReturnedEntryCount, SortedBuffer)

@NetApi32Proxy()
def NetUserEnum(servername, level, filter, bufptr, prefmaxlen, entriesread, totalentries, resume_handle):
    return NetUserEnum.ctypes_function(servername, level, filter, bufptr, prefmaxlen, entriesread, totalentries, resume_handle)

@NetApi32Proxy()
def NetGroupEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle):
    return NetGroupEnum.ctypes_function(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle)

@NetApi32Proxy()
def NetGroupGetInfo(servername, groupname, level, bufptr):
    return NetGroupGetInfo.ctypes_function(servername, groupname, level, bufptr)

@NetApi32Proxy()
def NetGroupGetUsers(servername, groupname, level, bufptr, prefmaxlen, entriesread, totalentries, ResumeHandle):
    return NetGroupGetUsers.ctypes_function(servername, groupname, level, bufptr, prefmaxlen, entriesread, totalentries, ResumeHandle)

@NetApi32Proxy()
def NetLocalGroupEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle):
    return NetLocalGroupEnum.ctypes_function(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)

@NetApi32Proxy()
def NetLocalGroupGetInfo(servername, groupname, level, bufptr):
    return NetLocalGroupGetInfo.ctypes_function(servername, groupname, level, bufptr)

@NetApi32Proxy()
def NetLocalGroupGetMembers(servername, localgroupname, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle):
    return NetLocalGroupGetMembers.ctypes_function(servername, localgroupname, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)

@NetApi32Proxy()
def NetLocalGroupGetInfo(servername, groupname, level, bufptr):
    return NetLocalGroupGetInfo.ctypes_function(servername, groupname, level, bufptr)

@NetApi32Proxy()
def NetLocalGroupEnum(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle):
    return NetLocalGroupEnum.ctypes_function(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resumehandle)

@NetApi32Proxy()
def NetApiBufferFree(Buffer):
    return NetApiBufferFree.ctypes_function(Buffer)