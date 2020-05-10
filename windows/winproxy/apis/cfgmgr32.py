import ctypes
from ctypes import wintypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter, is_implemented
from ..error import WinproxyError, result_is_error_code

CFGMGR32_ERRORS = gdef.FlagMapper(
    gdef.CR_SUCCESS,
    gdef.CR_DEFAULT,
    gdef.CR_OUT_OF_MEMORY,
    gdef.CR_INVALID_POINTER,
    gdef.CR_INVALID_FLAG,
    gdef.CR_INVALID_DEVNODE,
    gdef.CR_INVALID_DEVINST,
    gdef.CR_INVALID_RES_DES,
    gdef.CR_INVALID_LOG_CONF,
    gdef.CR_INVALID_ARBITRATOR,
    gdef.CR_INVALID_NODELIST,
    gdef.CR_DEVNODE_HAS_REQS,
    gdef.CR_DEVINST_HAS_REQS,
    gdef.CR_INVALID_RESOURCEID,
    gdef.CR_DLVXD_NOT_FOUND,
    gdef.CR_NO_SUCH_DEVNODE,
    gdef.CR_NO_SUCH_DEVINST,
    gdef.CR_NO_MORE_LOG_CONF,
    gdef.CR_NO_MORE_RES_DES,
    gdef.CR_ALREADY_SUCH_DEVNODE,
    gdef.CR_ALREADY_SUCH_DEVINST,
    gdef.CR_INVALID_RANGE_LIST,
    gdef.CR_INVALID_RANGE,
    gdef.CR_FAILURE,
    gdef.CR_NO_SUCH_LOGICAL_DEV,
    gdef.CR_CREATE_BLOCKED,
    gdef.CR_NOT_SYSTEM_VM,
    gdef.CR_REMOVE_VETOED,
    gdef.CR_APM_VETOED,
    gdef.CR_INVALID_LOAD_TYPE,
    gdef.CR_BUFFER_SMALL,
    gdef.CR_NO_ARBITRATOR,
    gdef.CR_NO_REGISTRY_HANDLE,
    gdef.CR_REGISTRY_ERROR,
    gdef.CR_INVALID_DEVICE_ID,
    gdef.CR_INVALID_DATA,
    gdef.CR_INVALID_API,
    gdef.CR_DEVLOADER_NOT_READY,
    gdef.CR_NEED_RESTART,
    gdef.CR_NO_MORE_HW_PROFILES,
    gdef.CR_DEVICE_NOT_THERE,
    gdef.CR_NO_SUCH_VALUE,
    gdef.CR_WRONG_TYPE,
    gdef.CR_INVALID_PRIORITY,
    gdef.CR_NOT_DISABLEABLE,
    gdef.CR_FREE_RESOURCES,
    gdef.CR_QUERY_VETOED,
    gdef.CR_CANT_SHARE_IRQ,
    gdef.CR_NO_DEPENDENT,
    gdef.CR_SAME_RESOURCES,
    gdef.CR_NO_SUCH_REGISTRY_KEY,
    gdef.CR_INVALID_MACHINENAME,
    gdef.CR_REMOTE_COMM_FAILURE,
    gdef.CR_MACHINE_UNAVAILABLE,
    gdef.CR_NO_CM_SERVICES,
    gdef.CR_ACCESS_DENIED,
    gdef.CR_CALL_NOT_IMPLEMENTED,
    gdef.CR_INVALID_PROPERTY,
    gdef.CR_DEVICE_INTERFACE_ACTIVE,
    gdef.CR_NO_SUCH_DEVICE_INTERFACE,
    gdef.CR_INVALID_REFERENCE_STRING,
    gdef.CR_INVALID_CONFLICT_LIST,
    gdef.CR_INVALID_INDEX,
    gdef.CR_INVALID_STRUCTURE_SIZE
)



class CfgMgr32Error(WinproxyError):
    def __new__(cls, func_name, error_code):
        error_flag = CFGMGR32_ERRORS[error_code]
        api_error = super(WinproxyError, cls).__new__(cls)
        api_error.api_name = func_name
        api_error.winerror = error_flag
        api_error.strerror = error_flag.name
        api_error.args = (func_name, api_error.winerror, api_error.strerror)
        return api_error

def tst_error(func_name, result, func, args):
    if result:
        raise CfgMgr32Error(func_name, result)
    return args

class CfgMgr32Proxy(ApiProxy):
    APIDLL = "CfgMgr32"
    # We can make a custom error_check taht translate error code to CR_ flags if needed
    default_error_check = staticmethod(tst_error)



@CfgMgr32Proxy()
def CM_Enumerate_Classes(ulClassIndex, ClassGuid, ulFlags):
    return CM_Enumerate_Classes.ctypes_function(ulClassIndex, ClassGuid, ulFlags)


@CfgMgr32Proxy()
def CM_Get_First_Log_Conf(plcLogConf, dnDevInst, ulFlags):
    return CM_Get_First_Log_Conf.ctypes_function(plcLogConf, dnDevInst, ulFlags)

@CfgMgr32Proxy()
def CM_Get_First_Log_Conf_Ex(plcLogConf, dnDevInst, ulFlags, hMachine):
    return CM_Get_First_Log_Conf_Ex.ctypes_function(plcLogConf, dnDevInst, ulFlags, hMachine)

@CfgMgr32Proxy()
def CM_Get_Next_Log_Conf(plcLogConf, lcLogConf, ulFlags=0):
    return CM_Get_Next_Log_Conf.ctypes_function(plcLogConf, lcLogConf, ulFlags)

@CfgMgr32Proxy()
def CM_Get_Next_Log_Conf_Ex(plcLogConf, lcLogConf, ulFlags, hMachine):
    return CM_Get_Next_Log_Conf_Ex.ctypes_function(plcLogConf, lcLogConf, ulFlags, hMachine)


@CfgMgr32Proxy()
def CM_Free_Res_Des_Handle(hRes):
    return CM_Free_Res_Des_Handle.ctypes_function(hRes)

@CfgMgr32Proxy()
def CM_Get_Next_Res_Des(prdResDes, rdResDes, ForResource, pResourceID, ulFlags=0):
    return CM_Get_Next_Res_Des.ctypes_function(prdResDes, rdResDes, ForResource, pResourceID, ulFlags)


@CfgMgr32Proxy()
def CM_Get_Res_Des_Data_Size(pulSize, rdResDes, ulFlags=0):
    return CM_Get_Res_Des_Data_Size.ctypes_function(pulSize, rdResDes, ulFlags)


@CfgMgr32Proxy()
def CM_Get_Res_Des_Data(rdResDes, Buffer, BufferLen, ulFlags=0):
    return CM_Get_Res_Des_Data.ctypes_function(rdResDes, Buffer, BufferLen, ulFlags)


@CfgMgr32Proxy()
def CM_Get_Parent(pdnDevInst, dnDevInst, ulFlags=0):
    return CM_Get_Parent.ctypes_function(pdnDevInst, dnDevInst, ulFlags)