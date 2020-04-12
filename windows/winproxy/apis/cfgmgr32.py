import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter, is_implemented
from ..error import succeed_on_zero, no_error_check

class CfgMgr32Proxy(ApiProxy):
    APIDLL = "CfgMgr32"
    default_error_check = staticmethod(succeed_on_zero)


# We suppress error checks since CM_Enumerate_Classes return either :
#  - CR_SUCCESS on success
#  - usually CR_NO_SUCH_VALUE on an invalid class index
@CfgMgr32Proxy(error_check=no_error_check)
def CM_Enumerate_Classes(ClassIndex, Params):
    """ 
        Given a class index, either return the class GUID or None.
    """
    
    guid = gdef.GUID()
    cr_status = CM_Enumerate_Classes.ctypes_function(ClassIndex, ctypes.byref(guid), Params)

    if cr_status != gdef.CR_SUCCESS:
        return None

    return guid


# @CfgMgr32Proxy()
# def CM_Get_First_Log_Conf(hDevInst):
#     return CM_Get_First_Log_Conf.ctypes_function(hDevInst)

# @CfgMgr32Proxy()
# def CM_Get_Next_Res_Des(hRes, ResourceType):
#     return CM_Get_Next_Res_Des.ctypes_function(hRes, ResourceType)

# @CfgMgr32Proxy()
# def CM_Get_Res_Des_Data_Size(hRes):
#     return CM_Get_Res_Des_Data_Size.ctypes_function(hRes)

# @CfgMgr32Proxy()
# def CM_Get_Res_Des_Data(hRes, ResourceSize):
#     return CM_Get_Res_Des_Data.ctypes_function(hRes, ResourceSize)

# @CfgMgr32Proxy()
# def CM_Free_Res_Des_Handle(hRes):
#     return CM_Free_Res_Des_Handle.ctypes_function(hRes)
