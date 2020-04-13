import ctypes
from ctypes import wintypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter, is_implemented
from ..error import succeed_on_zero, no_error_check

class CfgMgr32Proxy(ApiProxy):
    APIDLL = "CfgMgr32"

    # We suppress error checks since CM_** APIs return either :
    #  - CR_SUCCESS on success
    #  - or a custom status, e.g. CR_NO_SUCH_VALUE on an invalid class index
    # if necessary, we can convert them to Win32 error usign CM_MapCrToWin32Err
    default_error_check = staticmethod(no_error_check)


@CfgMgr32Proxy()
def CM_Enumerate_Classes(ClassIndex, Params):
    """ 
        Given a class index, either return the class GUID or None.
    """
    
    guid = gdef.GUID()
    cr_status = CM_Enumerate_Classes.ctypes_function(ClassIndex, ctypes.byref(guid), Params)

    if cr_status != gdef.CR_SUCCESS:
        return None

    return guid


@CfgMgr32Proxy()
def CM_Get_First_Log_Conf(hDevInst, Flags):

    # TODO : test if process is running as wow64 on a windows >8 and raise an exception if true


    conf = wintypes.HANDLE(0)

    cr_status = CM_Get_First_Log_Conf.ctypes_function(
        ctypes.byref(conf),
        hDevInst,
        Flags
    )

    if cr_status != gdef.CR_SUCCESS:
        return None

    return conf

@CfgMgr32Proxy()
def CM_Free_Res_Des_Handle(hRes):
    return CM_Free_Res_Des_Handle.ctypes_function(hRes)

@CfgMgr32Proxy()
def CM_Get_Next_Res_Des(hRes, ResourceType):

    # TODO : test if process is running as wow64 on a windows >8 and raise an exception if true

    updated_hRes = wintypes.HANDLE(0)
    
    # TODO : support ResType_All query (design change since we need to return the resource type queried)
    if not ResourceType:
        raise ValueError("ResType_All not supported")

    if ResourceType > 7:
        raise ValueError("ResourceType %x > ResType_MAX" % ResourceType)

    status =  CM_Get_Next_Res_Des.ctypes_function(
        ctypes.byref(updated_hRes),
        hRes, 
        ResourceType,
        None,
        0       # flags parameter is not used, and must always be 0
    )

    # clean up previous hRes
    CM_Free_Res_Des_Handle(hRes)

    if status != gdef.CR_SUCCESS:
        return None

    return updated_hRes

@CfgMgr32Proxy()
def CM_Get_Res_Des_Data_Size(hRes):

    resource_size = wintypes.ULONG(0)
    status = CM_Get_Res_Des_Data_Size.ctypes_function(
        ctypes.byref(resource_size),
        hRes,
        0       # flags parameter is not used, and must always be 0
    )

    if status != gdef.CR_SUCCESS:
        return None

    return resource_size.value

@CfgMgr32Proxy()
def CM_Get_Res_Des_Data(hRes, ResourceSize):

    resource_buffer =  ctypes.create_string_buffer(ResourceSize)
    result = CM_Get_Res_Des_Data.ctypes_function(
        hRes,
        ctypes.byref(resource_buffer),
        ResourceSize,
        0       # flags parameter is not used, and must always be 0
    )

    if result != gdef.CR_SUCCESS:
        return None

    # truncate and return data
    return bytes(resource_buffer)[0:ResourceSize]
