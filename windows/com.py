import struct
import ctypes
import functools
from ctypes.wintypes import HRESULT, byref, pointer, cast

import windows
from windows import winproxy
from windows.generated_def.winstructs import *

from windows.generated_def import RPC_C_IMP_LEVEL_IMPERSONATE, CLSCTX_INPROC_SERVER
from windows.generated_def import interfaces
from windows.generated_def.interfaces import generate_IID, IID


# Simple raw -> UUID
# "-".join("{:02X}".format(c) for c in struct.unpack("<IHHHBBBBBB", x))

def init():
    t = winproxy.CoInitializeEx()
    if t:
        return t
    return winproxy.CoInitializeSecurity(0, -1, None, 0, 0, RPC_C_IMP_LEVEL_IMPERSONATE, 0,0,0)


class ImprovedSAFEARRAY(SAFEARRAY):
        @classmethod
        def of_type(cls, addr, t):
            self = cls.from_address(addr)
            self.elt_type = t
            return self

        @classmethod
        def from_PSAFEARRAY(self, psafearray):
            res = cast(psafearray, POINTER(ImprovedSAFEARRAY))[0]
            return res

        def to_list(self, t=None):
            if t is None:
                if hasattr(self, "elt_type"):
                    t = self.elt_type
                else:
                    raise ValueError("Missing type of the array")
            if self.cDims !=  1:
                raise NotImplementedError("tagSAFEARRAY if dims != 1")

            nb_element = self.rgsabound[0].cElements
            llbound = self.rgsabound[0].lLbound
            if self.cbElements != ctypes.sizeof(t):
                raise ValueError("Size of elements != sizeof(type)")
            data = [t.from_address(self.pvData + (i + llbound) * ctypes.sizeof(t)).value for i in range(nb_element)]
            return data

#VT_VALUE_TO_TYPE = {
#VT_I2 : SHORT,
#VT_I4 : LONG,
#VT_BSTR : BSTR,
#VT_VARIANT : VARIANT,
#VT_UI1 : UCHAR,
#VT_UI2 : USHORT,
#VT_UI4 : DWORD,
#VT_I8 : LONGLONG,
#VT_UI8 : ULONG64,
#VT_INT : INT,
#VT_UINT : UINT,
#VT_HRESULT : HRESULT,
#VT_PTR : PVOID,
#VT_LPSTR : LPCSTR,
#VT_LPWSTR : LPWSTR,
#}

class ImprovedVariant(VARIANT):
    @property
    def asbstr(self):
        if self.vt != VT_BSTR:
            raise ValueError("asbstr on non-bstr variant")
        #import pdb;pdb.set_trace()
        return self._VARIANT_NAME_3.bstrVal

    @property
    def aslong(self):
        if not self.vt in [VT_I4]:
            raise ValueError("aslong on non-long variant")
        return self._VARIANT_NAME_3.lVal

    @property
    def asbool(self):
        if not self.vt in [VT_BOOL]:
            raise ValueError("get_bstr on non-bool variant")
        return bool(self._VARIANT_NAME_3.boolVal)

    @property
    def asdispatch(self):
        if not self.vt in [VT_DISPATCH]:
            raise ValueError("asdispatch on non-VT_DISPATCH variant")
        return interfaces.IDispatch(self._VARIANT_NAME_3.pdispVal)

    @property
    def asshort(self):
        if not self.vt in [VT_I2]:
            raise ValueError("asshort on non-VT_I2 variant")
        return self._VARIANT_NAME_3.iVal

    @property
    def asbyte(self):
        if not self.vt in [VT_UI1]:
            raise ValueError("asbyte on non-VT_UI1 variant")
        return self._VARIANT_NAME_3.bVal

    @property
    def asarray(self):
        if not self.vt & VT_ARRAY:
            raise ValueError("asarray on non-VT_ARRAY variant")
        # TODO: auto extract VT_TYPE for the array ?
        #type = VT_VALUE_TO_TYPE[self.vt & VT_TYPEMASK]
        return ImprovedSAFEARRAY.from_PSAFEARRAY(self._VARIANT_NAME_3.parray)



def create_instance(clsiid, targetinterface, custom_iid=None, context=CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER):
    if custom_iid is None:
        custom_iid = targetinterface.IID
    return winproxy.CoCreateInstance(byref(clsiid), None, context, byref(custom_iid), byref(targetinterface))
