import struct
import ctypes
import functools
from ctypes.wintypes import HRESULT, byref, pointer, cast

import windows
from windows import winproxy
from windows.generated_def.winstructs import *

from windows.generated_def import RPC_C_IMP_LEVEL_IMPERSONATE, CLSCTX_INPROC_SERVER
from windows.generated_def import interfaces
from windows.generated_def.interfaces import generate_IID, IID, COMImplementation


# Simple raw -> UUID
# "-".join("{:02X}".format(c) for c in struct.unpack("<IHHHBBBBBB", x))

def init():
    try:
        t = winproxy.CoInitializeEx()
    except WindowsError as e:
        t = e.winerror
    if t:
        return t
    return initsecurity()

def initsecurity(): # Should take some parameters..
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
    def asunknown(self):
        if not self.vt in [VT_UNKNOWN]:
            raise ValueError("asunknown on non-VT_UNKNOWN variant")
        return self._VARIANT_NAME_3.punkVal

    @property
    def asarray(self):
        if not self.vt & VT_ARRAY:
            raise ValueError("asarray on non-VT_ARRAY variant")
        # TODO: auto extract VT_TYPE for the array ?
        #type = VT_VALUE_TO_TYPE[self.vt & VT_TYPEMASK]
        return ImprovedSAFEARRAY.from_PSAFEARRAY(self._VARIANT_NAME_3.parray)


    @property
    def aslong_array(self):
        if not self.vt & VT_I4:
            raise ValueError("as_bstr_array on non-VT_BSTR variant")
        return self.asarray.to_list(LONG)

    def generate_asarray_property(vttype):
        @property
        def as_array_generated(self):
            # TODO: vt check like the others ?
            return self.asarray.to_list(vttype)
        return as_array_generated

    asbstr_array = generate_asarray_property(BSTR)
    aslong_array = generate_asarray_property(LONG)
    asbyte_array = generate_asarray_property(BYTE)
    asbool_array = generate_asarray_property(VARIANT_BOOL)

    def to_pyobject(self):
        # if self.vt & VT_ARRAY:
            # # Something better TODO i guess
            # if self.vt & VT_TYPEMASK == VT_BSTR:
                # import pdb;pdb.set_trace()
                # print("VT_TYPEMASK ARRAY")
                # return self.asarray.to_list(BSTR)
            # if self.vt & VT_TYPEMASK == VT_I4:
                # import pdb;pdb.set_trace()
                # print("VT_TYPEMASK ARRAY")
                # return self.asarray.to_list(LONG)
            # raise NotImplementedError("Variant of type {0:#x}".format(self.vt))
        # use the ImprovedVariant.MAPPER that dispatch by self.vt
        try:
            return self.MAPPER[self.vt](self)
        except KeyError:
            raise NotImplementedError("Variant of type {0:#x}".format(self.vt))


ImprovedVariant.MAPPER = {
    VT_UI1: ImprovedVariant.asbyte.fget,
    VT_I2: ImprovedVariant.asshort.fget,
    VT_DISPATCH: ImprovedVariant.asdispatch.fget,
    VT_BOOL: ImprovedVariant.asbool.fget,
    VT_I4: ImprovedVariant.aslong.fget,
    VT_BSTR: ImprovedVariant.asbstr.fget,
    VT_EMPTY: (lambda x: None),
    VT_NULL: (lambda x: None),
    VT_UNKNOWN: ImprovedVariant.asunknown.fget,
    (VT_ARRAY | VT_BSTR): ImprovedVariant.asbstr_array.fget,
    (VT_ARRAY | VT_I4): ImprovedVariant.aslong_array.fget,
    (VT_ARRAY | VT_UI1): ImprovedVariant.asbyte_array.fget,
    (VT_ARRAY | VT_BOOL): ImprovedVariant.asbool_array.fget
}


def create_instance(clsiid, targetinterface, custom_iid=None, context=CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER):
    if custom_iid is None:
        custom_iid = targetinterface.IID
    return winproxy.CoCreateInstance(byref(clsiid), None, context, byref(custom_iid), byref(targetinterface))
