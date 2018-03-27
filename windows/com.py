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
    """Init COM with some default parameters"""
    try:
        t = winproxy.CoInitializeEx()
    except WindowsError as e:
        t = e.winerror
    if t:
        return t
    return initsecurity()

def initsecurity(): # Should take some parameters..
    return winproxy.CoInitializeSecurity(0, -1, None, 0, 0, RPC_C_IMP_LEVEL_IMPERSONATE, 0,0,0)


def create_instance(clsiid, targetinterface, custom_iid=None, context=CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER):
    """A simple wrapper around ``CoCreateInstance <https://msdn.microsoft.com/en-us/library/windows/desktop/ms686615(v=vs.85).aspx>``"""
    if custom_iid is None:
        custom_iid = targetinterface.IID
    return winproxy.CoCreateInstance(byref(clsiid), None, context, byref(custom_iid), byref(targetinterface))

# Improved COM object
# Todo: ctypes_genertation extended struct ?
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



class COMImplementation(object):
    """The base class to implements COM object respecting a given interface"""
    IMPLEMENT = None

    def get_index_of_method(self, method):
        # This code is horrible but not totally my fault
        # the PyCFuncPtrObject->index is not exposed to Python..
        # repr is: '<COM method offset 2: WinFunctionType at 0x035DDBE8>'
        rpr = repr(method)
        if not rpr.startswith("<COM method offset ") or ":" not in rpr:
            raise ValueError("Could not extract offset of {0}".format(rpr))
        return int(rpr[len("<COM method offset "): rpr.index(":")])

    def extract_methods_order(self, interface):
        index_and_method = sorted((self.get_index_of_method(m),name, m) for name, m in interface._functions_.items())
        return index_and_method

    def verify_implem(self, interface):
        for func_name in interface._functions_:
            implem = getattr(self, func_name, None)
            if implem is None:
                raise ValueError("<{0}> implementing <{1}> has no method <{2}>".format(type(self).__name__, self.IMPLEMENT.__name__, func_name))
            if not callable(implem):
                raise ValueError("{0} implementing <{1}>: <{2}> is not callable".format(type(self).__name__, self.IMPLEMENT.__name__, func_name))
        return True

    def _create_vtable(self, interface):
        implems = []
        names = []
        for index, name, method in self.extract_methods_order(interface):
            func_implem = getattr(self, name)
            #'this' is a COM-interface of the type we are implementing
            types = [method.restype, interface] + list(method.argtypes)
            implems.append(ctypes.WINFUNCTYPE(*types)(func_implem))
            names.append(name)
        class Vtable(ctypes.Structure):
            _fields_ = [(name, ctypes.c_void_p) for name in names]
        return Vtable(*[ctypes.cast(x, ctypes.c_void_p) for x in implems]), implems

    def __init__(self):
        self.verify_implem(self.IMPLEMENT)
        vtable, implems = self._create_vtable(self.IMPLEMENT)
        self.vtable = vtable
        self.implems = implems
        self.vtable_pointer = ctypes.pointer(self.vtable)
        self._as_parameter_ = ctypes.addressof(self.vtable_pointer)

    def QueryInterface(self, this, piid, result):
        """Default ``QueryInterface`` implementation that returns ``self`` if piid is the implemented interface"""
        if piid[0] in (IUnknown.IID, self.IMPLEMENT.IID):
            result[0] = this
            return 1
        return E_NOINTERFACE

    def AddRef(self, *args):
        """Default ``AddRef`` implementation that returns ``1``"""
        return 1

    def Release(self, *args):
        """Default ``Release`` implementation that returns ``1``"""
        return 0
