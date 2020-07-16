import sys
import struct
import ctypes
import functools
from ctypes import HRESULT, byref, cast

import windows
from windows import winproxy
from windows.generated_def.winstructs import *

import windows.generated_def as gdef
from windows.generated_def import RPC_C_IMP_LEVEL_IMPERSONATE, CLSCTX_INPROC_SERVER
from windows.generated_def import interfaces
from windows.generated_def.interfaces import generate_IID, IID

from windows.pycompat import int_types, basestring

# We have    windows.com.COMImplementation
# So we need windows.com.COMInterface
COMInterface = interfaces.COMInterface

# Simple raw -> UUID
# "-".join("{:02X}".format(c) for c in struct.unpack("<IHHHBBBBBB", x))

def init():
    """Init COM with some default parameters"""
    try:
        t = winproxy.CoInitializeEx()
    except WindowsError as e:
        t = e.winerror
    if t:
        return t & 0xffffffff
    return initsecurity()

def initsecurity(): # Should take some parameters..
    return winproxy.CoInitializeSecurity(0, -1, None, 0, 0, RPC_C_IMP_LEVEL_IMPERSONATE, 0,0,0)


class Dispatch(interfaces.IDispatch):
    def TypeInfoCount(self):
        count = gdef.UINT()
        self.GetTypeInfoCount(count)
        return count

    def type_info(self, idx):
        type_info = TypeInfo()
        self.GetTypeInfo(idx, 0, type_info)
        return type_info

class TypeInfo(interfaces.ITypeInfo):
    def func(self, idx):
        res = gdef.LPFUNCDESC()
        self.GetFuncDesc(idx, res)
        return res

    def attr(self):
        res = gdef.LPTYPEATTR()
        self.GetTypeAttr(res)
        return res

    def names(self, memid):
        size = gdef.UINT()
        x = (gdef.BSTR * 10)(*tuple(gdef.BSTR() for i in range(10)))
        self.GetNames(memid, x, 10, size)
        return x[:size.value]

    def docu(self, id):
        res = gdef.BSTR()
        self.GetDocumentation(id, res, None, None, None)
        return res

def create_instance(clsiid, targetinterface, custom_iid=None, context=CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER):
    """A simple wrapper around ``CoCreateInstance <https://msdn.microsoft.com/en-us/library/windows/desktop/ms686615(v=vs.85).aspx>``"""
    if custom_iid is None:
        custom_iid = targetinterface.IID
    if isinstance(clsiid, basestring):
        clsiid = IID.from_string(clsiid)
    winproxy.CoCreateInstance(byref(clsiid), None, context, byref(custom_iid), byref(targetinterface))
    return targetinterface


def resolve_progid(progid):
    clsid = CLSID()
    winproxy.CLSIDFromProgID(progid, clsid)
    # We just filed the CLSID: refresh the __repr__
    clsid.update_strid()
    return clsid

# Improved COM object
# Todo: ctypes_generation extended struct ?
class SafeArray(SAFEARRAY):
        @classmethod
        def of_type(cls, addr, t):
            self = cls.from_address(addr)
            self.elt_type = t
            return self

        @classmethod
        def from_PSAFEARRAY(self, psafearray):
            res = cast(psafearray, POINTER(SafeArray))[0]
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

# VARIANT type checker
# Allow to guess a VARIANT_TYPE og a python value

def never_match(value):
    return False

def check_type_null(value):
    return value is None

def check_type_i4(value):
    # 31 ? as we may want to keep sign :)
    return isinstance(value, int_types) and (value).bit_length() <= 32

def check_type_i8(value):
    # 63 ? as we may want to keep sign :)
    return isinstance(value, int_types) and (value).bit_length() <= 64

def check_type_bstr(value):
    return isinstance(value, basestring)

def check_type_bool(value):
    return isinstance(value, bool)

def check_type_array(value):
    return True


VARIAN_NAME_3_TYPE = [f[1] for f in VARIANT._fields_ if f[0] == "_VARIANT_NAME_3"][0]

empty = object()
class Variant(VARIANT):
    def __init__(self, value=empty, type=None):
        if type is not None:
            self.set_value_and_type(value, type)
            return
        elif value is empty:
            self.vt = VT_EMPTY
            return
        self.guess_type_and_set_value(value)

    # Copy raw-ctypes fields which is a descriptor :)
    rawvt = VARIANT.vt

    # Most of the value in the colunm[1]
    # are attribute of the sub-union _VARIANT_NAME_3
    # This union must be ctypes-anonymous for this code to works
    # We want to access these directly from the VARIANT
    # to allow custom descriptor for complexe type to be referenced here
    CHECK_TYPE = [
        # Order is important
        # as VT_I4 check may match VT_BOOL values
        # VT_BOOL check must be before VT_I4 one
        (VT_BOOL, "boolVal", check_type_bool),
        (VT_I4, "lVal", check_type_i4),
        (VT_I8, "llVal", check_type_i8),
        (VT_BSTR, "bstrVal", check_type_bstr),
        (VT_NULL, None, check_type_null),
        (VT_EMPTY, None, never_match),
        (VT_DISPATCH, "pdispVal", never_match), # I cannot recognize DISPATCH ptr for now
        (VT_UNKNOWN, "punkVal", never_match), # recognise PFW ComInterface ?
        # Test: do not allow auto-creation of small int values
        # I don't know but a feel it may confuse some API expecting VT_I4
        (VT_I2, "iVal", never_match),
        (VT_UI1, "bVal", never_match),
    ]

    VARIANT_TYPE_BY_NAME = {f[0]: f[1] for f in VARIAN_NAME_3_TYPE._fields_}
    QUICK_CHECK_TYPE = {x: y for x,y, _ in CHECK_TYPE}

    def get_vt(self):
        rawvt = super(Variant, self).vt
        return gdef.VARENUM.mapper[self.rawvt]

    def set_vt(self, value):
        self.rawvt = value

    vt = property(get_vt, set_vt)

    def set_value_and_type(self, value, type):
        attr = self.QUICK_CHECK_TYPE[type]
        # No check: user must be careful about non-match value&type
        setattr(self, attr, value)
        self.vt = type

    def get_value_based_on_type(self):
        rawvt = self.rawvt
        if rawvt & VT_ARRAY:
            realtype = rawvt & ~VT_ARRAY
            attr = self.QUICK_CHECK_TYPE[realtype]
            attrtype = self.VARIANT_TYPE_BY_NAME[attr]
            array = SafeArray.from_PSAFEARRAY(self._VARIANT_NAME_3.parray)
            return array.to_list(attrtype)
        attr = self.QUICK_CHECK_TYPE[rawvt]
        if attr is None:
            return None
        if attr == "punkVal":
            # Quick hack for COM interface type
            # Do something clean with CHECK_TYPE ?
            x = gdef.IUnknown(self.punkVal)
            x.AddRef()
            return x
        return getattr(self, attr)

    def guess_type_and_set_value(self, value):
        for t, attr, check in self.CHECK_TYPE:
            try:
                checkres = check(value)
            except TypeError as e:
                continue
            if checkres:
                self.vt = t
                if attr is not None:
                    setattr(self, attr, value)
                return True
        raise ValueError("Could not guess VT_TYPE for <{0}> of type <{1}>".format(value, type(value)))

    value = property(get_value_based_on_type, guess_type_and_set_value)

    # quick_check: bypass python lookup-limitation
    def generate_getter(vt_type, transfo=(lambda x:x), quick_check=QUICK_CHECK_TYPE):
        attr = quick_check[vt_type]
        @property
        def getter(self):
            if not self.rawvt == vt_type:
                raise ValueError("Invalid vt-type for attribute expected <{0}> got <{1}>".format(vt_type, self.vt))
            return transfo(getattr(self, attr))
        return getter

    asbstr = generate_getter(VT_BSTR)
    aslong = generate_getter(VT_I4)
    asbool = generate_getter(VT_BOOL)
    asdispatch = generate_getter(VT_DISPATCH, transfo=interfaces.IDispatch)
    asshort = generate_getter(VT_I2)
    asbyte = generate_getter(VT_UI1)
    asunknown = generate_getter(VT_UNKNOWN)

    def __repr__(self):
        return """<{0} of type {1}>""".format(type(self).__name__, self.vt)

# Deprecated: remove me when test pass :)
# ImprovedVariant.MAPPER = {
    # VT_UI1: ImprovedVariant.asbyte.fget,
    # VT_I2: ImprovedVariant.asshort.fget,
    # VT_DISPATCH: ImprovedVariant.asdispatch.fget,
    # VT_BOOL: ImprovedVariant.asbool.fget,
    # VT_I4: ImprovedVariant.aslong.fget,
    # VT_BSTR: ImprovedVariant.asbstr.fget,
    # VT_EMPTY: (lambda x: None),
    # VT_NULL: (lambda x: None),
    # VT_UNKNOWN: ImprovedVariant.asunknown.fget,
    # (VT_ARRAY | VT_BSTR): ImprovedVariant.asbstr_array.fget,
    # (VT_ARRAY | VT_I4): ImprovedVariant.aslong_array.fget,
    # (VT_ARRAY | VT_UI1): ImprovedVariant.asbyte_array.fget,
    # (VT_ARRAY | VT_BOOL): ImprovedVariant.asbool_array.fget
# }



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
        if piid[0] in (gdef.IUnknown.IID, self.IMPLEMENT.IID):
            result[0] = this
            return 1
        return E_NOINTERFACE

    def AddRef(self, *args):
        """Default ``AddRef`` implementation that returns ``1``"""
        return 1

    def Release(self, *args):
        """Default ``Release`` implementation that returns ``1``"""
        return 0
