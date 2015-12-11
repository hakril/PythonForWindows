import windows
import ctypes
from ctypes.wintypes import *
from windows.generated_def.winstructs import *
import struct
import functools


# Move simple_com from LKD to windows ?

IID_PACK = "<I", "<H", "<H", "<B", "<B", "<B", "<B", "<B", "<B", "<B", "<B"


def get_IID_from_raw(raw):
    return "".join([struct.pack(i, j) for i, j in zip(IID_PACK, raw)])


class COMInterface(ctypes.c_void_p):
    _functions_ = {
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, ctypes.c_void_p, ctypes.c_void_p)(0, "QueryInterface"),
        "AddRef": ctypes.WINFUNCTYPE(HRESULT)(1, "AddRef"),
        "Release": ctypes.WINFUNCTYPE(HRESULT)(2, "Release")
    }

    def __getattr__(self, name):
        if name in self._functions_:
            return functools.partial(self._functions_[name], self)
        return super(COMInterface, self).__getattribute__(name)


class IWbemLocator(COMInterface):
    _functions_ = {
        "ConnectServer": ctypes.WINFUNCTYPE(HRESULT, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                                ctypes.c_long, ctypes.c_wchar_p, ctypes.c_void_p, POINTER(ctypes.c_void_p))(3, "ConnectServer")
    }


class IWbemServices(COMInterface):
    _functions_ = {
        "ExecQuery": ctypes.WINFUNCTYPE(HRESULT, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_long, ctypes.c_void_p, POINTER(ctypes.c_void_p))(20, "ExecQuery")
    }


class IEnumWbemClassObject(COMInterface):
    _functions_ = {
        "Next": ctypes.WINFUNCTYPE(HRESULT, ctypes.c_long, ctypes.c_ulong, POINTER(ctypes.c_void_p), POINTER(ctypes.c_long))(4, "Next")
    }


class IWbemClassObject(COMInterface):
    _functions_ = {
        "Get": ctypes.WINFUNCTYPE(HRESULT, ctypes.c_wchar_p, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long)(4, "Get"),
        "GetNames": ctypes.WINFUNCTYPE(HRESULT, ctypes.c_wchar_p, ctypes.c_long, ctypes.c_void_p, POINTER(ctypes.c_void_p))(7, "GetNames")
    }


CLSID_WbemAdministrativeLocator_raw = 0xcb8555cc, 0x9128, 0x11d1, 0xad, 0x9b, 0x00, 0xc0, 0x4f, 0xd8, 0x0fd, 0xff
CLSID_WbemAdministrativeLocator_IID = get_IID_from_raw(CLSID_WbemAdministrativeLocator_raw)

IID_IWbemLocator_raw = 0x0DC12A687, 0x737F, 0x11CF, 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24
IID_IWbemLocator= get_IID_from_raw(IID_IWbemLocator_raw)


BSTR = ctypes.c_wchar_p


class _tagBRECORD(ctypes.Structure):
    _fields_ = [("pvRecord", PVOID), ("pRecInfo", PVOID)]

    
class SAFEARRAY(windows.generated_def.winstructs.SAFEARRAY):

        @classmethod
        def of_type(cls, addr, t):
            self = cls.from_address(addr)
            self.elt_type = t
            return self

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


class SimpleVariantData(ctypes.Union):
    _fields_ = [("llVal", LONGLONG),
                ("lVal", LONG),
                ("bVal", BYTE),
                ("iVal", SHORT),
                ("fltVal", FLOAT),
                ("dblVal", DOUBLE),
                ("bstrVal", BSTR),
                ("pbstrVal", POINTER(BSTR)),
                ("byref", PVOID),
                ("parray", POINTER(SAFEARRAY)),
                ("pbyref", PVOID),
                ("ullVal", ULONGLONG),
                ("llVal", LONGLONG),
                ("__VARIANT_NAME_4", _tagBRECORD)]

                
# TODO: put real struct in winstruct (need a real parser for generation)
class SimpleVariant(ctypes.Structure):
    _fields_ = [("vt", WORD), ("wReserved1", WORD), ("wReserved2", WORD), ("wReserved3", WORD),  ("_Data", SimpleVariantData)]

    @property
    def asbstr(self):
        if self.vt != VT_BSTR:
            raise ValueError("asbstr on non-bstr variant")
        return self._Data.bstrVal

    @property
    def aslong(self):
        if not self.vt in [VT_I4, VT_BOOL]:
            raise ValueError("aslong on non-long variant")
        return self._Data.lVal

    @property
    def asbool(self):
        if not self.vt in [VT_BOOL]:
            raise ValueError("get_bstr on non-bool variant")
        return bool(self.aslong)


class WmiRequester(object):
    def __init__(self):
        locator = IWbemLocator()
        service = IWbemServices()

        assert ctypes.windll.ole32.CoInitializeEx(0, 0) == 0
        assert ctypes.windll.ole32.CoInitializeSecurity(0, -1, 0,0, 0, 3, 0,0,0) == 0
        assert ctypes.windll.ole32.CoCreateInstance(CLSID_WbemAdministrativeLocator_IID, 0, 1, IID_IWbemLocator, ctypes.byref(locator)) == 0

        locator.ConnectServer("root\\cimv2", None, None , None, 0x80, None, None, ctypes.byref(service))
        self.service = service


    def request_select(self, frm, attrs):
        enumerator = IEnumWbemClassObject()
        self.service.ExecQuery("WQL", "select * from {0}".format(frm), 0x20, 0, ctypes.byref(enumerator))

        count = ctypes.c_long(0)
        processor = IWbemClassObject()
        res = []
        enumerator.Next(0xffffffff, 1, ctypes.byref(processor), ctypes.byref(count))
        while count.value:
            current_res = {}
            variant_res = SimpleVariant()
            self.get_names(processor)
            if attrs == "*":
                attrs = [x for x in self.get_names(processor) if not x.startswith("__")]
            for name in attrs:
                processor.Get(name, 0, ctypes.byref(variant_res), 0, 0)
                # TODO: something clean and generic
                if variant_res.vt & VT_ARRAY:
                    if variant_res.vt & VT_TYPEMASK == VT_BSTR:
                        current_res[name] = variant_res._Data.parray[0].to_list(BSTR)
                    if variant_res.vt & VT_TYPEMASK == VT_I4:
                        current_res[name] = variant_res._Data.parray[0].to_list(LONG)
                elif variant_res.vt in [VT_EMPTY, VT_NULL]:
                    current_res[name] = None
                elif variant_res.vt == VT_BSTR:
                    current_res[name] = variant_res.asbstr
                elif variant_res.vt == VT_I4:
                    current_res[name] = variant_res.aslong
                elif variant_res.vt == VT_BOOL:
                    current_res[name] = variant_res.asbool
                else:
                    print("Ignore variant of type {0}".format(hex(variant_res.vt)))
            res.append(current_res)
            enumerator.Next(0xffffffff, 1, ctypes.byref(processor), ctypes.byref(count))
        return res

    def get_names(self, processor):
        res = PVOID()
        processor.GetNames(None, 0, None, res)
        return SAFEARRAY.of_type(res.value, BSTR).to_list()


req = WmiRequester()

#v = req.request_select("Win32_Process", ["Name", "CommandLine", "ExecutablePath"])
#import pprint
#
#pprint.pprint(v)
#
#
#v = req.request_select("Win32_StartupCommand", ["Command"]);
#print("========")
#pprint.pprint(v)
#
#v = req.request_select("Win32_ComputerSystemProduct", ["Name"]);
#print("========")
#pprint.pprint(v)

v = req.request_select("Win32_Bios", "*")
