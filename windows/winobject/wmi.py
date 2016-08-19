import windows
import ctypes
import struct
import functools

from ctypes.wintypes import *

import windows.com
from windows.generated_def.winstructs import *
from windows.generated_def.interfaces import IWbemLocator, IWbemServices, IEnumWbemClassObject, IWbemClassObject


class WmiRequester(object):
    r"""An object to perform wmi request to ``root\cimv2``"""
    INSTANCE = None

    def __new__(cls, *args, **kwargs):
        if cls.INSTANCE is not None:
            return cls.INSTANCE
        cls.INSTANCE = super(cls, cls).__new__(cls, *args, **kwargs)
        return cls.INSTANCE

    def __init__(self, target="root\\cimv2", user=None, password=None):
        locator = IWbemLocator()
        service = IWbemServices()
        #CLSID_WbemAdministrativeLocator_IID = windows.com.IID.from_string('CB8555CC-9128-11D1-AD9B-00C04FD8FDFF')
        WbemLocator_CLSID = windows.com.IID.from_string('4590F811-1D3A-11D0-891F-00AA004B2E24')

        windows.com.init()
        windows.com.create_instance(WbemLocator_CLSID, locator)
        locator.ConnectServer(target, user, password , None, 0x80, None, None, ctypes.byref(service))
        self.service = service

    def select(self, frm, attrs="*"):
        """Select ``attrs`` from ``frm``

        :rtype: list of dict
        """
        enumerator = IEnumWbemClassObject()
        try:
            self.service.ExecQuery("WQL", "select * from {0}".format(frm), 0x20, 0, ctypes.byref(enumerator))
        except WindowsError as e:
            if (e.winerror & 0xffffffff) ==  WBEM_E_INVALID_CLASS:
                raise WindowsError(e.winerror, 'WBEM_E_INVALID_CLASS <Invalid WMI class "{0}">'.format(frm))
            elif (e.winerror & 0xffffffff) in WBEMSTATUS.values:
                raise WindowsError(e.winerror, WBEMSTATUS(e.winerror & 0xffffffff).value)
            raise

        count = ctypes.c_ulong(0)
        processor = IWbemClassObject()
        res = []
        enumerator.Next(0xffffffff, 1, ctypes.byref(processor), ctypes.byref(count))
        while count.value:
            current_res = {}
            variant_res = windows.com.ImprovedVariant()
            if attrs == "*":
                attrs = [x for x in self.get_names(processor) if not x.startswith("__")]
            for name in attrs:
                processor.Get(name, 0, ctypes.byref(variant_res), None, None)
                # TODO: something clean and generic
                if variant_res.vt & VT_ARRAY:
                    if variant_res.vt & VT_TYPEMASK == VT_BSTR:
                        current_res[name] = variant_res.asarray.to_list(BSTR)
                    if variant_res.vt & VT_TYPEMASK == VT_I4:
                        current_res[name] = variant_res.asarray.to_list(LONG)
                elif variant_res.vt in [VT_EMPTY, VT_NULL]:
                    current_res[name] = None
                elif variant_res.vt == VT_BSTR:
                    current_res[name] = variant_res.asbstr
                elif variant_res.vt == VT_I4:
                    current_res[name] = variant_res.aslong
                elif variant_res.vt == VT_BOOL:
                    current_res[name] = variant_res.asbool
                elif variant_res.vt == VT_I2:
                    current_res[name] = variant_res.asshort
                elif variant_res.vt == VT_UI1:
                    current_res[name] = variant_res.asbyte
                else:
                    print("[WARN] WMI Ignore variant of type {0}".format(hex(variant_res.vt)))
            res.append(current_res)
            enumerator.Next(0xffffffff, 1, ctypes.byref(processor), ctypes.byref(count))
        return res

    def get_names(self, processor):
        res = POINTER(SAFEARRAY)()
        processor.GetNames(None, 0, None, byref(res))
        safe_array = ctypes.cast(res, POINTER(windows.com.ImprovedSAFEARRAY))[0]
        safe_array.elt_type = BSTR
        return safe_array.to_list()