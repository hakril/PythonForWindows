import windows
import ctypes
import struct
import functools

from ctypes.wintypes import *

import windows.com
from windows.generated_def.winstructs import *
from windows.generated_def.interfaces import IWbemLocator, IWbemServices, IEnumWbemClassObject, IWbemClassObject
# import windows.generated_def as gdef


class WmiRequester(object):
    r"""An object to perform wmi request to ``root\cimv2``"""
    INSTANCE = None

    def __init__(self, target="root\\cimv2", user=None, password=None):
        self.namespace = target
        locator = IWbemLocator()
        service = IWbemServices()
        #CLSID_WbemAdministrativeLocator_IID = windows.com.IID.from_string('CB8555CC-9128-11D1-AD9B-00C04FD8FDFF')
        WbemLocator_CLSID = windows.com.IID.from_string('4590F811-1D3A-11D0-891F-00AA004B2E24')

        windows.com.init()
        windows.com.create_instance(WbemLocator_CLSID, locator)
        locator.ConnectServer(target, user, password , None, 0x80, None, None, ctypes.byref(service))
        self.service = service

    def select(self, frm, attrs="*", **kwargs):
        """Select ``attrs`` from ``frm``

        :rtype: list of dict
        """
        return list(self.gen_select(frm, attrs, **kwargs))

    def gen_select(self, frm, attrs="*", **kwargs):
        """Select ``attrs`` from ``frm`` in a generator (like :func:`gen_query`)

        :rtype: generator
        """
        return self.gen_query("select * from {0}".format(frm), attrs, **kwargs)

    @property
    def classes(self):
        """The list of class available

        :rtype: list of str
        """
        return [x["__CLASS"] for x in self.query('SELECT * FROM meta_class', attrs=["__CLASS"])]

    def query(self, query, attrs="*", timeout=WBEM_INFINITE):
        """Execute WMI ``query`` and return the attributes ``attrs``
        Timeout is not applied for the full query time but the time to retrieve one object each time.

        :rtype: list of dict
        """
        return list(self.gen_query(query, attrs, timeout))

    def gen_query(self, query, attrs="*", timeout=WBEM_INFINITE):
        """Execute WMI ``query`` and return a generator that will yield the ``attrs`` for one object each time.
        Each iteration is susceptible to raise.

        :rtype: generator
        """
        enumerator = self._exec_query(query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY)
        try:
            for obj, retval in self._enumerator_values_generator(enumerator, timeout=timeout):
                if obj is None:
                    raise WindowsError(retval, WBEMSTATUS(retval & 0xffffffff).value)
                yield self._iwbemclassobject_to_dict(obj, attrs)
        finally:
            enumerator.Release()

    def _exec_query(self, query, flags, ctx=None):
        enumerator = IEnumWbemClassObject()
        try:
            self.service.ExecQuery("WQL", query, flags, ctx, ctypes.byref(enumerator))
        except WindowsError as e:
            if (e.winerror & 0xffffffff) ==  WBEM_E_INVALID_CLASS:
                raise WindowsError(e.winerror, 'WBEM_E_INVALID_CLASS <Invalid WMI class "{0}">'.format(query))
            elif (e.winerror & 0xffffffff) in WBEMSTATUS.values:
                raise WindowsError(e.winerror, WBEMSTATUS(e.winerror & 0xffffffff).value)
            raise
        return enumerator

    def _enumerator_values_generator(self, enumerator, timeout=WBEM_INFINITE):
        count = ULONG(0)
        processor = IWbemClassObject()
        result = 0
        while result != WBEM_S_FALSE:
            try:
                result = enumerator.Next(timeout, 1, ctypes.byref(processor), ctypes.byref(count))
            except WindowsError as e:
                if (e.winerror & 0xffffffff) ==  WBEM_E_INVALID_CLASS:
                    raise WindowsError(e.winerror, 'WBEM_E_INVALID_CLASS <Invalid WMI class "{0}">'.format(query))
                if (e.winerror & 0xffffffff) in WBEMSTATUS.values:
                    raise WindowsError(e.winerror, WBEMSTATUS(e.winerror & 0xffffffff).value)
                raise
            procres = processor if count else None
            if result != WBEM_S_FALSE:
                yield procres, result

    def _iwbemclassobject_to_dict(self, wbemclassobj, attrs):
        if attrs == "*":
            attrs = [x for x in self.get_names(wbemclassobj) if not x.startswith("__")]
        obj_as_dict = {}
        variant_res = windows.com.ImprovedVariant()
        for name in attrs:
            try:
                wbemclassobj.Get(name, 0, ctypes.byref(variant_res), None, None)
            except WindowsError as e:
                if (e.winerror & 0xffffffff) ==  WBEM_E_NOT_FOUND:
                    raise WindowsError(e.winerror, 'WBEM_E_NOT_FOUND <Invalid Attribute "{0}">'.format(name))
                if (e.winerror & 0xffffffff) in WBEMSTATUS.values:
                    raise WindowsError(e.winerror, WBEMSTATUS(e.winerror & 0xffffffff).value)
                raise
            try:
                obj_as_dict[name] = variant_res.to_pyobject()
            except NotImplementedError as e:
                print("[WMI-ERROR] Field <{0}> ignored: {1}".format(name, e))
        return obj_as_dict

    def get_names(self, processor):
        res = POINTER(SAFEARRAY)()
        processor.GetNames(None, 0, None, byref(res))
        safe_array = ctypes.cast(res, POINTER(windows.com.ImprovedSAFEARRAY))[0]
        safe_array.elt_type = BSTR
        return safe_array.to_list()

    def __repr__(self):
        return """<{0} namespace="{1}">""".format(type(self).__name__, self.namespace)

class WmiManager(dict):
    """The main WMI class exposed, used to list and access differents WMI namespace, can be used as a dict to access
    :cls:`WmiRequester` by namespace"""
    DEFAULT_NAMESPACE = "root\\cimv2"
    def __init__(self):
        self.wmi_requester_by_namespace = {}

    @property
    def select(self):
        r""":func:`WmiRequester.select` for default WMI namespace 'root\\cimv2'"""
        return self[self.DEFAULT_NAMESPACE].select

    @property
    def query(self):
        r""":func:`WmiRequester.query` for default WMI namespace 'root\\cimv2'"""
        return self[self.DEFAULT_NAMESPACE].query

    def get_subnamespaces(self, root="root"):
        return [x["Name"] for x in self[root].select("__NameSpace", ["Name"])]

    namespaces = property(get_subnamespaces)
    """The list of available WMI namespaces"""

    def _open_wmi_requester(self, namespace):
        return WmiRequester(namespace)

    def __missing__(self, key):
        self[key] = self._open_wmi_requester(key)
        return self[key]

    def __repr__(self):
        return object.__repr__(self)