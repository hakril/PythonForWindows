import windows
import ctypes
import struct
import functools

from ctypes.wintypes import *

import windows.com
import windows.generated_def as gdef
from windows.generated_def.winstructs import *
from windows.generated_def.interfaces import IWbemLocator, IWbemServices, IEnumWbemClassObject, IWbemClassObject, IWbemCallResult

# Common error check for all WMI COM interfaces
# This 'just' add the corresponding 'WBEMSTATUS' to the hresult error code
class WmiComInterface(object):
    def errcheck(self, result, func, args):
        if result < 0:
            wmitag = gdef.WBEMSTATUS.mapper[result & 0xffffffff]
            raise WindowsError(result , wmitag)
        return args

# https://docs.microsoft.com/en-us/windows/desktop/api/wbemcli/nn-wbemcli-iwbemclassobject

# https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/calling-a-method
class WmiObject(IWbemClassObject, WmiComInterface):
    def get_variant(self, name):
        variant_res = windows.com.ImprovedVariant()
        self.Get(name, 0, variant_res, None, None)
        return variant_res

    def get(self, name):
        return self.get_variant(name).to_pyobject()

    def get_method(self, name):
        inpararm = type(self)()
        outpararm = type(self)()
        variant_res = windows.com.ImprovedVariant()
        self.GetMethod(name, 0, inpararm, outpararm)
        return inpararm, outpararm

    def put_variant(self, name, variant):
        return self.Put(name, 0, variant, 0)

    def put(self, name, value):
        variant_value = windows.com.ImprovedVariant(value)
        return self.put_variant(name, variant_value)

    def spawn(self):
        instance = type(self)()
        self.SpawnInstance(0, instance)
        return instance

    @property
    def genus(self):
        return gdef.tag_WBEM_GENUS_TYPE.mapper[self.get("__GENUS")]

    @property
    def properties(self):
        res = POINTER(SAFEARRAY)()
        self.GetNames(None, 0, None, byref(res))
        safe_array = ctypes.cast(res, POINTER(windows.com.ImprovedSAFEARRAY))[0]
        safe_array.elt_type = BSTR
        return safe_array.to_list()

    # TODO: put this in WmiObject
    def as_dict(self, attrs="**"):
        return {k: self.get(k) for k in self.properties}

    def __repr__(self):
        if self.genus == gdef.WBEM_GENUS_CLASS:
            return """<{0} class "{1}">""".format(type(self).__name__, self.get("__Class"))
        return """<{0} instance of "{1}">""".format(type(self).__name__, self.get("__Class"))


class WmiEnumeration(gdef.IEnumWbemClassObject, WmiComInterface):
    DEFAULT_TIMEOUT = gdef.WBEM_INFINITE

    def next(self, timeout=None):
        timeout = self.DEFAULT_TIMEOUT if timeout is None else timeout
        # For now the count is hardcoded to 1
        obj = WmiObject()
        return_count = gdef.ULONG(0)
        self.Next(timeout, 1, obj, return_count)
        if not return_count or not obj:
            return None
        return obj

    def __iter__(self):
        while True:
            obj = self.next()
            if obj is None:
                return
            yield obj

    def all(self):
        return list(self) # SqlAlchemy like :)

class WmiLocator(IWbemLocator, WmiComInterface):
    pass # Just for the WMI errcheck callback


# !TEST CODE
class WmiNamespace(IWbemServices, WmiComInterface):
    r"""An object to perform wmi request to ``a given namespace``"""

    #CLSID_WbemAdministrativeLocator_IID = windows.com.IID.from_string('CB8555CC-9128-11D1-AD9B-00C04FD8FDFF')
    WbemLocator_CLSID = windows.com.IID.from_string('4590F811-1D3A-11D0-891F-00AA004B2E24')

    DEFAULT_ENUM_FLAGS = (gdef.WBEM_FLAG_RETURN_IMMEDIATELY |
        WBEM_FLAG_FORWARD_ONLY)

    def __init__(self, namespace, *args, **kwargs):
        self.namespace = namespace

    @classmethod
    def connect(cls, namespace, user=None, password=None):
        # this method assert com is initialised
        self = cls(namespace) # IWbemServices subclass
        locator = WmiLocator()
        windows.com.create_instance(cls.WbemLocator_CLSID, locator)
        locator.ConnectServer(namespace, user, password , None, gdef.WBEM_FLAG_CONNECT_USE_MAX_WAIT, None, None, self)
        locator.Release()
        return self


    ### OLD IMPLEM

    def query(self, query):
        """TODO: doc"""
        return list(self.exec_query(query))

    def exec_query(self, query, flags=DEFAULT_ENUM_FLAGS, ctx=None):
        """TODO:DOC: Default flags are: WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY"""
        enumerator = WmiEnumeration()
        # import pdb;pdb.set_trace()
        execq = self.ExecQuery
        # execq.func.errcheck = self.errck
        # execq.func.restype = YoloCheck
        # import pdb;pdb.set_trace()
        # self.ExecQuery("WQL", query, flags, ctx, enumerator)
        execq("WQL", query, flags, ctx, enumerator)
        return enumerator

    def create_class_enum(self, superclass, flags=DEFAULT_ENUM_FLAGS, deep=True):
        flags |= gdef.WBEM_FLAG_DEEP if deep else gdef.WBEM_FLAG_SHALLOW

        enumerator = WmiEnumeration()
        self.CreateClassEnum(superclass, flags, None, enumerator)
        return enumerator

    # subclasses

    def create_instance_enum(self, filter, flags=DEFAULT_ENUM_FLAGS, deep=True):
        # ??? marche pas :(
        flags |= gdef.WBEM_FLAG_DEEP if deep else gdef.WBEM_FLAG_SHALLOW

        enumerator = WmiEnumeration()
        self.CreateInstanceEnum(filter, flags, None, enumerator)
        return enumerator

    select = create_instance_enum

    # TEST 2
    def get_object(self, path):
        result = WmiObject()
        self.GetObject(path, gdef.WBEM_FLAG_RETURN_WBEM_COMPLETE, None, result, None)
        return result

    def put_instance(self, instance):
        # TODO: change flag
        res = IWbemCallResult()
        self.service.PutInstance(instance, gdef.WBEM_FLAG_CREATE_ONLY, None, res)
        return res

    def exec_method(self, obj, method, inparam):
        result = IWbemCallResult()
        outparam = IWbemClassObject()
        if isinstance(obj, IWbemClassObject):
            obj = obj.get("__Path")
        self.ExecMethod(obj, method, 0, None, inparam, outparam, result)
        return outparam, result


    def __repr__(self):
        null = "" if self else " (NULL)"
        return """<{0} "{1}"{2}>""".format(type(self).__name__, self.namespace, null)

class WmiManager(dict):
    """The main WMI class exposed, used to list and access differents WMI namespace, can be used as a dict to access
    :class:`WmiRequester` by namespace

    Example:
        >>> windows.system.wmi["root\\SecurityCenter2"]
        <WmiRequester namespace="root\\SecurityCenter2">
    """
    DEFAULT_NAMESPACE = "root\\cimv2" #: The default namespace for :func:`select` & :func:`query`
    def __init__(self):
        # Someone is going to use wmi: let's init com !
        windows.com.init()
        self.wmi_requester_by_namespace = {}

    @property
    def default_namespace(self):
        return self[self.DEFAULT_NAMESPACE]

    @property
    def select(self):
        r""":func:`WmiRequester.select` for default WMI namespace 'root\\cimv2'"""
        return self.default_namespace.select

    @property
    def query(self):
        r""":func:`WmiRequester.query` for default WMI namespace 'root\\cimv2'"""
        return self.default_namespace.query

    def get_subnamespaces(self, root="root"):
        return [x["Name"] for x in self[root].select("__NameSpace", ["Name"])]

    namespaces = property(get_subnamespaces)
    """The list of available WMI namespaces"""

    def _open_wmi_requester(self, namespace):
        return WmiNamespace.connect(namespace)

    def __missing__(self, key):
        self[key] = self._open_wmi_requester(key)
        return self[key]

    def __repr__(self):
        return object.__repr__(self)