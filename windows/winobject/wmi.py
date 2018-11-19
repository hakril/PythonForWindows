import windows
import ctypes
import struct
import functools
from collections import namedtuple

from ctypes.wintypes import *

import windows.com
import windows.generated_def as gdef
from windows.generated_def.winstructs import *

# Common error check for all WMI COM interfaces
# This 'just' add the corresponding 'WBEMSTATUS' to the hresult error code
class WmiComInterface(object):
    def errcheck(self, result, func, args):
        if result < 0:
            wmitag = gdef.WBEMSTATUS.mapper[result & 0xffffffff]
            raise WindowsError(result, wmitag)
        return args

# https://docs.microsoft.com/en-us/windows/desktop/api/wbemcli/nn-wbemcli-iwbemclassobject

WmiMethod = namedtuple("WmiMethod", ["inparam", "outparam"])

# https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/calling-a-method
class WmiObject(gdef.IWbemClassObject, WmiComInterface):
    ## low level API

    def get_variant(self, name):
        if not isinstance(name, basestring):
            nametype = type(name).__name__
            raise TypeError("WmiObject attributes name must be str, not <{0}>".format(nametype))
        variant_res = windows.com.Variant()
        self.Get(name, 0, variant_res, None, None)
        return variant_res

    def get(self, name):
        return self.get_variant(name).value

    def get_method(self, name):
        inpararm = type(self)()
        outpararm = type(self)()
        variant_res = windows.com.Variant()
        self.GetMethod(name, 0, inpararm, outpararm)
        return WmiMethod(inpararm, outpararm)


    def put_variant(self, name, variant):
        if not isinstance(name, basestring):
            nametype = type(name).__name__
            raise TypeError("WmiObject attributes name must be str, not <{0}>".format(nametype))
        return self.Put(name, 0, variant, 0)

    def put(self, name, value):
        variant_value = windows.com.Variant(value)
        return self.put_variant(name, variant_value)

    def spawn_instance(self):
        instance = type(self)()
        self.SpawnInstance(0, instance)
        return instance

    @property
    def genus(self):
        return gdef.tag_WBEM_GENUS_TYPE.mapper[self.get("__GENUS")]

    ## Higher level API

    def get_properties(self):
        # res = POINTER(SAFEARRAY)()
        res = POINTER(windows.com.SafeArray)()
        x = ctypes.pointer(res)
        self.GetNames(None, 0, None, cast(x, POINTER(POINTER(gdef.SAFEARRAY))))
        # need to free the safearray / unlock ?
        return res[0].to_list(BSTR)

    properties = property(get_properties)

    # Make WmiObject a mapping object
    keys = get_properties
    __getitem__ = get
    __setitem__ = put

    def items(self):
        return [(k, self.get(k)) for k in self.properties]

    def values(self): # Not sur anyone will use this but keep the dict interface
        return [x[1] for x in self.items()]

    ## Make it callable like any class :D
    __call__ = spawn_instance

    def __repr__(self):
        if not self:
            return """<{0} (NULL)>""".format(type(self).__name__,)
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
        error = self.Next(timeout, 1, obj, return_count)
        if error == gdef.WBEM_S_TIMEDOUT:
            raise WindowsError(gdef.WBEM_S_TIMEDOUT, "Wmi timeout")
        elif error == WBEM_S_FALSE:
            return None
        else:
            return obj

    def __iter__(self):
        return self.iter_timeout(self.DEFAULT_TIMEOUT)

    def iter_timeout(self, timeout=None):
        while True:
            obj = self.next(timeout)
            if obj is None:
                return
            yield obj

    def all(self):
        return list(self) # SqlAlchemy like :)


class WmiCallResult(gdef.IWbemCallResult, WmiComInterface):
    def __init__(self, result_type=None, namespace_name=None):
        self.result_type = result_type
        self.namespace_name = namespace_name

    def get_call_status(self, timeout=gdef.WBEM_INFINITE):
        status = gdef.LONG()
        self.GetCallStatus(timeout, status)
        return WBEMSTATUS.mapper[status.value & 0xffffffff]

    def get_result_object(self, timeout=gdef.WBEM_INFINITE):
        result = WmiObject()
        self.GetResultObject(timeout, result)
        return result

    def get_result_string(self, timeout=gdef.WBEM_INFINITE):
        result = gdef.BSTR()
        self.GetResultString(timeout, result)
        return result

    def get_result_service(self, timeout=gdef.WBEM_INFINITE):
        result = WmiNamespace()
        self.GetResultServices(timeout, result)
        return result

    @property
    def result(self):
        if self.result_type is None:
            raise ValueError("Cannot call <result> with no result_type")
        return getattr(self, "get_result_" + self.result_type)()


class WmiLocator(gdef.IWbemLocator, WmiComInterface):
    pass # Just for the WMI errcheck callback


# !TEST CODE
class WmiNamespace(gdef.IWbemServices, WmiComInterface):
    r"""An object to perform wmi request to ``a given namespace``"""

    #CLSID_WbemAdministrativeLocator_IID = windows.com.IID.from_string('CB8555CC-9128-11D1-AD9B-00C04FD8FDFF')
    WbemLocator_CLSID = windows.com.IID.from_string('4590F811-1D3A-11D0-891F-00AA004B2E24')

    DEFAULT_ENUM_FLAGS = (gdef.WBEM_FLAG_RETURN_IMMEDIATELY |
        WBEM_FLAG_FORWARD_ONLY)

    def __init__(self, namespace, *args, **kwargs):
        self.name = namespace

    @classmethod
    def connect(cls, namespace, user=None, password=None):
        # this method assert com is initialised
        self = cls(namespace) # IWbemServices subclass
        locator = WmiLocator()
        windows.com.create_instance(cls.WbemLocator_CLSID, locator)
        locator.ConnectServer(namespace, user, password , None, gdef.WBEM_FLAG_CONNECT_USE_MAX_WAIT, None, None, self)
        locator.Release()
        return self

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

    # Create friendly name for create_class_enum & create_instance_enum ?

    def create_class_enum(self, superclass, flags=DEFAULT_ENUM_FLAGS, deep=True):
        flags |= gdef.WBEM_FLAG_DEEP if deep else gdef.WBEM_FLAG_SHALLOW

        enumerator = WmiEnumeration()
        self.CreateClassEnum(superclass, flags, None, enumerator)
        return enumerator

    # subclasses ?

    def create_instance_enum(self, filter, flags=DEFAULT_ENUM_FLAGS, deep=True):
        # ??? marche pas :(
        flags |= gdef.WBEM_FLAG_DEEP if deep else gdef.WBEM_FLAG_SHALLOW

        enumerator = WmiEnumeration()
        self.CreateInstanceEnum(filter, flags, None, enumerator)
        return enumerator

    select = create_instance_enum

    def get_object(self, path):
        result = WmiObject()
        self.GetObject(path, gdef.WBEM_FLAG_RETURN_WBEM_COMPLETE, None, result, None)
        return result

    def put_instance(self, instance):
        # TODO: change flag
        res = WmiCallResult(result_type="string")
        self.PutInstance(instance, gdef.WBEM_FLAG_CREATE_ONLY, None, res)
        return res

    def exec_method(self, obj, method, inparam, flags=0):
        if flags & gdef.WBEM_FLAG_RETURN_IMMEDIATELY:
            # semisynchronous call -> WmiCallResult
            result = WmiCallResult(result_type="object")
            outparam = None
        else:
            # Synchronous call -> WmiObject (outparam)
            result = None
            outparam = WmiObject()
        if isinstance(obj, gdef.IWbemClassObject):
            obj = obj.get("__Path")
        # Flags 0 -> synchronous call
        # No WmiCallResult result is directly in outparam
        self.ExecMethod(obj, method, 0, None, inparam, outparam, result)
        return outparam or result

    def __repr__(self):
        null = "" if self else " (NULL)"
        return """<{0} "{1}"{2}>""".format(type(self).__name__, self.name, null)

class WmiManager(dict):
    """The main WMI class exposed, used to list and access differents WMI namespace, can be used as a dict to access
    :class:`WmiNamespace` by name

    Example:
        >>> windows.system.wmi["root\\SecurityCenter2"]
        <WmiNamespace "root\SecurityCenter2">
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
        return [x["Name"] for x in self[root].select("__NameSpace")]

    namespaces = property(get_subnamespaces)
    """The list of available WMI namespaces"""

    def _open_wmi_requester(self, namespace):
        return WmiNamespace.connect(namespace)

    def __missing__(self, key):
        self[key] = self._open_wmi_requester(key)
        return self[key]

    def __repr__(self):
        return object.__repr__(self)