import windows
import ctypes
import struct
import functools
from functools import partial
from collections import namedtuple

from ctypes.wintypes import *

import windows.com
import windows.generated_def as gdef
from windows.generated_def.winstructs import *

from windows.pycompat import basestring

# Common error check for all WMI COM interfaces
# This 'just' add the corresponding 'WBEMSTATUS' to the hresult error code
class WmiComInterface(object):
    """Base class used for COM call error checking for WMI interfaces"""
    def errcheck(self, result, func, args):
        if result < 0:
            wmitag = gdef.WBEMSTATUS.mapper[result & 0xffffffff]
            raise ctypes.WinError(result, wmitag)
        return args

sentinel = object()
# POC
class QualifierSet(gdef.IWbemQualifierSet):
    def get_variant(self, name):
        """Retrieve the value of property ``name`` as a :class:`~windows.com.Variant`

        :return: :class:`~windows.com.Variant`
        """
        if not isinstance(name, basestring):
            nametype = type(name).__name__
            raise TypeError("WmiObject attributes name must be str, not <{0}>".format(nametype))
        variant_res = windows.com.Variant()
        self.Get(name, 0, variant_res, None)
        return variant_res

    def get(self, name, default=sentinel):
        """Return the value of the property ``name``. The return value depends of the type of the property and can vary"""
        try:
            return self.get_variant(name).value
        except WindowsError as e:
            if (e.winerror & 0xffffffff) != gdef.WBEM_E_NOT_FOUND:
                raise
            if default is sentinel:
                raise
            return default

    def names(self):
        res = POINTER(windows.com.SafeArray)()
        x = ctypes.pointer(res)
        self.GetNames(0, cast(x, POINTER(POINTER(gdef.SAFEARRAY))))
        # need to free the safearray / unlock ?
        properties = [p for p in res[0].to_list(BSTR)]
        return properties


# https://docs.microsoft.com/en-us/windows/desktop/api/wbemcli/nn-wbemcli-iwbemclassobject

WmiMethod = namedtuple("WmiMethod", ["inparam", "outparam"])

# https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/calling-a-method
class WmiObject(gdef.IWbemClassObject, WmiComInterface):
    """The WmiObject (which wrap ``IWbemClassObject``) contains and manipulates both class definitions and class object instances.
    Can be used as a mapping to access properties.
    """

    def get_variant(self, name):
        """Retrieve the value of property ``name`` as a :class:`~windows.com.Variant`

        :return: :class:`~windows.com.Variant`
        """
        if not isinstance(name, basestring):
            nametype = type(name).__name__
            raise TypeError("WmiObject attributes name must be str, not <{0}>".format(nametype))
        variant_res = windows.com.Variant()
        self.Get(name, 0, variant_res, None, None)
        return variant_res

    def get(self, name):
        """Return the value of the property ``name``. The return value depends of the type of the property and can vary"""
        return self.get_variant(name).value

    def get_method(self, name):
        """Return the information about the method ``name``

        :returns: :class:`WmiMethod`
        """
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
        """Set the property ``name`` to ``value``"""
        variant_value = windows.com.Variant(value)
        return self.put_variant(name, variant_value)

    def spawn_instance(self):
        """Create a new object of the class represented by the current :class:`WmiObject`

        :returns: :class:`WmiObject`
        """
        instance = type(self)()
        self.SpawnInstance(0, instance)
        return instance

    @property
    def genus(self):
        """The genus of the object.

        :returns: ``WBEM_GENUS_CLASS(0x1L)`` if the :class:`WmiObject` is a Class and ``WBEM_GENUS_INSTANCE(0x2L)`` for instances and events.
        """
        return gdef.tag_WBEM_GENUS_TYPE.mapper[self.get("__GENUS")]

    ## Higher level API
    def get_properties(self, system_properties=False):
        """Return the list of properties names available for the current object.
        If ``system_properties`` is ``False`` property names begining with ``_`` are ignored.

        :returns: [:class:`str`] -- A list of string

        .. note:

            About system properties: https://docs.microsoft.com/en-us/windows/desktop/wmisdk/wmi-system-properties
        """
        res = POINTER(windows.com.SafeArray)()
        x = ctypes.pointer(res)
        self.GetNames(None, 0, None, cast(x, POINTER(POINTER(gdef.SAFEARRAY))))
        # need to free the safearray / unlock ?
        properties = [p for p in res[0].to_list(BSTR) if system_properties or (not p.startswith("_"))]
        return properties

    properties = property(get_properties) #: The properties of the object (exclude system properties)

    @property
    def qualifier_set(self): # changer de nom ?
        res = QualifierSet()
        self.GetQualifierSet(res)
        return res

    def get_p_set(self, name): # Changer de nom ?
        res = QualifierSet()
        self.GetPropertyQualifierSet(name, res)
        return res

    # Make WmiObject a mapping object

    def keys(self):
        """The properties of the object (include system properties)"""
        return self.get_properties(system_properties=True)

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

    def __sprint__(self):
        return """ {0}\n
        {1}
        """.format(repr(self), "\n".join(": ".join([x[0], str(x[1])]) for x in sorted(self.items())))


class WmiEnumeration(gdef.IEnumWbemClassObject, WmiComInterface):
    """Represent an enumeration of object that can be itered"""
    DEFAULT_TIMEOUT = gdef.WBEM_INFINITE #: The default timeout

    def next(self, timeout=None):
        """Return the next object in the enumeration with `timeout`.

        :raises: ``WindowsError(WBEM_S_TIMEDOUT)`` if timeout expire
        :returns: :class:`WmiObject`
        """
        timeout = self.DEFAULT_TIMEOUT if timeout is None else timeout
        # For now the count is hardcoded to 1
        obj = WmiObject()
        return_count = gdef.ULONG(0)
        error = self.Next(timeout, 1, obj, return_count)
        if error == gdef.WBEM_S_TIMEDOUT:
            raise ctypes.WinError(gdef.WBEM_S_TIMEDOUT, "Wmi timeout")
        elif error == WBEM_S_FALSE:
            return None
        else:
            return obj

    def __iter__(self):
        """Return an iterator with ``DEFAULT_TIMEOUT``"""
        return self.iter_timeout(self.DEFAULT_TIMEOUT)

    def iter_timeout(self, timeout=None):
        """Return an iterator with a custom ``timeout``"""
        while True:
            obj = self.next(timeout)
            if obj is None:
                return
            yield obj

    def all(self):
        """Return all elements in the enumeration as a list

        :returns: [:class:`WmiObject`] - A list of :class:`WmiObject`
        """
        return list(self) # SqlAlchemy like :)


class WmiCallResult(gdef.IWbemCallResult, WmiComInterface):
    """The result of a WMI call/query. Real result value type depends of the context"""
    def __init__(self, result_type=None, namespace_name=None):
        self.result_type = result_type
        self.namespace_name = namespace_name

    def get_call_status(self, timeout=gdef.WBEM_INFINITE):
        """The status of the call"""
        status = gdef.LONG()
        self.GetCallStatus(timeout, status)
        return WBEMSTATUS.mapper[status.value & 0xffffffff]

    def get_result_object(self, timeout=gdef.WBEM_INFINITE):
        """The result as a :class:`WmiObject` (returned by :func:`WmiNamespace.exec_method`)"""
        result = WmiObject()
        self.GetResultObject(timeout, result)
        return result

    def get_result_string(self, timeout=gdef.WBEM_INFINITE):
        """The result as a :class:`WmiObject` (returned by :func:`WmiNamespace.put_instance`)"""
        result = gdef.BSTR()
        self.GetResultString(timeout, result)
        return result

    def get_result_service(self, timeout=gdef.WBEM_INFINITE):
        """The result as a :class:`WmiNamespace` (not used yet)"""
        result = WmiNamespace()
        self.GetResultServices(timeout, result)
        return result

    @property
    def result(self):
        """The result of the correct type based on ``self.result_type``"""
        if self.result_type is None:
            raise ValueError("Cannot call <result> with no result_type")
        return getattr(self, "get_result_" + self.result_type)()


class WmiLocator(gdef.IWbemLocator, WmiComInterface):
    pass # Just for the WMI errcheck callback


# !TEST CODE
class WmiNamespace(gdef.IWbemServices, WmiComInterface):
    r"""An object to perform wmi request to a given ``namespace``"""

    #CLSID_WbemAdministrativeLocator_IID = windows.com.IID.from_string('CB8555CC-9128-11D1-AD9B-00C04FD8FDFF')
    WbemLocator_CLSID = windows.com.IID.from_string('4590F811-1D3A-11D0-891F-00AA004B2E24')

    DEFAULT_ENUM_FLAGS = (gdef.WBEM_FLAG_RETURN_IMMEDIATELY |
        WBEM_FLAG_FORWARD_ONLY) #: The defauls flags used for enumeration. ``(WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY)``

    def __init__(self, namespace):
        self.name = namespace

    @classmethod
    def connect(cls, namespace, user=None, password=None):
        """Connect to ``namespace`` using ``user`` and ``password`` for authentification if given

        :return: :class:`WmiNamespace` - The connected :class:`WmiNamespace`"""
        # this method assert com is initialised
        self = cls(namespace) # IWbemServices subclass
        locator = WmiLocator()
        windows.com.create_instance(cls.WbemLocator_CLSID, locator)
        locator.ConnectServer(namespace, user, password , None, gdef.WBEM_FLAG_CONNECT_USE_MAX_WAIT, None, None, self)
        locator.Release()
        return self

    def query(self, query):
        """Return the list of :class:`WmiObject` matching ``query``.

        This API is the `simple one`, if you need timeout or complexe feature see :func:`exec_query`

        :return: [:class:`WmiObject`] - A list of :class:`WmiObject`
        """
        return list(self.exec_query(query))

    def select(self, clsname, deep=True):
        """Return the list of :class:`WmiObject` that are instance of ``clsname``. Deep has the same meaning as in :func:`create_instance_enum`.

        This API is the `simple one`, if you need timeout or complexe feature see :func:`create_instance_enum`

        :return: [:class:`WmiObject`] - A list of :class:`WmiObject`
        """
        return list(self.create_instance_enum(clsname, deep=deep))


    def exec_query(self, query, flags=DEFAULT_ENUM_FLAGS, ctx=None):
        """Execute a WQL query with custom flags and returns a ::class:`WmiEnumeration` that can be used to
        iter the result with timeouts

        :returns: :class:`WmiEnumeration`
        """
        enumerator = WmiEnumeration()
        self.ExecQuery("WQL", query, flags, ctx, enumerator)
        return enumerator

    # Create friendly name for create_class_enum & create_instance_enum ?

    def create_class_enum(self, superclass, flags=DEFAULT_ENUM_FLAGS, deep=True):
        """Enumerate the classes in the ``namespace`` that match ``superclass``.
        if ``superclass`` is None will enumerate all top-level class. ``deep`` allow to returns all subclasses

        :returns: :class:`WmiEnumeration`

        .. note::

            See https://docs.microsoft.com/en-us/windows/desktop/api/wbemcli/nf-wbemcli-iwbemservices-createclassenum
        """

        flags |= gdef.WBEM_FLAG_DEEP if deep else gdef.WBEM_FLAG_SHALLOW
        enumerator = WmiEnumeration()
        self.CreateClassEnum(superclass, flags, None, enumerator)
        return enumerator

    @property
    def classes(self):
        """The list of classes in the namespace. This a a wrapper arround :func:`create_class_enum`.

        :return: [:class:`WmiObject`] - A list of :class:`WmiObject`
        """
        return self.create_class_enum(None, deep=True)

    def create_instance_enum(self, clsname, flags=DEFAULT_ENUM_FLAGS, deep=True):
        """Enumerate the instances of ``clsname``. Deep allows to enumerate the instance of subclasses as well

        :returns: :class:`WmiEnumeration`

        Example:
            >>> windows.system.wmi["root\\subscription"].create_instance_enum("__EventConsumer", deep=False).all()
            []
            >>> windows.system.wmi["root\\subscription"].create_instance_enum("__EventConsumer", deep=True).all()
            [<WmiObject instance of "NTEventLogEventConsumer">]

        .. note::

            See https://docs.microsoft.com/en-us/windows/desktop/api/wbemcli/nf-wbemcli-iwbemservices-createinstanceenum
        """
        flags |= gdef.WBEM_FLAG_DEEP if deep else gdef.WBEM_FLAG_SHALLOW
        enumerator = WmiEnumeration()
        self.CreateInstanceEnum(clsname, flags, None, enumerator)
        return enumerator

    def get_object(self, path):
        """Return the object matching ``path``. If ``path`` is a class name return the class object``

        :return: :class:`WmiObject`
        """
        result = WmiObject()
        self.GetObject(path, gdef.WBEM_FLAG_RETURN_WBEM_COMPLETE, None, result, None)
        return result

    def put_instance(self, instance, flags=gdef.WBEM_FLAG_CREATE_ONLY):
        """Creates or updates an instance of an existing class in the namespace

        :return: :class:`WmiCallResult` ``(string)`` - Used to retrieve the string representing the path of the object created/updated
        """
        res = WmiCallResult(result_type="string")
        self.PutInstance(instance, flags, None, res)
        return res

    def delete_instance(self, instance, flags=0):
        """TODO: Document"""
        if isinstance(instance, gdef.IWbemClassObject):
            instance = instance["__Path"]
        return self.DeleteInstance(instance, flags, None, None)

    def exec_method(self, obj, method, inparam, flags=0):
        """Exec method named on ``object`` with ``inparam``.

           :params obj: The :class:`WmiObject` or path of the object the call apply to
           :params method: The name of the method to call on the object
           :params inparam: The :class:`WmiObject` representing the input parameters and retrieve using :func:`WmiObject.get_method`

        :returns: :class:`WmiCallResult` ``(object)`` if flag `WBEM_FLAG_RETURN_IMMEDIATELY` was passed
        :returns: :class:`WmiObject` the outparam object if flag `WBEM_FLAG_RETURN_IMMEDIATELY` was NOT passed

        .. note::

            This API will lakely change to better wrap with WmiObject/inparam/Dict & co
        """
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