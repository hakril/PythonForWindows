import _winreg
import itertools
import struct
from collections import namedtuple

import windows
from windows.generated_def.windef import KEY_READ, REG_QWORD



class ExpectWindowsError(object):
    def __init__(self, errornumber):
        self.errornumber = errornumber

    def __enter__(self):
        pass

    def __exit__(self, etype, e, tb):
        return (etype == WindowsError and e.winerror == self.errornumber)


KeyValue = namedtuple("KeyValue", ["name", "value", "type"])
"""A registry value (name, value, type)"""


class PyHKey(object):
    """A windows registry key"""
    def __init__(self, surkey, name, sam=KEY_READ):
        self.surkey = surkey
        self.name = name
        self.fullname = self.surkey.fullname + "\\" + self.name if self.name else self.surkey.name
        self.sam = sam
        self._phkey = None
        #self.phkey

    def __repr__(self):
        return '<PyHKey "{0}">'.format(self.fullname)

    @property
    def phkey(self):
        if self._phkey is not None:
            return self._phkey
        try:
            self._phkey = _winreg.OpenKeyEx(self.surkey.phkey, self.name, 0, self.sam)
        except WindowsError as e:
            raise WindowsError("Could not open registry key <{0}>".format(self.fullname))
        return self._phkey


    @property
    def subkeys(self):
        """The subkeys of the registry key

        :type: [:class:`PyHKey`] - A list of keys"""
        res = []
        with ExpectWindowsError(259):
            for i in itertools.count():
                res.append(_winreg.EnumKey(self.phkey, i))
        return [PyHKey(self, n) for n in  res]

    @property
    def values(self):
        """The values of the registry key

        :type: [:class:`KeyValue`] - A list of values"""
        res = []
        with ExpectWindowsError(259):
            for i in itertools.count():
                name_value_type = _winreg.EnumValue(self.phkey, i)
                # _winreg doest not support REG_QWORD
                # See http://bugs.python.org/issue23026
                if name_value_type[2] == REG_QWORD:
                    name = name_value_type[0]
                    value = struct.unpack("<Q", name_value_type[1])[0]
                    type = name_value_type[2]
                    name_value_type = name, value, type
                res.append(name_value_type)
        return [KeyValue(*r) for r in res]

    @property
    def info(self):
        return _winreg.QueryInfoKey(self.phkey)

    @property
    def last_write(self):
        return self.info[2]

    def get(self, value_name):
        """Retrieves the value ``value_name``

        :rtype: :class:`KeyValue`
        """
        value, type = _winreg.QueryValueEx(self.phkey, value_name)
        if type == REG_QWORD:
            value = struct.unpack("<Q", value)[0]
        return KeyValue(value_name, value, type)

    def _guess_value_type(self, value):
        if isinstance(value, basestring):
            return _winreg.REG_SZ
        elif isinstance(value, (int, long)):
            return _winreg.REG_DWORD
        raise ValueError("Cannot guest registry type of value to set <{0}>".format(value))


    def set(self, name, value, type=None):
        """Set the value for ``name`` to ``value``. if ``type`` is None try to guess items"""
        if type is None:
            type = self._guess_value_type(value)
        if type == REG_QWORD:
            value = struct.pack("<Q", value)
        return _winreg.SetValueEx(self.phkey, name, 0, type, value)


    def open_subkey(self, name, sam=None):
        """Open the subkey ``name``

        :rtype: :class:`PyHKey`
        """
        if sam is None:
            sam = self.sam
        return PyHKey(self, name, sam)

    def reopen(self, new_sam):
        return PyHKey(self.surkey, self.name, new_sam)


    def __setitem__(self, name, value):
        rtype = None
        if not isinstance(value, (int, long, basestring)):
            value, rtype = value
        return self.set(name, value, rtype)

    __getitem__ = get

    __call__ = open_subkey


class DummyPHKEY(object):
    def __init__(self, phkey, name):
        self.phkey = phkey
        self.name = name


HKEY_LOCAL_MACHINE = PyHKey(DummyPHKEY(_winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"), "", _winreg.KEY_READ)
HKEY_CLASSES_ROOT = PyHKey(DummyPHKEY(_winreg.HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"), "", _winreg.KEY_READ )
HKEY_CURRENT_USER = PyHKey(DummyPHKEY(_winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"), "", _winreg.KEY_READ)
HKEY_DYN_DATA = PyHKey(DummyPHKEY(_winreg.HKEY_DYN_DATA, "HKEY_DYN_DATA"), "", _winreg.KEY_READ)
HKEY_PERFORMANCE_DATA = PyHKey(DummyPHKEY(_winreg.HKEY_PERFORMANCE_DATA, "HKEY_PERFORMANCE_DATA"), "", _winreg.KEY_READ)
HKEY_USERS = PyHKey(DummyPHKEY(_winreg.HKEY_USERS, "HKEY_USERS"), "", _winreg.KEY_READ )


class Registry(object):
    """The ``Windows`` registry: a read only (for now) mapping"""

    registry_base_keys = {
        "HKEY_LOCAL_MACHINE" : HKEY_LOCAL_MACHINE,
        "HKEY_CLASSES_ROOT" : HKEY_CLASSES_ROOT,
        "HKEY_CURRENT_USER" : HKEY_CURRENT_USER,
        "HKEY_DYN_DATA" : HKEY_DYN_DATA,
        "HKEY_PERFORMANCE_DATA": HKEY_PERFORMANCE_DATA,
        "HKEY_USERS" : HKEY_USERS
    }

    def __call__(self, name, sam=KEY_READ):
        """Get a registry key::

            registry[r"HKEY_LOCAL_MACHINE\\Software"]
            registry["HKEY_LOCAL_MACHINE"]["Software"]

        :rtype: :class:`PyHKey`
        """

        if name in self.registry_base_keys:
            key = self.registry_base_keys[name]
            if sam != key.sam:
                key = key.reopen(sam)
            return key
        if "\\" not in name:
            raise ValueError("Unknow registry base key <{0}>".format(name))
        base_name, subkey = name.split("\\", 1)
        if base_name not in self.registry_base_keys:
            raise ValueError("Unknow registry base key <{0}>".format(base_name))
        return self.registry_base_keys[base_name](subkey,  sam)
