import _winreg
import windows
import itertools
import collections


class ExpectWindowsError(object):
    def __init__(self, errornumber):
        self.errornumber = errornumber

    def __enter__(self):
        pass

    def __exit__(self, etype, e, tb):
        return (etype == WindowsError and e.winerror == self.errornumber)


KeyValue = collections.namedtuple("KeyValue", ["name", "value", "type"])

class PyHKey(object):
    def __init__(self, surkey, name, sam=_winreg.KEY_READ):
        self.surkey = surkey
        self._phkey = None
        self.name = name
        self.fullname = self.surkey.fullname + "\\" + self.name if self.name else self.surkey.name
        self.sam = sam

    def __repr__(self):
        return '<PyHKey "{0}">'.format(self.fullname)

    @property
    def phkey(self):
        if self._phkey is not None:
            return self._phkey
        print("OPEN <{0}, {1}>".format(self.surkey.phkey, self.name))
        self._phkey = _winreg.OpenKeyEx(self.surkey.phkey, self.name, 0, self.sam)
        return self._phkey

    @property
    def subkeys(self):
        res = []
        with ExpectWindowsError(259):
            for i in itertools.count():
                res.append(_winreg.EnumKey(self.phkey, i))
        return [PyHKey(self, n) for n in  res]

    @property
    def values(self):
        res = []
        with ExpectWindowsError(259):
            for i in itertools.count():
                res.append(_winreg.EnumValue(self.phkey, i))
        return [KeyValue(*r) for r in res]

    def open_subkey(self, name):
        return PyHKey(self, name, self.sam)
        
    def reopen(self, new_sam):
        return PyHKey(self.surkey, self.name, new_sam)
        
    __getitem__ = open_subkey

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


HKEY_CURRENT_USER[r"Software\Microsoft\Windows\CurrentVersion\Run"].values
