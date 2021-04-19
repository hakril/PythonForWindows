import sys
import ctypes
import itertools
import struct
from collections import namedtuple, defaultdict

import windows
from windows.dbgprint import dbgprint
import windows.generated_def as gdef
from windows import winproxy
from windows.pycompat import basestring, int_types, is_py3

WENCODING = "utf-16-le"

# So _winreg does not handle unicode stuff in Py2 :(
# Need to rewrite everything to get it working with unicode

class WinRegistryKey(gdef.HKEY):
    _close_function = staticmethod(winproxy.RegCloseKey)

    def __del__(self):
        if sys is None or sys.path is None: # Late shutdown (not sur winproxy is still up)
            return
        if self: # Not NULL handle ?
            dbgprint(u"Closing registry key handle {0:#x}".format(self.value), 'REGISTRY')
            self._close_function(self)




class ExpectWindowsError(object):
    def __init__(self, errornumber):
        self.errornumber = errornumber

    def __enter__(self):
        pass

    def __exit__(self, etype, e, tb):
        return (etype in (winproxy.WinproxyError, WindowsError) and e.winerror == self.errornumber)

# Translation reg-buffer <-> python methodes
def Reg2Py_QWORD(buffer, size):
    return buffer.cast(gdef.PULONG64)[0]

def Py2Reg_QWORD(obj):
    return struct.pack("<Q", obj)

def Reg2Py_DWORD(buffer, size):
    # Check size ?
    return buffer.cast(gdef.LPDWORD)[0]

def Py2Reg_DWORD(obj):
    return struct.pack("<I", obj)


def Reg2Py_DWORD_BIG_ENDIAN(buffer, size):
    # Check size ?
    return (buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3]

def Py2Reg_DWORD_BIG_ENDIAN(obj):
    return struct.pack(">I", obj)


def Reg2Py_BINARY(buffer, size):
    return bytes(bytearray(buffer[:size]))

def Py2Reg_BINARY(obj):
    # latin-1 encoding if py3 & type is str ?
    return obj


def Reg2Py_SZ(buffer, size):
    # Buffer is UTF16. buffer is extended-buffer
    if size == 0:
        return u""
    if buffer[size - 1] == 0 and buffer[size - 2] == 0:
        # NULL TERMINATED: EASY
        return buffer.as_wstring()
    # Not null terminated: keep last byte
    assert not size % 2
    return (gdef.WCHAR * (size // 2)).from_buffer(buffer)[:]

def Py2Reg_SZ(obj):
    return obj.encode(WENCODING)

def Reg2Py_Multi_SZ(buffer, size):
    if not size:
        return []
    # Simple path
    if is_py3:
        rawstr = bytes(buffer)
    else:
        rawstr = "".join([chr(c) for c in buffer[:size]])
    try:
        unistr = rawstr.decode(WENCODING)
        return unistr.rstrip(u"\x00").split(u"\x00")
    except UnicodeDecodeError as e:
        pass
    # Complexe-path
    # This is not some valide UTF-16
    # Try our best to extract some stuff from raw
    return rawstr.rstrip(b"\x00").split(b"\x00")


def Py2Reg_Multi_SZ(obj):
    # Work on encoded values (to prevent str/unicode errors)
    uni_list = [s.encode(WENCODING) for s in obj]
    # Separate by UTF-16 NULL BYTE (2 \x00)
    uni_str = b"\x00\x00".join(uni_list)
    # Add UTF-16 NULL byte for final string + final UTF-16 \x00 (4 \x00)
    return uni_str + b"\x00\x00\x00\x00"

DECODE_METHOD = 0
ENCODE_METHOD = 1


KNOWN_ENCODE_DECODE_METHODS = {
    gdef.REG_SZ: (Reg2Py_SZ, Py2Reg_SZ),
    gdef.REG_EXPAND_SZ: (Reg2Py_SZ, Py2Reg_SZ),
    gdef.REG_MULTI_SZ: (Reg2Py_Multi_SZ, Py2Reg_Multi_SZ),
    gdef.REG_DWORD: (Reg2Py_DWORD, Py2Reg_DWORD),
    gdef.REG_DWORD_BIG_ENDIAN: (Reg2Py_DWORD_BIG_ENDIAN, Py2Reg_DWORD_BIG_ENDIAN),
    gdef.REG_QWORD: (Reg2Py_QWORD, Py2Reg_QWORD),
    # Binary formats
    gdef.REG_LINK: (Reg2Py_BINARY, Py2Reg_BINARY), # TESTING
    gdef.REG_BINARY: (Reg2Py_BINARY, Py2Reg_BINARY),
    gdef.REG_NONE: (Reg2Py_BINARY, Py2Reg_BINARY),
}

# All unknown format are seens as binary data
UNKNOWM_FORMAT = (Reg2Py_BINARY, Py2Reg_BINARY)
ENCODE_DECODE_METHODS = defaultdict(lambda: UNKNOWM_FORMAT, KNOWN_ENCODE_DECODE_METHODS)

def decode_registry_buffer(type, buffer, size):
    try:
        return ENCODE_DECODE_METHODS[type][DECODE_METHOD](buffer, size)
    except UnicodeDecodeError as e:
        # Best effort if any decoding error happen
        return "".join(chr(c) for c in buffer[:size])


KeyValue = namedtuple("KeyValue", ["name", "value", "type"])
"""A registry value (name, value, type)"""


class PyHKey(object):
    """A windows registry key"""
    def __init__(self, surkey, name, sam=gdef.KEY_READ):
        self.surkey = surkey
        self.name = name
        self.fullname = self.surkey.fullname + "\\" + self.name if self.name else self.surkey.name
        self.sam = sam
        self._phkey = None
        #self.phkey

    def __repr__(self):
        return '<PyHKey "{0}">'.format(self.fullname)

    def _open_key(self, handle, name, sam):
        result = WinRegistryKey()
        winproxy.RegOpenKeyExW(handle, name, 0, sam, result) # TODO: options REG_OPTION_OPEN_LINK
        dbgprint(u"Opening registry key <{0}> (handle={1:#x})".format(name, result.value), "REGISTRY")
        return result

    def _create_key(self, parent, name, sam):
        result = WinRegistryKey()
        flags = 0
        winproxy.RegCreateKeyExW(parent, name, 0, None, flags, sam, None, result, None)
        dbgprint(u"Creating registry key <{0}> (handle={1:#x})".format(name, result.value), "REGISTRY")
        return result

    @property
    def phkey(self):
        if self._phkey is not None:
            return self._phkey
        try:
            self._phkey = self._open_key(self.surkey.phkey, self.name, self.sam)
        except WindowsError as e:
            raise WindowsError(e.winerror, "Could not open registry key <{0}> ({1})".format(self.fullname, e.strerror))
        return self._phkey

    @property
    def exists(self):
        # May have been deleted in between
        # So <self._phkey> tells use nothing
        if self._phkey: # Not None + pointer not NULL
            try:
                self.get_key_size_info()
            except WindowsError as e:
                if e.winerror == gdef.ERROR_KEY_DELETED:
                    return False
                raise
            return True
        try:
            tmpphkey = self._open_key(self.surkey.phkey, self.name, gdef.KEY_READ)
        except WindowsError as e:
            return False
        # tmpphkey will be garbage collected and auto-closed
        return True

    @property
    def subkeys(self):
        """The subkeys of the registry key

        :type: [:class:`PyHKey`] - A list of keys"""
        res = []
        with ExpectWindowsError(259):
            default_name_size = 256 + 1
            name_size = gdef.DWORD(default_name_size)
            name_buffer = ctypes.create_unicode_buffer(name_size.value)
            for i in itertools.count():
                name_size.value = default_name_size
                winproxy.RegEnumKeyExW(self.phkey, i, name_buffer, name_size, None, None, None, None)
                res.append(name_buffer[:name_size.value]) # Will allow key name with \x00 inside
        return [PyHKey(self, n) for n in  res]

    def get_key_size_info(self):
        max_name_len = gdef.DWORD()
        max_value_len = gdef.DWORD()
        winproxy.RegQueryInfoKeyW(self.phkey, None, None, None, None, None, None, None, max_name_len, max_value_len, None, None)
        return (max_name_len.value, max_value_len.value)

    @property
    def values(self):
        """The values of the registry key

        :type: [:class:`KeyValue`] - A list of values"""
        res = []
        # Get max info keys

        max_name_size, max_data_size = self.get_key_size_info()
        # Null terminators
        max_name_size += 1
        max_data_size += 2
        with ExpectWindowsError(259):
            for i in itertools.count():
                value_type = gdef.DWORD()
                namesize = gdef.DWORD(max_name_size)
                keyname = ctypes.create_unicode_buffer(namesize.value)
                datasize = gdef.DWORD(max_data_size)
                databuffer = windows.utils.BUFFER(gdef.BYTE, nbelt=datasize.value)()
                # A value can have been added in-between.
                # So recheck the size given by get_key_size_info :)
                # But check 10 times max as RegEnumValueW may bug (seen) and always return  ERROR_MORE_DATA even with enought size
                for _ in range(10):
                    try:
                        winproxy.RegEnumValueW(self.phkey, i, keyname, namesize, None, value_type, databuffer, datasize)
                        break
                    except WindowsError as e:
                        if e.winerror != gdef.ERROR_MORE_DATA:
                            raise
                        # I found some strange Windows where even with a big enought buffer:
                        # - the data was filled
                        # - ERROR_MORE_DATA was returned
                        ## To prevent such bug to trigger and infinite loop, two things
                        # - If the retuned namesize <= the passed keysize and keyname is not empty -> return the data`
                        # - Max 10 test to prevent Infinite loop
                        if ((namesize.value <= max_name_size)  and (datasize.value <= max_data_size) and
                            (keyname[:namesize.value].count("\x00") < namesize.value)): # Not just 0 Zero ?
                            break

                        # Update the sizes / buffers & try again :)
                        max_name_size, max_data_size = self.get_key_size_info()
                        max_name_size = max(max_name_size + 1, namesize.value + 1) # namesize.value may be > to max_name_size apparently (guessed)
                        max_data_size = max(max_data_size + 2, datasize.value + 2) # datasize.value may be > to max_data_size apparently (seen)
                        namesize = gdef.DWORD(max_name_size)
                        keyname = ctypes.create_unicode_buffer(namesize.value)
                        datasize = gdef.DWORD(max_data_size)
                        databuffer = windows.utils.BUFFER(gdef.BYTE, nbelt=datasize.value)()
                else:
                    # Probably a windows bug that prevent us from retrieving the data
                    # Raise something (thus preventing getting the other values..) ? ignore it ?
                    raise ValueError("Could not extract registry key values, problably a Windows/hook bug")
                vobj = decode_registry_buffer(value_type.value, databuffer, datasize.value)
                res.append(KeyValue(keyname.value, vobj, value_type.value))
        return res


    @property
    def info(self):
        # Need other stuff ?
        nb_key = gdef.DWORD()
        nb_values = gdef.DWORD()
        last_modif = gdef.FILETIME()
        winproxy.RegQueryInfoKeyW(self.phkey, None, None, None, nb_key, None, None, nb_values, None, None, None, last_modif)
        return nb_key.value, nb_values.value, int(last_modif)

    @property
    def last_write(self):
        return self.info[2]

    def get(self, value_name):
        """Retrieves the value ``value_name``

        :rtype: :class:`KeyValue`
        """

        type = gdef.DWORD(0)
        size = gdef.DWORD(0x100)
        while True:
            buffer = windows.utils.BUFFER(gdef.BYTE, nbelt=size.value)()
            try:
                winproxy.RegQueryValueExW(self.phkey, value_name, None, type, buffer, size)
                break
            except WindowsError as e:
                if e.winerror != gdef.ERROR_MORE_DATA:
                    raise
                size.value *= 2
                buffer = windows.utils.BUFFER(gdef.BYTE, nbelt=size.value)()
                continue
        vobj = decode_registry_buffer(type.value, buffer, size.value)
        return KeyValue(value_name, vobj, type.value)

    def _guess_value_type(self, value):
        if isinstance(value, basestring):
            return gdef.REG_SZ
        elif isinstance(value, int_types):
            return gdef.REG_DWORD
        # elif isinstance(value, (list, tuple)):
            # if all(isinstance(v, basestring) in value):
                # return _winreg.REG_MULTI_SZ
        raise ValueError("Cannot guest registry type of value to set <{0}>".format(value))


    def set(self, name, value, type=None):
        """Set the value for ``name`` to ``value``. if ``type`` is None try to guess items"""
        if type is None:
            type = self._guess_value_type(value)


        buffer = ENCODE_DECODE_METHODS[type][ENCODE_METHOD](value)
        if isinstance(buffer, bytes): # Should not be unicode at this point
            buffer = windows.utils.BUFFER(gdef.BYTE).from_buffer_copy(buffer)
        return winproxy.RegSetValueExW(self.phkey, name, 0, type, buffer, len(buffer))

    def delete_value(self, name):
        """Delete the value with ``name``"""
        return winproxy.RegDeleteValueW(self.phkey, name)


    def open_subkey(self, name, sam=None):
        """Open the subkey ``name``

        :rtype: :class:`PyHKey`
        """
        if sam is None:
            sam = self.sam
        return PyHKey(self, name, sam)

    def reopen(self, sam):
        """Reopen the registry key with a new ``sam``

        :rtype: :class:`PyHKey`
        """
        return PyHKey(self.surkey, self.name, sam)

    def create(self):
        """Create the registry key"""
        try:
            self._phkey = self._create_key(self.surkey.phkey, self.name, self.sam)
        except WindowsError as e:
            raise WindowsError(e.winerror, "Could not create registry key <{0}> ({1})".format(self.fullname, e.strerror))
        return self

    def delete(self):
        """Delete the registry key"""
        # Allow a 'recursive' param to empty before delete ?
        try:
            windows.winproxy.RegDeleteKeyExW(self.surkey.phkey, self.name, self.sam, 0)
        except WindowsError as e:
            raise WindowsError(e.winerror, "Could not delete registry key <{0}> ({1})".format(self.fullname, e.strerror))
        return None

    def empty(self):
        windows.winproxy.RegDeleteTreeW(self.phkey, None)



    def __setitem__(self, name, value):
        rtype = None
        if not (isinstance(value, basestring) or isinstance(value, int_types)):
            value, rtype = value
        return self.set(name, value, rtype)

    __getitem__ = get

    __delitem__ = delete_value

    __call__ = open_subkey


class DummyPHKEY(object):
    def __init__(self, phkey, name):
        self.phkey = phkey
        self.name = name


HKEY_LOCAL_MACHINE = PyHKey(DummyPHKEY(gdef.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"), "", gdef.KEY_READ)
HKEY_CLASSES_ROOT = PyHKey(DummyPHKEY(gdef.HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"), "", gdef.KEY_READ )
HKEY_CURRENT_USER = PyHKey(DummyPHKEY(gdef.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"), "", gdef.KEY_READ)
HKEY_DYN_DATA = PyHKey(DummyPHKEY(gdef.HKEY_DYN_DATA, "HKEY_DYN_DATA"), "", gdef.KEY_READ)
HKEY_PERFORMANCE_DATA = PyHKey(DummyPHKEY(gdef.HKEY_PERFORMANCE_DATA, "HKEY_PERFORMANCE_DATA"), "", gdef.KEY_READ)
HKEY_USERS = PyHKey(DummyPHKEY(gdef.HKEY_USERS, "HKEY_USERS"), "", gdef.KEY_READ )


class Registry(object):
    """The ``Windows`` registry"""

    registry_base_keys = {
        "HKEY_LOCAL_MACHINE" : HKEY_LOCAL_MACHINE,
        "HKEY_CLASSES_ROOT" : HKEY_CLASSES_ROOT,
        "HKEY_CURRENT_USER" : HKEY_CURRENT_USER,
        "HKEY_DYN_DATA" : HKEY_DYN_DATA,
        "HKEY_PERFORMANCE_DATA": HKEY_PERFORMANCE_DATA,
        "HKEY_USERS" : HKEY_USERS
    }

    def __init__(self, sam=gdef.KEY_READ):
        self.sam = sam

    @classmethod
    def reopen(cls, sam):
        """Return a new :class:`Registry` using ``sam`` as the new default

        :rtype: :class:`Registry`
        """
        return cls(sam)

    def __call__(self, name, sam=None):
        """Get a registry key::

            registry(r"HKEY_LOCAL_MACHINE\\Software")
            registry("HKEY_LOCAL_MACHINE")("Software")

        :rtype: :class:`PyHKey`
        """
        if sam is None:
            sam = self.sam

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
