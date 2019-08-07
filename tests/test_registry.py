import datetime

import pytest
from pfwtest import *

import windows


testbasekeypath = r"HKEY_CURRENT_USER\SOFTWARE\PythonForWindows\Test"
basekeytest = windows.system.registry(testbasekeypath, gdef.KEY_WOW64_64KEY | gdef.KEY_READ | gdef.KEY_WRITE)

if not basekeytest.exists:
    basekeytest.create()

@pytest.fixture()
def empty_test_base_key():
    assert basekeytest.exists
    for subkey in basekeytest.subkeys:
            subkey.delete()
    # Use of lowlevel_value_enum allow deleting value with NULL bytes
    for value in basekeytest.values:
        del basekeytest[value.name]
    assert not basekeytest.subkeys
    assert not basekeytest.values

# Clean registry before everytest
pytestmark = pytest.mark.usefixtures("empty_test_base_key")


@pytest.mark.parametrize("value", [1, "LOL", 0x11223344, ""])
def test_registry_set_get_simple_values(value):
    basekeytest["tst1"] = value
    assert basekeytest["tst1"].value == value

# TODO: test with other registry type (the stranges ones)
@pytest.mark.parametrize("value, type", [
    (0x11223344, gdef.REG_DWORD),
    (0x1122334455667788, gdef.REG_QWORD),
    ("", gdef.REG_SZ),
    (["AAAA", "BBBB", "CCCC"], gdef.REG_MULTI_SZ),
    ("123\x00123" + "".join(chr(c) for c in range(256)), gdef.REG_BINARY),
])
def test_registry_set_get_simple_values_with_types(value, type):
    basekeytest["tst2"] = (value, type)
    assert basekeytest["tst2"].value == value

UNICODE_PATH_NAME = u'\u4e2d\u56fd\u94f6\u884c\u7f51\u94f6\u52a9\u624b'
UNICODE_RU_STRING = u"\u0441\u0443\u043a\u0430\u0020\u0431\u043b\u044f\u0442\u044c" # CYKA BLYAT in Cyrillic

# Could be done in test_registry_set_get_simple_values
# But was the cause a special bug / reimplem due to _winreg using ANSI functions
# So create a special test with a very identifiable name / bug cause

@pytest.mark.parametrize("unistr", ['\u52a9' * 126, UNICODE_PATH_NAME, UNICODE_RU_STRING, u""])
def test_registry_unicode_string_value(unistr):
    basekeytest["tst3"] = unistr
    assert basekeytest["tst3"].value == unistr

@pytest.mark.parametrize("unistr", [
    # Looks like this value with this size MAY lead to non-existing NULL BYTE ?
    # This bug is tested in test_registry_Reg2Py_SZ
    u'c:\\users\\hakril\\appdata\\local\\temp\\test_unicode_\u4e2d\u56fd\u94f6\u884c\u7f51\u94f6\u52a9\u624bdbqsm3',
    u'\u52a9' * 126,
    UNICODE_PATH_NAME,
    UNICODE_PATH_NAME * 10,
    UNICODE_RU_STRING * 10,
    UNICODE_RU_STRING
])
def test_registry_unicode_string_values_enumeration(unistr):
    basekeytest["tst5"] = unistr
    values_by_name = {x.name: x for x in basekeytest.values}
    assert values_by_name["tst5"].value == unistr


def test_registry_unicode_multi_string():
    TST_MULTI = [UNICODE_PATH_NAME, "Hello World", UNICODE_RU_STRING]
    basekeytest["tst4"] = (TST_MULTI, gdef.REG_MULTI_SZ)
    assert basekeytest["tst4"].value == TST_MULTI


@pytest.mark.parametrize("unistr", [UNICODE_PATH_NAME, UNICODE_RU_STRING])
def test_registry_unicode_value_name(unistr):
    basekeytest[unistr] = 42
    assert basekeytest[unistr].value == 42
    # assert unistr in [v.name for v in basekeytest.values]
    del basekeytest[unistr]

def test_registry_subkeys_create_delete():
    subname = "MyTestSubKey"
    subkey = basekeytest(subname)
    assert not subkey.exists
    subkey.create()
    assert subkey.exists
    subkey.delete()
    assert not subkey.exists

def test_registry_get_key_info():
    subname = "MyTestSubKeySizeInfo"
    subkey = basekeytest(subname).create()
    subkey["A"] = "12345"
    subkey["AAAA"] = "1"
    max_name_size, max_value_size = subkey.get_key_size_info()
    assert max_name_size == 4 # AAAA
    assert max_value_size == 6 * 2 # 12345\x00 -> 2 BYTE per char (utf-16)
    other_info = subkey.info
    assert other_info[0] == 0 # Nb subkeys
    assert other_info[1] == 2 # Nb values
    assert isinstance(other_info[2], (int, long)) # Last write


def test_registry_unicode_value_name_enumerate():
    name1 = u"enum_" + UNICODE_PATH_NAME
    name2 = u"enum_" + UNICODE_RU_STRING
    basekeytest[name1] = 1
    basekeytest[name2] = 2
    values_names = [v.name for v in basekeytest.values]
    assert name1 in values_names
    assert name2 in values_names


class CustomCountForRegistryTest(object):
    TESTKEY = None

    def __init__(self):
        self.value = 0


    def __iter__(self):
        while True:
            print("NEXT")
            if self.value == 1:
                print("ADDING HARDCODE KEY !")
                self.TESTKEY[BIG_KEY_NAME] = BIG_KEY_VALUE
            yield self.value
            self.value += 1

BIG_KEY_NAME = "BIG" * 50
BIG_KEY_VALUE = "BIG" * 0x2000

def test_registry_unicode_value_name_enumerate_with_race_condition(monkeypatch):
    import itertools
    # With itertools.count() to add a big key in the middle of the enumeration
    # With a bigger name & data that the key currently existing

    # Create a new subkey so that the KeyInfos are "reset"
    subkeyname = str(datetime.datetime.now())
    assert not basekeytest(subkeyname).exists
    subkey = basekeytest(subkeyname).create()
    try:
        CustomCountForRegistryTest.TESTKEY = subkey
        monkeypatch.setattr(itertools, "count", CustomCountForRegistryTest)
        name1 = u"enum_" + UNICODE_PATH_NAME
        name2 = u"enum_" + UNICODE_RU_STRING
        subkey[name1] = 1
        subkey[name2] = 2
        values_names = [v.name for v in subkey.values]
        assert name1 in values_names
        assert name2 in values_names
        assert BIG_KEY_NAME in values_names
    finally:
        subkey.delete()

def test_registry_unicode_subkeys_create_delete():
    subname =  UNICODE_RU_STRING + unicode(datetime.datetime.now())
    subkey = basekeytest(subname)
    assert not subkey.exists
    subkey.create()
    assert subkey.exists
    subkey.delete()
    assert not subkey.exists


def test_registry_unicode_subkeys_enumerate():
    name1 = u"subkey" + UNICODE_PATH_NAME
    name2 = u"subkey" + UNICODE_RU_STRING
    basekeytest(name1).create()
    basekeytest(name2).create()
    subkey_names = [sk.name for sk in basekeytest.subkeys]
    assert name1 in subkey_names
    assert name2 in subkey_names


# Test Py<->REG conversion bug

# [99, 0, 58, 0, 92, 0, 117, 0, 115, 0, 101, 0, 114, 0, 115, 0, 92, 0, 104, 0, 97, 0, 107, 0, 114, 0, 105, 0, 108, 0, 92, 0, 97, 0, 112, 0, 112, 0, 100, 0, 97, 0, 116, 0, 97, 0, 92, 0, 108, 0, 111, 0, 99, 0, 97, 0, 108, 0, 92, 0, 116, 0, 101, 0, 109, 0, 112, 0, 92, 0, 116, 0, 101, 0, 115, 0, 116, 0, 95, 0, 117, 0, 110, 0, 105, 0, 99, 0, 111, 0, 100, 0, 101, 0, 95, 0, 45, 78, 253, 86, 246, 148, 76, 136, 81, 127, 246, 148, 169, 82, 75, 98, 100, 0, 98, 0, 113, 0, 115, 0, 109, 0, 51, 0, 0]
# 124
# def test_registry_Reg2Py_SZ(

