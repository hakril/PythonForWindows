import pytest
import pickle

import windows
import windows.generated_def as gdef

def _test_pickle_unpickle(obj, protocol=0):
    pickled = pickle.dumps(obj, protocol)
    unpickled = pickle.loads(pickled)
    assert unpickled == obj

def test_str_flags_value():
    assert gdef.MS_ENHANCED_PROV == gdef.MS_ENHANCED_PROV_A

def test_long_flag_pickle_v0():
    _test_pickle_unpickle(gdef.PAGE_EXECUTE_READWRITE, 0)

def test_long_flag_pickle_v1():
    _test_pickle_unpickle(gdef.PAGE_EXECUTE_READWRITE, 1)

def test_long_flag_pickle_v2():
    _test_pickle_unpickle(gdef.PAGE_EXECUTE_READWRITE, 2)

def test_str_flag_pickle_v0():
    _test_pickle_unpickle(gdef.szOID_RSA, 0)

def test_str_flag_pickle_v1():
    _test_pickle_unpickle(gdef.szOID_RSA, 1)

def test_str_flag_pickle_v2():
    _test_pickle_unpickle(gdef.szOID_RSA, 2)

def test_enum_value_pickle_v0():
    _test_pickle_unpickle(gdef.SystemBasicInformation, 0)

def test_enum_value_pickle_v1():
    _test_pickle_unpickle(gdef.SystemBasicInformation, 1)

def test_enum_value_pickle_v2():
    _test_pickle_unpickle(gdef.SystemBasicInformation, 2)

