import sys
import pytest
import os
import tempfile

from datetime import datetime, timedelta
import windows.utils
import windows.generated_def as gdef
from .pfwtest import *

if sys.version_info.major >= 3:
    unicode = str

pytestmark = pytest.mark.usefixtures('check_for_gc_garbage')

ntqueryinformationfile_info_structs = {
    gdef.FileAccessInformation: gdef.FILE_ACCESS_INFORMATION,
    gdef.FileAlignmentInformation: gdef.FILE_ALIGNMENT_INFORMATION,
    gdef.FileAllInformation: gdef.FILE_ALL_INFORMATION,
    gdef.FileAttributeTagInformation: gdef.FILE_ATTRIBUTE_TAG_INFORMATION,
    gdef.FileBasicInformation: gdef.FILE_BASIC_INFORMATION,
    gdef.FileEaInformation: gdef.FILE_EA_INFORMATION ,
    gdef.FileInternalInformation: gdef.FILE_INTERNAL_INFORMATION,
    gdef.FileIoPriorityHintInformation: gdef.FILE_IO_PRIORITY_HINT_INFORMATION,
    gdef.FileModeInformation: gdef.FILE_MODE_INFORMATION,
    gdef.FileNetworkOpenInformation: gdef.FILE_NETWORK_OPEN_INFORMATION,
    gdef.FileNameInformation: gdef.FILE_NAME_INFORMATION,
    gdef.FilePositionInformation: gdef.FILE_POSITION_INFORMATION,
    gdef.FileStandardInformation: gdef.FILE_STANDARD_INFORMATION,
    gdef.FileIsRemoteDeviceInformation: gdef.FILE_IS_REMOTE_DEVICE_INFORMATION,
}

def test_query_file_information():
    f = open(r"C:\windows\system32\ntdll.dll")
    handle = windows.utils.get_handle_from_file(f)
    for info_class, info_struct in ntqueryinformationfile_info_structs.items():
        res = windows.utils.query_file_information(handle, info_class) # Fail should raise
        resf = windows.utils.query_file_information(f, info_class) # Try with the file directly
        # Check return type
        assert isinstance(res, info_struct)
        assert isinstance(resf, info_struct)


ntqueryvolumeinformationfile_info_structs = {
    gdef.FileFsAttributeInformation: gdef.FILE_FS_ATTRIBUTE_INFORMATION,
    gdef.FileFsControlInformation: gdef.FILE_FS_CONTROL_INFORMATION,
    gdef.FileFsDeviceInformation: gdef.FILE_FS_DEVICE_INFORMATION,
    # gdef.FileFsDriverPathInformation: gdef.FILE_FS_DRIVER_PATH_INFORMATION, # Not handled for now
    gdef.FileFsFullSizeInformation: gdef.FILE_FS_FULL_SIZE_INFORMATION,
    gdef.FileFsObjectIdInformation: gdef.FILE_FS_OBJECTID_INFORMATION,
    gdef.FileFsSizeInformation: gdef.FILE_FS_SIZE_INFORMATION,
    gdef.FileFsVolumeInformation: gdef.FILE_FS_VOLUME_INFORMATION,
    gdef.FileFsSectorSizeInformation: gdef.FILE_FS_SECTOR_SIZE_INFORMATION,
}

def test_query_volume_information():
    f = open(r"C:\windows\system32\ntdll.dll")
    handle = windows.utils.get_handle_from_file(f)

    for info_class, info_struct in ntqueryvolumeinformationfile_info_structs.items():
        res = windows.utils.query_volume_information(handle, info_class) # Fail should raise
        resf = windows.utils.query_volume_information(f, info_class) # Try with the file directly
        # Check return type
        assert isinstance(res, info_struct)
        assert isinstance(resf, info_struct)

def date_equals(d1, d2, acceptable_delta=timedelta(microseconds=1)):
    if d2 > d1:
        delta = d2 - d1
    else:
        delta = d1 - d2
    return delta <= acceptable_delta

def test_datetime_from_filetime():
    FILENAME = "C:\\windows\\system32\\ntdll.dll"
    f = open(FILENAME)

    datetime_from_filetime = windows.utils.datetime_from_filetime

    # Compare to os.stat
    stats = os.stat(FILENAME)
    utc_satime = datetime.utcfromtimestamp(stats.st_atime)
    utc_smtime = datetime.utcfromtimestamp(stats.st_mtime)
    utc_sctime = datetime.utcfromtimestamp(stats.st_ctime)

    # Compare to NtQueryInformationFile
    fileinfo = windows.utils.query_file_information(f, gdef.FileBasicInformation)

    utc_watime = datetime_from_filetime(fileinfo.LastAccessTime)
    utc_wmtime = datetime_from_filetime(fileinfo.LastWriteTime)
    utc_wctime = datetime_from_filetime(fileinfo.CreationTime)

    assert date_equals(utc_satime, utc_watime)
    assert date_equals(utc_smtime, utc_wmtime)
    assert date_equals(utc_sctime, utc_wctime)

    # Test rounding
    ## Round-down


    assert date_equals(datetime_from_filetime(131492395680727300), datetime(2017, 9, 7, 6, 32, 48, 72730))
    assert date_equals(datetime_from_filetime(131492395680727304), datetime(2017, 9, 7, 6, 32, 48, 72730))

    assert date_equals(datetime_from_filetime(131492395680727305), datetime(2017, 9, 7, 6, 32, 48, 72731))
    assert date_equals(datetime_from_filetime(131492395680727309), datetime(2017, 9, 7, 6, 32, 48, 72731))

    assert date_equals(datetime.utcfromtimestamp(1504764215.5896280), datetime_from_filetime(131492378155896280))
    assert date_equals(datetime.utcfromtimestamp(1504764215.5896284), datetime_from_filetime(131492378155896284))
    assert date_equals(datetime.utcfromtimestamp(1504764215.5896285), datetime_from_filetime(131492378155896285))
    assert date_equals(datetime.utcfromtimestamp(1504764215.5896289), datetime_from_filetime(131492378155896289))



def test_unix_timestamp_from_filetime():
    # Check date vs timestamps to be sure
    assert datetime.utcfromtimestamp(1504765968.072730) == datetime(2017, 9, 7, 6, 32, 48, 72730)
    assert windows.utils.unix_timestamp_from_filetime(131492395680727300) == 1504765968.072730
    assert windows.utils.unix_timestamp_from_filetime(131492395680727304) == 1504765968.072730

    assert datetime.utcfromtimestamp(1504765968.072731) == datetime(2017, 9, 7, 6, 32, 48, 72731)
    assert windows.utils.unix_timestamp_from_filetime(131492395680727309) == 1504765968.072731
    # Well py3 will round it to 1504765968.07273
    # Because round(0.5) == 0 (vs 1 in py2)
    assert windows.utils.unix_timestamp_from_filetime(131492395680727305) == 1504765968.072731

# Test values from https://docs.microsoft.com/en-us/cpp/atl-mfc-shared/date-type?view=vs-2019
@pytest.mark.parametrize("comtime, date", [
    (0, datetime(1899, 12, 30)),
    (2, datetime(1900, 1, 1)),
    (5, datetime(1900, 1, 4)),
    (5.25, datetime(1900, 1, 4, hour=6)),
    (5.5, datetime(1900, 1, 4, hour=12)),
    (5.875, datetime(1900, 1, 4, hour=21)),
    (-0.25, datetime(1899, 12, 30, hour=6)),
    (-0.5, datetime(1899, 12, 30, hour=12)),
    (-2, datetime(1899, 12, 28)),
    (-2.5, datetime(1899, 12, 28, hour=12)),
    (-2.75, datetime(1899, 12, 28, hour=18)),
])
def test_datetime_from_comtime(comtime, date):
    assert windows.utils.datetime_from_comdate(comtime) == date

@pytest.mark.parametrize("prefix", [
    ("long_ascii_prefix"),
    (u'\u4e2d\u56fd\u94f6\u884c\u7f51\u94f6\u52a9\u624b'),
    ])
def test_long_short_path_str_unicode(prefix):
    """Test that get_short_path/get_long_path works with str/unicode path and returns unicode"""
    with tempfile.NamedTemporaryFile(prefix=prefix) as f:
        # Basename may be a mix of short & long path depending on version ? username ? (seen as short in github CI)
        # Short for the dir + long for the filename
        basename = f.name.lower()
        short_name = windows.utils.get_short_path(basename).lower()
        assert "~" in short_name
        assert isinstance(short_name, unicode)
        full_name = windows.utils.get_long_path(short_name).lower()
        assert "~" not in full_name
        assert isinstance(full_name, unicode)

        assert len(full_name) > len(short_name)

TEST_CERT = b"""
MIIBwTCCASqgAwIBAgIQG46Uyws+67ZBOfPJCbFrRjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQD
ExRQeXRob25Gb3JXaW5kb3dzVGVzdDAeFw0xNzA0MTIxNDM5MjNaFw0xODA0MTIyMDM5MjNaMB8x
HTAbBgNVBAMTFFB5dGhvbkZvcldpbmRvd3NUZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQCRHwC/sRfXh5pc4poc85aidrudbPdya+0OeonQlf1JQ1ekf7KSfADV5FLkSQu2BzgBK9DIWTGX
XknBJIzZF03UZsVg5D67V2mnSClXucc0cGFcK4pDDt0tHeabA2GPinVe7Z6qDT4ZxPR8lKaXDdV2
Pg2hTdcGSpqaltHxph7G/QIDAQABMA0GCSqGSIb3DQEBCwUAA4GBACcQFdOlVjYICOIyAXowQaEN
qcLpN1iWoL9UijNhTY37+U5+ycFT8QksT3Xmh9lEIqXMh121uViy2P/3p+Ek31AN9bB+BhWIM6PQ
gy+ApYDdSwTtWFARSrMqk7rRHUveYEfMw72yaOWDxCzcopEuADKrrYEute4CzZuXF9PbbgK6"""


def test_sprint_certificate():
    cert = windows.crypto.Certificate.from_buffer(b64decode(TEST_CERT))
    # Certificate is quite a complexe Windows structure
    # With Sub-struct / Pointer & string
    # It was broken on py3 -> ense this test
    windows.utils.sprint(cert)
