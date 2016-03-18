import ctypes
import struct
import windows
from  collections import namedtuple
from windows.generated_def.winstructs import *
from windows.winproxy import WinVerifyTrust

IID_PACK = "<I", "<H", "<H", "<B", "<B", "<B", "<B", "<B", "<B", "<B", "<B"
def get_IID_from_raw(raw):
    s = "".join([struct.pack(i, j) for i, j in zip(IID_PACK, raw)])
    return ctypes.create_string_buffer(s)


WINTRUST_ACTION_GENERIC_VERIFY_V2_RAW = (0xaac56b, 0xcd44,  0x11d0,
                    0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee)

WINTRUST_ACTION_GENERIC_VERIFY_V2_STR = get_IID_from_raw(WINTRUST_ACTION_GENERIC_VERIFY_V2_RAW)
# Otherwise there is a problem with `Data4` of `type c_char_Array_8` containing 0x00 (0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee)
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID.from_address(ctypes.addressof(WINTRUST_ACTION_GENERIC_VERIFY_V2_STR))

DRIVER_ACTION_VERIFY_RAW = 0xf750e6c3, 0x38ee, 0x11d1, 0x85, 0xe5, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee
DRIVER_ACTION_VERIFY_STR = get_IID_from_raw(DRIVER_ACTION_VERIFY_RAW)
DRIVER_ACTION_VERIFY = GUID.from_address(ctypes.addressof(DRIVER_ACTION_VERIFY_STR))

WTD_UI_ALL    = 1
WTD_UI_NONE   = 2
WTD_UI_NOBAD  = 3
WTD_UI_NOGOOD = 4

WTD_REVOKE_NONE         = 0x00000000
WTD_REVOKE_WHOLECHAIN   = 0x00000001

WTD_CHOICE_FILE    = 1
WTD_CHOICE_CATALOG = 2
WTD_CHOICE_BLOB    = 3
WTD_CHOICE_SIGNER  = 4
WTD_CHOICE_CERT    = 5

WTD_STATEACTION_IGNORE           = 0x00000000
WTD_STATEACTION_VERIFY           = 0x00000001
WTD_STATEACTION_CLOSE            = 0x00000002
WTD_STATEACTION_AUTO_CACHE       = 0x00000003
WTD_STATEACTION_AUTO_CACHE_FLUSH = 0x00000004

def check_signature(filename):
    """Check if ``filename`` is a valid signed file

        :return: 0 if file have a valid signature
    """
    file_data = WINTRUST_FILE_INFO()
    file_data.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_data.pcwszFilePath = filename
    file_data.hFile = None
    file_data.pgKnownSubject = None

    WVTPolicyGUID =  WINTRUST_ACTION_GENERIC_VERIFY_V2

    win_trust_data = WINTRUST_DATA()
    win_trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    win_trust_data.pPolicyCallbackData = None
    win_trust_data.pSIPClientData = None
    win_trust_data.dwUIChoice = WTD_UI_NONE
    win_trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    win_trust_data.dwUnionChoice = WTD_CHOICE_FILE
    win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    win_trust_data.hWVTStateData = None
    win_trust_data.pwszURLReference = None
    win_trust_data.dwUIContext = 0

    #win_trust_data.dwProvFlags  = 0x1000 + 0x10 + 0x800
    win_trust_data.tmp_union.pFile = ctypes.pointer(file_data)

    x = WinVerifyTrust(None, ctypes.byref(WVTPolicyGUID), ctypes.byref(win_trust_data))
    win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE
    WinVerifyTrust(None, ctypes.byref(WVTPolicyGUID), ctypes.byref(win_trust_data))
    return x & 0xffffffff


def get_catalog_for_filename(filename):
    ctx = HCATADMIN()
    windows.winproxy.CryptCATAdminAcquireContext(ctypes.byref(ctx), DRIVER_ACTION_VERIFY, 0)
    hash = get_file_hash(filename)
    t = windows.winproxy.CryptCATAdminEnumCatalogFromHash(ctx, hash, len(hash), 0, None)
    if t is None:
        return None
    tname = get_catalog_name_from_handle(t)

    while t is not None:
        t = windows.winproxy.CryptCATAdminEnumCatalogFromHash(ctx, hash, len(hash), 0, ctypes.byref(HCATINFO(t)))
    windows.winproxy.CryptCATAdminReleaseCatalogContext(ctx, t, 0)
    windows.winproxy.CryptCATAdminReleaseContext(ctx, 0)
    return tname


def get_file_hash(filename):
    f = open(filename)
    handle = windows.utils.get_handle_from_file(f)

    size = DWORD(0)
    x = windows.winproxy.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), None, 0)

    buffer = (BYTE * size.value)()
    x = windows.winproxy.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), buffer, 0)
    return buffer


def get_catalog_name_from_handle(handle):
    cat_info = CATALOG_INFO()
    cat_info.cbStruct = ctypes.sizeof(cat_info)
    windows.winproxy.CryptCATCatalogInfoFromContext(handle, ctypes.byref(cat_info), 0)
    return cat_info.wszCatalogFile

SignatureData = namedtuple("SignatureData", ["signed", "catalog", "catalogsigned"])

def full_signature_information(filename):
    signed = not bool(check_signature(filename))
    catalog = get_catalog_for_filename(filename)
    catalogsigned = not bool(check_signature(catalog))
    return SignatureData(signed, catalog, catalogsigned)
