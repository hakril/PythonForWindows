import ctypes
import struct
import windows
from  collections import namedtuple
from windows import winproxy
import windows.generated_def as gdef
from windows.generated_def.winstructs import *



# From: um/SoftPub.h
WINTRUST_ACTION_GENERIC_VERIFY_V2 = gdef.IID.from_string("00AAC56B-CD44-11d0-8CC2-00C04FC295EE")
DRIVER_ACTION_VERIFY = gdef.IID.from_string("F750E6C3-38EE-11d1-85E5-00C04FC295EE")

wintrust_know_return_value = [
TRUST_E_PROVIDER_UNKNOWN,
TRUST_E_ACTION_UNKNOWN,
TRUST_E_SUBJECT_FORM_UNKNOWN,
DIGSIG_E_ENCODE,
TRUST_E_SUBJECT_NOT_TRUSTED,
TRUST_E_BAD_DIGEST,
DIGSIG_E_DECODE,
DIGSIG_E_EXTENSIBILITY,
PERSIST_E_SIZEDEFINITE,
DIGSIG_E_CRYPTO,
PERSIST_E_SIZEINDEFINITE,
PERSIST_E_NOTSELFSIZING,
TRUST_E_NOSIGNATURE,
CERT_E_EXPIRED,
CERT_E_VALIDITYPERIODNESTING,
CERT_E_PURPOSE,
CERT_E_ISSUERCHAINING,
CERT_E_MALFORMED,
CERT_E_UNTRUSTEDROOT,
CERT_E_CHAINING,
TRUST_E_FAIL,
CERT_E_REVOKED,
CERT_E_UNTRUSTEDTESTROOT,
CERT_E_REVOCATION_FAILURE,
CERT_E_CN_NO_MATCH,
CERT_E_WRONG_USAGE,
TRUST_E_EXPLICIT_DISTRUST,
CERT_E_UNTRUSTEDCA,
CERT_E_INVALID_POLICY,
CERT_E_INVALID_NAME,
CRYPT_E_FILE_ERROR,
]
wintrust_return_value_mapper = gdef.FlagMapper(*wintrust_know_return_value)


def check_signature(filename):
    """Check if ``filename`` embeds a valid signature.

        :return: :class:`int`: ``0`` if ``filename`` have a valid signature else the error
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
    # win_trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    win_trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN
    win_trust_data.dwUnionChoice = WTD_CHOICE_FILE
    win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    win_trust_data.hWVTStateData = None
    win_trust_data.pwszURLReference = None
    win_trust_data.dwUIContext = 0

    #win_trust_data.dwProvFlags  = 0x1000 + 0x10 + 0x800
    win_trust_data.tmp_union.pFile = ctypes.pointer(file_data)

    x = winproxy.WinVerifyTrust(None, ctypes.byref(WVTPolicyGUID), ctypes.byref(win_trust_data))
    win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE
    winproxy.WinVerifyTrust(None, ctypes.byref(WVTPolicyGUID), ctypes.byref(win_trust_data))
    return wintrust_return_value_mapper[x & 0xffffffff]


def get_catalog_for_filename(filename):
    ctx = HCATADMIN()
    winproxy.CryptCATAdminAcquireContext(ctypes.byref(ctx), DRIVER_ACTION_VERIFY, 0)
    hash = get_file_hash(filename)
    if hash is None:
        return None
    t = winproxy.CryptCATAdminEnumCatalogFromHash(ctx, hash, len(hash), 0, None)
    if t is None:
        return None
    tname = get_catalog_name_from_handle(t)

    while t is not None:
        t = winproxy.CryptCATAdminEnumCatalogFromHash(ctx, hash, len(hash), 0, ctypes.byref(HCATINFO(t)))
        # Todo: how to handle multiple catalog ?
    winproxy.CryptCATAdminReleaseCatalogContext(ctx, t, 0)
    winproxy.CryptCATAdminReleaseContext(ctx, 0)
    return tname


def get_file_hash(filename):
    f = open(filename, "rb")
    handle = windows.utils.get_handle_from_file(f)

    size = DWORD(0)
    x = winproxy.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), None, 0)
    buffer = (BYTE * size.value)()
    try:
        x = winproxy.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), buffer, 0)
    except WindowsError as e:
        if e.winerror == 1006:
            # CryptCATAdminCalcHashFromFileHandle: [Error 1006]
            # The volume for a file has been externally altered so that the opened file is no longer valid.
            # (returned for empty file)
            return None
        raise
    return buffer

def get_file_hash2(filename): #POC: name/API will change/disapear
    f = open(filename, "rb")
    handle = windows.utils.get_handle_from_file(f)

    cathand = HANDLE()
    h = winproxy.CryptCATAdminAcquireContext2(cathand, None, "SHA256", None, 0)
    print(cathand)

    size = DWORD(0)
    x = winproxy.CryptCATAdminCalcHashFromFileHandle2(cathand, handle, ctypes.byref(size), None, 0)
    buffer = (BYTE * size.value)()
    try:
        x = winproxy.CryptCATAdminCalcHashFromFileHandle2(cathand, handle, ctypes.byref(size), buffer, 0)
    except WindowsError as e:
        if e.winerror == 1006:
            # CryptCATAdminCalcHashFromFileHandle: [Error 1006]
            # The volume for a file has been externally altered so that the opened file is no longer valid.
            # (returned for empty file)
            return None
        raise
    return buffer


def get_catalog_name_from_handle(handle):
    cat_info = CATALOG_INFO()
    cat_info.cbStruct = ctypes.sizeof(cat_info)
    winproxy.CryptCATCatalogInfoFromContext(handle, ctypes.byref(cat_info), 0)
    return cat_info.wszCatalogFile

SignatureData = namedtuple("SignatureData", ["signed", "catalog", "catalogsigned", "additionalinfo"])
"""Signature information for ``FILENAME``:

    * ``signed``: True if ``FILENAME`` embeds a valide signature
    * ``catalog``: The filename of the catalog ``FILENAME`` is part of (if any)
    * ``catalogsigned``: True if ``catalog`` embeds a valide signature
    * ``additionalinfo``: The return error of ``check_signature(FILENAME)``

``additionalinfo`` is useful to know if ``FILENAME`` signature was rejected for an invalid root / expired cert.
"""

def full_signature_information(filename):
    """Returns more information about the signature of ``filename``

    :return: :class:`SignatureData`
    """
    check_sign = check_signature(filename)
    signed = not bool(check_sign)
    catalog = get_catalog_for_filename(filename)
    if catalog is None:
        return SignatureData(signed, None, False, check_sign)
    catalogsigned = not bool(check_signature(catalog))
    return SignatureData(signed, catalog, catalogsigned, check_sign)

def is_signed(filename):
    """Check if ``filename`` is signed:

        * File embeds a valid signature
        * File is part of a signed catalog file

    :return: :class:`bool`
    """
    check_sign = check_signature(filename)
    if check_sign == 0:
        return True
    catalog = get_catalog_for_filename(filename)
    if catalog is None:
        return False
    catalogsigned = not bool(check_signature(catalog))
    return catalogsigned
