from windows import winproxy
from windows.generated_def import *

from windows.crypto.helper import ECRYPT_DATA_BLOB
from windows.crypto import DEFAULT_ENCODING, EHCERTSTORE


def generate_selfsigned_certificate(name="CN=DEFAULT", prov=None, key_info=None, flags=0, signature_algo=None):
    size = ULONG(len(name) + 0x100)
    buffer = (ctypes.c_ubyte * size.value)()
    winproxy.CertStrToNameA(X509_ASN_ENCODING, name,  CERT_OID_NAME_STR, None, buffer, size, None)
    blobname = ECRYPT_DATA_BLOB(size.value, buffer)
    cert = winproxy.CertCreateSelfSignCertificate(prov, blobname, flags, key_info, signature_algo, None, None, None)
    return windows.crypto.CertificatContext(cert[0])


def generate_key(prov, keytype=AT_KEYEXCHANGE, flags=CRYPT_EXPORTABLE):
    key = HCRYPTKEY()
    winproxy.CryptGenKey(prov, keytype, flags , key)
    return key
    # print(key[0])
    # print("[OK] Key created")
    # size = DWORD()
    # winproxy.CryptExportKey(key, None, PRIVATEKEYBLOB, 0, None, size)
    # buffer = (BYTE *  size.value)()
    # print("needed size = {0}".format(size))
    # winproxy.CryptExportKey(key, None, PRIVATEKEYBLOB, 0, buffer, size)
    # print("[OK] Key in buffer")
    # keyraw = bytearray(buffer)
    # # openssl.exe rsa -in key.out -inform MS\PRIVATEKEYBLOB -text
    # save_as(keyraw, "key.out")
    # #res = ctypes.WinDLL("advapi32").CryptReleaseContext(prov, 0)
    # return key

def generate_pfx(hstore, password=None):
    blob = ECRYPT_DATA_BLOB(0, None)
    winproxy.PFXExportCertStoreEx(hstore, blob, password, None, EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)
    blob.pbData = (ctypes.c_ubyte * blob.cbData)()
    winproxy.PFXExportCertStoreEx(hstore, blob, password, None, EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)
    return blob.data