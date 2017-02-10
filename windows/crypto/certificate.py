import itertools
import ctypes

import windows
from windows import winproxy
from windows.generated_def import *

from windows.crypto import DEFAULT_ENCODING
from windows.crypto.helper import ECRYPT_DATA_BLOB



CRYPT_OBJECT_FORMAT_TYPE = [
    CERT_QUERY_OBJECT_FILE,
    CERT_QUERY_OBJECT_BLOB,
    CERT_QUERY_CONTENT_CERT,
    CERT_QUERY_CONTENT_CTL,
    CERT_QUERY_CONTENT_CRL,
    CERT_QUERY_CONTENT_SERIALIZED_STORE,
    CERT_QUERY_CONTENT_SERIALIZED_CERT,
    CERT_QUERY_CONTENT_SERIALIZED_CTL,
    CERT_QUERY_CONTENT_SERIALIZED_CRL,
    CERT_QUERY_CONTENT_PKCS7_SIGNED,
    CERT_QUERY_CONTENT_PKCS7_UNSIGNED,
    CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED,
    CERT_QUERY_CONTENT_PKCS10,
    CERT_QUERY_CONTENT_PFX,
    CERT_QUERY_CONTENT_CERT_PAIR,
    CERT_QUERY_CONTENT_PFX_AND_LOAD
    ]

CRYPT_OBJECT_FORMAT_TYPE_DICT = {x:x for x in CRYPT_OBJECT_FORMAT_TYPE}

## Move CryptObject to new .py ?

class CryptObject(object):
    MSG_PARAM_KNOW_TYPES = {CMSG_SIGNER_INFO_PARAM: CMSG_SIGNER_INFO,
                            CMSG_SIGNER_COUNT_PARAM: DWORD,
                            CMSG_CERT_COUNT_PARAM: DWORD}

    def __init__(self, filename, content_type=CERT_QUERY_CONTENT_FLAG_ALL):
        # No other API than filename for now..
        self.filename = filename

        dwEncoding    = DWORD()
        dwContentType = DWORD()
        dwFormatType  = DWORD()
        hStore        = PVOID()
        hMsg          = PVOID()

        winproxy.CryptQueryObject(CERT_QUERY_OBJECT_FILE,
            LPWSTR(filename),
            content_type,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            dwEncoding,
            dwContentType,
            dwFormatType,
            hStore,
            hMsg,
            None)

        self.hstore = hStore
        self.hmsg = hMsg
        self.encoding = dwEncoding
        self.content_type = CRYPT_OBJECT_FORMAT_TYPE_DICT.get(dwContentType.value, dwContentType)

    def msg_get_param(self, param_type, index=0):
        signer_info = DWORD()
        winproxy.CryptMsgGetParam(self.hmsg, param_type, index, None, signer_info)
        buffer = ctypes.c_buffer(signer_info.value)
        winproxy.CryptMsgGetParam(self.hmsg, param_type, index, buffer, signer_info)

        if param_type in self.MSG_PARAM_KNOW_TYPES:
            buffer = self.MSG_PARAM_KNOW_TYPES[param_type].from_buffer_copy(buffer)
        return buffer

    def get_nb_signer(self):
        return self.msg_get_param(CMSG_SIGNER_COUNT_PARAM).value

    def get_signer_data(self, index=0):
        return self.msg_get_param(CMSG_SIGNER_INFO_PARAM, index)

    def get_signer_certificate(self):
        data = self.get_signer_data()
        cert_info = CERT_INFO()
        cert_info.Issuer = data.Issuer
        cert_info.SerialNumber = data.SerialNumber
        rawcertcontext = winproxy.CertFindCertificateInStore(self.hstore, self.encoding, 0, CERT_FIND_SUBJECT_CERT, byref(cert_info), None)
        #return rawcertcontext
        return CertificatContext(rawcertcontext[0])

    def get_cert(self, index=0):
        return self.msg_get_param(CMSG_CERT_PARAM, index)

    def get_nb_cert(self):
        "TEST"
        return self.msg_get_param(CMSG_CERT_COUNT_PARAM).value

    def test_all_certs(self):
        nb_cert = self.get_nb_cert()
        return [CertificatContext.from_buffer(self.get_cert(i)) for i in range(nb_cert)]


    def __repr__(self):
        return '<{0} "{1}" content_type={2}>'.format(type(self).__name__, self.filename, self.content_type)


class EHCERTSTORE(HCERTSTORE):
    # def __str__(self):
    #     return "CertStore()"

    @property
    def certs(self):
        res = []
        last = None
        while True:
            try:
                cert = winproxy.CertEnumCertificatesInStore(self, last)
            except winproxy.Kernel32Error as e:
                if (e.winerror & 0xffffffff) in (CRYPT_E_NOT_FOUND,):
                    return tuple(res)
                raise
            # Need to duplicate as CertEnumCertificatesInStore will free the context 'last'
            ecert = windows.crypto.CertificatContext(cert[0])
            res.append(ecert.duplicate())
            last = ecert
        raise RuntimeError("Out of infinit loop")

    def add_certificate(self, certificate):
        winproxy.CertAddCertificateContextToStore(self, certificate, CERT_STORE_ADD_NEW, None)

    @classmethod
    def from_file(cls, filename):
        res = winproxy.CertOpenStore(CERT_STORE_PROV_FILENAME_A, DEFAULT_ENCODING, None, CERT_STORE_OPEN_EXISTING_FLAG, filename)
        return ctypes.cast(res, cls)

    @classmethod
    def from_system_store(cls, store_name):
        res = winproxy.CertOpenStore(CERT_STORE_PROV_SYSTEM_A, DEFAULT_ENCODING, None, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG, store_name)
        return ctypes.cast(res, cls)

    @classmethod
    def new_in_memory(cls):
        res = winproxy.CertOpenStore(CERT_STORE_PROV_MEMORY, DEFAULT_ENCODING, None, 0, None)
        return ctypes.cast(res, cls)

# PKCS12_NO_PERSIST_KEY -> do not save it in a key container on disk
# Without it a key container is created at 'C:\Users\USERNAME\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3241049326-165485355-1070449050-1001'
def import_pfx(pfx, password=None, flags=CRYPT_USER_KEYSET | PKCS12_NO_PERSIST_KEY):
    if isinstance(pfx, basestring):
        pfx = ECRYPT_DATA_BLOB.from_string(pfx)
    cert_store = winproxy.PFXImportCertStore(pfx, password, flags)
    return EHCERTSTORE(cert_store)


# Why PCCERT_CONTEXT (pointer type) and not _CERT_CONTEXT ?
class CertificatContext(PCCERT_CONTEXT):
    _type_ = PCCERT_CONTEXT._type_ # Not herited from PCCERT_CONTEXT


    def __repr__(self):
        return '<{0} "{1}" serial="{2}">'.format(type(self).__name__, self.name, self.serial)

    @property
    def raw_serial(self):
        serial_number = self[0].pCertInfo[0].SerialNumber
        return [(c & 0xff) for c in serial_number.pbData[:serial_number.cbData][::-1]]

    @property
    def serial(self):
        serial_number = self[0].pCertInfo[0].SerialNumber
        serial_bytes = self.raw_serial
        return " ".join("{:02x}".format(x) for x in serial_bytes)


    def get_name(self, flags=0):
        size = winproxy.CertGetNameStringA(self, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None, 0)
        namebuff = ctypes.c_buffer(size)
        size = winproxy.CertGetNameStringA(self, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, namebuff, size)
        return namebuff[:-1]

    name = property(get_name)

    @property
    def issuer(self):
        return self.get_name(flags=CERT_NAME_ISSUER_FLAG)

    @property
    def store(self):
        return EHCERTSTORE(self[0].hCertStore)

    def get_certificate_chain(self):
        chain_context = PCCERT_CHAIN_CONTEXT()

        enhkey_usage = CERT_ENHKEY_USAGE()
        enhkey_usage.cUsageIdentifier = 0
        enhkey_usage.rgpszUsageIdentifier = None

        cert_usage = CERT_USAGE_MATCH()
        cert_usage.dwType = USAGE_MATCH_TYPE_AND
        cert_usage.Usage   = enhkey_usage

        chain_para = CERT_CHAIN_PARA()
        chain_para.cbSize = sizeof(chain_para)
        chain_para.RequestedUsage = cert_usage

        winproxy.CertGetCertificateChain(None, self, None, self[0].hCertStore, byref(chain_para), 0, None, byref(chain_context))
        return CertficateChain(chain_context)

    def duplicate(self):
        res = winproxy.CertDuplicateCertificateContext(self)
        # Check what the doc says: the pointer returned is actually the PCERT in parameter
        # Only the refcount is incremented
        # This postulate allow us to return 'self' directly
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376045(v=vs.85).aspx
        if not ctypes.cast(res, PVOID).value == ctypes.cast(self, PVOID).value:
            raise ValueError("CertDuplicateCertificateContext did not returned the argument (check doc)")
        return self

    def enum_properties(self):
        prop = 0
        res = []
        while True:
            prop = winproxy.CertEnumCertificateContextProperties(self, prop)
            if not prop:
                return res
            res.append(prop)
        raise RuntimeError("Unreachable code")

    properties = property(enum_properties)


    def encoded(self):
        return bytearray(self[0].pbCertEncoded[:self[0].cbCertEncoded])

    @classmethod
    def from_file(cls, filename):
        with open(filename, "rb") as f:
            data = f.read()
            buf = (ctypes.c_ubyte * len(data))(*bytearray(data))
            res = windows.winproxy.CertCreateCertificateContext(windows.crypto.DEFAULT_ENCODING, buf, len(data))
            return ctypes.cast(res, cls)

    @classmethod
    def from_buffer(cls, data):
        buf = (ctypes.c_ubyte * len(data))(*bytearray(data))
        res = windows.winproxy.CertCreateCertificateContext(windows.crypto.DEFAULT_ENCODING, buf, len(data))
        return ctypes.cast(res, cls)




class CertficateChain(object):
    def __init__(self, pc_chain_context):
        self.chain = pc_chain_context[0]

    def to_list(self):
        res = []
        for i in range(self.chain.rgpChain[0][0].cElement):
            res.append(CertificatContext(self.chain.rgpChain[0][0].rgpElement[i][0].pCertContext[0]))
        return res

# Move this in another .py ?

class CryptContext(HCRYPTPROV):
    _type_ = HCRYPTPROV._type_

    def __init__(self, pszContainer=None, pszProvider=None, dwProvType=0, dwFlags=0, retrycreate=False):
        self.pszContainer = pszContainer
        self.pszProvider = pszProvider
        self.dwProvType = dwProvType
        self.dwFlags = dwFlags
        self.retrycreate = True
        #self.value = HCRYPTPROV()
        pass

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        self.release()

    def acquire(self):
        try:
            return winproxy.CryptAcquireContextW(self, self.pszContainer, self.pszProvider, self.dwProvType, self.dwFlags)
        except WindowsError as e:
            if not self.retrycreate:
                raise
        return winproxy.CryptAcquireContextW(self, self.pszContainer, self.pszProvider, self.dwProvType, self.dwFlags | CRYPT_NEWKEYSET)

    def release(self):
        return winproxy.CryptReleaseContext(self, False)