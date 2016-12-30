import itertools
import ctypes

import windows
from windows import winproxy
from windows.generated_def import *

from windows.crypto import DEFAULT_ENCODING
from windows.crypto.helper import ECRYPT_DATA_BLOB




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
    def new_in_memory(cls):
        res = winproxy.CertOpenStore(CERT_STORE_PROV_MEMORY, DEFAULT_ENCODING, None, 0, None)
        return ctypes.cast(res, cls)


def import_pfx(pfx, password=None, flags=CRYPT_USER_KEYSET):
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

    @classmethod
    def from_file(cls, filename):
        with open(filename, "rb") as f:
            data = f.read()
            buf = (ctypes.c_ubyte * len(data))(*bytearray(data))
            res = windows.winproxy.CertCreateCertificateContext(windows.crypto.DEFAULT_ENCODING, buf, len(data))
            return ctypes.cast(res, cls)



class CertficateChain(object):
    def __init__(self, pc_chain_context):
        self.chain = pc_chain_context[0]

    def to_list(self):
        res = []
        for i in range(self.chain.rgpChain[0][0].cElement):
            res.append(CertificatContext(self.chain.rgpChain[0][0].rgpElement[i][0].pCertContext))
        return res