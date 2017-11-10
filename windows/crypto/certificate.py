import itertools
import ctypes

import windows
from windows import winproxy
import windows.generated_def as gdef

from windows.crypto import DEFAULT_ENCODING

import windows.crypto.cryptmsg


CRYPT_OBJECT_FORMAT_TYPE = [
    gdef.CERT_QUERY_OBJECT_FILE,
    gdef.CERT_QUERY_OBJECT_BLOB,
    gdef.CERT_QUERY_CONTENT_CERT,
    gdef.CERT_QUERY_CONTENT_CTL,
    gdef.CERT_QUERY_CONTENT_CRL,
    gdef.CERT_QUERY_CONTENT_SERIALIZED_STORE,
    gdef.CERT_QUERY_CONTENT_SERIALIZED_CERT,
    gdef.CERT_QUERY_CONTENT_SERIALIZED_CTL,
    gdef.CERT_QUERY_CONTENT_SERIALIZED_CRL,
    gdef.CERT_QUERY_CONTENT_PKCS7_SIGNED,
    gdef.CERT_QUERY_CONTENT_PKCS7_UNSIGNED,
    gdef.CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED,
    gdef.CERT_QUERY_CONTENT_PKCS10,
    gdef.CERT_QUERY_CONTENT_PFX,
    gdef.CERT_QUERY_CONTENT_CERT_PAIR,
    gdef.CERT_QUERY_CONTENT_PFX_AND_LOAD
    ]

CRYPT_OBJECT_FORMAT_TYPE_DICT = gdef.FlagMapper(*CRYPT_OBJECT_FORMAT_TYPE)

## Move CryptObject to new .py ?

class CryptObject(object):
    """Extract information from an CryptoAPI object.

       Current main use is extracting the signers certificates from a PE file.
    """
    MSG_PARAM_KNOW_TYPES = {gdef.CMSG_SIGNER_INFO_PARAM: gdef.CMSG_SIGNER_INFO,
                            gdef.CMSG_SIGNER_COUNT_PARAM: gdef.DWORD,
                            gdef.CMSG_CERT_COUNT_PARAM: gdef.DWORD}

    def __init__(self, filename, content_type=gdef.CERT_QUERY_CONTENT_FLAG_ALL):
        # No other API than filename for now..
        self.filename = filename

        dwEncoding    = gdef.DWORD()
        dwContentType = gdef.DWORD()
        dwFormatType  = gdef.DWORD()
        hStore        = EHCERTSTORE()
        hMsg          = windows.crypto.cryptmsg.CryptMessage()

        winproxy.CryptQueryObject(gdef.CERT_QUERY_OBJECT_FILE,
            gdef.LPWSTR(filename),
            # filename,
            content_type,
            gdef.CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            dwEncoding,
            dwContentType,
            dwFormatType,
            hStore,
            hMsg,
            None)

        self.cert_store = hStore if hStore else None
        self.crypt_msg = hMsg if hMsg else None
        self.encoding = dwEncoding
        self.content_type = CRYPT_OBJECT_FORMAT_TYPE_DICT[dwContentType.value]

    def _signers_and_certs_generator(self):
        for signer in self.crypt_msg.signers:
            cert = self.cert_store.find(signer.Issuer, signer.SerialNumber)
            yield signer, cert

    @property
    def signers_and_certs(self):
        return list(self._signers_and_certs_generator())

    def __repr__(self):
        return '<{0} "{1}" content_type={2}>'.format(type(self).__name__, self.filename, self.content_type)

# TODO: rename to CertificateStore ?
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa382037(v=vs.85).aspx
class EHCERTSTORE(gdef.HCERTSTORE):
    """A certificate store"""
    @property
    def certs(self):
        """The certificates in the store

        :type: [:class:`CertificateContext`] -- A list of Certificate
        """
        res = []
        last = None
        while True:
            try:
                cert = winproxy.CertEnumCertificatesInStore(self, last)
            except winproxy.Kernel32Error as e:
                if (e.winerror & 0xffffffff) in (gdef.CRYPT_E_NOT_FOUND,):
                    return tuple(res)
                raise
            # Need to duplicate as CertEnumCertificatesInStore will free the context 'last'
            ecert = windows.crypto.CertificateContext(cert[0])
            res.append(ecert.duplicate())
            last = ecert
        raise RuntimeError("Out of infinit loop")

    def add_certificate(self, certificate):
        """Add a certificate to the store"""
        winproxy.CertAddCertificateContextToStore(self, certificate, gdef.CERT_STORE_ADD_NEW, None)

    @classmethod
    def from_file(cls, filename):
        """Create a new :class:`EHCERTSTORE` from ``filename``"""
        res = winproxy.CertOpenStore(gdef.CERT_STORE_PROV_FILENAME_A, DEFAULT_ENCODING, None, gdef.CERT_STORE_OPEN_EXISTING_FLAG, filename)
        return ctypes.cast(res, cls)

    def yolo(self):
        x = winproxy.CertEnumCTLsInStore(self, None)
        title = None
        windows.winproxy.CryptUIDlgViewContext(gdef.CERT_STORE_CTL_CONTEXT, x, None, title, 0, None)

        return x


    # See https://msdn.microsoft.com/en-us/library/windows/desktop/aa388136(v=vs.85).aspx
    @classmethod
    def from_system_store(cls, store_name):
        """Create a new :class:`EHCERTSTORE` from system store``store_name``
        (see https://msdn.microsoft.com/en-us/library/windows/desktop/aa388136(v=vs.85).aspx)
        """
        res = winproxy.CertOpenStore(gdef.CERT_STORE_PROV_SYSTEM_A, DEFAULT_ENCODING, None, gdef.CERT_SYSTEM_STORE_LOCAL_MACHINE | gdef.CERT_STORE_READONLY_FLAG, store_name)
        return ctypes.cast(res, cls)

    @classmethod
    def new_in_memory(cls):
        """Create a new temporary :class:`EHCERTSTORE` in memory"""
        res = winproxy.CertOpenStore(gdef.CERT_STORE_PROV_MEMORY, DEFAULT_ENCODING, None, 0, None)
        return ctypes.cast(res, cls)


    # TODO: a more complete search API ?
    def find(self, issuer, serialnumber):
        """Return the certificate that match `issuer` and `serialnumber`

        :return: :class:`CertificateContext`
        """
        # data = self.get_signer_data(index)
        cert_info = gdef.CERT_INFO()
        cert_info.Issuer = issuer
        cert_info.SerialNumber = serialnumber
        rawcertcontext = winproxy.CertFindCertificateInStore(self, DEFAULT_ENCODING, 0, gdef.CERT_FIND_SUBJECT_CERT, ctypes.byref(cert_info), None)
        # return rawcertcontext
        return CertificateContext(rawcertcontext[0])


# PKCS12_NO_PERSIST_KEY -> do not save it in a key container on disk
# Without it, a key container is created at 'C:\Users\USERNAME\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3241049326-165485355-1070449050-1001'
def import_pfx(pfx, password=None, flags=gdef.CRYPT_USER_KEYSET | gdef.PKCS12_NO_PERSIST_KEY):
    """Import the file ``pfx`` with the ``password``.

    ``default flags = PKCS12_NO_PERSIST_KEY | CRYPT_USER_KEYSET``.

    ``PKCS12_NO_PERSIST_KEY`` tells ``CryptoAPI`` to NOT save the keys in a on-disk container.

    :return: :class:`EHCERTSTORE`
    """
    if isinstance(pfx, basestring):
        pfx = gdef.CRYPT_DATA_BLOB.from_string(pfx)
    cert_store = winproxy.PFXImportCertStore(pfx, password, flags)
    return EHCERTSTORE(cert_store)


# Why PCCERT_CONTEXT (pointer type) and not _CERT_CONTEXT ?
class CertificateContext(gdef.PCCERT_CONTEXT):
    """Represent a Certificate.

       note: It is a pointer ctypes structure (``PCCERT_CONTEXT``)
    """
    _type_ = gdef.PCCERT_CONTEXT._type_ # Not herited from PCCERT_CONTEXT


    def __repr__(self):
        return '<{0} "{1}" serial="{2}">'.format(type(self).__name__, self.name, self.serial)

    @property
    def raw_serial(self):
        """The raw serial number of the certificate.

        :type: [:class:`int`]: A list of int ``0 <= x <= 255``"""
        serial_number = self[0].pCertInfo[0].SerialNumber
        return [(c & 0xff) for c in serial_number.pbData[:serial_number.cbData][::-1]]

    @property
    def serial(self):
        """The string representation of the certificate's serial.

        :type: :class:`str`
        """
        serial_number = self[0].pCertInfo[0].SerialNumber
        serial_bytes = self.raw_serial
        return " ".join("{:02x}".format(x) for x in serial_bytes)


    def get_name(self, nametype=gdef.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags=0):
        """Retrieve the subject or issuer name of the certificate. See ``CertGetNameStringA``

        :returns: :class:`str`
        """
        size = winproxy.CertGetNameStringA(self, nametype, flags, None, None, 0)
        namebuff = ctypes.c_buffer(size)
        size = winproxy.CertGetNameStringA(self, nametype, flags, None, namebuff, size)
        return namebuff[:-1]

    name = property(get_name)
    """The name of the certificate.

    :type: :class:`str`"""

    @property
    def issuer(self):
        """The name of the certificate's issuer.

        :type: :class:`str`"""
        return self.get_name(flags=gdef.CERT_NAME_ISSUER_FLAG)

    @property
    def store(self):
        """The certificate store that contains the certificate

        :type: :class:`EHCERTSTORE`
        """
        return EHCERTSTORE(self[0].hCertStore)

    def get_raw_certificate_chains(self): # Rename to all_chains ?
        chain_context = EPCCERT_CHAIN_CONTEXT()

        enhkey_usage = gdef.CERT_ENHKEY_USAGE()
        enhkey_usage.cUsageIdentifier = 0
        enhkey_usage.rgpszUsageIdentifier = None

        cert_usage = gdef.CERT_USAGE_MATCH()
        cert_usage.dwType = gdef.USAGE_MATCH_TYPE_AND
        cert_usage.Usage   = enhkey_usage

        chain_para = gdef.CERT_CHAIN_PARA()
        chain_para.cbSize = ctypes.sizeof(chain_para)
        chain_para.RequestedUsage = cert_usage

        winproxy.CertGetCertificateChain(None, self, None, self[0].hCertStore, ctypes.byref(chain_para), 0, None, ctypes.byref(chain_context))
        #return CertficateChain(chain_context)
        return chain_context

    @property # fixedproperty ?
    def chains(self):
        """The list of chain context available for this certificate. Each elements of this list is a list of ``CertificateContext`` that should
        go from the ``self`` certificate to a trusted certificate.

        :type: [[:class:`CertificateContext`]] -- A list of chain (list) of :class:`CertificateContext`
        """
        chain_context = self.get_raw_certificate_chains()
        res = []
        for chain in chain_context.chains:
            chain_res = [elt.cert for elt in chain.elements]
            res.append(chain_res)
        return res

    # API Arround CertSelectCertificateChains ?
    # https://msdn.microsoft.com/en-us/library/windows/desktop/dd433797(v=vs.85).aspx

    def duplicate(self):
        """Duplicate the certificate by incrementing the internal refcount. (see ``CertDuplicateCertificateContext``)

        note: The object returned is ``self``

        :return: :class:`CertificateContext`
        """
        res = winproxy.CertDuplicateCertificateContext(self)
        # Check what the doc says: the pointer returned is actually the PCERT in parameter
        # Only the refcount is incremented
        # This postulate allow us to return 'self' directly
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376045(v=vs.85).aspx
        if not ctypes.cast(res, gdef.PVOID).value == ctypes.cast(self, gdef.PVOID).value:
            raise ValueError("CertDuplicateCertificateContext did not returned the argument (check doc)")
        return self

    def view(self, title=None):
        return windows.winproxy.CryptUIDlgViewContext(gdef.CERT_STORE_CERTIFICATE_CONTEXT, self, None, title, 0, None)

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

    #def get_property(self):
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376079(v=vs.85).aspx
        # - Usefull:
            # CERT_SHA1_HASH_PROP_ID


    @property
    def encoded(self):
        """The encoded certificate.

        :type: :class:`bytearray`"""
        return bytearray(self[0].pbCertEncoded[:self[0].cbCertEncoded])

    @property
    def version(self):
        "TODO: doc"
        return self[0].pbCertInfo.dwVersion


    @classmethod
    def from_file(cls, filename):
        """Create a :class:`CertificateContext` from the file ``filename``

        :return: :class:`CertificateContext`
        """
        with open(filename, "rb") as f:
            data = f.read()
            buf = (ctypes.c_ubyte * len(data))(*bytearray(data))
            res = windows.winproxy.CertCreateCertificateContext(windows.crypto.DEFAULT_ENCODING, buf, len(data))
            return ctypes.cast(res, cls)

    @classmethod
    def from_buffer(cls, data):
        """Create a :class:`CertificateContext` from the buffer ``data``

        :return: :class:`CertificateContext`
        """
        buf = (ctypes.c_ubyte * len(data))(*bytearray(data))
        res = windows.winproxy.CertCreateCertificateContext(windows.crypto.DEFAULT_ENCODING, buf, len(data))
        return ctypes.cast(res, cls)

    def __eq__(self, other):
        if not isinstance(other, CertificateContext):
            return NotImplemented
        return windows.winproxy.CertCompareCertificate(DEFAULT_ENCODING, self[0].pCertInfo, other[0].pCertInfo)

    # CertCompareCertificate  ?
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376027(v=vs.85).aspx


# class CertficateChain(object):
#     def __init__(self, pc_chain_context):
#         self.chain = pc_chain_context[0]
#
#     def to_list(self):
#         res = []
#         for i in range(self.chain.rgpChain[0][0].cElement):
#             res.append(CertificateContext(self.chain.rgpChain[0][0].rgpElement[i][0].pCertContext[0]))
#         return res


# Those classes are more of a POC than anything else
class EPCCERT_CHAIN_CONTEXT(gdef.PCCERT_CHAIN_CONTEXT):
    _type_ = gdef.PCCERT_CHAIN_CONTEXT._type_

    @property
    def chains(self):
        res = []
        for i in range(self[0].cChain):
            simple_chain = ctypes.cast(self[0].rgpChain[i], EPCCERT_SIMPLE_CHAIN)
            res.append(simple_chain)
        return res

    @property
    def all_cert(self):
        res = []
        for chain in self.chains:
            ch = []
            res.append(ch)
            for element in chain.elements:
                ch.append(element.cert)
        return res

class EPCCERT_SIMPLE_CHAIN(gdef.PCCERT_SIMPLE_CHAIN):
    _type_ = gdef.PCCERT_SIMPLE_CHAIN._type_

    @property
    def elements(self):
        res = []
        for i in range(self[0].cElement):
            element = ctypes.cast(self[0].rgpElement[i], EPCERT_CHAIN_ELEMENT)
            res.append(element)
        return res

class EPCERT_CHAIN_ELEMENT(gdef.PCERT_CHAIN_ELEMENT):
    _type_ = gdef.PCERT_CHAIN_ELEMENT._type_

    @property
    def cert(self):
        return ctypes.cast(self[0].pCertContext, CertificateContext)


# Move this in another .py ?
class CryptContext(gdef.HCRYPTPROV):
    """ A context manager arround ``CryptAcquireContextW`` & ``CryptReleaseContext``"""
    _type_ = gdef.HCRYPTPROV._type_

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
        return winproxy.CryptAcquireContextW(self, self.pszContainer, self.pszProvider, self.dwProvType, self.dwFlags | gdef.CRYPT_NEWKEYSET)

    def release(self):
        return winproxy.CryptReleaseContext(self, False)