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
    (see `CryptQueryObject <https://msdn.microsoft.com/en-us/library/windows/desktop/aa380264(v=vs.85).aspx>`_)

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
        hStore        = CertificateStore()
        hMsg          = windows.crypto.CryptMessage()

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
        """The :class:`CertificateStore` that includes all of the certificates, CRLs, and CTLs in the object"""
        self.crypt_msg = hMsg if hMsg else None #: yolo
        """The :class:`CryptMessage` for any ``PKCS7`` content in the object"""
        self.encoding = dwEncoding
        self.content_type = CRYPT_OBJECT_FORMAT_TYPE_DICT[dwContentType.value]
        """The type of the opened message"""

    def _signers_and_certs_generator(self):
        if self.crypt_msg is None:
            return
        for signer in self.crypt_msg.signers:
            # We could directly extract the certificates from the 'crypt_msg' (I guess)
            # But 'CryptQueryObject' had the sympathy of already opening a CertificateStore
            # for us. So we use it.
            # I am open to counter-argument on this methodology.
            cert = self.cert_store.find(signer.Issuer, signer.SerialNumber)
            yield signer, cert

    @property
    def signers_and_certs(self):
        """The list of signer info and certificates signing the object.

        :rtype: [(:class:`~windows.generated_def.winstructs.CMSG_SIGNER_INFO`, :class:`Certificate`)]

        .. note::

            :class:`~windows.generated_def.winstructs.CMSG_SIGNER_INFO` might be changed to a wrapping-subclass.
        """
        return list(self._signers_and_certs_generator())

    def __repr__(self):
        return '<{0} "{1}" content_type={2!r}>'.format(type(self).__name__, self.filename, self.content_type)


# https://msdn.microsoft.com/en-us/library/windows/desktop/aa382037(v=vs.85).aspx
class CertificateStore(gdef.HCERTSTORE):
    """A certificate store"""
    @property
    def certs(self):
        """The list of certificates in the store

        :type: [:class:`Certificate`] -- A list of certificate
        """
        res = []
        last = None
        while True:
            try:
                cert = winproxy.CertEnumCertificatesInStore(self, last)
            except winproxy.WinproxyError as e:
                if (e.winerror & 0xffffffff) in (gdef.CRYPT_E_NOT_FOUND,):
                    return tuple(res)
                raise
            # Need to duplicate as CertEnumCertificatesInStore will free the context 'last'
            ecert = windows.crypto.Certificate.from_pointer(cert)
            res.append(ecert.duplicate())
            last = ecert
        raise RuntimeError("Out of infinit loop")

    def add_certificate(self, certificate):
        """Add a certificate to the store"""
        winproxy.CertAddCertificateContextToStore(self, certificate, gdef.CERT_STORE_ADD_NEW, None)

    @classmethod
    def from_file(cls, filename):
        """Create a new :class:`CertificateStore` from ``filename``"""
        res = winproxy.CertOpenStore(gdef.CERT_STORE_PROV_FILENAME_A, DEFAULT_ENCODING, None, gdef.CERT_STORE_OPEN_EXISTING_FLAG, filename)
        return ctypes.cast(res, cls)

    def _yolo(self):
        x = winproxy.CertEnumCTLsInStore(self, None)
        title = None
        windows.winproxy.CryptUIDlgViewContext(gdef.CERT_STORE_CTL_CONTEXT, x, None, title, 0, None)
        return x


    # See https://msdn.microsoft.com/en-us/library/windows/desktop/aa388136(v=vs.85).aspx
    @classmethod
    def from_system_store(cls, store_name):
        """Create a new :class:`CertificateStore` from system store ``store_name``
        (see `System Store Locations <https://msdn.microsoft.com/en-us/library/windows/desktop/aa388136(v=vs.85).aspx>`_)
        """
        res = winproxy.CertOpenStore(gdef.CERT_STORE_PROV_SYSTEM_A, DEFAULT_ENCODING, None, gdef.CERT_SYSTEM_STORE_LOCAL_MACHINE | gdef.CERT_STORE_READONLY_FLAG, store_name)
        return ctypes.cast(res, cls)

    @classmethod
    def new_in_memory(cls):
        """Create a new temporary :class:`CertificateStore` in memory"""
        res = winproxy.CertOpenStore(gdef.CERT_STORE_PROV_MEMORY, DEFAULT_ENCODING, None, 0, None)
        return ctypes.cast(res, cls)


    # TODO: a more complete search API ?
    def find(self, issuer, serialnumber):
        """Return the certificate that match `issuer` and `serialnumber`

        :return: :class:`Certificate` -- ``None`` if certificate is not found
        """
        # data = self.get_signer_data(index)
        cert_info = gdef.CERT_INFO()
        cert_info.Issuer = issuer
        cert_info.SerialNumber = serialnumber
        try:
            rawcertcontext = winproxy.CertFindCertificateInStore(self, DEFAULT_ENCODING, 0, gdef.CERT_FIND_SUBJECT_CERT, ctypes.byref(cert_info), None)
        except WindowsError as e:
            if not e.winerror & 0xffffffff == gdef.CRYPT_E_NOT_FOUND:
                raise
            return None
        return Certificate.from_pointer(rawcertcontext)

    def __del__(self):
        return winproxy.CertCloseStore(self, 0)


# PKCS12_NO_PERSIST_KEY -> do not save it in a key container on disk
# Without it, a key container is created at 'C:\Users\USERNAME\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3241049326-165485355-1070449050-1001'
# More about this:
# If you use 'PKCS12_NO_PERSIST_KEY' the key are indeed NOT STORED but there is a problem
# If you use an algo like 'szOID_NIST_AES256_CBC' the function 'CryptDecryptMessage' won't be able to decrypt the message
# Unless you also specify the 'PKCS12_ALWAYS_CNG_KSP' flags.

# My guess: somewhere 'CryptDecryptMessage' ask for each (CNG_KSP | CSP ?) to try to decrypt with the keys
# BUT: as we DID NOT EXPORT the keys, they are not able to get the key from memory and expect them on disk.
# By forcing PKCS12_ALWAYS_CNG_KSP we remove this as the key are directly linked to the correct CNG_KSP in the CertStore
# Look like it's based on this part of the PFX:
# Microsoft CSP Name: Microsoft Enhanced Cryptographic Provider v1.0
# BUT this will not allow to decrypt RSA_RC4 ?

def import_pfx(pfx, password=None, flags=gdef.CRYPT_USER_KEYSET | gdef.PKCS12_NO_PERSIST_KEY | gdef.PKCS12_ALWAYS_CNG_KSP):
    """Import the file ``pfx`` with the ``password``.

    ``default flags = PKCS12_NO_PERSIST_KEY | CRYPT_USER_KEYSET``.

    ``PKCS12_NO_PERSIST_KEY`` tells ``CryptoAPI`` to NOT save the keys in a on-disk container.

    :return: :class:`CertificateStore`
    """
    if isinstance(pfx, windows.pycompat.anybuff) or isinstance(pfx,  bytearray):
        pfx = gdef.CRYPT_DATA_BLOB.from_string(pfx)
    cert_store = winproxy.PFXImportCertStore(pfx, password, flags)
    return CertificateStore(cert_store)


class Certificate(gdef.CERT_CONTEXT):
    """Represent a Certificate """

    @property
    def raw_serial(self):
        """The raw serial number of the certificate.

        :type: [:class:`int`]: A list of int ``0 <= x <= 255``"""
        serial_number = self.pCertInfo[0].SerialNumber
        return [(c & 0xff) for c in serial_number.pbData[:serial_number.cbData][::-1]]

    @property
    def serial(self):
        """The string representation of the certificate's serial.

        :type: :class:`str`
        """
        serial_bytes = self.raw_serial
        return " ".join("{:02x}".format(x) for x in serial_bytes)


    def get_name(self, nametype=gdef.CERT_NAME_SIMPLE_DISPLAY_TYPE, param_type=0, flags=0):
        """Retrieve the subject or issuer name of the certificate.
        See `CertGetNameStringA <https://msdn.microsoft.com/en-us/library/windows/desktop/aa376086(v=vs.85).aspx>`_

        :returns: :class:`str`
        """
        if nametype == gdef.CERT_NAME_RDN_TYPE:
            param_type = gdef.DWORD(param_type)
            param_type = gdef.LPDWORD(param_type)
        size = winproxy.CertGetNameStringA(self, nametype, flags, param_type, None, 0)
        namebuff = ctypes.c_buffer(size)
        size = winproxy.CertGetNameStringA(self, nametype, flags, param_type, namebuff, size)
        return namebuff[:-1]



    name = property(get_name)
    """The name of the certificate.

    :type: :class:`str`"""


    def raw_hash(self):
        size = gdef.DWORD(100)
        buffer = ctypes.c_buffer(size.value)
        winproxy.CryptHashCertificate(None, 0, 0, self.pbCertEncoded, self.cbCertEncoded, ctypes.cast(buffer, gdef.LPBYTE), size)
        return buffer[:size.value]

    @property
    def thumbprint(self):
        """The thumbprint of the certificate (which is the sha1 of the encoded cert).

        Example:

            >>> x
            <Certificate "YOLO2" serial="6f 1d 3e 7d d9 77 59 a9 4c 1c 53 dc 80 db 0c fe">
            >>> x.thumbprint
            'E2 A2 DB 76 A1 DD 8E 70 0D C6 9F CB 71 CF 29 12 C6 D9 78 97'

        :type: :class:`str`
        """
        return " ".join("{:02X}".format(x) for x in bytearray(self.raw_hash()))

    @property
    def distinguished_name(self):
        """The distinguished name (DN) of the certificate.

        Example:

            >>> x
            <Certificate "Microsoft Windows Production PCA 2011" serial="61 07 76 56 00 00 00 00 00 08">
            >>> x.distinguished_name
            'C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Production PCA 2011'

        :type: :class:`str`
        """
        return self.get_name(gdef.CERT_NAME_RDN_TYPE, gdef.CERT_X500_NAME_STR)

    @property
    def issuer(self):
        """The name of the certificate's issuer.

        :type: :class:`str`"""
        return self.get_name(flags=gdef.CERT_NAME_ISSUER_FLAG)


    @property
    def store(self):
        """The certificate store that contains the certificate

        :type: :class:`CertificateStore`
        """
        return CertificateStore(self.hCertStore)

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

        winproxy.CertGetCertificateChain(None, self, None, self.hCertStore, ctypes.byref(chain_para), 0, None, ctypes.byref(chain_context))
        # Lower chains ?
        # winproxy.CertGetCertificateChain(None, self, None, self[0].hCertStore, ctypes.byref(chain_para), 0x80, None, ctypes.byref(chain_context))
        #return CertficateChain(chain_context)
        return chain_context

    @property # fixedproperty ?
    def chains(self):
        """The list of chain context available for this certificate. Each elements of this list is a list of ``Certificate`` that should
        go from the ``self`` certificate to a trusted certificate.

        :type: [[:class:`Certificate`]] -- A list of chain (list) of :class:`Certificate`
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
        """Duplicate the certificate by incrementing the internal refcount. (see `CertDuplicateCertificateContext <https://msdn.microsoft.com/en-us/library/windows/desktop/aa376045(v=vs.85).aspx>`_)

        note: The object returned is ``self``

        :return: :class:`Certificate`
        """
        res = winproxy.CertDuplicateCertificateContext(self)
        # Check what the doc says: the pointer returned is actually the PCERT in parameter
        # Only the refcount is incremented
        # This postulate allow us to return 'self' directly
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376045(v=vs.85).aspx
        if not ctypes.addressof(res[0]) == ctypes.addressof(self):
            raise ValueError("CertDuplicateCertificateContext did not returned the argument (check doc)")
        return self

    def view(self, title=None):
        return windows.winproxy.CryptUIDlgViewContext(gdef.CERT_STORE_CERTIFICATE_CONTEXT, ctypes.byref(self), None, title, 0, None)

    KNOWN_PROPERTIES_VALUES = gdef.FlagMapper(
        gdef.CERT_KEY_PROV_HANDLE_PROP_ID,
        gdef.CERT_KEY_PROV_INFO_PROP_ID,
        gdef.CERT_SHA1_HASH_PROP_ID,
        gdef.CERT_MD5_HASH_PROP_ID,
        gdef.CERT_HASH_PROP_ID,
        gdef.CERT_KEY_CONTEXT_PROP_ID,
        gdef.CERT_KEY_SPEC_PROP_ID,
        gdef.CERT_IE30_RESERVED_PROP_ID,
        gdef.CERT_PUBKEY_HASH_RESERVED_PROP_ID,
        gdef.CERT_ENHKEY_USAGE_PROP_ID,
        gdef.CERT_CTL_USAGE_PROP_ID,
        gdef.CERT_NEXT_UPDATE_LOCATION_PROP_ID,
        gdef.CERT_FRIENDLY_NAME_PROP_ID,
        gdef.CERT_PVK_FILE_PROP_ID,
        gdef.CERT_DESCRIPTION_PROP_ID,
        gdef.CERT_ACCESS_STATE_PROP_ID,
        gdef.CERT_SIGNATURE_HASH_PROP_ID,
        gdef.CERT_SMART_CARD_DATA_PROP_ID,
        gdef.CERT_EFS_PROP_ID,
        gdef.CERT_FORTEZZA_DATA_PROP_ID,
        gdef.CERT_ARCHIVED_PROP_ID,
        gdef.CERT_KEY_IDENTIFIER_PROP_ID,
        gdef.CERT_AUTO_ENROLL_PROP_ID,
        gdef.CERT_PUBKEY_ALG_PARA_PROP_ID,
        gdef.CERT_CROSS_CERT_DIST_POINTS_PROP_ID,
        gdef.CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID,
        gdef.CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID,
        gdef.CERT_ENROLLMENT_PROP_ID,
        gdef.CERT_DATE_STAMP_PROP_ID,
        gdef.CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID,
        gdef.CERT_SUBJECT_NAME_MD5_HASH_PROP_ID,
        gdef.CERT_EXTENDED_ERROR_INFO_PROP_ID,
        gdef.CERT_RENEWAL_PROP_ID,
        gdef.CERT_ARCHIVED_KEY_HASH_PROP_ID,
        gdef.CERT_AUTO_ENROLL_RETRY_PROP_ID,
        gdef.CERT_AIA_URL_RETRIEVED_PROP_ID,
        gdef.CERT_AUTHORITY_INFO_ACCESS_PROP_ID,
        gdef.CERT_BACKED_UP_PROP_ID,
        gdef.CERT_OCSP_RESPONSE_PROP_ID,
        gdef.CERT_REQUEST_ORIGINATOR_PROP_ID,
        gdef.CERT_SOURCE_LOCATION_PROP_ID)

    def enum_properties(self):
        prop = 0
        res = []
        while True:
            prop = winproxy.CertEnumCertificateContextProperties(self, prop)
            if not prop:
                return res
            res.append(self.KNOWN_PROPERTIES_VALUES[prop])
        raise RuntimeError("Unreachable code")

    properties = property(enum_properties)
    """The properties of the certificate

    :type: [:class:`int` or :class:`~windows.generated_def.Flag`] -- A list of property ID
    """

    #def get_property(self):
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa376079(v=vs.85).aspx
        # - Usefull:
            # CERT_SHA1_HASH_PROP_ID

    def get_property(self, prop):
        "TODO: DOC :D + auto-type ?"
        datasize = gdef.DWORD()
        windows.winproxy.CertGetCertificateContextProperty(self, prop, None, datasize)
        buf = (gdef.BYTE * datasize.value)()
        windows.winproxy.CertGetCertificateContextProperty(self, prop, buf, datasize)
        return bytearray(buf)


    @property
    def encoded(self):
        """The encoded certificate.

        :type: :class:`bytearray`"""
        return bytearray(self.pbCertEncoded[:self.cbCertEncoded])

    @property
    def version(self):
        """The version number of the certificate

        :type: :class:`int`
        """
        return self.pCertInfo[0].dwVersion


    @classmethod
    def from_file(cls, filename):
        """Create a :class:`Certificate` from the file ``filename``

        :return: :class:`Certificate`
        """
        with open(filename, "rb") as f:
            data = f.read()
            buf = (ctypes.c_ubyte * len(data))(*bytearray(data))
            pcert = windows.winproxy.CertCreateCertificateContext(windows.crypto.DEFAULT_ENCODING, buf, len(data))
            return cls.from_pointer(pcert)

    @classmethod
    def from_buffer(cls, data):
        """Create a :class:`Certificate` from the buffer ``data``

        :return: :class:`Certificate`
        """
        buf = (ctypes.c_ubyte * len(data))(*bytearray(data))
        pcert = windows.winproxy.CertCreateCertificateContext(windows.crypto.DEFAULT_ENCODING, buf, len(data))
        return cls.from_pointer(pcert)

    @classmethod
    def from_pointer(self, ptr):
        return ctypes.cast(ptr, ctypes.POINTER(Certificate))[0]


    def __eq__(self, other):
        if not isinstance(other, Certificate):
            return NotImplemented
        return windows.winproxy.CertCompareCertificate(DEFAULT_ENCODING, self.pCertInfo, other.pCertInfo)

    def __repr__(self):
        return '<{0} "{1}" serial="{2}">'.format(type(self).__name__, self.name, self.serial)





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
# Should be the struct itself (like Certificate ?)
class EPCCERT_CHAIN_CONTEXT(gdef.PCCERT_CHAIN_CONTEXT):
    _type_ = gdef.PCCERT_CHAIN_CONTEXT._type_

    @property
    def chains(self):
        res = []
        # if (self[0].cLowerQualityChainContext):
            # print("LOL")
            # import pdb;pdb.set_trace()
        # if self[0].cChain > 1:
            # print("HAAAAA")
            # import pdb;pdb.set_trace()
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
        return  Certificate.from_pointer(self[0].pCertContext)


# Move this in another .py ?
class CryptContext(gdef.HCRYPTPROV):
    """ A context manager arround ``CryptAcquireContextW`` & ``CryptReleaseContext``

    .. note::
        see usage in sample :ref:`sample_crypto_encryption` (function ``genkeys``)
    """
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