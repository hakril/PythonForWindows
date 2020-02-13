from os import urandom

from windows import winproxy
from windows.crypto import DEFAULT_ENCODING
from windows.generated_def import *

__all__ = ["encrypt", "decrypt"]

def encode_init_vector(data):
    blob = CRYPT_DATA_BLOB.from_string(data)
    size = DWORD()
    buf = None
    winproxy.CryptEncodeObjectEx(DEFAULT_ENCODING, X509_OCTET_STRING, ctypes.byref(blob), 0, None, buf, size)
    buf = (BYTE * size.value)()
    winproxy.CryptEncodeObjectEx(DEFAULT_ENCODING, X509_OCTET_STRING, ctypes.byref(blob), 0, None, buf, size)
    return buf[:]


class GenerateInitVector(object):
    def __repr__(self):
        return "GenerateInitVector()"

    def generate_init_vector(self, algo):
        if algo in [szOID_OIWSEC_desCBC, szOID_RSA_DES_EDE3_CBC]:
            return urandom(8)
        if algo in [szOID_NIST_AES128_CBC, szOID_NIST_AES192_CBC, szOID_NIST_AES256_CBC]:
            return urandom(16)
        return None
geninitvector = GenerateInitVector()


def encrypt(cert_or_certlist, msg, algo=szOID_NIST_AES256_CBC, initvector=geninitvector):
    """Encrypt ``msg`` one or many :class:`Certificate` using ``algo`` with the initial
       vector ``initvector``.

       If ``geninitvector`` is left as it is, it will generate a random one.

       Algorithms supported by ``GenerateInitVector`` are:

        * ``szOID_OIWSEC_desCBC``
        * ``szOID_RSA_DES_EDE3_CBC``
        * ``szOID_NIST_AES128_CBC``
        * ``szOID_NIST_AES192_CBC``
        * ``szOID_NIST_AES256_CBC``

       :param cert_or_certlist: One or many :class:`Certificate` used to encrypt the msg
       :type cert_or_certlist: :class:`Certificate` | [:class:`Certificate`]
       :return: :class:`bytearray`: The encrypted message
    """
    alg_ident = CRYPT_ALGORITHM_IDENTIFIER()
    alg_ident.pszObjId = algo.encode("ascii")
    # We want to have automatique translation of Certificate -> PCERT_CONTEXT
    # In order to simple create the  'PCERT_CONTEXT[] certs'
    # For that we need a tuple of X * 1-item-tuple
    # as a (cert,) will be automaticly translatable to a PCERT_CONTEXT
    if isinstance(cert_or_certlist, CERT_CONTEXT):
        certlist = ((cert_or_certlist,),)
    else:
        certlist = tuple((c,) for c in cert_or_certlist)

    # Set (compute if needed) the IV
    if initvector is None:
        alg_ident.Parameters.cbData = 0
    elif initvector is geninitvector:
        initvector = initvector.generate_init_vector(algo)
        if initvector is None:
            raise ValueError("I don't know how to generate an <initvector> for <{0}> please provide one (or None)".format(algo))
        initvector_encoded = encode_init_vector(initvector)
        alg_ident.Parameters = CRYPT_DATA_BLOB.from_string(initvector_encoded)
    else:
        initvector_encoded = encode_init_vector(initvector)
        alg_ident.Parameters = CRYPT_DATA_BLOB.from_string(initvector_encoded)

    # Setup encryption parameters
    param = CRYPT_ENCRYPT_MESSAGE_PARA()
    param.cbSize = ctypes.sizeof(param)
    param.dwMsgEncodingType = DEFAULT_ENCODING
    param.hCryptProv = None
    param.ContentEncryptionAlgorithm = alg_ident
    param.pvEncryptionAuxInfo = None
    param.dwFlags = 0
    param.dwInnerContentType = 0


    certs = (PCERT_CONTEXT * len(certlist))(*certlist)
    #Ask the output buffer size
    size = DWORD()
    winproxy.CryptEncryptMessage(param, len(certs), certs, msg, len(msg), None, size)
    #Encrypt the msg
    buf =  (BYTE * size.value)()
    winproxy.CryptEncryptMessage(param, len(certs), certs, msg, len(msg), buf, size)
    return bytearray(buf[:size.value])


def decrypt(cert_store, encrypted):
    """Try to decrypt the ``encrypted`` msg with any certificate in ``cert_store``.

        If there is no certificate able to decrypt the message ``WinproxyError(winerror=0x8009200c)`` is raised.

        :param cert_store:
        :type cert_store: :class:`CertificateStore`
        :return: :class:`str`: The decrypted message
    """
    # Setup decryption parameters
    dparam = CRYPT_DECRYPT_MESSAGE_PARA()
    dparam.cbSize = ctypes.sizeof(dparam)
    dparam.dwMsgAndCertEncodingType = DEFAULT_ENCODING
    dparam.cCertStore = 1
    dparam.rghCertStore = (cert_store,)
    dparam.dwFlags = 0

    #Ask the output buffer size
    buf = (BYTE * len(encrypted)).from_buffer_copy(encrypted)
    dcryptsize = DWORD()
    winproxy.CryptDecryptMessage(dparam, buf, ctypes.sizeof(buf), None, dcryptsize, None)
    #Decrypt the msg
    dcryptbuff = (BYTE * (dcryptsize.value + 0x1000))()
    winproxy.CryptDecryptMessage(dparam, buf, ctypes.sizeof(buf), dcryptbuff, dcryptsize, None)
    return bytes(bytearray(dcryptbuff[:dcryptsize.value]))
