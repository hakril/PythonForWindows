import windows
from windows import winproxy
from windows.crypto import DEFAULT_ENCODING
import windows.generated_def as gdef

import ctypes

__all__ = ["sign", "verify_signature"]

def sign(cert, msg, detached_signature=False, algo=gdef.szOID_RSA_SHA256RSA):
    # hash algorithm
    alg_hash = gdef.CRYPT_ALGORITHM_IDENTIFIER()
    alg_hash.pszObjId = algo.encode()

    # Signing parameters
    sign_para = gdef.CRYPT_SIGN_MESSAGE_PARA()
    sign_para.cbSize = ctypes.sizeof(sign_para)
    sign_para.dwMsgEncodingType = DEFAULT_ENCODING
    sign_para.pSigningCert = gdef.PCERT_CONTEXT(cert)
    sign_para.HashAlgorithm = alg_hash
    sign_para.pvHashAuxInfo = None
    sign_para.cMsgCert = 0
    sign_para.rgpMsgCert = None
    sign_para.cMsgCrl = 0
    sign_para.rgpMsgCrl = None
    sign_para.cAuthAttr = 0
    sign_para.rgAuthAttr = None
    sign_para.cUnauthAttr = 0
    sign_para.rgUnauthAttr = None
    sign_para.dwFlags = 0
    sign_para.dwInnerContentType = 0
    sign_para.HashEncryptionAlgorithm = alg_hash
    sign_para.pvHashEncryptionAuxInfo = None

    ByteBuffer = windows.utils.BUFFER(gdef.BYTE)

    result_buffer = ByteBuffer(nbelt=0x2000)
    result_size = gdef.DWORD(len(result_buffer))
    buff = ByteBuffer(*bytearray(msg))
    buff_pr = windows.utils.BUFFER(gdef.LPBYTE, nbelt=1)(buff)
    buff_size = gdef.DWORD(len(msg))
    try:
        windows.winproxy.CryptSignMessage(sign_para, False, 1, buff_pr, buff_size, result_buffer, result_size)
    except WindowsError as e:
        if not e.winerror == gdef.ERROR_MORE_DATA:
            raise
        result_buffer = ByteBuffer(nbelt=result_size.value)
        windows.winproxy.CryptSignMessage(sign_para, False, 1, buff_pr, buff_size, result_buffer, result_size)
    return bytearray(result_buffer[:result_size.value])


def verify_signature(cert, encoded_blob):
    # Verify parameters
    verif_param = gdef.CRYPT_KEY_VERIFY_MESSAGE_PARA()
    verif_param.cbSize = ctypes.sizeof(gdef.CRYPT_KEY_VERIFY_MESSAGE_PARA)
    verif_param.dwMsgEncodingType = windows.crypto.DEFAULT_ENCODING
    verif_param.hCryptProv = None
    # The public key used
    pubkey = cert.pCertInfo[0].SubjectPublicKeyInfo
    # Preparing in/out buffer/size
    signed_buffer = windows.utils.BUFFER(gdef.BYTE).from_buffer_copy(encoded_blob)
    decoded_buffer = windows.utils.BUFFER(gdef.BYTE).from_buffer_copy(encoded_blob)
    decoded_size = gdef.DWORD(len(decoded_buffer))
    winproxy.CryptVerifyMessageSignatureWithKey(verif_param,
                                                    pubkey,
                                                    signed_buffer,
                                                    len(encoded_blob),
                                                    decoded_buffer,
                                                    decoded_size)
    return bytearray(decoded_buffer[:decoded_size.value])