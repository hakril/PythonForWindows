import windows
from windows import winproxy
from windows.crypto import DEFAULT_ENCODING
from windows.crypto.helper import ECRYPT_DATA_BLOB
import windows.generated_def as gdef

import ctypes

__all__ = ["sign", "verify_signature"]

def sign(cert, msg, detached_signature=False):
    # hash algorithm
    alg_hash = gdef.CRYPT_ALGORITHM_IDENTIFIER()
    alg_hash.pszObjId = gdef.szOID_RSA_SHA256RSA # Set as parameter ?

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

    # TODO: Clean
    result_buffer = windows.utils.buffer(gdef.BYTE, len(msg) + 0x2000)()
    result_size = gdef.DWORD(len(result_buffer))
    buff_pr = windows.utils.buffer(gdef.LPBYTE)(windows.utils.CharBuffer.from_buffer_copy(msg).cast(gdef.LPBYTE))
    buff_size = gdef.DWORD(len(msg))
    windows.winproxy.CryptSignMessage(sign_para, False, 1, buff_pr, buff_size, result_buffer.cast(gdef.LPBYTE), result_size)
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
    signed_buffer = windows.utils.buffer(gdef.BYTE).from_buffer_copy(encoded_blob)
    decoded_buffer = windows.utils.CharBuffer.from_buffer_copy(encoded_blob)
    decoded_size = gdef.DWORD(len(decoded_buffer))
    winproxy.CryptVerifyMessageSignatureWithKey(verif_param,
                                                    pubkey,
                                                    signed_buffer.cast(gdef.LPBYTE),
                                                    len(encoded_blob),
                                                    decoded_buffer.cast(gdef.LPBYTE),
                                                    decoded_size)
    return decoded_buffer[:decoded_size.value]