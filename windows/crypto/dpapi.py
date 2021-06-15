from windows import winproxy
import windows.generated_def as gdef

__all__ = ["protect", "unprotect"]


def protect(data, entropy=None, flags=gdef.CRYPTPROTECT_UI_FORBIDDEN):
    in_blob = gdef.DATA_BLOB.from_string(data)
    out_blob = gdef.DATA_BLOB()
    if entropy is not None:
        entropy = gdef.DATA_BLOB.from_string(entropy)
    winproxy.CryptProtectData(in_blob, pOptionalEntropy=entropy, dwFlags=flags, pDataOut=out_blob)
    encrypted_data = bytes(out_blob.data)
    # https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
    # pDataOut:     A pointer to a DATA_BLOB structure that receives the encrypted data.
    # When you have finished using the DATA_BLOB structure, free its pbData member by calling the LocalFree function.
    winproxy.LocalFree(out_blob.pbData)
    del out_blob
    return encrypted_data


def unprotect(data, entropy=None, flags=gdef.CRYPTPROTECT_UI_FORBIDDEN):
    in_blob = gdef.DATA_BLOB.from_string(data)
    out_blob = gdef.DATA_BLOB()
    if entropy is not None:
        entropy = gdef.DATA_BLOB.from_string(entropy)
    winproxy.CryptUnprotectData(in_blob, pOptionalEntropy=entropy, dwFlags=flags, pDataOut=out_blob)
    decrypted_data = bytes(out_blob.data)
    # https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
    # pDataOut:     A pointer to a DATA_BLOB structure that receives the encrypted data.
    # When you have finished using the DATA_BLOB structure, free its pbData member by calling the LocalFree function.
    winproxy.LocalFree(out_blob.pbData)
    del out_blob
    return decrypted_data