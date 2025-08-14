import windows.winproxy as winproxy
import windows.generated_def as gdef

def binary_to_string(data, flags=gdef.CRYPT_STRING_BASE64, header=None):
    if header is not None:
        if flags != gdef.CRYPT_STRING_BASE64:
            raise ValueError("custom_header parameter can only be used with flags==CRYPT_STRING_BASE64")
    databuff = (gdef.BYTE * len(data))(*data)
    buffsize = gdef.DWORD(0)
    winproxy.CryptBinaryToStringW (databuff, len(databuff), flags, None, buffsize)

    resbuff = (gdef.WCHAR * buffsize.value)()

    winproxy.CryptBinaryToStringW(databuff, len(databuff), flags, resbuff, buffsize)
    strres = resbuff[:buffsize.value]
    if header:
        strres = "-----BEGIN {header}-----\r\n{0}-----END {header}-----".format(strres, header=header)
    return strres

def string_to_binary(data, flags=gdef.CRYPT_STRING_ANY):
    # Get the buffer size
    buffsize = gdef.DWORD(0)
    winproxy.CryptStringToBinaryW(data, len(data), flags, None, buffsize, None, None)

    # Decode
    resbuff = (gdef.BYTE * buffsize.value)()
    skipped = gdef.DWORD()
    outflags = gdef.DWORD()

    winproxy.CryptStringToBinaryW(data, len(data), flags, resbuff, buffsize, skipped, outflags)
    return bytearray(resbuff[:buffsize.value])
