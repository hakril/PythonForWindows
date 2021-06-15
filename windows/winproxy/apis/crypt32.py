import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import no_error_check, fail_on_zero

import windows.pycompat
from windows.pycompat import int_types

class Crypt32Proxy(ApiProxy):
    APIDLL = "crypt32"
    default_error_check = staticmethod(fail_on_zero)

# Certificate

@Crypt32Proxy()
def CertStrToNameA(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError):
    return CertStrToNameA.ctypes_function(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)


@Crypt32Proxy()
def CertStrToNameW(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError):
    return CertStrToNameW.ctypes_function(dwCertEncodingType, pszX500, dwStrType, pvReserved, pbEncoded, pcbEncoded, ppszError)

@Crypt32Proxy()
def CertGetNameStringA(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString):
    return CertGetNameStringA.ctypes_function(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)


@Crypt32Proxy()
def CertGetNameStringW(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString):
    return CertGetNameStringW.ctypes_function(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString)

@Crypt32Proxy()
def CertCreateSelfSignCertificate(hCryptProvOrNCryptKey, pSubjectIssuerBlob, dwFlags, pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions):
    return CertCreateSelfSignCertificate.ctypes_function(hCryptProvOrNCryptKey, pSubjectIssuerBlob, dwFlags, pKeyProvInfo, pSignatureAlgorithm, pStartTime, pEndTime, pExtensions)

@Crypt32Proxy()
def CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, pcbData):
    return CertGetCertificateContextProperty.ctypes_function(pCertContext, dwPropId, pvData, pcbData)

@Crypt32Proxy(error_check=no_error_check)
def CertEnumCertificateContextProperties(pCertContext, dwPropId):
    return CertEnumCertificateContextProperties.ctypes_function(pCertContext, dwPropId)

@Crypt32Proxy()
def CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded):
    return CertCreateCertificateContext.ctypes_function(dwCertEncodingType, pbCertEncoded, cbCertEncoded)


## Certificate chain

@Crypt32Proxy()
def CertGetCertificateChain(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext):
    return CertGetCertificateChain.ctypes_function(hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext)

@Crypt32Proxy()
def CertDuplicateCertificateContext(pCertContext):
    return CertDuplicateCertificateContext.ctypes_function(pCertContext)

@Crypt32Proxy()
def CertFreeCertificateContext(pCertContext):
   return CertFreeCertificateContext.ctypes_function(pCertContext)

@Crypt32Proxy(error_check=no_error_check)
def CertCompareCertificate(dwCertEncodingType, pCertId1, pCertId2):
    """This function does not raise is compare has failed:
        return 0 if cert are NOT equals
    """
    return CertCompareCertificate.ctypes_function(dwCertEncodingType, pCertId1, pCertId2)

@Crypt32Proxy()
def CryptHashCertificate(hCryptProv, Algid, dwFlags, pbEncoded, cbEncoded, pbComputedHash, pcbComputedHash):
   return CryptHashCertificate.ctypes_function(hCryptProv, Algid, dwFlags, pbEncoded, cbEncoded, pbComputedHash, pcbComputedHash)

## Certificate store

@Crypt32Proxy()
def CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara):
    if isinstance(lpszStoreProvider, int_types):
        lpszStoreProvider = gdef.LPCSTR(lpszStoreProvider)
    return CertOpenStore.ctypes_function(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara)

@Crypt32Proxy()
def CertAddCertificateContextToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext):
    return CertAddCertificateContextToStore.ctypes_function(hCertStore, pCertContext, dwAddDisposition, ppStoreContext)

@Crypt32Proxy()
def CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext):
    return CertFindCertificateInStore.ctypes_function(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, pvFindPara, pPrevCertContext)

@Crypt32Proxy()
def CertEnumCertificatesInStore(hCertStore, pPrevCertContext):
    return CertEnumCertificatesInStore.ctypes_function(hCertStore, pPrevCertContext)

@Crypt32Proxy()
def PFXExportCertStoreEx(hStore, pPFX, szPassword, pvPara, dwFlags):
    return PFXExportCertStoreEx.ctypes_function(hStore, pPFX, szPassword, pvPara, dwFlags)

@Crypt32Proxy()
def PFXImportCertStore(pPFX, szPassword, dwFlags):
    return PFXImportCertStore.ctypes_function(pPFX, szPassword, dwFlags)

@Crypt32Proxy()
def CertEnumCTLsInStore(hCertStore, pPrevCtlContext):
    return CertEnumCTLsInStore.ctypes_function(hCertStore, pPrevCtlContext)

@Crypt32Proxy()
def CertCloseStore(hCertStore, dwFlags):
    return CertCloseStore.ctypes_function(hCertStore, dwFlags)


# Key

@Crypt32Proxy()
def CryptAcquireCertificatePrivateKey(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey):
    return CryptAcquireCertificatePrivateKey.ctypes_function(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey)



# Encrypt / Decrypt

@Crypt32Proxy()
def CryptEncryptMessage(pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob, pcbEncryptedBlob):
    if isinstance(pbToBeEncrypted, windows.pycompat.anybuff):
        # Transform string to array of byte
        pbToBeEncrypted = (gdef.BYTE * len(pbToBeEncrypted))(*bytearray(pbToBeEncrypted))
    if cbToBeEncrypted is None and pbToBeEncrypted is not None:
        cbToBeEncrypted = len(pbToBeEncrypted)
    return CryptEncryptMessage.ctypes_function(pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob, pcbEncryptedBlob)

@Crypt32Proxy()
def CryptDecryptMessage(pDecryptPara, pbEncryptedBlob, cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert):
    return CryptDecryptMessage.ctypes_function(pDecryptPara, pbEncryptedBlob, cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert)




# Sign / Verify

@Crypt32Proxy()
def CryptSignMessage(pSignPara, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, pbSignedBlob, pcbSignedBlob):
    return CryptSignMessage.ctypes_function(pSignPara, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, pbSignedBlob, pcbSignedBlob)


@Crypt32Proxy()
def CryptSignAndEncryptMessage(pSignPara, pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeSignedAndEncrypted, cbToBeSignedAndEncrypted, pbSignedAndEncryptedBlob, pcbSignedAndEncryptedBlob):
    return CryptSignAndEncryptMessage.ctypes_function(pSignPara, pEncryptPara, cRecipientCert, rgpRecipientCert, pbToBeSignedAndEncrypted, cbToBeSignedAndEncrypted, pbSignedAndEncryptedBlob, pcbSignedAndEncryptedBlob)


@Crypt32Proxy()
def CryptVerifyMessageSignature(pVerifyPara, dwSignerIndex, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded, ppSignerCert):
    return CryptVerifyMessageSignature.ctypes_function(pVerifyPara, dwSignerIndex, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded, ppSignerCert)


@Crypt32Proxy()
def CryptVerifyMessageSignatureWithKey(pVerifyPara, pPublicKeyInfo, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded):
    return CryptVerifyMessageSignatureWithKey.ctypes_function(pVerifyPara, pPublicKeyInfo, pbSignedBlob, cbSignedBlob, pbDecoded, pcbDecoded)


@Crypt32Proxy()
def CryptVerifyMessageHash(pHashPara, pbHashedBlob, cbHashedBlob, pbToBeHashed, pcbToBeHashed, pbComputedHash, pcbComputedHash):
    return CryptVerifyMessageHash.ctypes_function(pHashPara, pbHashedBlob, cbHashedBlob, pbToBeHashed, pcbToBeHashed, pbComputedHash, pcbComputedHash)


# Crypt-object

@Crypt32Proxy()
def CryptEncodeObjectEx(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded):
    lpszStructType = gdef.LPCSTR(lpszStructType) if isinstance(lpszStructType, int_types) else lpszStructType
    return CryptEncodeObjectEx.ctypes_function(dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded)

@Crypt32Proxy()
def CryptQueryObject(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext):
    return CryptQueryObject.ctypes_function(dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags, dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType, phCertStore, phMsg, ppvContext)

@Crypt32Proxy()
def CryptDecodeObject(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo):
    return CryptDecodeObject.ctypes_function(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo)

@Crypt32Proxy()
def CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, pvData, pcbData):
    return CryptMsgGetParam.ctypes_function(hCryptMsg, dwParamType, dwIndex, pvData, pcbData)

@Crypt32Proxy()
def CryptMsgOpenToEncode(dwMsgEncodingType, dwFlags, dwMsgType, pvMsgEncodeInfo, pszInnerContentObjID, pStreamInfo):
    return CryptMsgOpenToEncode.ctypes_function(dwMsgEncodingType, dwFlags, dwMsgType, pvMsgEncodeInfo, pszInnerContentObjID, pStreamInfo)

@Crypt32Proxy()
def CryptMsgOpenToDecode(dwMsgEncodingType, dwFlags, dwMsgType, hCryptProv, pRecipientInfo, pStreamInfo):
    return CryptMsgOpenToDecode.ctypes_function(dwMsgEncodingType, dwFlags, dwMsgType, hCryptProv, pRecipientInfo, pStreamInfo)

@Crypt32Proxy()
def CryptMsgUpdate(hCryptMsg, pbData, cbData, fFinal):
    return CryptMsgUpdate.ctypes_function(hCryptMsg, pbData, cbData, fFinal)

@Crypt32Proxy()
def CryptMsgControl(hCryptMsg, dwFlags, dwCtrlType, pvCtrlPara):
    return CryptMsgControl.ctypes_function(hCryptMsg, dwFlags, dwCtrlType, pvCtrlPara)


@Crypt32Proxy()
def CryptMsgVerifyCountersignatureEncoded(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, pciCountersigner):
    return CryptMsgVerifyCountersignatureEncoded.ctypes_function(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, pciCountersigner)

@Crypt32Proxy()
def CryptMsgVerifyCountersignatureEncodedEx(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, dwSignerType, pvSigner, dwFlags, pvExtra):
    return CryptMsgVerifyCountersignatureEncodedEx.ctypes_function(hCryptProv, dwEncodingType, pbSignerInfo, cbSignerInfo, pbSignerInfoCountersignature, cbSignerInfoCountersignature, dwSignerType, pvSigner, dwFlags, pvExtra)


@Crypt32Proxy()
def CryptMsgClose(hCryptMsg):
    return CryptMsgClose.ctypes_function(hCryptMsg)

@Crypt32Proxy()
def CryptEnumOIDFunction(dwEncodingType, pszFuncName, pszOID, dwFlags, pvArg, pfnEnumOIDFunc):
    return CryptEnumOIDFunction.ctypes_function(dwEncodingType, pszFuncName, pszOID, dwFlags, pvArg, pfnEnumOIDFunc)

@Crypt32Proxy()
def CryptGetOIDFunctionValue(dwEncodingType, pszFuncName, pszOID, pwszValueName, pdwValueType, pbValueData, pcbValueData):
    return Cry
    ptGetOIDFunctionValue.ctypes_function(dwEncodingType, pszFuncName, pszOID, pwszValueName, pdwValueType, pbValueData, pcbValueData)


# DPAPI

@Crypt32Proxy()
def CryptProtectData(pDataIn, szDataDescr=None, pOptionalEntropy=None, pvReserved=None, pPromptStruct=None, dwFlags=0, pDataOut=NeededParameter):
    return CryptProtectData.ctypes_function(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)

@Crypt32Proxy()
def CryptUnprotectData(pDataIn, ppszDataDescr=None, pOptionalEntropy=None, pvReserved=None, pPromptStruct=None, dwFlags=0, pDataOut=NeededParameter):
    return CryptUnprotectData.ctypes_function(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)

@Crypt32Proxy()
def CryptProtectMemory(pDataIn, cbDataIn, dwFlags):
    return CryptProtectMemory.ctypes_function(pDataIn, cbDataIn, dwFlags)

@Crypt32Proxy()
def CryptUnprotectMemory(pDataIn, cbDataIn, dwFlags):
    return CryptUnprotectMemory.ctypes_function(pDataIn, cbDataIn, dwFlags)
