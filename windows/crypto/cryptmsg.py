import ctypes

from windows import winproxy
import windows.generated_def as gdef
import windows.crypto

class CryptMessage(gdef.HCRYPTMSG):
    MSG_PARAM_KNOW_TYPES = {gdef.CMSG_SIGNER_INFO_PARAM: gdef.CMSG_SIGNER_INFO,
                            gdef.CMSG_SIGNER_COUNT_PARAM: gdef.DWORD,
                            gdef.CMSG_CERT_COUNT_PARAM: gdef.DWORD}


    def get_param(self, param_type, index=0):
        data_size = gdef.DWORD()
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa380227(v=vs.85).aspx
        winproxy.CryptMsgGetParam(self, param_type, index, None, data_size)
        buffer = ctypes.c_buffer(data_size.value)
        winproxy.CryptMsgGetParam(self, param_type, index, buffer, data_size)

        if param_type in self.MSG_PARAM_KNOW_TYPES:
            buffer = self.MSG_PARAM_KNOW_TYPES[param_type].from_buffer(buffer)
        if isinstance(buffer, gdef.DWORD): # DWORD -> return the Python int
            return buffer.value
        return buffer


    # Certificate accessors

    @property
    def nb_cert(self):
        """The number of certificate embded in the :class:`CryptObject`

        :type: :class:`int`
        """
        return self.get_param(gdef.CMSG_CERT_COUNT_PARAM)

    def get_raw_cert(self, index=0):
        return self.get_param(gdef.CMSG_CERT_PARAM, index)

    def get_cert(self, index=0):
        """Return embded certificate number ``index``.

        note: not all embded certificate are directly used to sign the :class:`CryptObject`.

        :return: :class:`CertificateContext`
        """
        return windows.crypto.CertificateContext.from_buffer(self.get_raw_cert(index))

    @property
    def certs(self):
        "TODO: DOC"
        return [self.get_cert(i) for i in range(self.nb_cert)]

    # Signers accessors

    @property
    def nb_signer(self):
        """The number of signers for the CryptObject

        :type: :class:`int`
        """
        try:
            return self.get_param(gdef.CMSG_SIGNER_COUNT_PARAM)
        except WindowsError as e:
            if (e.winerror & 0xffffffff) == gdef.CRYPT_E_INVALID_MSG_TYPE:
                return 0
            raise


    def get_signer_data(self, index=0):
        """Returns the signer informations for signer nb ``index``

        :return: :class:`CMSG_SIGNER_INFO`
        """
        return self.get_param(gdef.CMSG_SIGNER_INFO_PARAM, index)

    @property
    def signers(self):
        return [self.get_signer_data(i) for i in range(self.nb_signer)]

    @property
    def signers_and_certs(self):
        return [(self.get_signer_data(i), self.get_signer_certificate(i)) for i in range(self.nb_signer)]

    # def __repr__