import ctypes

from windows import winproxy
import windows.generated_def as gdef
import windows.crypto

class CryptMessage(gdef.HCRYPTMSG):
    """Represent a PKCS #7 message
    (see `Low-level Message Functions <https://msdn.microsoft.com/en-us/library/windows/desktop/aa380252(v=vs.85).aspx#low_level_message_functions>`_)
    """
    MSG_PARAM_KNOW_TYPES = {gdef.CMSG_SIGNER_INFO_PARAM: gdef.CMSG_SIGNER_INFO,
                            gdef.CMSG_SIGNER_COUNT_PARAM: gdef.DWORD,
                            gdef.CMSG_CERT_COUNT_PARAM: gdef.DWORD,
                            gdef.CMSG_ENVELOPE_ALGORITHM_PARAM: gdef.CRYPT_ALGORITHM_IDENTIFIER,
                            gdef.CMSG_RECIPIENT_COUNT_PARAM: gdef.DWORD,
                            gdef.CMSG_RECIPIENT_INFO_PARAM: gdef.CERT_INFO,
                            }


    def get_param(self, param_type, index=0, raw=False):
        data_size = gdef.DWORD()
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa380227(v=vs.85).aspx
        winproxy.CryptMsgGetParam(self, param_type, index, None, data_size)
        buffer = ctypes.c_buffer(data_size.value)
        winproxy.CryptMsgGetParam(self, param_type, index, buffer, data_size)
        if raw:
            return (buffer, data_size)

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
        """Return embded :class:`Certificate` number ``index``.

        .. note::

            Not all embded certificate are directly used to sign the :class:`CryptObject`.
        """
        return windows.crypto.Certificate.from_buffer(self.get_raw_cert(index))

    @property
    def certs(self):
        """The list of :class:`Certificate` embded in the message"""
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

        :return: :class:`~windows.generated_def.winstructs.CMSG_SIGNER_INFO`
        """
        return self.get_param(gdef.CMSG_SIGNER_INFO_PARAM, index)

    @property
    def signers(self):
        """The list of :class:`~windows.generated_def.winstructs.CMSG_SIGNER_INFO` embed in the message"""
        return [self.get_signer_data(i) for i in range(self.nb_signer)]

    @property
    def nb_recipient(self):
        """TODO: DOC"""
        return self.get_param(gdef.CMSG_RECIPIENT_COUNT_PARAM)


    def get_recipient_data(self, index=0):
        """TODO: DOC"""
        return self.get_param(gdef.CMSG_RECIPIENT_INFO_PARAM, index)

    @property
    def recipients(self):
        """TODO: DOC"""
        return [self.get_recipient_data(i) for i in range(self.nb_recipient)]

    @property
    def content(self):
        return self.get_param(gdef.CMSG_CONTENT_PARAM)[:]

    @property
    def content_type(self):
        data = self.get_param(gdef.CMSG_INNER_CONTENT_TYPE_PARAM)
        assert data[-1] == "\x00", "CMSG_INNER_CONTENT_TYPE_PARAM not NULL TERMINATED"
        return data[:-1]


    def update(self, blob, final):
        # Test isinstance string ?
        if isinstance(blob, (windows.pycompat.anybuff, bytearray)):
            blob = windows.pycompat.raw_encode(blob)
            buffer = windows.utils.BUFFER(gdef.BYTE).from_buffer_copy(blob)
            return winproxy.CryptMsgUpdate(self, buffer, len(blob), final)
        return winproxy.CryptMsgUpdate(self, blob.pbData, blob.cbData, final)

    # constructor
    @classmethod
    def from_buffer(self, data):
        hmsg = winproxy.CryptMsgOpenToDecode(windows.crypto.DEFAULT_ENCODING, 0, 0, None, None, None)
        newmsg = CryptMessage(hmsg)
        newmsg.update(data, final=True)
        return newmsg

    def __del__(self):
        return winproxy.CryptMsgClose(self)
