class _CRYPT_BIT_BLOB(_CRYPT_BIT_BLOB):

    @property
    def data(self):
        return bytearray(self.pbData[:self.cbData])