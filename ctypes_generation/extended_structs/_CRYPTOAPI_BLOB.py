class _CRYPTOAPI_BLOB(_CRYPTOAPI_BLOB):
    @classmethod
    def from_string(cls, buf):
        self = cls()
        self.cbData = len(buf)
        self.pbData = (BYTE * self.cbData)(*bytearray(buf))
        return self

    @property
    def data(self):
        return bytearray(self.pbData[:self.cbData])