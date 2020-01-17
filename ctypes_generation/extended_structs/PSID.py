_INITIAL_PSID = PSID
class PSID(_INITIAL_PSID): # _INITIAL_PSID -> PVOID

    def __eq__(self, other):
        return bool(windows.winproxy.EqualSid(self, other))

    def __ne__(self, other):
        return not windows.winproxy.EqualSid(self, other)

    @property
    def size(self):
        return windows.winproxy.GetLengthSid(self)

    def duplicate(self):
        size = self.size
        buffer = ctypes.c_buffer(size)
        windows.winproxy.CopySid(size, buffer, self)
        return ctypes.cast(buffer, type(self))

    @classmethod
    def from_string(cls, strsid):
        self = cls()
        windows.winproxy.ConvertStringSidToSidA(strsid, self)
        return self

    def to_string(self):
       sid_str  = LPCSTR()
       windows.winproxy.ConvertSidToStringSidA(self, sid_str)
       result = sid_str.value
       windows.winproxy.LocalFree(sid_str)
       return result

    __str__ = to_string

    def __repr__(self):
        try:
            return """<{0} "{1}">""".format(type(self).__name__, self.to_string())
        except WindowsError: # Case of PSID is not valide
            if not self:
                return """<{0} (NULL) at {1:#x}>""".format(type(self).__name__, id(self))
            return """<{0} "<conversion-failed>" at {1:#x}>""".format(type(self).__name__, id(self))

    __sprint__ = __repr__
