_INITIAL_PSID = PSID
class PSID(_INITIAL_PSID): # _INITIAL_PSID -> PVOID
    # def __init__(self, strsid=None):
        # if strsid is not None:
            # windows.winproxy.ConvertStringSidToSidA(strsid, self)

    def __str__(self):
       sid_str  = LPCSTR()
       windows.winproxy.ConvertSidToStringSidA(self, sid_str)
       result = sid_str.value
       windows.winproxy.LocalFree(sid_str)
       return result

    def __eq__(self, other):
        return windows.winproxy.EqualSid(self, other)

    @property
    def size(self):
        return windows.winproxy.GetLengthSid(self)

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

    def __repr__(self):
        try:
            return """<{0} "{1}">""".format(type(self).__name__, self.to_string())
        except WindowsError: # Case of PSID is not valide
            if not self:
                return """<{0} "None" at {1:#x}>""".format(type(self).__name__, id(self))
            return """<{0} "<conversion-failed>" at {1:#x}>""".format(type(self).__name__, id(self))

