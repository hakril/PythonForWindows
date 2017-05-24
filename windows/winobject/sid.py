from windows.generated_def import PSID
from windows import winproxy

class EPSID(PSID):
    def __repr__(self):
        return '<Sid "{0}" at {1:#8x}>'.format(str(self), id(self))

    def __str__(self):
       sid_str  = LPCSTR()
       winproxy.ConvertSidToStringSidA(self, sid_str)
       result = sid_str.value
       winproxy.LocalFree(sid_str)
       return result

    @classmethod
    def from_string(cls, sidstr):
        self = cls()
        winproxy.ConvertStringSidToSidA(sidstr, self)
        return self