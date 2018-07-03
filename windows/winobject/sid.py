import ctypes
from windows.generated_def import *
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
        
    def lookup(self):
        Name = LPCSTR()
        cchName = DWORD(-1)
        ReferencedDomainName = LPCSTR()
        cchReferencedDomainName = DWORD(-1)
        peUse = SID_NAME_USE()
        
        result = winproxy.LookupAccountSidA(
            None,
            self,
            Name, 
            ctypes.byref(cchName),
            ReferencedDomainName,
            ctypes.byref(cchReferencedDomainName),
            ctypes.byref(peUse)
        )
        
        if not result:
            return None
        
        cchName.value += 1
        cchReferencedDomainName.value += 1

        Name = ctypes.c_buffer(cchName.value)
        ReferencedDomainName = ctypes.c_buffer(cchReferencedDomainName.value)
        
        winproxy.LookupAccountSidA(
            None,
            self,
            Name, 
            ctypes.byref(cchName),
            ReferencedDomainName,
            ctypes.byref(cchReferencedDomainName),
            ctypes.byref(peUse)
        )
        
        result = "{0}\\{1}".format(ReferencedDomainName.value, Name.value)
        return result

