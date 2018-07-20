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
    

    def internal_lookup(self):
        Name = LPCSTR()
        cchName = DWORD(0x1000)
        ReferencedDomainName = LPCSTR()
        cchReferencedDomainName = DWORD(0x1000)
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
        
        return ReferencedDomainName.value, Name.value

    
    def lookup(self):
        return self.internal_lookup()
    
    
    def __eq__(self, other):
        return str(self) == str(other)