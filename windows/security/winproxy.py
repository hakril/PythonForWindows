import ctypes
from windows.winproxy import ApiProxy


def no_error_check(func_name, result, func, args):
    return args

    
class Advapi32Proxy(ApiProxy):
    APIDLL = "Advapi32"
    default_error_check = staticmethod(no_error_check)
    

######### SECURITY DESCRIPTOR FUNCTIONS #############
@Advapi32Proxy("IsValidSecurityDescriptor")
def IsValidSecurityDescriptor(pSecurityDescriptor):
   return IsValidSecurityDescriptor.ctypes_function(pSecurityDescriptor)

@Advapi32Proxy("ConvertStringSecurityDescriptorToSecurityDescriptorA")
def ConvertStringSecurityDescriptorToSecurityDescriptorA(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize):
   return ConvertStringSecurityDescriptorToSecurityDescriptorA.ctypes_function(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize)

@Advapi32Proxy("ConvertSecurityDescriptorToStringSecurityDescriptorA")
def ConvertSecurityDescriptorToStringSecurityDescriptorA(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen):
   return ConvertSecurityDescriptorToStringSecurityDescriptorA.ctypes_function(SecurityDescriptor, RequestedStringSDRevision, SecurityInformation, StringSecurityDescriptor, StringSecurityDescriptorLen)

@Advapi32Proxy("GetSecurityDescriptorDacl")
def GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted):
   return GetSecurityDescriptorDacl.ctypes_function(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted)

@Advapi32Proxy("GetSecurityDescriptorLength")
def GetSecurityDescriptorLength(pSecurityDescriptor):
   return GetSecurityDescriptorLength.ctypes_function(pSecurityDescriptor)
   
@Advapi32Proxy("IsValidSecurityDescriptor")
def IsValidSecurityDescriptor(pSecurityDescriptor):
   return IsValidSecurityDescriptor.ctypes_function(pSecurityDescriptor)
   
@Advapi32Proxy("GetSecurityDescriptorControl")
def GetSecurityDescriptorControl(pSecurityDescriptor, pControl, lpdwRevision):
   return GetSecurityDescriptorControl.ctypes_function(pSecurityDescriptor, pControl, lpdwRevision)

@Advapi32Proxy("GetSecurityDescriptorOwner")
def GetSecurityDescriptorOwner(pSecurityDescriptor, pOwner, lpbOwnerDefaulted):
   return GetSecurityDescriptorOwner.ctypes_function(pSecurityDescriptor, pOwner, lpbOwnerDefaulted)

@Advapi32Proxy("GetSecurityDescriptorGroup")
def GetSecurityDescriptorGroup(pSecurityDescriptor, pGroup, lpbGroupDefaulted):
   return GetSecurityDescriptorGroup.ctypes_function(pSecurityDescriptor, pGroup, lpbGroupDefaulted)

@Advapi32Proxy("GetSecurityDescriptorDacl")
def GetSecurityDescriptorDacl(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted):
   return GetSecurityDescriptorDacl.ctypes_function(pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted)

@Advapi32Proxy("GetSecurityDescriptorSacl")
def GetSecurityDescriptorSacl(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted):
   return GetSecurityDescriptorSacl.ctypes_function(pSecurityDescriptor, lpbSaclPresent, pSacl, lpbSaclDefaulted)

@Advapi32Proxy("GetAce")
def GetAce(pAcl, dwAceIndex, pAce):
   return GetAce.ctypes_function(pAcl, dwAceIndex, pAce)

