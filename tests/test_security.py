import pytest
import threading
import time

from windows.security import *
import windows.generated_def as gdef

from pfwtest import *


GROUP_SID = 'S-1-5-18'
SDDL = "O:LAG:SYD:PAI(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;SY)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;SY)S:AI(AU;SAFA;DCLCRPCRSDWDWO;;;WD)"
INVALID_SDDL = "E:LAG:SYD:PAI(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;SY)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;SY)S:AI(AU;SAFA;DCLCRPCRSDWDWO;;;WD)"


def test_load_sddl_from_string():
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR().from_string(SDDL)
    assert pSecurityDescriptor.to_string() == SDDL


def test_security_descriptor_validity():
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR().from_string(SDDL)
    assert pSecurityDescriptor.valid
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR().from_string(INVALID_SDDL)
    assert not pSecurityDescriptor.valid


def test_security_descriptor_control():
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR().from_string(SDDL)
    assert SE_DACL_PRESENT in pSecurityDescriptor.control.flags
    assert SE_SACL_PRESENT in pSecurityDescriptor.control.flags
    assert SE_DACL_AUTO_INHERITED in pSecurityDescriptor.control.flags
    assert SE_SACL_AUTO_INHERITED in pSecurityDescriptor.control.flags
    assert SE_SELF_RELATIVE in pSecurityDescriptor.control.flags

    
def test_security_descriptor_owner():
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR().from_string(SDDL)
    owner = pSecurityDescriptor.owner
    # Not perfect for now... we will see later
    assert str(owner).endswith('-500')


def test_security_descriptor_group():
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR().from_string(SDDL)
    group = pSecurityDescriptor.primary_group
    assert str(group) == GROUP_SID
    

def test_security_descriptor_dacl():
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR().from_string(SDDL)
    dacl = pSecurityDescriptor.dacl
    
    assert len(dacl) == 6
    
    # 1st DACL ACE = Authorized FA to System
    assert dacl[0].type == ACCESS_ALLOWED_ACE_TYPE
    assert str(dacl[0].sid) == SECURITY_LOCAL_SYSTEM_RID
    assert dacl[0].Mask == ADS_RIGHT_DS_CREATE_CHILD | ADS_RIGHT_DS_SELF | ADS_RIGHT_DS_WRITE_PROP | ADS_RIGHT_DS_LIST_OBJECT | ADS_RIGHT_READ_CONTROL | ADS_RIGHT_SYNCHRONIZE
    
    
def test_security_descriptor_sacl():
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR().from_string(SDDL)
    sacl = pSecurityDescriptor.sacl

    assert len(sacl) == 1
    
    # 1st SACL ACE = Success access on all properties by Everyone (WD)
    assert sacl[0].type == SYSTEM_AUDIT_ACE_TYPE
    assert SUCCESSFUL_ACCESS_ACE_FLAG in sacl[0].flags
    assert str(sacl[0].sid) == "S-1-1-0"
    

def test_security_descriptor_load_from_handle():
    filename = "C:\\Windows\\System32\\lsass.exe"
    if windows.current_process.bitness == 32:
        filename = "C:\\Windows\\sysnative\\lsass.exe"
    handle = winproxy.CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL)
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR.from_handle(handle, object_type=SE_FILE_OBJECT)
    assert pSecurityDescriptor.valid
    assert pSecurityDescriptor.owner.lookup() == "NT SERVICE\\TrustedInstaller"
    winproxy.CloseHandle(handle)


def test_security_descriptor_load_from_name():
    filename = "C:\\Windows\\System32\\lsass.exe"
    if windows.current_process.bitness == 32:
        filename = "C:\\Windows\\sysnative\\lsass.exe"
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR.from_name(filename, object_type=SE_FILE_OBJECT)
    assert pSecurityDescriptor.valid
    assert pSecurityDescriptor.valid
    assert pSecurityDescriptor.owner.lookup() == "NT SERVICE\\TrustedInstaller"
    
    pSecurityDescriptor = EPSECURITY_DESCRIPTOR.from_name('Spooler', object_type=SE_SERVICE)
    assert str(pSecurityDescriptor.owner) == SECURITY_LOCAL_SYSTEM_RID

    pSecurityDescriptor = EPSECURITY_DESCRIPTOR.from_name('CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', object_type=SE_REGISTRY_KEY)
    assert str(pSecurityDescriptor.owner) == SECURITY_LOCAL_SYSTEM_RID

