import ctypes

import windows
from windows import winproxy
from windows.generated_def.winstructs import *




class LogicalDrive(object):
    DRIVE_TYPE = {x:x for x in [DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR, DRIVE_REMOVABLE,
                    DRIVE_FIXED, DRIVE_REMOTE, DRIVE_CDROM, DRIVE_RAMDISK]}

    def __init__(self, name):
        self.name = name

    @property
    def type(self):
        t = winproxy.GetDriveTypeA(self.name)
        return self.DRIVE_TYPE.get(t,t)

    @property
    def path(self):
        return query_dos_device(self.name.strip("\\"))

    def __repr__(self):
        return """<{0} "{1}" ({2})>""".format(type(self).__name__, self.name, self.type.name)



def enum_logical_drive():
    return [LogicalDrive(name) for name in get_logical_drive_names()]

def get_logical_drive_names():
    size = 0x100
    buffer = ctypes.c_buffer(size)
    rsize = winproxy.GetLogicalDriveStringsA(0x1000, buffer)
    return buffer[:rsize].rstrip("\x00").split("\x00")

def get_info(drivename):
    size = 0x1000
    volume_name = ctypes.c_buffer(size)
    fs_name = ctypes.c_buffer(size)
    flags = DWORD()
    winproxy.GetVolumeInformationA(drivename, volume_name, size, None, None, ctypes.byref(flags), fs_name, size)
    raise NotImplementedError("get_info")

def query_dos_device(name):
    size = 0x1000
    buffer = ctypes.c_buffer(size)
    rsize = winproxy.QueryDosDeviceA(name, buffer, size)
    return buffer[:rsize].rstrip("\x00").split("\x00")