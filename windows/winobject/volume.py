import ctypes

import windows
from windows import winproxy
import windows.generated_def as gdef
from windows.generated_def.winstructs import *

from windows.utils import AutoHandle

import sys


class LogicalDrive(AutoHandle):
    DRIVE_TYPE = gdef.FlagMapper(DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR, DRIVE_REMOVABLE,
                    DRIVE_FIXED, DRIVE_REMOTE, DRIVE_CDROM, DRIVE_RAMDISK)

    def __init__(self, name):
        self.name = name

    @property
    def type(self):
        """The type of drive, values are:

            * DRIVE_UNKNOWN(0x0L)
            * DRIVE_NO_ROOT_DIR(0x1L)
            * DRIVE_REMOVABLE(0x2L)
            * DRIVE_FIXED(0x3L)
            * DRIVE_REMOTE(0x4L)
            * DRIVE_CDROM(0x5L)
            * DRIVE_RAMDISK(0x6L)

        :type: :class:`long` or :class:`int` (or subclass)
        """
        t = winproxy.GetDriveTypeW(self.name)
        return self.DRIVE_TYPE.get(t,t)

    @property
    def path(self):
        """The target path of the device

        :type: :class:`str`"""
        # QueryDosDevice can returns multiple path if DefineDosDevice(AW) was used before
        # Looks like its per-process
        # But in ths cas the first entry is the effective-one and the others are the previous entries
        # https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-querydosdevicea
        # The first null-terminated string stored into the buffer is the current mapping for the device. The other null-terminated strings represent undeleted prior mappings for the device.
        return query_dos_device(self.name.strip("\\"))[0]

    @property
    def query_dos_device(self):
        return query_dos_device(self.name.strip("\\"))

    def query_info(self, info):
        return windows.utils.query_volume_information(self.handle, info)

    @property
    def volume_info(self):
        return self.query_info(gdef.FileFsVolumeInformation)

    @property
    def serial(self):
        return self.volume_info.VolumeSerialNumber

    def _get_handle(self):
        nt_name = windows.utils.dospath_to_ntpath(self.name)
        handle = windows.winproxy.CreateFileW(nt_name, gdef.GENERIC_READ,
                                                gdef.FILE_SHARE_READ, None, gdef.OPEN_EXISTING, gdef.FILE_FLAG_BACKUP_SEMANTICS , None)
        return handle

    def __repr__(self):
        return """<{0} "{1}" ({2})>""".format(type(self).__name__, self.name, self.type.name)

def enum_logical_drive():
    return [LogicalDrive(name) for name in get_logical_drive_names()]

def get_logical_drive_names():
    size = 0x100
    buffer = ctypes.create_unicode_buffer(size)
    rsize = winproxy.GetLogicalDriveStringsW(size, buffer)
    return buffer[:rsize].rstrip(u"\x00").split(u"\x00")

def get_info(drivename):
    size = 0x1000
    volume_name = ctypes.create_unicode_buffer(size)
    fs_name = ctypes.create_unicode_buffer(size)
    flags = DWORD()
    winproxy.GetVolumeInformationW(drivename, volume_name, size, None, None, ctypes.byref(flags), fs_name, size)
    return volume_name[:10], fs_name[:10]

def query_dos_device(name):
    size = 0x1000
    buffer = ctypes.create_unicode_buffer(size)
    rsize = winproxy.QueryDosDeviceW(name, buffer, size)
    return buffer[:rsize].rstrip(u"\x00").split(u"\x00")