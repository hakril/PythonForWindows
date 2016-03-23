import os
import ctypes
import copy
import struct

import windows
from windows import winproxy
from windows import utils
from windows.generated_def import windef

from windows.winobject import process
from windows.winobject import network
from windows.winobject import registry
from windows.winobject import exception
from windows.winobject import service
from windows.winobject import volume
from windows.winobject import wmi

from windows.generated_def.winstructs import *

class System(object):
    """Represent the current ``Windows`` system ``Python`` is running on"""

    network = network.Network()  # Object of class :class:`windows.network.Network`
    registry = registry.Registry()  # Object of class :class:`windows.registry.Registry`

    @property
    def processes(self):
        """The list of running processes

        :type: [:class:`WinProcess`] -- A list of Process
		"""
        return self.enumerate_processes()

    @property
    def threads(self):
        """The list of running threads

        :type: [:class:`WinThread`] -- A list of Thread
		"""
        return self.enumerate_threads()

    @property
    def logicaldrives(self):
        return volume.enum_logical_drive()

    @property
    def services(self):
        """The list of services (TODO: BETTER DOC)"""
        return service.enumerate_services()

    #@property
    #def handles(self):
    #    size_needed = ULONG()
    #    size = 0x1000
    #    buffer = ctypes.c_buffer(size)
    #
    #    try:
    #        winproxy.NtQuerySystemInformation(16, buffer, size, ReturnLength=ctypes.byref(size_needed))
    #    except WindowsError as e:
    #        pass
    #
    #    size = size_needed.value + 0x1000
    #    buffer = ctypes.c_buffer(size)
    #    winproxy.NtQuerySystemInformation(16, buffer, size, ReturnLength=ctypes.byref(size_needed))
    #
    #    x = SYSTEM_HANDLE_INFORMATION.from_buffer(buffer)
    #
    #    class _GENERATED_SYSTEM_HANDLE_INFORMATION(ctypes.Structure):
    #        _fields_ = [
    #            ("HandleCount", ULONG),
    #            ("Handles", SYSTEM_HANDLE * x.HandleCount),
    #        ]
    #    return _GENERATED_SYSTEM_HANDLE_INFORMATION.from_buffer_copy(buffer[:size_needed.value]).Handles[:]

    @utils.fixedpropety
    def bitness(self):
        """The bitness of the system

        :type: :class:`int` -- 32 or 64
		"""
        if os.environ["PROCESSOR_ARCHITECTURE"].lower() != "x86":
            return 64
        if "PROCESSOR_ARCHITEW6432" in os.environ:
            return 64
        return 32

    @utils.fixedpropety
    def wmi(self):
        return wmi.WmiRequester()

    #TODO: use GetComputerNameExA ? and recover other names ?
    @utils.fixedpropety
    def computer_name(self):
        size = DWORD(0x1000)
        buf = ctypes.c_buffer(size.value)
        winproxy.GetComputerNameA(buf, ctypes.byref(size))
        return buf[:size.value]

    @staticmethod
    def enumerate_processes():
        process_entry = PROCESSENTRY32()
        process_entry.dwSize = ctypes.sizeof(process_entry)
        snap = winproxy.CreateToolhelp32Snapshot(windef.TH32CS_SNAPPROCESS, 0)
        winproxy.Process32First(snap, process_entry)
        res = []
        res.append(process.WinProcess._from_PROCESSENTRY32(process_entry))
        while winproxy.Process32Next(snap, process_entry):
            res.append(process.WinProcess._from_PROCESSENTRY32(process_entry))
        return res

    @staticmethod
    def enumerate_threads():
        thread_entry = process.WinThread()
        thread_entry.dwSize = ctypes.sizeof(thread_entry)
        snap = winproxy.CreateToolhelp32Snapshot(windef.TH32CS_SNAPTHREAD, 0)
        threads = []
        winproxy.Thread32First(snap, thread_entry)
        threads.append(copy.copy(thread_entry))
        while winproxy.Thread32Next(snap, thread_entry):
            threads.append(copy.copy(thread_entry))
        return threads

    @utils.fixedpropety
    def version(self):
        data = self.get_version()
        result = data.dwMajorVersion, data.dwMinorVersion
        if result == (6,2):
            result_str = self.get_file_version("kernel32")
            result_tup = [int(x) for x in result_str.split(".")]
            result = tuple(result_tup[:2])
        return result

    @utils.fixedpropety
    def version_name(self):
        version = self.version
        is_workstation = self.product_type == VER_NT_WORKSTATION
        if version == (10, 0):
            return ["Windows Server 2016, ""Windows 10"][is_workstation]
        elif version == (6, 3):
            return  ["Windows Server 2012 R2", "Windows 8.1"][is_workstation]
        elif version == (6, 2):
            return ["Windows Server 2012", "Windows 8"][is_workstation]
        elif version == (6, 1):
            return ["Windows Server 2008 R2", "Windows 7"][is_workstation]
        elif version == (6, 0):
            return ["Windows Server 2008", "Windows Vista"][is_workstation]
        elif version == (5, 2):
            metric = winproxy.GetSystemMetrics(SM_SERVERR2)
            if is_workstation:
                if self.bitness == 64:
                    return "Windows XP Professional x64 Edition"
                else:
                    return "TODO: version (5.2) + is_workstation + bitness == 32"
            elif metric != 0:
                return "Windows Server 2003 R2"
            else:
                return "Windows Server 2003"
        elif version == (5, 1):
            return "Windows XP"
        elif version == (5, 0):
            return "Windows 2000"
        else:
            return "Unknow Windows <version={0} | is_workstation={1}>".format(version, is_workstation)

    @utils.fixedpropety
    def product_type(self):
        version_map = {x:x for x in [VER_NT_WORKSTATION, VER_NT_DOMAIN_CONTROLLER, VER_NT_SERVER]}
        version = self.get_version()
        return version_map.get(version.wProductType, version.wProductType)

    def get_version(self):
        data = windows.generated_def.OSVERSIONINFOEXA()
        data.dwOSVersionInfoSize = ctypes.sizeof(data)
        winproxy.GetVersionExA(ctypes.cast(ctypes.pointer(data), ctypes.POINTER(windows.generated_def.OSVERSIONINFOA)))
        return data

    def get_file_version(self, name):
        size = winproxy.GetFileVersionInfoSizeA(name)
        buf = ctypes.c_buffer(size)
        winproxy.GetFileVersionInfoA(name, 0, size, buf)

        bufptr = PVOID()
        bufsize = UINT()
        winproxy.VerQueryValueA(buf, "\\VarFileInfo\\Translation", ctypes.byref(bufptr), ctypes.byref(bufsize))
        bufstr = ctypes.cast(bufptr, LPCSTR)
        tup = struct.unpack("<HH", bufstr.value[:4])
        req = "{0:04x}{1:04x}".format(*tup)
        winproxy.VerQueryValueA(buf, "\\StringFileInfo\\{0}\\ProductVersion".format(req), ctypes.byref(bufptr), ctypes.byref(bufsize))
        bufstr = ctypes.cast(bufptr, LPCSTR)
        return bufstr.value