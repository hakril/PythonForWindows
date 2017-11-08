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
from windows.winobject import kernobj
from windows.winobject import handle

from windows.generated_def.winstructs import *
from windows.dbgprint import dbgprint

class System(object):
    """The state of the current ``Windows`` system ``Python`` is running on"""

    network = network.Network()
    """Object of class :class:`windows.winobject.network.Network`"""
    registry = registry.Registry()
    """Object of class :class:`windows.winobject.registry.Registry`"""

    @property
    def processes(self):
        """The list of running processes

        :type: [:class:`process.WinProcess`] -- A list of Process
		"""
        return self.enumerate_processes()

    @property
    def threads(self):
        """The list of running threads

        :type: [:class:`process.WinThread`] -- A list of Thread
		"""
        return self.enumerate_threads_setup_owners()

    @property
    def logicaldrives(self):
        """List of logical drives [C:\, ...]

        :type: [:class:`volume.LogicalDrive`] -- A list of LogicalDrive
        """
        return volume.enum_logical_drive()

    @property
    def services(self):
        """The list of services

        :type: [:class:`service.ServiceA`] -- A list of Service"""
        return service.enumerate_services()

    @property
    def handles(self):
        """The list of system handles

        :type: [:class:`handle.Handle`] -- A list of Hanlde"""
        return handle.enumerate_handles()

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
        r"""An object to perform wmi requests to various namespaces

        :type: :class:`windows.winobject.wmi.WmiManager`"""
        return wmi.WmiManager()

    #TODO: use GetComputerNameExA ? and recover other names ?
    @utils.fixedpropety
    def computer_name(self):
        """The name of the computer

        :type: :class:`str`
        """
        size = DWORD(0x1000)
        buf = ctypes.c_buffer(size.value)
        winproxy.GetComputerNameA(buf, ctypes.byref(size))
        return buf[:size.value]

    @utils.fixedpropety
    def version(self):
        """The version of the system

        :type: (:class:`int`, :class:`int`) -- (Major, Minor)
        """
        data = self.get_version()
        result = data.dwMajorVersion, data.dwMinorVersion
        if result == (6,2):
            result_str = self.get_file_version("kernel32")
            result_tup = [int(x) for x in result_str.split(".")]
            result = tuple(result_tup[:2])
        return result

    @utils.fixedpropety
    def version_name(self):
        """The name of the system version,  values are:

            * Windows Server 2016
            * Windows 10
            * Windows Server 2012 R2
            * Windows 8.1
            * Windows Server 2012
            * Windows 8
            * Windows Server 2008
            * Windows 7
            * Windows Server 2008
            * Windows Vista
            * Windows XP Professional x64 Edition
            * TODO: version (5.2) + is_workstation + bitness == 32 (don't even know if possible..)
            * Windows Server 2003 R2
            * Windows Server 2003
            * Windows XP
            * Windows 2000
            * "Unknow Windows <version={0} | is_workstation={1}>".format(version, is_workstation)

        :type: :class:`str`
        """
        version = self.version
        is_workstation = self.product_type == VER_NT_WORKSTATION
        if version == (10, 0):
            return ["Windows Server 2016", "Windows 10"][is_workstation]
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
        """The product type, value might be:

            * VER_NT_WORKSTATION(0x1L)
            * VER_NT_DOMAIN_CONTROLLER(0x2L)
            * VER_NT_SERVER(0x3L)

        :type: :class:`long` or :class:`int` (or subclass)
        """
        version_map = {x:x for x in [VER_NT_WORKSTATION, VER_NT_DOMAIN_CONTROLLER, VER_NT_SERVER]}
        version = self.get_version()
        return version_map.get(version.wProductType, version.wProductType)


    @utils.fixedpropety
    def windir(self):
        buffer = ctypes.c_buffer(0x100)
        reslen = winproxy.GetWindowsDirectoryA(buffer)
        return buffer[:reslen]

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

    @utils.fixedpropety
    def build_number(self):
        return self.get_file_version("ntdll")

    @staticmethod
    def enumerate_processes():
        dbgprint("Enumerating processes with CreateToolhelp32Snapshot", "SLOW")
        process_entry = PROCESSENTRY32()
        process_entry.dwSize = ctypes.sizeof(process_entry)
        snap = winproxy.CreateToolhelp32Snapshot(windef.TH32CS_SNAPPROCESS, 0)
        winproxy.Process32First(snap, process_entry)
        res = []
        res.append(process.WinProcess._from_PROCESSENTRY32(process_entry))
        while winproxy.Process32Next(snap, process_entry):
            res.append(process.WinProcess._from_PROCESSENTRY32(process_entry))
        winproxy.CloseHandle(snap)
        return res

    @staticmethod
    def enumerate_threads_generator():
        # Ptet dangereux, parce que on yield la meme THREADENTRY32 a chaque fois
        dbgprint("Enumerating threads with CreateToolhelp32Snapshot <generator>", "SLOW")
        thread_entry = THREADENTRY32()
        thread_entry.dwSize = ctypes.sizeof(thread_entry)
        snap = winproxy.CreateToolhelp32Snapshot(windef.TH32CS_SNAPTHREAD, 0)
        dbgprint("New handle CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) <generator> | {0:#x}".format(snap), "HANDLE")
        try:
            winproxy.Thread32First(snap, thread_entry)
            yield thread_entry
            while winproxy.Thread32Next(snap, thread_entry):
                yield thread_entry
        finally:
            winproxy.CloseHandle(snap)
        dbgprint("CLOSE CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) <generator> | {0:#x}".format(snap), "HANDLE")


    @staticmethod
    def enumerate_threads():
        return [WinThread._from_THREADENTRY32(th) for th in System.enumerate_threads_generator()]


    def enumerate_threads_setup_owners(self):
        # Enumerating threads is a special operation concerning the owner process.
        # We may not be able to retrieve the name of the owning process by normal way
        # (as we need to get a handle on the process)
        # So, this implementation of enumerate_thread also setup the owner with the result of enumerate_processes
        dbgprint("Enumerating threads with CreateToolhelp32Snapshot and setup owner", "SLOW")

        # One snap for both enum to be prevent race
        snap = winproxy.CreateToolhelp32Snapshot(windef.TH32CS_SNAPTHREAD | windef.TH32CS_SNAPPROCESS, 0)

        process_entry = PROCESSENTRY32()
        process_entry.dwSize = ctypes.sizeof(process_entry)
        winproxy.Process32First(snap, process_entry)
        processes = []
        processes.append(process.WinProcess._from_PROCESSENTRY32(process_entry))
        while winproxy.Process32Next(snap, process_entry):
            processes.append(process.WinProcess._from_PROCESSENTRY32(process_entry))

        # Forge a dict pid -> process
        proc_dict = {proc.pid: proc for proc in processes}

        thread_entry = THREADENTRY32()
        thread_entry.dwSize = ctypes.sizeof(thread_entry)
        threads = []
        winproxy.Thread32First(snap, thread_entry)
        parent = proc_dict[thread_entry.th32OwnerProcessID]
        threads.append(process.WinThread._from_THREADENTRY32(thread_entry, owner=parent))
        while winproxy.Thread32Next(snap, thread_entry):
            parent = proc_dict[thread_entry.th32OwnerProcessID]
            threads.append(process.WinThread._from_THREADENTRY32(thread_entry, owner=parent))
        winproxy.CloseHandle(snap)
        return threads