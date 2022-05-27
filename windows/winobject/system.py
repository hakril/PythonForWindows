import os
import ctypes
import copy
import struct

import windows
from windows import winproxy
from windows import utils

import windows.generated_def as gdef



from windows.winobject import process
from windows.winobject import network
from windows.winobject import registry
from windows.winobject import exception
from windows.winobject import service
from windows.winobject import volume
from windows.winobject import wmi
from windows.winobject import object_manager
from windows.winobject import device_manager
from windows.winobject import handle
from windows.winobject import event_log
from windows.winobject import event_trace
from windows.winobject import task_scheduler
from windows.winobject import system_module
from windows.winobject import bits

from windows.dbgprint import dbgprint

class System(object):
    """The state of the current ``Windows`` system ``Python`` is running on"""

    # Setup these in a fixedproperty ?
    network = network.Network()
    """Object of class :class:`windows.winobject.network.Network`"""
    registry = registry.Registry()
    """Object of class :class:`windows.winobject.registry.Registry`"""

    @property
    def processes(self):
        """The list of running processes

        :type: [:class:`~windows.winobject.process.WinProcess`] -- A list of Process
		"""
        return self.enumerate_processes()

    @property
    def threads(self):
        """The list of running threads

        :type: [:class:`~windows.winobject.process.WinThread`] -- A list of Thread
		"""
        return self.enumerate_threads_setup_owners()

    @property
    def logicaldrives(self):
        """List of logical drives [C:\, ...]

        :type: [:class:`~windows.winobject.volume.LogicalDrive`] -- A list of LogicalDrive
        """
        return volume.enum_logical_drive()

    @utils.fixedpropety
    def services(self):
        """An object to query, list and explore services

        :type: :class:`~windows.winobject.service.ServiceManager`
        """
        return service.ServiceManager()

    @property
    def handles(self):
        """The list of system handles

        :type: [:class:`~windows.winobject.handle.Handle`] -- A list of Hanlde"""
        return handle.enumerate_handles()

    @property
    def modules(self):
        """The list of system modules

        :type: [:class:`~windows.winobject.system_module.SystemModule`] -- A list of :class:`~windows.winobject.system_module.SystemModule` or :class:`~windows.winobject.system_module.SystemModuleWow64`
        """
        return system_module.enumerate_kernel_modules()

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

        :type: :class:`~windows.winobject.wmi.WmiManager`"""
        return wmi.WmiManager()


    @utils.fixedpropety
    def event_log(self):
        """An object to open Event channel/publisher and evtx file

        :type: :class:`~windows.winobject.event_log.EvtlogManager`
        """
        return event_log.EvtlogManager()

    @utils.fixedpropety
    def etw(self):
        """An object to interact with  ETW (Event Tracing for Windows)

        :type: :class:`~windows.winobject.event_trace.EtwManager`
        """
        return event_trace.EtwManager()


    @utils.fixedpropety
    def task_scheduler(self):
        """An object able to manage scheduled tasks on the local system

        :type: :class:`~windows.winobject.task_scheduler.TaskService`
        """
        windows.com.init()
        clsid_task_scheduler = gdef.IID.from_string("0f87369f-a4e5-4cfc-bd3e-73e6154572dd")
        task_service = task_scheduler.TaskService()
        # What is non-implemented (WinXP)
        # Raise (NotImplementedError?) ? Return NotImplemented ?
        windows.com.create_instance(clsid_task_scheduler, task_service)
        task_service.connect()
        return task_service

    @utils.fixedpropety
    def object_manager(self):
        """An object to query the objects in the kernel object manager.

        :type: :class:`~windows.winobject.object_manager.ObjectManager`
        """
        return windows.winobject.object_manager.ObjectManager()

    @utils.fixedpropety
    def device_manager(self):
        """An object to query the device&driver configured on the computer.

        :type: :class:`~windows.winobject.device_manager.DeviceManager`
        """
        return windows.winobject.device_manager.DeviceManager()

    @utils.fixedpropety
    def bits(self):
        return bits.create_manager()

    #TODO: use GetComputerNameExA ? and recover other names ?
    @utils.fixedpropety
    def computer_name(self):
        """The name of the computer

        :type: :class:`str`
        """
        size = gdef.DWORD(0x1000)
        # For now I don't know what is best as A vs W APIs...
        if windows.pycompat.is_py3:
            buf = ctypes.create_unicode_buffer(size.value)
            winproxy.GetComputerNameW(buf, ctypes.byref(size))
        else:
            buf = ctypes.create_string_buffer(size.value)
            winproxy.GetComputerNameA(buf, ctypes.byref(size))
        return buf[:size.value]

    def _computer_name_ex(self, nametype):
        size = gdef.DWORD(0)
        try:
            winproxy.GetComputerNameExW(nametype, None, ctypes.byref(size))
        except WindowsError as e:
            if e.winerror != gdef.ERROR_MORE_DATA:
                raise

        buf = ctypes.create_unicode_buffer(size.value)
        winproxy.GetComputerNameExW(nametype, buf, ctypes.byref(size))
        return buf[:size.value]

    @utils.fixedproperty
    def domain(self):
        # [WIP] name of the domain joined by the computer, None is no domain joined
        return self._computer_name_ex(gdef.ComputerNameDnsDomain) or None

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
        is_workstation = self.product_type == gdef.VER_NT_WORKSTATION
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
            metric = winproxy.GetSystemMetrics(gdef.SM_SERVERR2)
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

    VERSION_MAPPER = gdef.FlagMapper(gdef.VER_NT_WORKSTATION, gdef.VER_NT_DOMAIN_CONTROLLER, gdef.VER_NT_SERVER)
    @utils.fixedpropety
    def product_type(self):
        """The product type, value might be:

            * VER_NT_WORKSTATION(0x1L)
            * VER_NT_DOMAIN_CONTROLLER(0x2L)
            * VER_NT_SERVER(0x3L)

        :type: :class:`long` or :class:`int` (or subclass)
        """
        version = self.get_version()
        return self.VERSION_MAPPER[version.wProductType]


    EDITION_MAPPER = gdef.FlagMapper(gdef.PRODUCT_UNDEFINED,
        gdef.PRODUCT_ULTIMATE,
        gdef.PRODUCT_HOME_BASIC,
        gdef.PRODUCT_HOME_PREMIUM,
        gdef.PRODUCT_ENTERPRISE,
        gdef.PRODUCT_HOME_BASIC_N,
        gdef.PRODUCT_BUSINESS,
        gdef.PRODUCT_STANDARD_SERVER,
        gdef.PRODUCT_DATACENTER_SERVER,
        gdef.PRODUCT_SMALLBUSINESS_SERVER,
        gdef.PRODUCT_ENTERPRISE_SERVER,
        gdef.PRODUCT_STARTER,
        gdef.PRODUCT_DATACENTER_SERVER_CORE,
        gdef.PRODUCT_STANDARD_SERVER_CORE,
        gdef.PRODUCT_ENTERPRISE_SERVER_CORE,
        gdef.PRODUCT_ENTERPRISE_SERVER_IA64,
        gdef.PRODUCT_BUSINESS_N,
        gdef.PRODUCT_WEB_SERVER,
        gdef.PRODUCT_CLUSTER_SERVER,
        gdef.PRODUCT_HOME_SERVER,
        gdef.PRODUCT_STORAGE_EXPRESS_SERVER,
        gdef.PRODUCT_STORAGE_STANDARD_SERVER,
        gdef.PRODUCT_STORAGE_WORKGROUP_SERVER,
        gdef.PRODUCT_STORAGE_ENTERPRISE_SERVER,
        gdef.PRODUCT_SERVER_FOR_SMALLBUSINESS,
        gdef.PRODUCT_SMALLBUSINESS_SERVER_PREMIUM,
        gdef.PRODUCT_HOME_PREMIUM_N,
        gdef.PRODUCT_ENTERPRISE_N,
        gdef.PRODUCT_ULTIMATE_N,
        gdef.PRODUCT_WEB_SERVER_CORE,
        gdef.PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT,
        gdef.PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY,
        gdef.PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING,
        gdef.PRODUCT_SERVER_FOUNDATION,
        gdef.PRODUCT_HOME_PREMIUM_SERVER,
        gdef.PRODUCT_SERVER_FOR_SMALLBUSINESS_V,
        gdef.PRODUCT_STANDARD_SERVER_V,
        gdef.PRODUCT_DATACENTER_SERVER_V,
        gdef.PRODUCT_ENTERPRISE_SERVER_V,
        gdef.PRODUCT_DATACENTER_SERVER_CORE_V,
        gdef.PRODUCT_STANDARD_SERVER_CORE_V,
        gdef.PRODUCT_ENTERPRISE_SERVER_CORE_V,
        gdef.PRODUCT_HYPERV,
        gdef.PRODUCT_STORAGE_EXPRESS_SERVER_CORE,
        gdef.PRODUCT_STORAGE_STANDARD_SERVER_CORE,
        gdef.PRODUCT_STORAGE_WORKGROUP_SERVER_CORE,
        gdef.PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE,
        gdef.PRODUCT_STARTER_N,
        gdef.PRODUCT_PROFESSIONAL,
        gdef.PRODUCT_PROFESSIONAL_N,
        gdef.PRODUCT_SB_SOLUTION_SERVER,
        gdef.PRODUCT_SERVER_FOR_SB_SOLUTIONS,
        gdef.PRODUCT_STANDARD_SERVER_SOLUTIONS,
        gdef.PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE,
        gdef.PRODUCT_SB_SOLUTION_SERVER_EM,
        gdef.PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM,
        gdef.PRODUCT_SOLUTION_EMBEDDEDSERVER,
        gdef.PRODUCT_SOLUTION_EMBEDDEDSERVER_CORE,
        gdef.PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE,
        gdef.PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT,
        gdef.PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL,
        gdef.PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC,
        gdef.PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC,
        gdef.PRODUCT_CLUSTER_SERVER_V,
        gdef.PRODUCT_EMBEDDED,
        gdef.PRODUCT_STARTER_E,
        gdef.PRODUCT_HOME_BASIC_E,
        gdef.PRODUCT_HOME_PREMIUM_E,
        gdef.PRODUCT_PROFESSIONAL_E,
        gdef.PRODUCT_ENTERPRISE_E,
        gdef.PRODUCT_ULTIMATE_E,
        gdef.PRODUCT_ENTERPRISE_EVALUATION,
        gdef.PRODUCT_MULTIPOINT_STANDARD_SERVER,
        gdef.PRODUCT_MULTIPOINT_PREMIUM_SERVER,
        gdef.PRODUCT_STANDARD_EVALUATION_SERVER,
        gdef.PRODUCT_DATACENTER_EVALUATION_SERVER,
        gdef.PRODUCT_ENTERPRISE_N_EVALUATION,
        gdef.PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER,
        gdef.PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER,
        gdef.PRODUCT_CORE_ARM,
        gdef.PRODUCT_CORE_N,
        gdef.PRODUCT_CORE_COUNTRYSPECIFIC,
        gdef.PRODUCT_CORE_LANGUAGESPECIFIC,
        gdef.PRODUCT_CORE,
        gdef.PRODUCT_PROFESSIONAL_WMC,
        gdef.PRODUCT_UNLICENSED)

    @utils.fixedpropety
    def edition(self): # Find a better name ?
        version = self.get_version()
        edition = gdef.DWORD()
        try:
            winproxy.GetProductInfo(version.dwMajorVersion,
                                        version.dwMinorVersion,
                                        version.wServicePackMajor,
                                        version.wServicePackMinor,
                                        edition)
        except winproxy.ExportNotFound as e:
            # Windows XP does not implem GetProductInfo
            assert version.dwMajorVersion, version.dwMinorVersion == (5,1)
            return self._edition_windows_xp()
        return self.EDITION_MAPPER[edition.value]

    def _edition_windows_xp(self):
        # Emulate standard response from IsOS(gdef.OS_PROFESSIONAL)
        if winproxy.IsOS(gdef.OS_PROFESSIONAL):
            return gdef.PRODUCT_PROFESSIONAL
        return gdef.PRODUCT_HOME_BASIC

    @utils.fixedpropety
    def windir(self):
        buffer = ctypes.c_buffer(0x100)
        reslen = winproxy.GetWindowsDirectoryA(buffer)
        return buffer[:reslen]

    def get_version(self):
        data = gdef.OSVERSIONINFOEXA()
        data.dwOSVersionInfoSize = ctypes.sizeof(data)
        winproxy.GetVersionExA(ctypes.cast(ctypes.pointer(data), ctypes.POINTER(gdef.OSVERSIONINFOA)))
        return data

    def get_file_version(self, name):
        size = winproxy.GetFileVersionInfoSizeA(name)
        buf = ctypes.c_buffer(size)
        winproxy.GetFileVersionInfoA(name, 0, size, buf)

        bufptr = gdef.PVOID()
        bufsize = gdef.UINT()
        winproxy.VerQueryValueA(buf, "\\VarFileInfo\\Translation", ctypes.byref(bufptr), ctypes.byref(bufsize))
        bufstr = ctypes.cast(bufptr, gdef.LPCSTR)
        tup = struct.unpack("<HH", bufstr.value[:4])
        req = "{0:04x}{1:04x}".format(*tup)
        winproxy.VerQueryValueA(buf, "\\StringFileInfo\\{0}\\ProductVersion".format(req), ctypes.byref(bufptr), ctypes.byref(bufsize))
        bufstr = ctypes.cast(bufptr, gdef.LPCSTR)
        return bufstr.value

    @utils.fixedpropety
    def build_number(self):
        # Best effort. use get_file_version if registry code fails
        try:
            # Does not works on Win7..
            # Missing CurrentMajorVersionNumber/CurrentMinorVersionNumber/UBR
            # We have CurrentVersion instead
            # Use this code and get_file_version as a backup ?
            curver_key = windows.system.registry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            try:
                major = curver_key["CurrentMajorVersionNumber"].value
                minor = curver_key["CurrentMinorVersionNumber"].value
            except WindowsError as e:
                version = curver_key["CurrentVersion"].value
                # May raise ValueError if no "."
                major, minor = version.split(".")
            build = curver_key["CurrentBuildNumber"].value
            # Update Build Revision
            try:
                ubr = curver_key["UBR"].value
            except WindowsError as e:
                ubr = 0 # Not present on Win7
            return "{0}.{1}.{2}.{3}".format(major, minor, build, ubr)
        except (WindowsError, ValueError):
            return self.get_file_version("ntdll")


    @staticmethod
    def enumerate_processes():
        dbgprint("Enumerating processes with CreateToolhelp32Snapshot", "SLOW")
        process_entry = gdef.PROCESSENTRY32W()
        process_entry.dwSize = ctypes.sizeof(process_entry)
        snap = winproxy.CreateToolhelp32Snapshot(gdef.TH32CS_SNAPPROCESS, 0)
        winproxy.Process32FirstW(snap, process_entry)
        res = []
        res.append(process.WinProcess._from_PROCESSENTRY32(process_entry))
        while winproxy.Process32NextW(snap, process_entry):
            res.append(process.WinProcess._from_PROCESSENTRY32(process_entry))
        winproxy.CloseHandle(snap)
        return res

    @staticmethod
    def enumerate_threads_generator():
        # Ptet dangereux, parce que on yield la meme THREADENTRY32 a chaque fois
        dbgprint("Enumerating threads with CreateToolhelp32Snapshot <generator>", "SLOW")
        thread_entry = gdef.THREADENTRY32()
        thread_entry.dwSize = ctypes.sizeof(thread_entry)
        snap = winproxy.CreateToolhelp32Snapshot(gdef.TH32CS_SNAPTHREAD, 0)
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
        snap = winproxy.CreateToolhelp32Snapshot(gdef.TH32CS_SNAPTHREAD | gdef.TH32CS_SNAPPROCESS, 0)

        process_entry = gdef.PROCESSENTRY32W()
        process_entry.dwSize = ctypes.sizeof(process_entry)
        winproxy.Process32FirstW(snap, process_entry)
        processes = []
        processes.append(process.WinProcess._from_PROCESSENTRY32(process_entry))
        while winproxy.Process32NextW(snap, process_entry):
            processes.append(process.WinProcess._from_PROCESSENTRY32(process_entry))

        # Forge a dict pid -> process
        proc_dict = {proc.pid: proc for proc in processes}

        thread_entry = gdef.THREADENTRY32()
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