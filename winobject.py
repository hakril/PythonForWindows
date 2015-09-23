import ctypes
import os
import copy
import time
import struct

import windows
import windows.syswow64
import windows.winproxy as winproxy
import windows.injection as injection
import windows.native_exec as native_exec
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

from . import utils
from windows.dbgprint import dbgprint
from windows.generated_def.winstructs import *
from .generated_def import windef

import windows.pe_parse as pe_parse


class AutoHandle(object):
    """An abstract class that allow easy handle creation/destruction"""
    def _get_handle(self):
        raise NotImplementedError("{0} is abstract".format(type(self).__name__))

    @property
    def handle(self):
        """A handle on the object

           .. note::
                The handle is automaticaly closed when the object is destroyed

           :type: int

        """
        if hasattr(self, "_handle"):
            return self._handle
        self._handle = self._get_handle()
        return self._handle

    def __del__(self):
        if hasattr(self, "_handle") and self._handle:
            winproxy.CloseHandle(self._handle)


class System(object):
    """Represent the current windows system python is running on"""
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

    @utils.fixedpropety
    def bitness(self):
        """The bitness of the system

        :type: int -- 32 or 64

        """
        if os.environ["PROCESSOR_ARCHITECTURE"].lower() != "x86":
            return 64
        if "PROCESSOR_ARCHITEW6432" in os.environ:
            return 64
        return 32

    @staticmethod
    def enumerate_processes():
        process_entry = WinProcess()
        process_entry.dwSize = ctypes.sizeof(process_entry)
        snap = winproxy.CreateToolhelp32Snapshot(windef.TH32CS_SNAPPROCESS, 0)
        winproxy.Process32First(snap, process_entry)
        res = []
        res.append(utils.swallow_ctypes_copy(process_entry))
        while winproxy.Process32Next(snap, process_entry):
            res.append(utils.swallow_ctypes_copy(process_entry))
        return res

    @staticmethod
    def enumerate_threads():
        thread_entry = WinThread()
        thread_entry.dwSize = ctypes.sizeof(thread_entry)
        snap = winproxy.CreateToolhelp32Snapshot(windef.TH32CS_SNAPTHREAD, 0)
        threads = []
        winproxy.Thread32First(snap, thread_entry)
        threads.append(copy.copy(thread_entry))
        while winproxy.Thread32Next(snap, thread_entry):
            threads.append(copy.copy(thread_entry))
        return threads


class WinThread(THREADENTRY32, AutoHandle):
    """Represent a thread """
    @utils.fixedpropety
    def tid(self):
        """Thread ID"""
        return self.th32ThreadID

    @utils.fixedpropety
    def owner(self):
        """The Process owning the thread

        :type: :class:`WinProcess`

        """
        if hasattr(self, "_owner"):
            return self._owner
        try:
            self._owner = [process for process in windows.system.processes if process.pid == self.th32OwnerProcessID][0]
        except IndexError:
            return None
        return self._owner

    @property
    def context(self):
        x = windows.vectored_exception.EnhancedCONTEXT()
        x.ContextFlags = CONTEXT_FULL
        winproxy.GetThreadContext(self.handle, x)
        return x

    def set_context(self, context):
        return winproxy.SetThreadContext(self.handle, context)

    def exit(self, code=0):
        return winproxy.TerminateThread(self.handle, code)

    def resume(self):
        return winproxy.ResumeThread(self.handle)

    def suspend(self):
        return winproxy.SuspendThread(self.handle)

    def _get_handle(self):
        return winproxy.OpenThread(dwThreadId=self.tid)

    def __repr__(self):
        owner = self.owner
        if owner is None:
            owner_name = "<Dead process with pid {0}>".format(hex(self.th32OwnerProcessID))
        else:
            owner_name = owner.name
        return '<{0} {1} owner "{2}" at {3}>'.format(self.__class__.__name__, self.tid, owner_name, hex(id(self)))

    @staticmethod
    def _from_handle(handle):
        tid = winproxy.GetThreadId(handle)
        print(tid)
        try:
            return [t for t in System().threads if t.tid == tid][0]
        except IndexError:
            return (tid, handle)


class Process(AutoHandle):
    @utils.fixedpropety
    def is_wow_64(self):
        """Is True if the process is a SysWow64 process

        This means a 32bits process on a 64bits system

        :type: bool
        """
        return utils.is_wow_64(self.handle)

    @utils.fixedpropety
    def bitness(self):
        """The bitness of the process

        :returns: int -- 32 or 64"""
        if windows.system.bitness == 32:
            return 32
        if self.is_wow_64:
            return 32
        return 64

    @property
    def threads(self):
        """The threads of the process

        :type: [:class:`WinThread`] -- A list of Thread

        """
        return [thread for thread in windows.system.threads if thread.th32OwnerProcessID == self.pid]

    def virtual_alloc(self, size):
        raise NotImplementedError("virtual_alloc")

    def execute(self, code):
        """Execute some raw code in the context of the process"""
        x = self.virtual_alloc(len(code))
        self.write_memory(x, code)
        return self.create_thread(x, 0)


class CurrentThread(AutoHandle):
    """The current thread"""
    @utils.fixedpropety
    def tid(self):
        """Thread ID"""
        return winproxy.GetCurrentThreadId()

    @utils.fixedpropety
    def owner(self):
        """The current process

        :type: :class:`CurrentProcess`
        """
        return windows.current_process

    def _get_handle(self):
        return winproxy.GetCurrentThread()

    def __del__(self):
        pass

    def exit(self, code=0):
        """Exit the thread"""
        return winproxy.ExitThread(code)


class CurrentProcess(Process):
    """The current process"""
    get_peb = None

    get_peb_32_code = x86.MultipleInstr()
    get_peb_32_code += x86.Mov('EAX', x86.mem('fs:[0x30]'))
    get_peb_32_code += x86.Ret()
    get_peb_32_code = get_peb_32_code.get_code()

    get_peb_64_code = x64.MultipleInstr()
    get_peb_64_code += x64.Mov('RAX', x64.mem('gs:[0x60]'))
    get_peb_64_code += x64.Ret()
    get_peb_64_code = get_peb_64_code.get_code()

    allocator = native_exec.native_function.allocator

    def get_peb_builtin(self):
        if self.get_peb is not None:
            return self.get_peb
        if self.bitness == 32:
            get_peb = native_exec.create_function(self.get_peb_32_code, [PVOID])
        else:
            get_peb = native_exec.create_function(self.get_peb_64_code, [PVOID])
        self.get_peb = get_peb
        return get_peb

    def _get_handle(self):
        return winproxy.GetCurrentProcess()

    def __del__(self):
        pass

    @property
    def pid(self):
        """Process ID

        :type: int
        """
        return os.getpid()

    # Is there a better way ?
    @utils.fixedpropety
    def ppid(self):
        """Parent Process ID

        :type: int
        """
        return [p for p in windows.system.processes if p.pid == self.pid][0].ppid

    @utils.fixedpropety
    def peb(self):
        """The Process Environment Block of the current process

        :type: :class:`PEB`
        """
        return PEB.from_address(self.get_peb_builtin()())

    @utils.fixedpropety
    def bitness(self):
        """The bitness of the process

        :returns: int -- 32 or 64"""
        import platform
        bits = platform.architecture()[0]
        return int(bits[:2])

    def virtual_alloc(self, size):
        """Allocate memory in the current process

        :returns: int
        """
        return winproxy.VirtualAlloc(dwSize=size)

    def write_memory(self, addr, data):
        """Write data at addr"""
        buffertype = (c_char * len(data)).from_address(addr)
        buffertype[:len(data)] = data
        return True

    def read_memory(self, addr, size):
        """Read size from adddr"""
        dbgprint('Read CurrentProcess Memory', 'READMEM')
        buffer = (c_char * size).from_address(addr)
        return buffer[:]

    def create_thread(self, lpStartAddress, lpParameter, dwCreationFlags=0):
        """Create a new thread

        .. note::
            CreateThread https://msdn.microsoft.com/en-us/library/windows/desktop/ms682453%28v=vs.85%29.aspx
        """
        handle = winproxy.CreateThread(lpStartAddress=lpStartAddress, lpParameter=lpParameter, dwCreationFlags=dwCreationFlags)
        return WinThread._from_handle(handle)

    def exit(self, code=0):
        """Exit the process"""
        return winproxy.ExitProcess(code)


class WinProcess(PROCESSENTRY32, Process):
    """A Process on the system"""
    is_pythondll_injected = 0
    is_remote_slave_running = False

    @utils.fixedpropety
    def name(self):
        """Name of the process

        :type: str
        """
        return self.szExeFile[:].decode()

    @utils.fixedpropety
    def pid(self):
        """Process ID

        :type: int
        """
        return self.th32ProcessID

    @utils.fixedpropety
    def ppid(self):
        """Parent Process ID

        :type: int
        """
        return self.th32ParentProcessID

    def _get_handle(self):
        return winproxy.OpenProcess(dwProcessId=self.pid)

    def __repr__(self):
        return '<{0} "{1}" pid {2} at {3}>'.format(self.__class__.__name__, self.name, self.pid, hex(id(self)))

    def virtual_alloc(self, size):
        """Allocate memory in the process

        :returns: int
        """
        return winproxy.VirtualAllocEx(self.handle, dwSize=size)

    def write_memory(self, addr, data):
        """Write `data` at `addr`"""
        return winproxy.WriteProcessMemory(self.handle, addr, lpBuffer=data)

    def low_read_memory(self, addr, buffer_addr, size):
        if windows.current_process.bitness == 32 and self.bitness == 64:
            # OptionalExport can be None (see winproxy.py)
            if winproxy.NtWow64ReadVirtualMemory64 is None:
                raise ValueError("NtWow64ReadVirtualMemory64 non available in ntdll: cannot write into 64bits processus")
            return winproxy.NtWow64ReadVirtualMemory64(self.handle, addr, buffer_addr, size)
        return winproxy.ReadProcessMemory(self.handle, addr, lpBuffer=buffer_addr, nSize=size)

    def read_memory(self, addr, size):
        """Read `size` from `addr`"""
        buffer = ctypes.create_string_buffer(size)
        self.low_read_memory(addr, ctypes.byref(buffer), size)
        return buffer[:]

    # Simple cache test
    # real_read = read_memory
    #
    # def read_memory(self, addr, size):
    #     """Cached version for test"""
    #     dbgprint('Read remote Memory of {0}'.format(self), 'READMEM')
    #     if not hasattr(self, "_cache_cache"):
    #         self._cache_cache = {}
    #     page_addr = addr & 0xfffffffffffff000
    #     if page_addr in self._cache_cache:
    #         #print("CACHED Read on page {0}".format(hex(page_addr)))
    #         page_data = self._cache_cache[page_addr]
    #         return page_data[addr & 0xfff: (addr & 0xfff) + size]
    #     else:
    #         page_data = self.real_read(page_addr, 0x1000)
    #         self._cache_cache[page_addr] = page_data
    #         return page_data[addr & 0xfff: (addr & 0xfff) + size]

    def read_memory_into(self, addr, struct):
        """Read a :mod:`ctypes` struct from `addr`"""
        self.low_read_memory(addr, ctypes.byref(struct), ctypes.sizeof(struct))
        return struct

    def create_thread(self, addr, param):
        """Create a remote thread"""
        if windows.current_process.bitness == 32 and self.bitness == 64:
            return windows.syswow64.NtCreateThreadEx_32_to_64(self, addr, param)
        return WinThread._from_handle(winproxy.CreateRemoteThread(hProcess=self.handle, lpStartAddress=addr, lpParameter=param))

    def load_library(self, dll_path):
        """Load the library in remote process"""
        x = self.virtual_alloc(0x1000)
        self.write_memory(x, dll_path)
        LoadLibrary = utils.get_func_addr('kernel32', 'LoadLibraryA')
        return self.create_thread(LoadLibrary, x)

    def execute_python(self, pycode):
        """Execute Python code into the remote process"""
        return injection.execute_python_code(self, pycode)

    def get_peb_addr(self):
        dest = self.virtual_alloc(0x1000)
        if self.bitness == 32:
            store_peb = x86.MultipleInstr()
            store_peb += x86.Mov('EAX', x86.mem('fs:[0x30]'))
            store_peb += x86.Mov(x86.create_displacement(disp=dest), 'EAX')
            store_peb += x86.Ret()
            get_peb_code = store_peb.get_code()
            self.write_memory(dest, "\x00" * 4)
            self.write_memory(dest + 4, get_peb_code)
            self.create_thread(dest + 4, 0)
            time.sleep(0.01)
            peb_addr = struct.unpack("<I", self.read_memory(dest, 4))[0]
            return peb_addr
        else:
            store_peb = x64.MultipleInstr()
            store_peb += x64.Mov('RAX', x64.mem('gs:[0x60]'))
            store_peb += x64.Mov(x64.create_displacement(disp=dest), 'RAX')
            store_peb += x64.Ret()
            get_peb_code = store_peb.get_code()
            self.write_memory(dest, "\x00" * 8)
            self.write_memory(dest + 8, get_peb_code)
            self.create_thread(dest + 8, 0)
            time.sleep(0.01)
            peb_addr = struct.unpack("<Q", self.read_memory(dest, 8))[0]
            return peb_addr

    @utils.fixedpropety
    def peb(self):
        if windows.current_process.bitness == 32 and self.bitness == 64:
            return RemotePEB64(self.get_peb_addr(), self)
        return RemotePEB(self.get_peb_addr(), self)

    def exit(self, code=0):
        """Exit the process"""
        return winproxy.TerminateProcess(self.handle, code)


class LoadedModule(LDR_DATA_TABLE_ENTRY):
    """An entry in the PEB Ldr list"""
    @property
    def baseaddr(self):
        """base address of the module

        :type: int
        """
        return self.DllBase

    @property
    def name(self):
        """Name of the module

        :type: str
        """
        return str(self.BaseDllName.Buffer).lower()

    @property
    def fullname(self):
        """Full name of the module (path)

        :type: str
        """
        return self.FullDllName.Buffer.decode()

    def __repr__(self):
        return '<{0} "{1}" at {2}>'.format(self.__class__.__name__, self.name, hex(id(self)))

    @property
    def pe(self):
        """A PE representation of the module

        :type: :class:`windows.pe_parse.PEFile`
        """
        return pe_parse.PEFile(self.baseaddr)


class WinUnicodeString(LSA_UNICODE_STRING):
    """LSA_UNICODE_STRING with a nice `__repr__`"""
    def __repr__(self):
        return """<{0} "{1}" at {2}>""".format(type(self).__name__, self.Buffer, hex(id(self)))


class LIST_ENTRY_PTR(PVOID):
    def TO_LDR_ENTRY(self):
        return LDR_DATA_TABLE_ENTRY.from_address(self.value - sizeof(PVOID) * 2)


def transform_ctypes_fields(struct, replacement):
    return [(name, replacement.get(name, type)) for name, type in struct._fields_]


class RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = transform_ctypes_fields(RTL_USER_PROCESS_PARAMETERS,  # The one in generated_def
                                       {"ImagePathName": WinUnicodeString,
                                        "CommandLine": WinUnicodeString}
                                       )


class PEB(Structure):
    """The PEB (Process Environment Block) of the current process"""
    _fields_ = transform_ctypes_fields(PEB,  # The one in generated_def
                                       {"ProcessParameters": POINTER(RTL_USER_PROCESS_PARAMETERS)}
                                       )

    @property
    def imagepath(self):
        """The ImagePathName of the PEB

        :type: :class:`WinUnicodeString`
        """
        return self.ProcessParameters.contents.ImagePathName

    @property
    def commandline(self):
        """The CommandLine of the PEB

        :type: :class:`WinUnicodeString`
        """
        # This or changing the __repr__ of LSA_UNICODE_STRING
        return self.ProcessParameters.contents.CommandLine

    @property
    def modules(self):
        """The loaded modules present in the PEB

        :type: [:class:`LoadedModule`] -- List of loaded modules
        """
        res = []
        list_entry_ptr = ctypes.cast(self.Ldr.contents.InMemoryOrderModuleList.Flink, LIST_ENTRY_PTR)
        current_dll = list_entry_ptr.TO_LDR_ENTRY()
        while current_dll.DllBase:
            res.append(current_dll)
            list_entry_ptr = ctypes.cast(current_dll.InMemoryOrderLinks.Flink, LIST_ENTRY_PTR)
            current_dll = list_entry_ptr.TO_LDR_ENTRY()
        return [LoadedModule.from_address(addressof(LDR)) for LDR in res]

import windows.remotectypes as rctypes


class RemotePEB(rctypes.RemoteStructure.from_structure(PEB)):
    RemoteLoadedModule = rctypes.RemoteStructure.from_structure(LoadedModule)

    def ptr_flink_to_remote_module(self, ptr_value):
        return self.RemoteLoadedModule(ptr_value - ctypes.sizeof(ctypes.c_void_p) * 2, self._target)

    @property
    def modules(self):
        """The loaded modules present in the PEB

        :type: [:class:`LoadedModule`] -- List of loaded modules
        """
        res = []
        list_entry_ptr = self.Ldr.contents.InMemoryOrderModuleList.Flink.raw_value

        current_dll = self.ptr_flink_to_remote_module(list_entry_ptr)
        while current_dll.DllBase:
            res.append(current_dll)
            list_entry_ptr = current_dll.InMemoryOrderLinks.Flink.raw_value
            current_dll = self.ptr_flink_to_remote_module(list_entry_ptr)
        return res


if CurrentProcess().bitness == 32:
    class RemoteLoadedModule64(rctypes.transform_type_to_remote64bits(LoadedModule)):
        @property
        def pe(self):
            """A PE representation of the module

            :type: :class:`windows.pe_parse.PEFile`
            """
            return pe_parse.PEFile(self.baseaddr, target=self._target)

    class RemotePEB64(rctypes.transform_type_to_remote64bits(PEB)):

        def ptr_flink_to_remote_module(self, ptr_value):
            return RemoteLoadedModule64(ptr_value - ctypes.sizeof(rctypes.c_void_p64) * 2, self._target)

        @property
        def modules(self):
            """The loaded modules present in the PEB

            :type: [:class:`LoadedModule`] -- List of loaded modules
            """
            res = []
            list_entry_ptr = self.Ldr.contents.InMemoryOrderModuleList.Flink.raw_value

            current_dll = self.ptr_flink_to_remote_module(list_entry_ptr)
            while current_dll.DllBase:
                res.append(current_dll)
                list_entry_ptr = current_dll.InMemoryOrderLinks.Flink.raw_value
                current_dll = self.ptr_flink_to_remote_module(list_entry_ptr)
            return res
