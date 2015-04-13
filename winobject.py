import ctypes
import os

import windows
import utils
import k32testing as kernel32proxy
import injection
import native_exec

from generated_def.winstructs import *
import pe_parse


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
         if hasattr(self, "_handle"):
            kernel32proxy.CloseHandle(self._handle)

class System(object):
    """Represent the current windows system python is running on"""
    @property
    def processes(self):
        """The list of running processes

        :type: [:class:`WinProcess`] -- A list of Process

        """
        return utils.enumerate_processes()

    @property
    def threads(self):
        """The list of running threads

        :type: [:class:`WinThread`] -- A list of Thread

        """
        return utils.enumerate_threads()

    @property
    def bitness(self):
        """The bitness of the system

        :type: int -- 32 or 64

        """
        if os.environ["PROCESSOR_ARCHITECTURE"].lower() != "x86":
            return 64
        if "PROCESSOR_ARCHITEW6432" in os.environ:
            return 64
        return 32


class WinThread(THREADENTRY32, AutoHandle):
    """Represent a thread """
    @property
    def tid(self):
        """Thread ID"""
        return self.th32ThreadID

    @property
    def owner(self):
        """The Process owning the thread

        :type: :class:`WinProcess`

        """
        if hasattr(self, "_owner"):
            return self._owner
        self._owner = [process for process in utils.enumerate_processes() if process.pid == self.th32OwnerProcessID][0]
        return self._owner

    def _get_handle(self):
        return kernel32proxy.OpenThread(dwThreadId=self.tid)

    def __repr__(self):
        return '<{0} {1} owner "{2}" at {3}>'.format(self.__class__.__name__, self.tid, self.owner.name, hex(id(self)))

class Process(AutoHandle):
    @property
    def is_wow_64(self):
        """Is True if the process is a SysWow64 process

        This means a 32bits process on a 64bits system

        :type: bool
        """
        return utils.is_wow_64(self.handle)

    @property
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
        return [thread for thread in utils.enumerate_threads() if thread.th32OwnerProcessID == self.pid]

    def virtual_alloc(self, size):
        raise NotImplementedError("virtual_alloc")

    def execute(self, code):
        """Execute some raw code in the context of the process"""
        x = self.virtual_alloc(len(code))
        self.write_memory(x, code)
        return self.create_thread(x, 0)


class CurrentThread(AutoHandle):
    """The current thread"""
    @property
    def tid(self):
        """Thread ID"""
        return kernel32proxy.GetCurrentThreadId()

    @property
    def owner(self):
        """The current process

        :type: :class:`CurrentProcess`
        """
        return windows.current_process

    def _get_handle(self):
        return kernel32proxy.GetCurrentThread()

    def exit(self, code=0):
        """Exit the thread"""
        return kernel32proxy.ExitThread(code)

class CurrentProcess(Process):
    """The current process"""
    get_peb = None
    get_peb_32_code = '64a130000000c3'.decode('hex')

    # mov    rax,QWORD PTR gs:0x60
    # ret
    get_peb_64_code = "65488B042560000000C3".decode('hex')

    allocator = native_exec.native_function.CustomAllocator()


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
        return kernel32proxy.GetCurrentProcess()

    @property
    def pid(self):
        """Process ID

        :type: int
        """
        return os.getpid()

    # Is there a better way ?
    @property
    def ppid(self):
        """Parent Process ID

        :type: int
        """
        return [p for p in windows.system.processes if p.pid == self.pid][0].ppid

    @property
    def peb(self):
        """The Process Environment Block of the current process

        :type: :class:`PEB`
        """
        return PEB.from_address(self.get_peb_builtin()())

    @property
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
        return kernel32proxy.VirtualAlloc(dwSize=size)

    def write_memory(self, addr, data):
        """Write data at addr"""
        buffertype = (c_char * len(data)).from_address(addr)
        buffertype[:len(data)] = data
        return True

    def read_memory(self, addr, size):
        """Read size from adddr"""
        buffer = (c_char * size).from_address(addr)
        return buffer[:]

    def create_thread(self, lpStartAddress, lpParameter, dwCreationFlags=0):
        """Create a new thread

        .. note::
            CreateThread https://msdn.microsoft.com/en-us/library/windows/desktop/ms682453%28v=vs.85%29.aspx
        """
        return  kernel32proxy.CreateThread(lpStartAddress=lpStartAddress, lpParameter=lpParameter, dwCreationFlags=dwCreationFlags)

    def exit(self, code=0):
        """Exit the process"""
        return kernel32proxy.ExitProcess(code)

class WinProcess(PROCESSENTRY32, Process):
    """A Process on the system"""
    is_pythondll_injected = 0
    is_remote_slave_running = False

    @property
    def name(self):
        """Name of the process

        :type: str
        """
        return self.szExeFile[:]

    @property
    def pid(self):
        """Process ID

        :type: int
        """
        return self.th32ProcessID

    @property
    def ppid(self):
        """Parent Process ID

        :type: int
        """
        return self.th32ParentProcessID

    def _get_handle(self):
        return kernel32proxy.OpenProcess(dwProcessId=self.pid)

    def __repr__(self):
        return '<{0} "{1}" pid {2} at {3}>'.format(self.__class__.__name__, self.name, self.pid, hex(id(self)))

    def virtual_alloc(self, size):
        """Allocate memory in the process

        :returns: int
        """
        return kernel32proxy.VirtualAllocEx(self.handle, dwSize=size)

    def write_memory(self, addr, data):
        """Write `data` at `addr`"""
        return kernel32proxy.WriteProcessMemory(self.handle, addr, lpBuffer=data)

    def low_read_memory(self, addr, buffer_addr, size):
        if windows.current_process.bitness == 32 and self.bitness == 64:
            NtWow64ReadVirtualMemory64Addr = windows.utils.get_func_addr("ntdll.dll", "NtWow64ReadVirtualMemory64")
            NtWow64ReadVirtualMemory64 = WINFUNCTYPE(HRESULT, HANDLE, ULONG64, PVOID, ULONG64, PULONG64)(NtWow64ReadVirtualMemory64Addr)
            return NtWow64ReadVirtualMemory64(self.handle, addr, buffer_addr, size, None)
        return kernel32proxy.ReadProcessMemory(self.handle, addr, lpBuffer=buffer_addr, nSize=size)

    def read_memory(self, addr, size):
        """Read `size` from `addr`"""
        buffer =  ctypes.create_string_buffer(size)
        self.low_read_memory(addr, ctypes.byref(buffer), size)
        return buffer[:]

    def read_memory_into(self, addr, struct):
        """Read a :mod:`ctypes` struct from `addr`"""
        self.low_read_memory(addr, ctypes.byref(struct), ctypes.sizeof(struct))
        return struct

    def create_thread(self, addr, param):
        """Create a remote thread"""
        if windows.current_process.bitness == 32 and self.bitness == 64:
            return windows.syswow64.NtCreateThreadEx_32_to_64(self, addr, param)
        return  kernel32proxy.CreateRemoteThread(hProcess=self.handle, lpStartAddress=addr, lpParameter=param)

    def load_library(self, dll_path):
        """Load the library in remote process"""
        x = self.virtual_alloc(0x1000)
        self.write_memory(x, dll_path)
        LoadLibrary = utils.get_func_addr('kernel32', 'LoadLibraryA')
        return self.create_thread(LoadLibrary, x)

    def execute_python(self, pycode):
        """Execute Python code into the remote process"""
        return injection.execute_python_code(self, pycode)


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
        return self.BaseDllName.Buffer

    @property
    def fullname(self):
        """Full name of the module (path)

        :type: str
        """
        return self.FullDllName.Buffer

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
        return LDR_DATA_TABLE_ENTRY.from_address(self.value - sizeof(PVOID) *  2)


class PEB(PEB):
    """The PEB (Process Environment Block) of the current process"""
    @property
    def imagepath(self):
        """The ImagePathName of the PEB

        :type: :class:`WinUnicodeString`
        """
        raw_imagepath = self.ProcessParameters.contents.ImagePathName
        return WinUnicodeString.from_address(ctypes.addressof(raw_imagepath))

    @property
    def commandline(self):
        """The CommandLine of the PEB

        :type: :class:`WinUnicodeString`
        """
        # This or changing the __repr__ of LSA_UNICODE_STRING
        raw_cmd = self.ProcessParameters.contents.CommandLine
        return WinUnicodeString.from_address(ctypes.addressof(raw_cmd))

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