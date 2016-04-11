import ctypes
import os
import copy
import time
import struct
import itertools

from contextlib import contextmanager

import windows
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64

from windows import injection
from windows import native_exec
from windows import pe_parse
from windows import winproxy
from windows import utils
from windows.dbgprint import dbgprint
from windows.generated_def.winstructs import *
from windows.generated_def.ntstatus import NtStatusException
from windows.generated_def import windef

from windows.winobject import exception

class AutoHandle(object):
    """An abstract class that allow easy handle creation/destruction/wait"""
     # Big bypass to prevent missing reference at programm close..
    _close_function = ctypes.WinDLL("kernel32").CloseHandle
    def _get_handle(self):
        raise NotImplementedError("{0} is abstract".format(type(self).__name__))

    @property
    def handle(self):
        """An handle on the object

        :type: HANDLE

           .. note::
                The handle is automaticaly closed when the object is destroyed
        """
        if hasattr(self, "_handle"):
            return self._handle
        self._handle = self._get_handle()
        dbgprint("Open handle {0} for {1}".format(hex(self._handle), self), "HANDLE")
        return self._handle

    def wait(self, timeout=INFINITE):
        """Wait for the object"""
        return winproxy.WaitForSingleObject(self.handle, timeout)

    def __del__(self):
        if hasattr(self, "_handle") and self._handle:
            #dbgprint("Closing Handle {0} for {1}".format(hex(self._handle), self), "HANDLE")
            self._close_function(self._handle)


class WinThread(THREADENTRY32, AutoHandle):
    """Represent a thread """
    @utils.fixedpropety
    def tid(self):
        """Thread ID

        :type: :class:`int`"""
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
        """The context of the thread, type depend of the target process.

        :type: :class:`windows.exception.ECONTEXT32` or  :class:`windows.exception.ECONTEXT64` or :class:`windows.exception.ECONTEXTWOW64`
		"""
        if self.owner.bitness == 32 and windows.current_process.bitness == 64:
            # Wow64
            x = exception.ECONTEXTWOW64()
            x.ContextFlags = CONTEXT_ALL
            winproxy.Wow64GetThreadContext(self.handle, x)
            return x

        if self.owner.bitness == 64 and windows.current_process.bitness == 32:
            x = exception.ECONTEXT64.new_aligned()
            x.ContextFlags = CONTEXT_ALL
            windows.syswow64.NtGetContextThread_32_to_64(self.handle, x)
            return x

        if self.owner.bitness == 32:
            x = exception.ECONTEXT32()
        else:
            x = exception.ECONTEXT64.new_aligned()
        x.ContextFlags = CONTEXT_ALL
        winproxy.GetThreadContext(self.handle, x)
        return x

    def set_context(self, context):
        """Set the thread context to ``context``"""
        if self.owner.bitness == windows.current_process.bitness:
            return winproxy.SetThreadContext(self.handle, context)
        if windows.current_process.bitness == 64 and self.owner.bitness == 32:
            return winproxy.Wow64SetThreadContext(self.handle, context)
        return windows.syswow64.NtSetContextThread_32_to_64(self.handle, ctypes.byref(context))

    @property
    def start_address(self):
        """The start address of the thread

            :type: :class:`int`
		"""
        if windows.current_process.bitness == 32 and self.owner.bitness == 64:
            res = ULONGLONG()
            windows.syswow64.NtQueryInformationThread_32_to_64(self.handle, ThreadQuerySetWin32StartAddress, byref(res), ctypes.sizeof(res))
            return res.value
        res_size = max(self.owner.bitness, windows.current_process.bitness)
        if res_size == 32:
            res = ULONG()
        else:
            res = ULONGLONG()
        winproxy.NtQueryInformationThread(self.handle, ThreadQuerySetWin32StartAddress, byref(res), ctypes.sizeof(res))
        return res.value

    def exit(self, code=0):
        """Exit the thread"""
        return winproxy.TerminateThread(self.handle, code)

    def resume(self):
        """Resume the thread"""
        return winproxy.ResumeThread(self.handle)

    def suspend(self):
        """Suspend the thread"""
        return winproxy.SuspendThread(self.handle)

    def _get_handle(self):
        return winproxy.OpenThread(dwThreadId=self.tid)

    @property
    def is_exit(self):
        """``True`` if the thread is terminated

        :type: :class:`bool`
		"""
        return self.exit_code != STILL_ACTIVE

    @property
    def exit_code(self):
        """The exit code of the thread : ``STILL_ACTIVE`` means the process is not dead

        :type: :class:`int`
		"""
        res = DWORD()
        winproxy.GetExitCodeThread(self.handle, byref(res))
        return res.value

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
        try:
            # Really useful ?
            thread = [t for t in windows.winobject.system.System().threads if t.tid == tid][0]
            # set AutoHandle _handle
            thread._handle = handle
            dbgprint("Thread {0} from handle {1}".format(thread, hex(handle)), "HANDLE")
            return thread
        except IndexError:
            dbgprint("DeadThread from handle {0}".format(hex(handle)), "HANDLE")
            return DeadThread(handle, tid)

class DeadThread(AutoHandle):
    """An already dead thread"""
    def __init__(self, handle, tid=None):
        if tid is None:
            tid = winproxy.GetThreadId(handle)
        self.tid = tid
        # set AutoHandle _handle
        self._handle = handle

    @property
    def is_exit(self):
        """``True`` if the thread is terminated

        :type: :class:`bool`
		"""
        return self.exit_code != STILL_ACTIVE

    @property
    def exit_code(self):
        """The exit code of the thread : ``STILL_ACTIVE`` means the process is not dead

        :type: :class:`int`
		"""
        res = DWORD()
        winproxy.GetExitCodeThread(self.handle, byref(res))
        return res.value


class Process(AutoHandle):
    @utils.fixedpropety
    def is_wow_64(self):
        """``True`` if the process is a SysWow64 process (32bit process on 64bits system).

        :type: :class:`bool`
		"""
        return utils.is_wow_64(self.handle)

    @utils.fixedpropety
    def bitness(self):
        """The bitness of the process

        :returns: :class:`int` -- 32 or 64
		"""
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

    def virtual_free(self):
        raise NotImplementedError("virtual_free")

    @property
    def exit_code(self):
        """The exit code of the process : ``STILL_ACTIVE`` means the process is not dead

        :type: :class:`int`
		"""
        res = DWORD()
        winproxy.GetExitCodeProcess(self.handle, byref(res))
        return res.value

    @property
    def is_exit(self):
        """``True`` if the process is terminated

        :type: :class:`bool`
		"""
        return self.exit_code != STILL_ACTIVE

    @contextmanager
    def allocated_memory(self, size):
        """ContextManager to allocate memory and free it

        :type: :class:`int` -- the address of the allocated memory
		"""
        addr = self.virtual_alloc(size)
        try:
            yield addr
        finally:
            winproxy.VirtualFreeEx(self.handle, addr)

    def execute(self, code, parameter=0):
        """Execute some native code in the context of the process

        :return: The thread executing the code
        :rtype: :class:`WinThread` or :class:`DeadThread`
		"""
        x = self.virtual_alloc(len(code)) #Todo: free this ? when ? how ? reuse ?
        self.write_memory(x, code)
        return self.create_thread(x, parameter)

    def query_memory(self, addr):
        """Query the memory informations about page at ``addr``

        :rtype: :class:`MEMORY_BASIC_INFORMATION`
		"""
        if windows.current_process.bitness == 32 and self.bitness == 64:
            res = MEMORY_BASIC_INFORMATION64()
            try:
                v = windows.syswow64.NtQueryVirtualMemory_32_to_64(ProcessHandle=self.handle, BaseAddress=addr, MemoryInformation=res)
            except NtStatusException as e:
                if e.code & 0xffffffff == 0XC000000D:
                    raise winproxy.Kernel32Error("NtQueryVirtualMemory_32_to_64")
                raise
            return res

        info_type = {32 : MEMORY_BASIC_INFORMATION32, 64 : MEMORY_BASIC_INFORMATION64}
        res = info_type[windows.current_process.bitness]()
        ptr = ctypes.cast(byref(res), POINTER(MEMORY_BASIC_INFORMATION))
        winproxy.VirtualQueryEx(self.handle, addr, ptr, sizeof(res))
        return res

    def memory_state(self):
        """Yield the memory information for the whole address space of the process

        :yield: :class:`MEMORY_BASIC_INFORMATION`
		"""
        addr = 0
        res = []
        while True:
            try:
                x = self.query_memory(addr)
                yield x
            except winproxy.Kernel32Error:
                return
            addr += x.RegionSize

    def query_working_set(self):
        if self.bitness == 64 or windows.current_process.bitness == 64:
            WSET_BLOCK = EPSAPI_WORKING_SET_BLOCK64
            dummy = PSAPI_WORKING_SET_INFORMATION64()
        else:
            WSET_BLOCK = EPSAPI_WORKING_SET_BLOCK32
            dummy = PSAPI_WORKING_SET_INFORMATION32()
        try:
            windows.winproxy.QueryWorkingSet(self.handle, ctypes.byref(dummy), ctypes.sizeof(dummy))
        except WindowsError as e:
            if e.winerror != 24:
                raise

        for i in range(10):
            # use the same type as WSET_BLOCK.Flags
            NumberOfEntriesType = [f for f in WSET_BLOCK._fields_ if f[0] == "Flags"][0][1]
            class GENERATED_PSAPI_WORKING_SET_INFORMATION(ctypes.Structure):
                _fields_ = [
                ("NumberOfEntries", NumberOfEntriesType),
                ("WorkingSetInfo", WSET_BLOCK * dummy.NumberOfEntries),
            ]
            res = GENERATED_PSAPI_WORKING_SET_INFORMATION()
            try:
                if windows.current_process.bitness == 32 and self.bitness == 64:
                    windows.syswow64.NtQueryVirtualMemory_32_to_64(self.handle, 0, 1, res)
                else:
                    windows.winproxy.QueryWorkingSet(self.handle, ctypes.byref(res), ctypes.sizeof(res))
            except WindowsError as e:
                if e.winerror != 24:
                    raise
                dummy.NumberOfEntries = res.NumberOfEntries
                continue
            except windows.generated_def.ntstatus.NtStatusException as e:
                if e.code != STATUS_INFO_LENGTH_MISMATCH:
                    raise
                dummy.NumberOfEntries = res.NumberOfEntries
                continue
            return res.WorkingSetInfo
        return None

    def query_working_set_ex(self, addresses):
        if self.bitness == 64 or windows.current_process.bitness == 64:
            info_type = EPSAPI_WORKING_SET_EX_INFORMATION64
        else:
            info_type = EPSAPI_WORKING_SET_EX_INFORMATION32
        info_array = (info_type * len(addresses))()
        for i, data in enumerate(info_array):
            info_array[i].VirtualAddress = addresses[i]
        winproxy.QueryWorkingSetEx(self.handle, ctypes.byref(info_array), ctypes.sizeof(info_array))
        return info_array


    def get_mapped_filename(self, addr):
        """The filename mapped at address ``addr`` or ``None``

        :rtype: :class:`str` or ``None``
		"""
        buffer = ctypes.c_buffer(0x1024)
        try:
            size = winproxy.GetMappedFileNameA(self.handle, addr, buffer)
        except winproxy.Kernel32Error:
            return None
        return buffer[:size]

    def read_byte(self, addr):
        """Read a ``CHAR`` at ``addr``"""
        sizeof_char = sizeof(CHAR)
        return struct.unpack("<B", self.read_memory(addr, sizeof_char))[0]

    def read_short(self, addr):
        """Read a ``SHORT`` at ``addr``"""
        sizeof_short = sizeof(ctypes.c_short)
        return struct.unpack("<H", self.read_memory(addr, sizeof_short))[0]

    def read_dword(self, addr):
        """Read a ``DWORD`` at ``addr``"""
        sizeof_dword = sizeof(DWORD)
        return struct.unpack("<I", self.read_memory(addr, sizeof_dword))[0]

    def read_qword(self, addr):
        """Read a ``ULONG64`` at ``addr``"""
        sizeof_qword = sizeof(ULONG64)
        return struct.unpack("<Q", self.read_memory(addr, sizeof_qword))[0]

    def read_ptr(self, addr):
        """Read a ``PTR`` at ``addr``"""
        if self.bitness == 32:
            return self.read_dword(addr)
        return self.read_qword(addr)

    def read_string(self, addr):
        """Read an ascii string at ``addr``"""
        res = []
        for i in itertools.count():
            x = self.read_memory(addr + (i * 0x100), 0x100)
            if "\x00" in x:
                res.append(x.split("\x00", 1)[0])
                break
            res.append(x)
        return "".join(res)

    def read_wstring(self, addr):
        """Read a windows UTF16 string at ``addr``"""
        res = []
        for i in itertools.count():
            x = self.read_memory(addr + (i * 0x100), 0x100)
            utf16_chars = ["".join(c) for c in zip(*[iter(x)] * 2)]
            if "\x00\x00" in utf16_chars:
                res.extend(utf16_chars[:utf16_chars.index("\x00\x00")])
                break
            res.extend(x)
        return "".join(res).decode('utf16')

    def write_byte(self, addr, byte):
        """write a byte at ``addr``"""
        return self.write_memory(addr, struct.pack("<B", byte))

    def write_short(self, addr, word):
        """write a word at ``addr``"""
        return self.write_memory(addr, struct.pack("<H", word))

    def write_dword(self, addr, dword):
        """write a dword at ``addr``"""
        return self.write_memory(addr, struct.pack("<I", dword))

    def write_qword(self, addr, qword):
        """write a qword at ``addr``"""
        return self.write_memory(addr, struct.pack("<Q", qword))

    @utils.fixedpropety
    def token(self):
        """The token of the process

        :type: :class:`Token`
		"""
        token_handle = HANDLE()
        winproxy.OpenProcessToken(self.handle, TOKEN_QUERY, byref(token_handle))
        return Token(token_handle.value)


class CurrentThread(AutoHandle):
    """The current thread"""
    @property #It's not a fixedpropety because executing thread might change
    def tid(self):
        """Thread ID

        :type: :class:`int`
		"""
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

    def wait(self, timeout=INFINITE):
        """Raise :class:`ValueError` to prevent deadlock :D"""
        raise ValueError("wait() on current thread")


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

    # Use RtlGetCurrentPeb ?
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

        :type: :class:`int`
		"""
        return os.getpid()

    # Is there a better way ?
    @utils.fixedpropety
    def ppid(self):
        """Parent Process ID

        :type: :class:`int`
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

        :type: :class:`int` -- 32 or 64
		"""
        import platform
        bits = platform.architecture()[0]
        return int(bits[:2])

    def virtual_alloc(self, size):
        """Allocate memory in the process

        :return: The address of the allocated memory
        :rtype: :class:`int`
		"""
        return winproxy.VirtualAlloc(dwSize=size)

    def virtual_free(self, addr):
        """Free memory in the process by virtual_alloc"""
        return winproxy.VirtualFree(addr)

    def write_memory(self, addr, data):
        """Write data at addr"""
        buffertype = (c_char * len(data)).from_address(addr)
        buffertype[:len(data)] = data
        return True

    def read_memory(self, addr, size):
        """Read ``size`` from ``addr``

        :return: The data read
        :rtype: :class:`str`
		"""
        dbgprint('Read CurrentProcess Memory', 'READMEM')
        buffer = (c_char * size).from_address(addr)
        return buffer[:]

    def create_thread(self, lpStartAddress, lpParameter, dwCreationFlags=0):
        """Create a new thread

        :rtype: :class:`WinThread` or :class:`DeadThread`
		"""
        handle = winproxy.CreateThread(lpStartAddress=lpStartAddress, lpParameter=lpParameter, dwCreationFlags=dwCreationFlags)
        return WinThread._from_handle(handle)

    def exit(self, code=0):
        """Exit the process"""
        return winproxy.ExitProcess(code)

    def wait(self, timeout=INFINITE):
        """Raise :class:`ValueError` to prevent deadlock :D"""
        raise ValueError("wait() on current thread")

    @utils.fixedpropety
    def peb_syswow(self):
        """The 64bits PEB of a SysWow64 process

            :type: :class:`PEB`
		"""
        if not self.is_wow_64:
            raise ValueError("Not a syswow process")
        return windows.syswow64.get_current_process_syswow_peb()

class WinProcess(Process):
    """A Process on the system"""
    def __init__(self, pid=None, handle=None, name=None, ppid=None):
        if pid is None and handle is None:
            raise ValueError("Need at lead <pid> or <handle> to create a {0}".format(type(self).__name))

        if pid is not None:    self._pid = pid
        if handle is not None: self._handle = handle
        if name is not None:   self._name = name
        if ppid is not None:   self._ppid = ppid


    @staticmethod
    def _from_handle(handle):
        #pid = winproxy.GetProcessId(handle)
        #proc = [p for p in windows.system.processes if p.pid == pid][0]
        #proc._handle = handle
        #dbgprint("Process {0} from handle {1}".format(proc, hex(handle)), "HANDLE")
        return WinProcess(handle=handle)

    @classmethod
    def _from_PROCESSENTRY32(cls, entry):
        #print("_from_PROCESSENTRY32")
        name = entry.szExeFile.decode()
        pid = entry.th32ProcessID
        ppid = entry.th32ParentProcessID
        return WinProcess(pid=pid, name=name, ppid=ppid)


    @utils.fixedpropety
    def name(self):
        """Name of the process

        :type: :class:`str`
		"""
        buffer = ctypes.c_buffer(0x1024)
        rsize = winproxy.GetProcessImageFileNameA(self.handle, buffer)
        # GetProcessImageFileNameA returns the fullpath
        return buffer[:49].decode().split("\\")[-1]

    @utils.fixedpropety
    def pid(self):
        """Process ID

        :type: :class:`int`
		"""
        return winproxy.GetProcessId(self.handle)

    @utils.fixedpropety
    def ppid(self):
        """Parent Process ID

        :type: :class:`int`
		"""
        # TODO: is there an API ?
        pid = self.pid
        return [p for p in windows.system.processes if p.pid == pid][0].th32ParentProcessID

    def _get_handle(self):
        return winproxy.OpenProcess(dwProcessId=self.pid)

    def __repr__(self):
        try:
            if self.is_exit:
                return '<{0} "{1}" pid {2} (DEAD) at {3}>'.format(self.__class__.__name__, self.name, self.pid, hex(id(self)))
        except WindowsError: # Cannot open process
            pass
        return '<{0} "{1}" pid {2} at {3}>'.format(self.__class__.__name__, self.name, self.pid, hex(id(self)))

    def virtual_alloc(self, size):
        """Allocate memory in the process

        :return: The address of the allocated memory
        :rtype: :class:`int`
		"""
        return winproxy.VirtualAllocEx(self.handle, dwSize=size)

    def virtual_free(self, addr):
        """Free memory in the process by virtual_alloc"""
        return winproxy.VirtualFreeEx(self.handle, addr)

    def write_memory(self, addr, data):
        """Write `data` at `addr`"""
        return winproxy.WriteProcessMemory(self.handle, addr, lpBuffer=data)

    def low_read_memory(self, addr, buffer_addr, size):
        if windows.current_process.bitness == 32 and self.bitness == 64:
            # OptionalExport can be None (see winproxy.py)
            if winproxy.NtWow64ReadVirtualMemory64 is None:
                raise ValueError("NtWow64ReadVirtualMemory64 non available in ntdll: cannot read into 64bits processus")
            return winproxy.NtWow64ReadVirtualMemory64(self.handle, addr, buffer_addr, size)
            NtWow64ReadVirtualMemory64
        #if self.is_wow_64 and addr > 0xffffffff:
        #    return winproxy.NtWow64ReadVirtualMemory64(self.handle, addr, buffer_addr, size)
        return winproxy.ReadProcessMemory(self.handle, addr, lpBuffer=buffer_addr, nSize=size)

    def read_memory(self, addr, size):
        """Read ``size`` from ``addr``

        :return: The data read
        :rtype: :class:`str`
		"""
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
        """Read a :mod:`ctypes` struct from `addr`

            :returns: struct
		"""
        self.low_read_memory(addr, ctypes.byref(struct), ctypes.sizeof(struct))
        return struct

    def create_thread(self, addr, param):
        """Create a remote thread

            :rtype: :class:`WinThread` or :class:`DeadThread`
		"""
        if windows.current_process.bitness == 32 and self.bitness == 64:
            thread_handle = HANDLE()
            windows.syswow64.NtCreateThreadEx_32_to_64(ThreadHandle=byref(thread_handle) ,ProcessHandle=self.handle, lpStartAddress=addr, lpParameter=param)
            return WinThread._from_handle(thread_handle.value)
        return WinThread._from_handle(winproxy.CreateRemoteThread(hProcess=self.handle, lpStartAddress=addr, lpParameter=param))

    def load_library(self, dll_path):
        """Load the library in remote process"""
        return windows.injection.load_dll_in_remote_process(self, dll_path)

    def execute_python(self, pycode):
        """Execute Python code into the remote process.

        This function waits for the remote process to end and
        raises an exception if the remote thread raised one
		"""
        return injection.safe_execute_python(self, pycode)

    def execute_python_unsafe(self, pycode):
        """Execute Python code into the remote process.

        Unsafe means that no information are returned about the execution of the thread
        """
        return injection.execute_python_code(self, pycode)

    @utils.fixedpropety
    def peb_addr(self):
        """The address of the PEB

            :type: :class:`int`
		"""
        if windows.current_process.bitness == 32 and self.bitness == 64:
            x = windows.remotectypes.transform_type_to_remote64bits(PROCESS_BASIC_INFORMATION)
            # Fuck-it <3
            data = (ctypes.c_char * ctypes.sizeof(x))()
            windows.syswow64.NtQueryInformationProcess_32_to_64(self.handle, ProcessInformation=data, ProcessInformationLength=ctypes.sizeof(x))
            peb_offset = x.PebBaseAddress.offset
            peb_addr = struct.unpack("<Q", data[x.PebBaseAddress.offset: x.PebBaseAddress.offset+8])[0]
        elif windows.current_process.bitness == 64 and self.bitness == 32:
            information_type = 26
            y = ULONGLONG()
            winproxy.NtQueryInformationProcess(self.handle, information_type, byref(y), sizeof(y))
            peb_addr = y.value
        else:
            information_type = 0
            x = PROCESS_BASIC_INFORMATION()
            winproxy.NtQueryInformationProcess(self.handle, information_type, x)
            peb_addr = ctypes.cast(x.PebBaseAddress, PVOID).value
        if peb_addr is None:
            raise ValueError("Could not get peb addr of process {0}".format(self.name))
        return peb_addr

    @utils.fixedpropety
    def peb(self):
        """The PEB of the process (see :mod:`remotectypes`)

            :type: :class:`PEB`
		"""
        if windows.current_process.bitness == 32 and self.bitness == 64:
            return RemotePEB64(self.peb_addr, self)
        if windows.current_process.bitness == 64 and self.bitness == 32:
            return RemotePEB32(self.peb_addr, self)
        return RemotePEB(self.peb_addr, self)

    @utils.fixedpropety
    def peb_syswow(self):
        """The 64bits PEB of a SysWow64 process

        :type: :class:`PEB`
		"""
        if not self.is_wow_64:
            raise ValueError("Not a syswow process")
        if windows.current_process.bitness == 64:
            information_type = 0
            x = PROCESS_BASIC_INFORMATION()
            winproxy.NtQueryInformationProcess(self.handle, information_type, x)
            peb_addr = ctypes.cast(x.PebBaseAddress, PVOID).value
            return RemotePEB(peb_addr, self)
        else: #current is 32bits
            x = windows.remotectypes.transform_type_to_remote64bits(PROCESS_BASIC_INFORMATION)
            # Fuck-it <3
            data = (ctypes.c_char * ctypes.sizeof(x))()
            windows.syswow64.NtQueryInformationProcess_32_to_64(self.handle, ProcessInformation=data, ProcessInformationLength=ctypes.sizeof(x))
            peb_offset = x.PebBaseAddress.offset
            peb_addr = struct.unpack("<Q", data[x.PebBaseAddress.offset: x.PebBaseAddress.offset+8])[0]
            return RemotePEB64(peb_addr, windows.syswow64.ReadSyswow64Process(self))

    def exit(self, code=0):
        """Exit the process"""
        return winproxy.TerminateProcess(self.handle, code)


# Create ProcessToken and Thread Token objects ?
class Token(AutoHandle):
    """The token of a process"""
    def __init__(self, handle):
        self._handle = handle

    @property
    def integrity(self):
        """Return the integrity level of a process

        :type: :class:`int`
		"""
        buffer_size = self.get_required_information_size(TokenIntegrityLevel)
        buffer = ctypes.c_buffer(buffer_size)
        self.get_informations(TokenIntegrityLevel, buffer)

        sid = ctypes.cast(buffer, POINTER(TOKEN_MANDATORY_LABEL))[0].Label.Sid
        count = winproxy.GetSidSubAuthorityCount(sid)
        integrity = winproxy.GetSidSubAuthority(sid, ord(count[0]) - 1)[0]
        return integrity

    @property
    def is_elevated(self):
        """``True`` if process is Admin"""
        elevation = TOKEN_ELEVATION()
        self.get_informations(TokenElevation, elevation)
        return bool(elevation.TokenIsElevated)

    @property
    def token_user(self):
        buffer_size = self.get_required_information_size(TokenUser)
        buffer = ctypes.c_buffer(buffer_size)
        self.get_informations(TokenUser, buffer)
        return ctypes.cast(ctypes.byref(buffer), POINTER(TOKEN_USER))[0]

    @property
    def computername(self):
        """The computername of the token"""
        return self._user_and_computer_name()[1]

    @property
    def username(self):
        """The username of the token"""
        return self._user_and_computer_name()[0]

    def _user_and_computer_name(self):
        tok_usr = self.token_user
        sid = tok_usr.User.Sid
        usernamesize = DWORD(0x1000)
        computernamesize = DWORD(0x1000)
        username = ctypes.c_buffer(usernamesize.value)
        computername = ctypes.c_buffer(computernamesize.value)
        peUse = SID_NAME_USE()
        winproxy.LookupAccountSidA(None, sid, username, byref(usernamesize), computername, byref(computernamesize), peUse)
        return username[:usernamesize.value], computername[:computernamesize.value]

    def get_informations(self, info_type, data):
        cbsize = DWORD()
        winproxy.GetTokenInformation(self.handle, info_type, ctypes.byref(data), ctypes.sizeof(data), ctypes.byref(cbsize))
        return cbsize.value

    def get_required_information_size(self, info_type):
        cbsize = DWORD()
        try:
            winproxy.GetTokenInformation(self.handle, info_type, None, 0, ctypes.byref(cbsize))
        except WindowsError:
            pass
        return cbsize.value


def transform_ctypes_fields(struct, replacement):
    return [(name, replacement.get(name, type)) for name, type in struct._fields_]


class WinUnicodeString(Structure):
    """LSA_UNICODE_STRING with a nice `__repr__`"""
    _fields_ = transform_ctypes_fields(LSA_UNICODE_STRING, {"Buffer": ctypes.c_void_p})
    fields = [f[0] for f in _fields_]
    """The fields of the structure"""

    @property
    def str(self):
        """The python string of the LSA_UNICODE_STRING object

        :type: :class:`unicode`
        """
        if getattr(self, "_target", None) is not None: #remote ctypes :D -> TRICKS OF THE YEAR
            raw_data = self._target.read_memory(self.Buffer, self.Length)
            return raw_data.decode("utf16")
        size = self.Length / 2
        return (ctypes.c_wchar * size).from_address(self.Buffer)[:]

    def __repr__(self):
        return """<{0} "{1}" at {2}>""".format(type(self).__name__, self.str, hex(id(self)))


class LoadedModule(Structure):
    _fields_ = transform_ctypes_fields(LDR_DATA_TABLE_ENTRY, {"BaseDllName": WinUnicodeString, "FullDllName": WinUnicodeString})
    """An entry in the PEB Ldr list"""
    @property
    def baseaddr(self):
        """Base address of the module

        :type: :class:`int`
		"""
        return self.DllBase

    @property
    def name(self):
        """Name of the module

        :type: :class:`str`
		"""
        return self.BaseDllName.str.lower()

    @property
    def fullname(self):
        """Full name of the module (path)

        :type: :class:`str`
		"""
        return self.FullDllName.str.lower()

    def __repr__(self):
        return '<{0} "{1}" at {2}>'.format(self.__class__.__name__, self.name, hex(id(self)))

    @property
    def pe(self):
        """A PE representation of the module

        :type: :class:`windows.pe_parse.PEFile`
		"""
        return pe_parse.GetPEFile(self.baseaddr)


class LIST_ENTRY_PTR(PVOID):
    def TO_LDR_ENTRY(self):
        return LDR_DATA_TABLE_ENTRY.from_address(self.value - sizeof(PVOID) * 2)


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


# Memory stuff

class EPSAPI_WORKING_SET_BLOCK_BASE(object):
    @property
    def protection(self):
        return self.Flags & 0b11111

    @property
    def sharecount(self):
        return (self.Flags >> 5) & 0b111

    @property
    def shared(self):
        return (self.Flags >> 8) & 1

    @property
    def virtualpage(self):
        return (self.Flags >> 12)


class EPSAPI_WORKING_SET_BLOCK(EPSAPI_WORKING_SET_BLOCK_BASE, PSAPI_WORKING_SET_BLOCK):
    pass

class EPSAPI_WORKING_SET_BLOCK32(EPSAPI_WORKING_SET_BLOCK_BASE, PSAPI_WORKING_SET_BLOCK32):
    pass

class EPSAPI_WORKING_SET_BLOCK64(EPSAPI_WORKING_SET_BLOCK_BASE, PSAPI_WORKING_SET_BLOCK64):
    pass


class EPSAPI_WORKING_SET_EX_BLOCK_BASE(object):
    @property
    def valid(self):
        return self.Flags & 0b1

    @property
    def sharecount(self):
        return (self.Flags >> 1) & 0b111

    @property
    def shared(self):
        return (self.Flags >> 15) & 1

class EPSAPI_WORKING_SET_EX_BLOCK(EPSAPI_WORKING_SET_EX_BLOCK_BASE, PSAPI_WORKING_SET_EX_BLOCK):
    pass

class EPSAPI_WORKING_SET_EX_BLOCK32(EPSAPI_WORKING_SET_EX_BLOCK_BASE, PSAPI_WORKING_SET_EX_BLOCK32):
    pass

class EPSAPI_WORKING_SET_EX_BLOCK64(EPSAPI_WORKING_SET_EX_BLOCK_BASE, PSAPI_WORKING_SET_EX_BLOCK64):
    pass

class EPSAPI_WORKING_SET_EX_INFORMATION(ctypes.Structure):
    _fields_ = windows.utils.transform_ctypes_fields(PSAPI_WORKING_SET_EX_INFORMATION, {"VirtualAttributes": EPSAPI_WORKING_SET_EX_BLOCK})

class EPSAPI_WORKING_SET_EX_INFORMATION32(ctypes.Structure):
    _fields_ = windows.utils.transform_ctypes_fields(PSAPI_WORKING_SET_EX_INFORMATION32, {"VirtualAttributes": EPSAPI_WORKING_SET_EX_BLOCK32})

class EPSAPI_WORKING_SET_EX_INFORMATION64(ctypes.Structure):
    _fields_ = windows.utils.transform_ctypes_fields(PSAPI_WORKING_SET_EX_INFORMATION64, {"VirtualAttributes": EPSAPI_WORKING_SET_EX_BLOCK64})


import windows.remotectypes as rctypes


class RemoteLoadedModule(rctypes.RemoteStructure.from_structure(LoadedModule)):
    @property
    def pe(self):
        """A PE representation of the module

        :type: :class:`windows.pe_parse.PEFile`
		"""
        return pe_parse.GetPEFile(self.baseaddr, target=self._target)


class RemotePEB(rctypes.RemoteStructure.from_structure(PEB)):
    def ptr_flink_to_remote_module(self, ptr_value):
        return RemoteLoadedModule(ptr_value - ctypes.sizeof(ctypes.c_void_p) * 2, self._target)

    @property
    def modules(self):
        """The loaded modules present in the PEB

        :type: [:class:`LoadedModule`] -- List of loaded modules
		"""
        res = []
        if not self.Ldr.value:
                raise ValueError("PEB->Ldr is NULL: cannot walk the module list")
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
            return pe_parse.GetPEFile(self.baseaddr, target=self._target)

    class RemotePEB64(rctypes.transform_type_to_remote64bits(PEB)):

        def ptr_flink_to_remote_module(self, ptr_value):
            return RemoteLoadedModule64(ptr_value - ctypes.sizeof(rctypes.c_void_p64) * 2, self._target)

        @property
        def modules(self):
            """The loaded modules present in the PEB

            :type: [:class:`LoadedModule`] -- List of loaded modules
			"""
            res = []
            if not self.Ldr.value:
                raise ValueError("PEB->Ldr is NULL: cannot walk the module list")
            list_entry_ptr = self.Ldr.contents.InMemoryOrderModuleList.Flink.raw_value
            current_dll = self.ptr_flink_to_remote_module(list_entry_ptr)
            while current_dll.DllBase:
                res.append(current_dll)
                list_entry_ptr = current_dll.InMemoryOrderLinks.Flink.raw_value
                current_dll = self.ptr_flink_to_remote_module(list_entry_ptr)
            return res

if CurrentProcess().bitness == 64:

    class RemoteLoadedModule32(rctypes.transform_type_to_remote32bits(LoadedModule)):
        @property
        def pe(self):
            """A PE representation of the module

            :type: :class:`windows.pe_parse.PEFile`
			"""
            return pe_parse.GetPEFile(self.baseaddr, target=self._target)

    class RemotePEB32(rctypes.transform_type_to_remote32bits(PEB)):
        def ptr_flink_to_remote_module(self, ptr_value):
            return RemoteLoadedModule32(ptr_value - ctypes.sizeof(rctypes.c_void_p32) * 2, self._target)

        @property
        def modules(self):
            """The loaded modules present in the PEB

            :type: [:class:`LoadedModule`] -- List of loaded modules
			"""
            res = []
            if not self.Ldr.value:
                raise ValueError("PEB->Ldr is NULL: cannot walk the module list")
            list_entry_ptr = self.Ldr.contents.InMemoryOrderModuleList.Flink.raw_value
            current_dll = self.ptr_flink_to_remote_module(list_entry_ptr)
            while current_dll.DllBase:
                res.append(current_dll)
                list_entry_ptr = current_dll.InMemoryOrderLinks.Flink.raw_value
                current_dll = self.ptr_flink_to_remote_module(list_entry_ptr)
            return res