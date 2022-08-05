import sys
import ctypes
import os
import copy
import time
import struct
import itertools

from contextlib import contextmanager
from collections import namedtuple

import windows
import windows.native_exec.simple_x86 as x86
import windows.native_exec.simple_x64 as x64
import windows.remotectypes as rctypes
import windows.generated_def as gdef

from windows import injection
from windows import native_exec
from windows import pe_parse
from windows import winproxy
from windows import utils
from windows.dbgprint import dbgprint
from windows.generated_def.winstructs import *
from windows.generated_def.ntstatus import NtStatusException

from windows.winobject import exception
from windows.winobject import apisetmap
from windows.winobject import token
from windows import security

from windows.pycompat import raw_encode, raw_decode, basestring

TimeInfo = namedtuple("TimeInfo", ["creation", "exit", "kernel", "user"])
"""Time information about a process"""


class DeadThread(utils.AutoHandle):
    """An already dead thread (returned only by API returning a new thread if thread die before being returned)"""
    def __init__(self, handle, tid=None):
        if tid is None:
            tid = WinThread._get_thread_id(handle)
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


class Process(utils.AutoHandle):
    @utils.fixedpropety
    def is_wow_64(self):
        """``True`` if the process is a SysWow64 process (32bit process on 64bits system).

        :type: :class:`bool`
		"""
        # return utils.is_wow_64(self.handle)
        return utils.is_wow_64(self.limited_handle)

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

    @utils.fixedpropety
    def limited_handle(self):
        if windows.system.version[0] <= 5:
            # Windows XP | Serveur 2003
            return winproxy.OpenProcess(PROCESS_QUERY_INFORMATION, dwProcessId=self.pid)
        return winproxy.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, dwProcessId=self.pid)


    @utils.fixedpropety
    def ppid(self):
        """Parent Process ID

        :type: :class:`int`
		"""
        if windows.current_process.bitness == 32 and self.bitness == 64:
            xtype = windows.remotectypes.transform_type_to_remote64bits(PROCESS_BASIC_INFORMATION)
            # Fuck-it <3
            data = (ctypes.c_char * ctypes.sizeof(xtype))()
            windows.syswow64.NtQueryInformationProcess_32_to_64(self.limited_handle, ProcessInformation=data, ProcessInformationLength=ctypes.sizeof(xtype))
            # Map a remote64bits(PROCESS_BASIC_INFORMATION) at the address of 'data'
            x = xtype(ctypes.addressof(data), windows.current_process)
        else:
            information_type = 0
            x = PROCESS_BASIC_INFORMATION()
            winproxy.NtQueryInformationProcess(self.limited_handle, information_type, x)
        return x.InheritedFromUniqueProcessId

    @property
    def threads(self):
        """The threads of the process

        :type: [:class:`WinThread`] -- A list of Thread
		"""
        owner_pid = self.pid
        return [WinThread._from_THREADENTRY32(th, owner=self) for th in windows.system.enumerate_threads_generator() if th.th32OwnerProcessID == owner_pid]

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
    def allocated_memory(self, size, prot=PAGE_EXECUTE_READWRITE):
        """ContextManager to allocate memory and free it

        :type: :class:`int` -- the address of the allocated memory
		"""
        addr = self.virtual_alloc(size, prot=prot)
        try:
            yield addr
        finally:
            winproxy.VirtualFreeEx(self.handle, addr)

    @contextmanager
    def virtual_protected(self, addr, size, protect):
        """A context manager for local virtual_protect (old Protection are restored at exit)"""
        old_protect = DWORD()
        self.virtual_protect(addr, size, protect, old_protect)
        try:
            yield addr
        finally:
             self.virtual_protect(addr, size, old_protect.value, old_protect)

    def virtual_protect(self, addr, size, protect, old_protect=None):
        """Change the access right of one or more page of the process"""
        if windows.current_process.bitness == 32 and self.bitness == 64:
            if size & 0x0fff:
                size = ((size >> 12) + 1) << 12
            if old_protect is None:
                old_protect = gdef.DWORD()
            xold_protect = ctypes.addressof(old_protect)
            xaddr = ULONG64(addr)
            addr = ctypes.addressof(xaddr)
            xsize = ULONG(size)
            size = ctypes.addressof(xsize)
            return windows.syswow64.NtProtectVirtualMemory_32_to_64(self.handle, addr, size, protect, xold_protect)
        else:
            winproxy.VirtualProtectEx(self.handle, addr, size, protect, old_protect)


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

        :rtype: :class:`~windows.generated_def.winstructs.MEMORY_BASIC_INFORMATION`
		"""
        if windows.current_process.bitness == 32 and self.bitness == 64:
            res = MEMORY_BASIC_INFORMATION64()
            try:
                v = windows.syswow64.NtQueryVirtualMemory_32_to_64(ProcessHandle=self.handle, BaseAddress=addr, MemoryInformationClass=MemoryBasicInformation, MemoryInformation=res)
            except NtStatusException as e:
                if e.code & 0xffffffff == 0XC000000D:
                    raise winproxy.WinproxyError("NtQueryVirtualMemory_32_to_64")
                raise
            return res

        info_type = {32 : MEMORY_BASIC_INFORMATION32, 64 : MEMORY_BASIC_INFORMATION64}
        res = info_type[windows.current_process.bitness]()
        ptr = ctypes.cast(byref(res), POINTER(MEMORY_BASIC_INFORMATION))
        winproxy.VirtualQueryEx(self.handle, addr, ptr, sizeof(res))
        return res

    def memory_state(self):
        """Yield the memory information for the whole address space of the process

        :yield: :class:`~windows.generated_def.winstructs.MEMORY_BASIC_INFORMATION`
		"""
        addr = 0
        res = []
        while True:
            try:
                x = self.query_memory(addr)
                yield x
            except winproxy.WinproxyError:
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

        NumberOfEntriesType = [f for f in WSET_BLOCK._fields_ if f[0] == "Flags"][0][1]
        for i in range(10):
            # use the same type as WSET_BLOCK.Flags
            class GENERATED_PSAPI_WORKING_SET_INFORMATION(ctypes.Structure):
                _fields_ = [
                ("NumberOfEntries", NumberOfEntriesType),
                ("WorkingSetInfo", WSET_BLOCK * dummy.NumberOfEntries),
            ]
            res = GENERATED_PSAPI_WORKING_SET_INFORMATION()
            try:
                if windows.current_process.bitness == 32 and self.bitness == 64:
                    windows.syswow64.NtQueryVirtualMemory_32_to_64(self.handle, 0, MemoryWorkingSetList, res)
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
        # Raise ?
        return None

    def query_working_setex(self, addresses):
        if self.bitness == 64 or windows.current_process.bitness == 64:
            info_type = EPSAPI_WORKING_SET_EX_INFORMATION64
        else:
            info_type = EPSAPI_WORKING_SET_EX_INFORMATION32
        info_array = (info_type * len(addresses))()
        for i, data in enumerate(info_array):
            info_array[i].VirtualAddress = addresses[i]
        if windows.current_process.bitness == 32 and self.bitness == 64:
            windows.syswow64.NtQueryVirtualMemory_32_to_64(self.handle, 0, MemoryWorkingSetListEx, info_array)
        else:
            winproxy.QueryWorkingSetEx(self.handle, ctypes.byref(info_array), ctypes.sizeof(info_array))
        return info_array


    def get_mapped_filename(self, addr):
        """The filename mapped at address ``addr`` or ``None``

        :rtype: :class:`unicode` or ``None``
		"""
        buffer_size = 0x1000
        buffer = ctypes.c_buffer(buffer_size)

        if  windows.current_process.bitness == 32 and self.bitness == 64:
             target_size = ctypes.c_buffer(buffer_size)
             try:
                windows.syswow64.NtQueryVirtualMemory_32_to_64(self.handle, addr, MemorySectionName, buffer, buffer_size, target_size)
             except NtStatusException as e:
                if e.code not in  (STATUS_FILE_INVALID, STATUS_INVALID_ADDRESS):
                    raise
                return None
             remote_winstring = rctypes.transform_type_to_remote64bits(gdef.LSA_UNICODE_STRING)
             mapped_filename = remote_winstring(ctypes.addressof(buffer), windows.current_process)
             return mapped_filename.str

        try:
                size = winproxy.GetMappedFileNameW(self.handle, addr, buffer, buffer_size)
        except winproxy.WinproxyError as e:
            if e.winerror not in (gdef.ERROR_UNEXP_NET_ERR, gdef.ERROR_FILE_INVALID):
                raise # Raise if error type is not expected: detect mapped aborted transaction
            return None
        return buffer[: size * 2].decode("utf16")

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
        read_size = 0x100
        readden = 0
        for i in itertools.count():
            try:
                x = self.read_memory(addr + readden, read_size)
            except WindowsError as e:
                if read_size == 2:
                    raise
                # handle read_wstring at end of page
                # Of read failed: read only the half of size
                # read_size must remain a multiple of 2
                read_size = read_size // 2
                continue
            readden += read_size
            if b"\x00" in x:
                res.append(x.split(b"\x00", 1)[0])
                break
            res.append(x)
        return b"".join(res).decode("ascii")

    def read_wstring(self, addr):
        """Read a windows UTF16 string at ``addr``"""
        res = []
        read_size = 0x100
        readden = 0
        # I am trying to do something smart here..
        while True:
            try:
                x = self.read_memory(addr + readden, read_size)
            except WindowsError as e:
                if read_size == 2:
                    raise
                # handle read_wstring at end of page
                # Of read failed: read only the half of size
                # read_size must remain a multiple of 2
                read_size = read_size // 2
                continue
            readden += read_size
            # Bytearray will work on py2 & py3
            # Py2: bytearray((0, 0)) == b"\x00\x00"
            # Py2: bytearray((0, 0)) == b"\x00\x00"
            utf16_chars = [bytearray(c) for c in zip(*[iter(x)] * 2)]
            if b"\x00\x00" in utf16_chars:
                # Translate bytearray to str/bytes for both py2 & py3
                res.extend(x[:utf16_chars.index(b"\x00\x00") * 2])
                break
            res.extend(x)
        return bytearray(res).decode("utf-16")

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

    def write_ptr(self, addr, value):
        """Write a ``PTR`` at ``addr``"""
        if self.bitness == 32:
            return self.write_dword(addr, value)
        return self.write_qword(addr, value)

    @property
    def time_info(self):
        """The time information of the process (creation, kernel/user time, exit time)

        :type: :class:`TimeInfo`"""
        CreationTime = FILETIME()
        ExitTime = FILETIME()
        KernelTime = FILETIME()
        UserTime = FILETIME()
        winproxy.GetProcessTimes(self.limited_handle, CreationTime, ExitTime, KernelTime, UserTime)

        creation = (CreationTime.dwHighDateTime << 32) + CreationTime.dwLowDateTime
        exit = (ExitTime.dwHighDateTime << 32) + ExitTime.dwLowDateTime
        kernel = (KernelTime.dwHighDateTime << 32) + KernelTime.dwLowDateTime
        user = (UserTime.dwHighDateTime << 32) + UserTime.dwLowDateTime
        return TimeInfo(creation, exit, kernel, user)

    PRIORITY_CLASS_MAPPER = gdef.FlagMapper(
        ABOVE_NORMAL_PRIORITY_CLASS,
        BELOW_NORMAL_PRIORITY_CLASS,
        HIGH_PRIORITY_CLASS,
        IDLE_PRIORITY_CLASS,
        NORMAL_PRIORITY_CLASS,
        PROCESS_MODE_BACKGROUND_BEGIN,
        PROCESS_MODE_BACKGROUND_END,
        REALTIME_PRIORITY_CLASS)

    @property
    def memory_info(self):
        result = gdef.PROCESS_MEMORY_COUNTERS_EX()
        result.cb = sizeof(gdef.PROCESS_MEMORY_COUNTERS_EX)
        cast_result = cast(pointer(result),  gdef.PPROCESS_MEMORY_COUNTERS)
        windows.winproxy.GetProcessMemoryInfo(self.limited_handle, cast_result, result.cb)
        return result

    def query_info(self, information_class, data=None):
        winproxy.NtQueryInformationProcess(self.handle, information_class, byref(data), sizeof(data))
        return data

    def set_info(self, information_class, data):
        winproxy.NtSetInformationProcess(self.handle, information_class, byref(data), sizeof(data))

    def get_priority(self):
        return self.PRIORITY_CLASS_MAPPER[winproxy.GetPriorityClass(self.handle)]

    def set_priority(self, priority):
        return winproxy.SetPriorityClass(self.handle, priority)

    priority = property(get_priority, set_priority)
    """The priority of the process"""


    def open_token(self, flags=MAXIMUM_ALLOWED):
        """Open the process Token

        :returns: :class:`~windows.winobject.token.Token`
        """
        token_handle = HANDLE()
        winproxy.OpenProcessToken(self.limited_handle, flags, byref(token_handle))
        return token.Token(token_handle.value)

    token = property(open_token, doc="The process :class:`~windows.winobject.token.Token`")

    def get_security_descriptor(self,  query_sacl=False, flags=security.SecurityDescriptor.DEFAULT_SECURITY_INFORMATION):
        open_flags = gdef.READ_CONTROL
        if query_sacl:
            open_flags |= gdef.ACCESS_SYSTEM_SECURITY
        tmp_handle = windows.winproxy.OpenProcess(open_flags, 0, self.pid)
        try:
            return security.SecurityDescriptor.from_handle(tmp_handle, query_sacl=query_sacl, flags=flags, obj_type="process")
        finally:
            windows.winproxy.CloseHandle(tmp_handle)


    def set_security_descriptor(self, sd):
        if  isinstance(sd, basestring):
            sd = security.SecurityDescriptor.from_string(sd)
        open_flags = gdef.WRITE_OWNER | gdef.WRITE_DAC
        if (sd.sacl and
            any(ace.Header.AceType != gdef.SYSTEM_MANDATORY_LABEL_ACE_TYPE for ace in sd.sacl)):
            # Print error if requested but no SecurityPrivilege ?
            open_flags |= gdef.ACCESS_SYSTEM_SECURITY
        tmp_handle = windows.winproxy.OpenProcess(open_flags, 0, self.pid)
        try:
            sd._apply_to_handle_and_type(tmp_handle, gdef.SE_KERNEL_OBJECT)
        finally:
            windows.winproxy.CloseHandle(tmp_handle)

    security_descriptor = property(get_security_descriptor, set_security_descriptor)

    @property # Document ?
    def handles(self):
        pid = self.pid
        return [h for h in windows.system.handles if h.dwProcessId == pid]

    def __del__(self):
        super(Process, self).__del__()
        # Same logic that AutoHandle.__del__ for Process.limited_handle
        # Assert that Process inherit AutoHandle
        # sys.path is not None -> check if python shutdown
        if sys.path is not None and hasattr(self, "_limited_handle") and self._limited_handle:
            # Prevent some bug where dbgprint might be None when __del__ is called in a closing process
            # This line is bad -> it reopens a handle closed by 'super(Process, self).__del__()' ._.
            dbgprint("Closing limited handle {0} for {1}".format(hex(self._limited_handle), self), "HANDLE") if dbgprint is not None else None
            self._close_function(self._limited_handle)

class Thread(utils.AutoHandle):
    def open_token(self, flags=MAXIMUM_ALLOWED, as_self=False):
        """Open the Thread token if any (Impersonation) else return None.
        ``as_self`` tells which security context should be used

        :returns: :class:`~windows.winobject.token.Token`

        .. note::

            see https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openthreadtoken

        """
        token_handle = HANDLE()
        try:
            winproxy.OpenThreadToken(self.handle, flags, as_self, byref(token_handle))
        except WindowsError as e:
            if e.winerror == gdef.ERROR_NO_TOKEN:
                # No token to open: return None
                return None
            raise
        return token.Token(token_handle.value)

    def set_token(self, token):
        """Set the token for the thread (impersonation). Setting the token to None revert the impersonation"""
        thandle = getattr(token, "handle", token) # Accept raw handle & token object
        return winproxy.SetThreadToken(self.handle, thandle)


    _TOKEN_PROPERTY_DOC = """The thread :class:`~windows.winobject.token.Token`

    :getter: :func:`open_token`
    :setter: :func:`set_token`
    """

    token = property(open_token, set_token, doc=_TOKEN_PROPERTY_DOC)


class CurrentThread(Thread):
    """The current thread"""
    @property #It's not a fixedpropety because executing thread might change
    def tid(self):
        """Thread ID

        :type: :class:`int`
		"""
        return winproxy.GetCurrentThreadId()

    @property
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

    name = "CurrentProcess" # Used by Winthread for __repr__

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

    @utils.fixedpropety
    def limited_handle(self):
        return winproxy.GetCurrentProcess()


    def __del__(self):
        pass

    @property
    def pid(self):
        """Process ID

        :type: :class:`int`
		"""
        return os.getpid()

    @utils.fixedpropety # leave it has fixed property as we don't care if CurrentProcess is never collected
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

    def virtual_alloc(self, size, prot=PAGE_EXECUTE_READWRITE):
        """Allocate memory in the process

        :return: The address of the allocated memory
        :rtype: :class:`int`
		"""
        return winproxy.VirtualAlloc(dwSize=size, flProtect=prot)

    def virtual_free(self, addr):
        """Free memory in the process by virtual_alloc"""
        return winproxy.VirtualFree(addr)

    def write_memory(self, addr, data):
        """Write data at addr"""
        data = raw_encode(data)
        # buffertype = (c_char * len(data)).from_address(addr)
        # buffertype[:len(data)] = data
        ctypes.memmove(addr, data, len(data))
        return True

    def read_memory(self, addr, size):
        """Read ``size`` from ``addr``

        :return: The data read
        :rtype: :class:`str`
		"""
        dbgprint('Read CurrentProcess Memory', 'READMEM')
        buffer = ctypes.c_buffer(size)
        ctypes.memmove(buffer, addr, size)
        return buffer[:]

    def create_thread(self, lpStartAddress, lpParameter, dwCreationFlags=0):
        """Create a new thread

        :rtype: :class:`WinThread` or :class:`DeadThread`
		"""
        handle = winproxy.CreateThread(lpStartAddress=lpStartAddress, lpParameter=lpParameter, dwCreationFlags=dwCreationFlags)
        return WinThread._from_handle(handle)

    def load_library(self, dll_path):
        """Load the library in current process

        :rtype: :class:`LoadedModule`
        """
        dllbase =  winproxy.LoadLibraryA(dll_path)
        return [m for m in self.peb.modules if m.baseaddr == dllbase][0]

    def execute(self, code, parameter=0):
        """Execute native code ``code`` in the current thread.

        :rtype: :class:`int` the return value of the native code"""
        f = windows.native_exec.create_function(code, [PVOID, PVOID])
        return f(parameter)

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

    # TODO: use ctypes.string_at / ctypes.wstring_at for read_string / read_wstring ?

    def read_string(self, addr):
        return ctypes.string_at(addr) # Raises WindowsError on fail

    def read_wstring(self, addr):
        return ctypes.wstring_at(addr) # Raises WindowsError on fail

class WinThread(Thread):
    """Represent a thread """

    def __init__(self, tid=None, handle=None, owner_pid=None, owner=None):
        if tid is None and handle is None:
            raise ValueError("Need at least <pid> or <handle> to create a {0}".format(type(self).__name__))

        if tid is not None:    self._tid = tid
        if handle is not None: self._handle = handle
        if owner is not None:   self._owner = owner
        if owner_pid is not None:   self._owner_pid = owner_pid
        if owner_pid is None and owner:
            self._owner_pid = owner.pid

    @classmethod
    def _from_THREADENTRY32(cls, entry, owner=None):
        tid = entry.th32ThreadID
        owner_pid = entry.th32OwnerProcessID
        return cls(tid=tid, owner_pid=owner_pid, owner=owner)

    @classmethod
    def _from_handle(cls, handle):
        # Create a DeadThread if thread is already dead ?
        return WinThread(handle=handle)

    @utils.fixedpropety
    def tid(self):
        """Thread ID

        :type: :class:`int`"""
        return self._get_thread_id(self.handle)

    @utils.fixedpropety
    def owner_pid(self):
        res = THREAD_BASIC_INFORMATION()
        windows.winproxy.NtQueryInformationThread(self.handle, ThreadBasicInformation, byref(res), ctypes.sizeof(res))
        owner_id = res.ClientId.UniqueProcess
        return owner_id

    @utils.fixedpropety
    def owner(self):
        """The Process owning the thread

        :type: :class:`WinProcess`
		"""
        return WinProcess(pid=self.owner_pid)

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

    @property
    def context_syswow(self):
        """The 64 bits context of a syswow thread.

        :type:  :class:`windows.exception.ECONTEXT64`
		"""
        if not self.owner.is_wow_64:
            raise ValueError("Not a syswow process")
        x = exception.ECONTEXT64.new_aligned()
        x.ContextFlags = CONTEXT_ALL
        if windows.current_process.bitness == 64:
            winproxy.GetThreadContext(self.handle, x)
        else:
            windows.syswow64.NtGetContextThread_32_to_64(self.handle, x)
        return x


    def set_context(self, context):
        """Set the thread's context to ``context``"""
        if self.owner.bitness == windows.current_process.bitness:
            return winproxy.SetThreadContext(self.handle, context)
        if windows.current_process.bitness == 64 and self.owner.bitness == 32:
            return winproxy.Wow64SetThreadContext(self.handle, context)
        return windows.syswow64.NtSetContextThread_32_to_64(self.handle, ctypes.byref(context))


    def set_syswow_context(self, context):
        """Set a syswow thread's 64 context to ``context``"""
        if not self.owner.is_wow_64:
            raise ValueError("Not a syswow process")
        if windows.current_process.bitness == 64:
            return winproxy.SetThreadContext(self.handle, context)
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

    def _get_principal_teb_addr(self):
        # Returns the 64bits TEB on a 64bits computer (syswow process or not)
        # Returns the 32bits TEB on a 32bits computer

        # If we are wow64 process its means we either
        # - Want the TEB of a 64b process
        # - Want the TEB64 of a Wowprocess
        # It's the same code for both
        if windows.current_process.is_wow_64:
            restype = rctypes.transform_type_to_remote64bits(THREAD_BASIC_INFORMATION)
            ressize = (ctypes.sizeof(restype))
            # Manual aligned allocation :DDDD
            nb_qword = (ressize + 8) / ctypes.sizeof(ULONGLONG)
            buffer = (nb_qword * ULONGLONG)()
            struct_address = ctypes.addressof(buffer)
            if (struct_address & 0xf) not in [0, 8]:
                raise ValueError("ULONGLONG array not aligned on 8")
            windows.syswow64.NtQueryInformationThread_32_to_64(self.handle, ThreadBasicInformation, struct_address, ressize)
            return restype(struct_address, windows.current_process).TebBaseAddress

        res = THREAD_BASIC_INFORMATION()
        windows.winproxy.NtQueryInformationThread(self.handle, ThreadBasicInformation, byref(res), ctypes.sizeof(res))
        return res.TebBaseAddress

    @property
    def teb_base(self):
        """The address of the thread's TEB. If the owner is a SysWow64 process, return the TEB32.

            :type: :class:`int`
		"""
        main_teb_addr = self._get_principal_teb_addr()
        if not self.owner.is_wow_64:
            return main_teb_addr
        # import pdb; pdb.set_trace()
        # TEB32 is pointed at the begining of the TEB64
        return self.owner.read_dword(main_teb_addr)



    @property
    def teb_syswow_base(self):
        """The address of the thread's TEB64 for a SysWow64 process

        :type: :class:`int`
		"""
        if not self.owner.is_wow_64:
            raise ValueError("Not a syswow process")
        # just return the main TEB
        return self._get_principal_teb_addr()


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
            try:
                owner_name = owner.name
            except EnvironmentError:
                owner_name = "!cannot-retrieve-owner-name"
        return '<{0} {1} owner "{2}" at {3}>'.format(self.__class__.__name__, self.tid, owner_name, hex(id(self)))


    @staticmethod
    def _get_thread_id_by_api(handle):
        return winproxy.GetThreadId(handle)

    @staticmethod
    def _get_thread_id_manual(handle):
        if windows.current_process.bitness == 32 and self.owner.bitness == 64:
            raise NotImplementedError("[_get_thread_id_manual] 32 -> 64 (XP64 bits + Syswow process ?)")
        res = THREAD_BASIC_INFORMATION()
        windows.winproxy.NtQueryInformationThread(handle, ThreadBasicInformation, byref(res), ctypes.sizeof(res))
        id2 = res.ClientId.UniqueThread
        return id2

    if winproxy.is_implemented(winproxy.GetThreadId):
        _get_thread_id = _get_thread_id_by_api
    else:
        _get_thread_id = _get_thread_id_manual


class WinProcess(Process):
    """A Process on the system"""
    def __init__(self, pid=None, handle=None, name=None, ppid=None):
        if pid is None and handle is None:
            raise ValueError("Need at least <pid> or <handle> to create a {0}".format(type(self).__name__))

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
        # Temporary encoded name
        name = entry.szExeFile.encode(errors="backslashreplace")
        pid = entry.th32ProcessID
        ppid = entry.th32ParentProcessID
        return cls(pid=pid, name=name, ppid=ppid)


    @utils.fixedpropety
    def name(self):
        """Name of the process

        :type: :class:`str`
		"""
        buffer = ctypes.c_buffer(0x1024)
        rsize = winproxy.GetProcessImageFileNameA(self.limited_handle, buffer) # Use a syscall and not some remote process reading
        # GetProcessImageFileNameA returns the fullpath
        return buffer[:rsize].decode().split("\\")[-1]

    @utils.fixedpropety
    def pid(self):
        """Process ID

        :type: :class:`int`
		"""
        return winproxy.GetProcessId(self.handle)

    def _get_handle(self):
        return winproxy.OpenProcess(dwProcessId=self.pid)

    def __repr__(self):
        try:
            exe_name = self.name
        except WindowsError as e:
            exe_name = "!cannot-retrieve-name"
        try:
            if self.is_exit:
                return '<{0} "{1}" pid {2} (DEAD) at {3}>'.format(self.__class__.__name__, exe_name, self.pid, hex(id(self)))
        except WindowsError: # Cannot open process
            pass
        return '<{0} "{1}" pid {2} at {3}>'.format(self.__class__.__name__, exe_name, self.pid, hex(id(self)))

    def virtual_alloc(self, size, prot=PAGE_EXECUTE_READWRITE, addr=None):
        """Allocate memory in the process

        :return: The address of the allocated memory
        :rtype: :class:`int`
		"""
        return winproxy.VirtualAllocEx(self.handle, lpAddress=addr, dwSize=size, flProtect=prot)

    def virtual_free(self, addr):
        """Free memory in the process by virtual_alloc"""
        return winproxy.VirtualFreeEx(self.handle, addr)

    def write_memory(self, addr, data):
        """Write `data` at `addr`"""
        data = raw_encode(data)
        if windows.current_process.bitness == 32 and self.bitness == 64:
            if not winproxy.is_implemented(winproxy.NtWow64WriteVirtualMemory64):
                raise ValueError("NtWow64WriteVirtualMemory64 non available in ntdll: cannot write into 64bits processus")
            return winproxy.NtWow64WriteVirtualMemory64(self.handle, addr, data, len(data))
        return winproxy.WriteProcessMemory(self.handle, addr, lpBuffer=data)

    def low_read_memory(self, addr, buffer_addr, size):
        if windows.current_process.bitness == 32 and self.bitness == 64:
            # OptionalExport can be None (see winproxy.py)
            if not winproxy.is_implemented(winproxy.NtWow64ReadVirtualMemory64):
                raise ValueError("NtWow64ReadVirtualMemory64 non available in ntdll: cannot read into 64bits processus")
            return winproxy.NtWow64ReadVirtualMemory64(self.handle, addr, buffer_addr, size)
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
        """Load the library in remote process

        :rtype: :class:`LoadedModule`
        """
        dllbase = windows.injection.load_dll_in_remote_process(self, dll_path)
        return [m for m in self.peb.modules if m.baseaddr == dllbase][0]

    def execute_python(self, pycode):
        """Execute Python code into the remote process.

        This function waits for the remote process to end and
        raises an exception if the remote thread raised one
		"""
        return injection.safe_execute_python(self, pycode)

    def execute_python_unsafe(self, pycode):
        """Execute Python code into the remote process.

        :rtype: :rtype: :class:`WinThread` or :class:`DeadThread` : The thread executing the python code
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

    # Not a fixedpropety to prevent ref-cycle and uncollectable WinProcess
    # Try with a weakref ?
    @property
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
    def peb_syswow_addr(self):
        if not self.is_wow_64:
            raise ValueError("Not a syswow process")
        if windows.current_process.bitness == 64:
            information_type = 0
            x = PROCESS_BASIC_INFORMATION()
            winproxy.NtQueryInformationProcess(self.handle, information_type, x)
            peb_addr = ctypes.cast(x.PebBaseAddress, PVOID).value
            return peb_addr
        else: #current is 32bits
            x = windows.remotectypes.transform_type_to_remote64bits(PROCESS_BASIC_INFORMATION)
            # Fuck-it <3
            data = (ctypes.c_char * ctypes.sizeof(x))()
            windows.syswow64.NtQueryInformationProcess_32_to_64(self.handle, ProcessInformation=data, ProcessInformationLength=ctypes.sizeof(x))
            peb_offset = x.PebBaseAddress.offset
            peb_addr = struct.unpack("<Q", data[x.PebBaseAddress.offset: x.PebBaseAddress.offset+8])[0]
            return peb_addr

    # Not a fixedpropety to prevent ref-cycle and uncollectable WinProcess
    # Try with a weakref ?
    @property
    def peb_syswow(self):
        """The 64bits PEB of a SysWow64 process

        :type: :class:`PEB`
		"""
        if not self.is_wow_64:
            raise ValueError("Not a syswow process")
        if windows.current_process.bitness == 64:
            return RemotePEB(self.peb_syswow_addr, self)
        else: #current is 32bits
            return RemotePEB64(self.peb_syswow_addr, windows.syswow64.ReadSyswow64Process(self))

    def exit(self, code=0):
        """Exit the process"""
        return winproxy.TerminateProcess(self.handle, code)




def transform_ctypes_fields(struct, replacement):
    return [(name, replacement.get(name, type)) for name, type in struct._fields_]


class LoadedModule(LDR_DATA_TABLE_ENTRY):
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


class PEB(gdef.PEB):
    """The PEB (Process Environment Block) of the current process"""

    @property
    def exe(self):
        """The executable of the process, as pointed by PEB.ImageBaseAddress

        :type: :class:`windows.pe_parse.PEFile`
        """
        return windows.pe_parse.GetPEFile(self.ImageBaseAddress)

    @property
    def imagepath(self):
        """The ImagePathName of the PEB

        :type: :class:`~windows.generated_def.winstructs.LSA_UNICODE_STRING`
		"""
        return self.ProcessParameters.contents.ImagePathName

    @property
    def commandline(self):
        """The CommandLine of the PEB

        :type: :class:`~windows.generated_def.winstructs.LSA_UNICODE_STRING`
		"""
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

    @staticmethod
    def _extract_environment(env_block_addr, target):
        result = []
        while True:
            venv = target.read_wstring(env_block_addr)
            if not venv:
                return result
            result.append(venv)
            env_block_addr += ((len(venv) + 1) * 2)
        # raise RuntimeError("Out of infinite loop")

    @property
    def environment(self):
        # TODO: Tests
        return self._extract_environment(self.ProcessParameters.contents.Environment, windows.current_process)

    @property
    def apisetmap(self):
        """The :class:`~windows.winobject.apisetmap.ApiSetMap` of the process

        :rtype: A subclass of :class:`~windows.winobject.apisetmap.ApiSetMap`
        :raise: :class:`~exception.NotImplementedError` -- Before ``6.2`` ApiSetMap did not exist
        :raise: :class:`~exception.NotImplementedError` -- Not implemented for remote process
        """
        if windows.system.version < (6,2):
            raise NotImplementedError("ApiSetMap does not exist prior to Windows 7")
        return apisetmap.get_api_set_map_for_current_process(self.ApiSetMap)


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
    def exe(self):
        """The executable of the process, as pointed by PEB.ImageBaseAddress

        :type: :class:`windows.pe_parse.PEFile`
        """
        return pe_parse.GetPEFile(self.ImageBaseAddress, target=self._target)

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

    @property
    def environment(self):
        # TODO: Tests
        return self._extract_environment(self.ProcessParameters.contents.Environment, self._target)

    @property
    def apisetmap(self):
        raise NotImplementedError("ApiSetMap for remote process not implemented yet")




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
        def exe(self):
            """The executable of the process, as pointed by PEB.ImageBaseAddress

            :type: :class:`windows.pe_parse.PEFile`
            """
            return pe_parse.GetPEFile(self.ImageBaseAddress, target=self._target)

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

        @property
        def environment(self):
            # TODO: Tests
            return self._extract_environment(self.ProcessParameters.contents.Environment, self._target)

        apisetmap = RemotePEB.apisetmap

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
        def exe(self):
            """The executable of the process, as pointed by PEB.ImageBaseAddress

            :type: :class:`windows.pe_parse.PEFile`
            """
            return pe_parse.GetPEFile(self.ImageBaseAddress, target=self._target)


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

        @property
        def environment(self):
            # TODO: Tests
            return self._extract_environment(self.ProcessParameters.contents.Environment, self._target)

        apisetmap = RemotePEB.apisetmap