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
    def _get_handle(self):
        raise NotImplementedError('_get_handle')

    @property
    def handle(self):
        if hasattr(self, "_handle"):
            return self._handle
        self._handle = self._get_handle()
        return self._handle

    def __del__(self):
         if hasattr(self, "_handle"):
            kernel32proxy.CloseHandle(self._handle)

class System(object):

    @property
    def processes(self):
        return utils.enumerate_processes()

    @property
    def threads(self):
        return utils.enumerate_threads()

    @property
    def bitness(self):
        if os.environ["PROCESSOR_ARCHITECTURE"].lower() != "x86":
            return 64
        if "PROCESSOR_ARCHITEW6432" in os.environ:
            return 64
        return 32


# May have a common class with WinProcess for is_wow_64 and stuff

class WinThread(THREADENTRY32, AutoHandle):
    @property
    def tid(self):
        return self.th32ThreadID

    @property
    def owner(self):
        if hasattr(self, "_owner"):
            return self._owner
        self._owner = [process for process in utils.enumerate_processes() if process.pid == self.th32OwnerProcessID][0]
        return self._owner

    def _get_handle(self):
        return kernel32proxy.OpenThread(dwThreadId=self.tid)

    def __repr__(self):
        return '<{0} {1} owner "{2}" at {3}>'.format(self.__class__.__name__, self.tid, self.owner.name, hex(id(self)))


class CurrentProcess(object):
    get_peb = None
    get_peb_32_code = '64a130000000c3'.decode('hex')

    # mov    rax,QWORD PTR gs:0x60
    # ret
    get_peb_64_code = "65488B042560000000C3".decode('hex')

    def get_peb_builtin(self):
        if self.get_peb is not None:
            return self.get_peb
        if self.bitness == 32:
            get_peb = native_exec.create_function(self.get_peb_32_code, [PVOID])
        else:
            get_peb = native_exec.create_function(self.get_peb_64_code, [PVOID])
        self.get_peb = get_peb
        return get_peb

    @property
    def peb(self):
        return PEB.from_address(self.get_peb_builtin()())

    @property
    def bitness(self):
        """Return 32 or 64"""
        import platform
        bits = platform.architecture()[0]
        return int(bits[:2])

    @property
    def is_wow_64(self):
        return utils.is_wow_64(kernel32proxy.GetCurrentProcess())

    def virtual_alloc(self, size):
        return kernel32proxy.VirtualAlloc(dwSize=size)

    def write_memory(self, addr, data):
        buffertype = (c_char * len(data)).from_address(addr)
        buffertype[:len(data)] = data
        return True

    def read_memory(self, addr, size):
        buffer = (c_char * size).from_address(addr)
        return buffer[:]

class WinProcess(PROCESSENTRY32, AutoHandle):
    is_pythondll_injected = 0
    is_remote_slave_running = False

    @property
    def name(self):
        return self.szExeFile[:]

    @property
    def pid(self):
        return self.th32ProcessID

    @property
    def ppid(self):
        return self.th32ParentProcessID

    @property
    def threads(self):
        return [thread for thread in utils.enumerate_threads() if thread.th32OwnerProcessID == self.pid]

    def _get_handle(self):
        return kernel32proxy.OpenProcess(dwProcessId=self.pid)

    def __repr__(self):
        return '<{0} "{1}" pid {2} at {3}>'.format(self.__class__.__name__, self.name, self.pid, hex(id(self)))

    @property
    def is_wow_64(self):
        return utils.is_wow_64(self.handle)

    @property
    def bitness(self):
        if windows.system.bitness == 32:
            return 32
        if self.is_wow_64:
            return 32
        return 64

    def virtual_alloc(self, size):
        return kernel32proxy.VirtualAllocEx(self.handle, dwSize=size)

    def write_memory(self, addr, data):
        return kernel32proxy.WriteProcessMemory(self.handle, addr, lpBuffer=data)

    def low_read_memory(self, addr, buffer_addr, size):
        if windows.current_process.bitness == 32 and self.bitness == 64:
            NtWow64ReadVirtualMemory64Addr = windows.utils.get_func_addr("ntdll.dll", "NtWow64ReadVirtualMemory64")
            NtWow64ReadVirtualMemory64 = WINFUNCTYPE(HRESULT, HANDLE, ULONG64, PVOID, ULONG64, PULONG64)(NtWow64ReadVirtualMemory64Addr)
            return NtWow64ReadVirtualMemory64(self.handle, addr, buffer_addr, size, None)
        return kernel32proxy.ReadProcessMemory(self.handle, addr, lpBuffer=buffer_addr, nSize=size)

    def read_memory(self, addr, size):
        buffer =  ctypes.create_string_buffer(size)
        self.low_read_memory(addr, ctypes.byref(buffer), size)
        return buffer[:]

    def read_memory_into(self, addr, struct):
        self.low_read_memory(addr, ctypes.byref(struct), ctypes.sizeof(struct))
        return struct

    def create_thread(self, addr, param):
        if windows.current_process.bitness == 32 and self.bitness == 64:
            return windows.syswow64.NtCreateThreadEx_32_to_64(self, addr, param)
        return  kernel32proxy.CreateRemoteThread(hProcess=self.handle, lpStartAddress=addr, lpParameter=param)

    def load_library(self, dll_path):
        x = self.virtual_alloc(0x1000)
        self.write_memory(x, dll_path)
        LoadLibrary = utils.get_func_addr('kernel32', 'LoadLibraryA')
        return self.create_thread(LoadLibrary, x)

    def execute(self, code):
        x = self.virtual_alloc(len(code))
        self.write_memory(x, code)
        return self.create_thread(x, 0)

    def execute_python(self, pycode):
        return injection.execute_python_code(self, pycode)

    #def NtCreateThreadEx(self, addr, param):
    #        print("CALLING SPECIAL NtCreateThreadEx")
    #        NtCreateThreadExAddr = utils.get_func_addr("ntdll.dll", "NtCreateThreadEx")
    #        NtCreateThreadEx = WINFUNCTYPE(HRESULT, PHANDLE, DWORD, PVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, DWORD, DWORD, DWORD, PVOID)(NtCreateThreadExAddr)
    #        thread_handle = HANDLE()
    #        res = NtCreateThreadEx(byref(thread_handle), 0x1fffff, None, self.handle, addr, param, False, 0, 0, 0, None)
    #        print("RES = {0}".format(hex(res & 0xffffffff)))
    #        if res:
    #            raise WinError()
    #
    #def RtlCreateUserThread(self, addr, param):
    #    print("CALLING SPECIAL RtlCreateUserThread")
    #    RtlCreateUserThreadAddr = utils.get_func_addr("ntdll.dll", "RtlCreateUserThread")
    #    RtlCreateUserThread = WINFUNCTYPE(HRESULT, HANDLE, LPSECURITY_ATTRIBUTES, BOOL, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PVOID)(RtlCreateUserThreadAddr)
    #    thread_handle = HANDLE()
    #    tmp1 = DWORD()
    #    tmp2 = DWORD()
    #    res = RtlCreateUserThread(self.handle, None, False, 0, None, None, addr, param, None, None)
    #    print("RES = {0}".format(hex(res & 0xffffffff)))
    #    if res:
    #        raise WinError()


class LoadedModule(LDR_DATA_TABLE_ENTRY):
    @property
    def baseaddr(self):
        return self.DllBase

    @property
    def name(self):
        return self.BaseDllName.Buffer

    @property
    def fullname(self):
        return self.FullDllName.Buffer

    def __repr__(self):
        return '<{0} "{1}" at {2}>'.format(self.__class__.__name__, self.name, hex(id(self)))

    @property
    def pe(self):
        return pe_parse.PEFile(self.baseaddr)

class WinUnicodeString(LSA_UNICODE_STRING):
    def __repr__(self):
        return """<{0} "{1}" at {2}>""".format(type(self).__name__, self.Buffer, hex(id(self)))


class LIST_ENTRY_PTR(PVOID):
    def TO_LDR_ENTRY(self):
        return LDR_DATA_TABLE_ENTRY.from_address(self.value - sizeof(PVOID) *  2)


# May want to have all known fields..
class PEB(PEB):

    @property
    def imagepath(self):
        raw_imagepath = self.ProcessParameters.contents.ImagePathName
        return WinUnicodeString.from_address(ctypes.addressof(raw_imagepath))

    @property
    def commandline(self):
        # This or changing the __repr__ of LSA_UNICODE_STRING
        raw_cmd = self.ProcessParameters.contents.CommandLine
        return WinUnicodeString.from_address(ctypes.addressof(raw_cmd))

    @property
    def modules(self):
        res = []
        list_entry_ptr = ctypes.cast(self.Ldr.contents.InMemoryOrderModuleList.Flink, LIST_ENTRY_PTR)
        current_dll = list_entry_ptr.TO_LDR_ENTRY()
        while current_dll.DllBase:
            res.append(current_dll)
            list_entry_ptr = ctypes.cast(current_dll.InMemoryOrderLinks.Flink, LIST_ENTRY_PTR)
            current_dll = list_entry_ptr.TO_LDR_ENTRY()
        return [LoadedModule.from_address(addressof(LDR)) for LDR in res]