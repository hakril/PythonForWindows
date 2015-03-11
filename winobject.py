import ctypes
import utils
import k32testing as kernel32proxy
import injection

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
    def threads(self):
        return [thread for thread in utils.enumerate_threads() if thread.th32OwnerProcessID == self.pid]
        
    def _get_handle(self):
        return kernel32proxy.OpenProcess(dwProcessId=self.pid)
          
    def __repr__(self):
        return '<{0} "{1}" pid {2} at {3}>'.format(self.__class__.__name__, self.name, self.pid, hex(id(self)))
        
    def virtual_alloc(self, size):
        return kernel32proxy.VirtualAllocEx(self.handle, dwSize=size)
        
    def write_memory(self, addr, data):
        return kernel32proxy.WriteProcessMemory(self.handle, addr, lpBuffer=data)
        
    def read_memory(self, addr, size):
        return kernel32proxy.ReadProcessMemory(self.handle, addr, nSize=size)
        
    def create_thread(self, addr, param):
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
        
    def get_remote_python(self):
        return injection.launch_remote_slave(self)
    
    
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