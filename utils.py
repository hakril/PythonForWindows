import ctypes
import k32testing as kernel32proxy
import generated_def.windef as windef
import winobject
import copy
import native_exec
import generated_def.winstructs as winstructs

# Function resolution !

def swallow_ctypes_copy(ctypes_object):
    new_copy = type(ctypes_object)()
    ctypes.memmove(ctypes.byref(new_copy), ctypes.byref(ctypes_object), ctypes.sizeof(new_copy))
    return new_copy

def get_func_addr(dll_name, func_name):
        dll = ctypes.WinDLL(dll_name)
        return kernel32proxy.GetProcAddress(dll._handle, func_name)
        
def enumerate_processes():
    process_entry = winobject.WinProcess()
    #process_entry = winstructs.PROCESSENTRY32()
    process_entry.dwSize = ctypes.sizeof(process_entry)
    snap = kernel32proxy.CreateToolhelp32Snapshot(windef.TH32CS_SNAPPROCESS, 0)
    kernel32proxy.Process32First(snap, process_entry)
    res = []
    res.append(swallow_ctypes_copy(process_entry))
    while kernel32proxy.Process32Next(snap, process_entry):
         res.append(swallow_ctypes_copy(process_entry))
    return res

def enumerate_threads():
    thread_entry = winobject.WinThread()
    thread_entry.dwSize = ctypes.sizeof(thread_entry)
    snap = kernel32proxy.CreateToolhelp32Snapshot(windef.TH32CS_SNAPTHREAD, 0)
    threads = []
    kernel32proxy.Thread32First(snap, thread_entry)
    threads.append(copy.copy(thread_entry))
    while kernel32proxy.Thread32Next(snap, thread_entry):
        threads.append(copy.copy(thread_entry))
    return threads
    
class System(object):

    @property
    def processes(self):
        return enumerate_processes()
        
    @property
    def threads(self):
        return enumerate_threads()

class CurrentProcess(object):
    get_peb = None
    
    get_peb_32_code = '64a130000000c3'.decode('hex')
 
    def get_peb_builtin(self):
        if self.get_peb is not None:
            return self.get_peb
        get_peb = native_exec.create_function(self.get_peb_32_code, [winstructs.PVOID])
        self.get_peb = get_peb
        return get_peb
        
    @property    
    def peb(self):
        return winobject.PEB.from_address(self.get_peb_builtin()())
    
        
class VirtualProtected(object):
    def __init__(self, addr, size, new_protect):
        if (addr % 0x1000):
            addr = addr - addr % 0x1000
        self.addr = addr
        self.size = size
        self.new_protect = new_protect
        
    def __enter__(self):
        self.old_protect = winstructs.DWORD()
        kernel32proxy.VirtualProtect(self.addr, self.size, self.new_protect, ctypes.byref(self.old_protect))
        return self
        
    def __exit__(self, exc_type, exc_value, traceback):
        kernel32proxy.VirtualProtect(self.addr, self.size, self.old_protect.value, ctypes.byref(self.old_protect))
        return False