import ctypes
import functools

from ctypes.wintypes import *
from windows.generated_def.winstructs import *
from windows.generated_def.windef import *
import windows.generated_def.winfuncs as winfuncs


kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.Advapi32



class Kernel32Error(WindowsError):

    def __new__(cls, func_name):
        win_error = ctypes.WinError()
        api_error = super(Kernel32Error, cls).__new__(cls)
        api_error.api_name = func_name
        api_error.winerror = win_error.winerror
        api_error.strerror =  win_error.strerror
        api_error.args = (func_name, win_error.winerror, win_error.strerror)
        return api_error
        
    def __init__(self, func_name):
        pass
        
    def __repr__(self):
        return "{0}: {1}".format(self.api_name, super(Kernel32Error, self).__repr__())
        
    def __str__(self):
        return "{0}: {1}".format(self.api_name, super(Kernel32Error, self).__str__())
 
def no_error_check(result, func, args):
    """Nothing special"""
    return args 
    
# Design 1     
class ApiProxy(object):
    APIDLL = None
    """Create a python wrapper around a kernel32 function"""
    def __init__(self, func_name, error_check=None):
        self.func_name = func_name
        if error_check is None:
            error_check = self.default_error_check
        self.error_check = error_check
        
    def default_error_check(self, result, func, args):
        """raise Kernel32Error if result is 0"""
        if not result:
            raise Kernel32Error(self.func_name)
        return args
        
    def __call__(self, python_proxy, ):
        prototype = getattr(winfuncs, self.func_name + "Prototype")
        params = getattr(winfuncs, self.func_name + "Params")
        c_prototyped = prototype((self.func_name, self.APIDLL), params)
        c_prototyped.errcheck = self.error_check
        if (self.error_check.__doc__):
            doc = python_proxy.__doc__
            doc = doc if doc else ""
            python_proxy.__doc__ = doc + "\nErrcheck:\n   " + self.error_check.__doc__
        params_name = [param[1] for param in params]
        def perform_call(*args):
            if len(params_name) != len(args):
                print("ERROR:")
                print("Expected params: {0}".format(params_name))
                print("Just Got params: {0}".format(args))
                raise ValueError("I do not have all parameters: how is that possible ?")
            for param_name, param_value in zip(params_name, args):
                if param_value is NeededParameter:
                    raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.func_name, param_name))
            return c_prototyped(*args)
        setattr(python_proxy, "ctypes_function", perform_call)
        return python_proxy
        
class Kernel32Proxy(ApiProxy):
    APIDLL = kernel32

class Advapi32Proxy(ApiProxy):
    APIDLL = advapi32
    
def TransparentApiProxy(APIDLL, func_name, error_check=None):
    """Create a ctypes function for 'func_name' with no python arg pre-check"""
    def default_error_check(result, func, args):
        if not result:
            raise Kernel32Error(func_name)
        return args
    if error_check is None:
        error_check = default_error_check
    prototype = getattr(winfuncs, func_name + "Prototype")
    args = getattr(winfuncs, func_name + "Params")
    c_prototyped = prototype((func_name, APIDLL), args)
    c_prototyped.errcheck = error_check
    return c_prototyped  

    
TransparentKernel32Proxy = lambda *args: TransparentApiProxy(kernel32, *args)
TransparentAdvapi32Proxy = lambda *args: TransparentApiProxy(advapi32, *args)
 
class NeededParameterType(object):
    _inst = None
    def __new__(cls):
        if cls._inst is None:
            cls._inst = super(NeededParameterType, cls).__new__(cls)
        return cls._inst
        
    def __repr__(self):
        return "NeededParameter"
        
NeededParameter =   NeededParameterType()
        


ExitProcess = TransparentKernel32Proxy("ExitProcess")
CloseHandle = TransparentKernel32Proxy("CloseHandle")
GetProcAddress = TransparentKernel32Proxy("GetProcAddress")
LoadLibraryA = TransparentKernel32Proxy("LoadLibraryA")
LoadLibraryW = TransparentKernel32Proxy("LoadLibraryW")
GetLastError = TransparentKernel32Proxy("GetLastError", no_error_check)
GetCurrentProcess = TransparentKernel32Proxy("GetCurrentProcess")

# This kind of function could be fully done by using paramflags
@Kernel32Proxy("VirtualAlloc")
def VirtualAlloc(lpAddress=0,  dwSize=NeededParameter, flAllocationType=MEM_COMMIT, flProtect=PAGE_EXECUTE_READWRITE):
    return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)
    
@Kernel32Proxy("VirtualAllocEx")
def VirtualAllocEx(hProcess, lpAddress=0,  dwSize=NeededParameter, flAllocationType=MEM_COMMIT, flProtect=PAGE_EXECUTE_READWRITE):
    return VirtualAllocEx.ctypes_function(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    
@Kernel32Proxy("CreateRemoteThread") 
def CreateRemoteThread(hProcess=NeededParameter, lpThreadAttributes=None, dwStackSize=0,
                           lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None):
    return CreateRemoteThread.ctypes_function(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)
 
@Kernel32Proxy("VirtualProtect")    
def VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect=0):
    return VirtualProtect.ctypes_function(lpAddress, dwSize, flNewProtect, lpflOldProtect)
     
@Kernel32Proxy("CreateProcessA")
def CreateProcessA(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False,
                        dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None):                 
    if lpStartupInfo is None:
        StartupInfo = STARTUPINFOA()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = STARTF_USESHOWWINDOW
        StartupInfo.wShowWindow = SW_HIDE
        lpStartupInfo = ctypes.byref(StartupInfo)
    if lpProcessInformation is None:
        lpProcessInformation = ctypes.byref(PROCESS_INFORMATION())  
    return CreateProcessA.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)

@Kernel32Proxy("CreateProcessW")
def CreateProcessW(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False,
                        dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None):                 
    if lpStartupInfo is None:
        StartupInfo = STARTUPINFOW()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = STARTF_USESHOWWINDOW
        StartupInfo.wShowWindow = SW_HIDE
        lpStartupInfo = ctypes.byref(StartupInfo)  
    if lpProcessInformation is None:
        lpProcessInformation = ctypes.byref(PROCESS_INFORMATION())  
    return CreateProcessW.ctypes_function(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
          
@Kernel32Proxy("GetThreadContext")
def GetThreadContext(hThread, lpContext=None):
    if lpContext is None:
        Context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        lpContext = ctypes.byref(Context)
    return GetThreadContext.ctypes_function(hThread, lpContext)
    
@Kernel32Proxy("SetThreadContext")
def SetThreadContext(hThread, lpContext):
    """ Allows to directly pass a CONTEXT and will call with byref(CONTEXT) by itself"""
    if type(lpContext) == CONTEXT:
        lpContext = ctypes.byref(lpContext)
    return SetThreadContext.ctypes_function(hThread, lpContext)
    
@Kernel32Proxy("OpenThread")
def OpenThread(dwDesiredAccess=THREAD_ALL_ACCESS, bInheritHandle=0, dwThreadId=NeededParameter):
    return OpenThread.ctypes_function(dwDesiredAccess, bInheritHandle, dwThreadId)

@Kernel32Proxy("OpenProcess")
def OpenProcess(dwDesiredAccess=PROCESS_ALL_ACCESS, bInheritHandle=0, dwProcessId=NeededParameter):
    return OpenProcess.ctypes_function(dwDesiredAccess, bInheritHandle, dwProcessId)
            
@Kernel32Proxy("ReadProcessMemory")
def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer=None, nSize=NeededParameter, lpNumberOfBytesRead=None):
    """Create a string buffer if lpBuffer is not given"""
    if lpBuffer is None and nSize is not NeededParameter:
        lpBuffer =  ctypes.create_string_buffer(nSize)
    return ReadProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
    
@Kernel32Proxy("WriteProcessMemory")
def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize=None, lpNumberOfBytesWritten=None):
    """Computer nSize with len(lpBuffer) if not given"""
    if nSize is None:
        nSize = len(lpBuffer)
    return WriteProcessMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
    
@Kernel32Proxy("CreateToolhelp32Snapshot") 
def CreateToolhelp32Snapshot(dwFlags, th32ProcessID=0):
    return CreateToolhelp32Snapshot.ctypes_function(dwFlags, th32ProcessID)
    
@Kernel32Proxy("Thread32First", no_error_check) 
def Thread32First(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return  Thread32First.ctypes_function(hSnapshot, lpte)

@Kernel32Proxy("Thread32Next", no_error_check) 
def Thread32Next(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return  Thread32Next.ctypes_function(hSnapshot, lpte)

@Kernel32Proxy("Process32First", no_error_check) 
def Process32First(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return  Process32First.ctypes_function(hSnapshot, lpte)

@Kernel32Proxy("Process32Next", no_error_check) 
def Process32Next(hSnapshot, lpte):
    """Set byref(lpte) if needed"""
    if type(lpte) == THREADENTRY32:
        lpte = ctypes.byref(lpte)
    return  Process32Next.ctypes_function(hSnapshot, lpte)

    
###### ADVAPI32 ########

@Advapi32Proxy('OpenProcessToken')
def OpenProcessToken(ProcessHandle=None, DesiredAccess=NeededParameter, TokenHandle=NeededParameter):
    """If ProcessHandle is None: take the current process"""
    if ProcessHandle is None:
        ProcessHandle = GetCurrentProcess()
    return OpenProcessToken.ctypes_function(ProcessHandle, DesiredAccess, TokenHandle)

@Advapi32Proxy('LookupPrivilegeValueA')
def LookupPrivilegeValueA(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter):
    return LookupPrivilegeValueA.ctypes_function(lpSystemName, lpName, lpLuid)
  
@Advapi32Proxy('LookupPrivilegeValueW')
def LookupPrivilegeValueW(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter):
    return LookupPrivilegeValueW.ctypes_function(lpSystemName, lpName, lpLuid)  
    
@Advapi32Proxy('AdjustTokenPrivileges')
def AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges=False, NewState=NeededParameter, BufferLength=None, PreviousState=None, ReturnLength=None):
    if BufferLength is None:
        BufferLength = ctypes.sizeof(NewState)
    return AdjustTokenPrivileges.ctypes_function(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength)
#	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
#		fprintf(stderr, "[-] The token does not have the specified privilege\n");
#		return FALSE; 
    
    
    
# Design 2
# Design 2 should use the automatics args

    