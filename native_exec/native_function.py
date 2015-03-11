import ctypes
import mmap
import platform

class PyObj(ctypes.Structure):
    _fields_ = [("ob_refcnt", ctypes.c_size_t),
                ("ob_type", ctypes.c_void_p)] #must be cast

class PyMmap(PyObj):
    _fields_ = [("ob_addr", ctypes.c_size_t), ("ob_size", ctypes.c_size_t)]

# Specific mmap class for code injection
   
class MyMap(mmap.mmap):
    """ A mmap that is never unmapped and that contains the page address """
    def __init__(self, *args, **kwarg):
        #Get the page address by 'introspection' of the C struct
        m = PyMmap.from_address(id(self))
        self.addr = m.ob_addr
        #Prevent garbage collection (so unmaping) of the page
        m.ob_refcnt += 1

    @classmethod
    def get_map(cls, size):
        """ Dispatch to the good mmap implem depending on the current system """
        systems = {'windows' : Win32MyMap,
                    'linux' : UnixMyMap }
        x = platform.system().lower()
        if x not in systems:
            raise ValueError("Unknow system {0}".format(x))
        return systems[x].get_map(size)

class Win32MyMap(MyMap):
    @classmethod
    def get_map(cls, size):
        #access = mmap.ACCESS_READ | mmap.ACCESS_WRITE
        #return cls(-1, size, access=access)
        access = mmap.ACCESS_READ | mmap.ACCESS_WRITE
        addr = ctypes.windll.kernel32.VirtualAlloc(0, size, 0x1000, 0x40)
  
        new_map = (ctypes.c_char * size).from_address(addr)
        new_map.addr = addr
        if new_map.addr == 0:
            raise ctypes.WinError()
        return new_map

class UnixMyMap(MyMap):
    @classmethod
    def get_map(cls, size):
        prot = mmap.PROT_EXEC | mmap.PROT_WRITE | mmap.PROT_READ
        return cls(-1, size, prot=prot)
        
        
class CustomAllocator(object):
    int_size = {'32bit' : 4, '64bit' : 8}

    def __init__(self):
        self.maps = []
        self.get_new_page(0x1000)
        self.names = []

    @classmethod
    def get_int_size(cls):
        bits = platform.architecture()[0]
        if bits not in cls.int_size:
            raise ValueError("Unknow platform bits <{0}>".format(bits))
        return cls.int_size[bits]

    def get_new_page(self, size):
        self.maps.append(MyMap.get_map(size))
        self.cur_offset = 0
        self.cur_page_size = size

    def reserve_size(self, size):
        if size + self.cur_offset > self.cur_page_size:
            self.get_new_page((payload_size + 0x1000) & ~0xfff)
        addr = self.maps[-1].addr + self.cur_offset
        self.cur_offset += size
        return addr
        
    def reserve_int(self):
        int_size = self.get_int_size()
        return self.reserve_size(int_size)
        
    def write_code(self, code):
        size = len(code)
        if size + self.cur_offset > self.cur_page_size:
            self.get_new_page((payload_size + 0x1000) & ~0xfff)
        self.maps[-1][self.cur_offset: self.cur_offset + size] = code
        addr = self.maps[-1].addr + self.cur_offset
        self.cur_offset += size
        return addr
        
allocator = CustomAllocator()


def get_functions():
    # Windows only with python27.dll | improve this
    import sys
    
    sys.path.append(r"C:\Users\hakril\Documents\Work\Python_Injection")
    
    import windows
    PyGILState_Ensure = windows.get_func_addr('python27', 'PyGILState_Ensure')
    PyObject_CallObject = windows.get_func_addr('python27', 'PyObject_CallObject')
    PyGILState_Release = windows.get_func_addr('python27', 'PyGILState_Release')
    return [PyGILState_Ensure, PyObject_CallObject, PyGILState_Release]
    
def analyse_callback(callback):
    if not callable(callback):
        raise ValueError("Need a callable object :)")
    obj_id = id(callback)
    if not hasattr(callback, '_objects'):
        raise ValueError("Need a ctypes PyCFuncPtr")
    return obj_id

from simple_x86 import *

# For windows 32 bits with stdcall
def generate_stub(callback):
    obj_id = analyse_callback(callback)
    
    c_callback = ctypes.c_ulong.from_address(id(callback._objects['0']) + 0xc).value
    gstate_save_addr = allocator.reserve_int()
    return_addr_save_addr = allocator.reserve_int()
    
    save_ebx = allocator.reserve_int()
    save_ecx = allocator.reserve_int()
    save_edx = allocator.reserve_int()
    save_esi = allocator.reserve_int()
    save_edi = allocator.reserve_int()
    
    ensure, objcall, release = get_functions()
    
    ### Shellcode ###
    code = MultipleInstr()
    
    code += Mov_DX_EBX(save_ebx)
    code += Mov_DX_ECX(save_ecx)
    code += Mov_DX_EDX(save_edx)
    code += Mov_DX_ESI(save_esi)
    code += Mov_DX_EDI(save_edi)
    
    code += Mov_EAX_X(ensure)
    code += Call_EAX()
    code += Mov_DX_EAX(gstate_save_addr)
    
    #Save real return addr (for good argument parsing by the callback)
    
    code += Pop_EAX()
    code += Mov_DX_EAX(return_addr_save_addr)
        
    # Set call_real_function to 0 (no call by default)    
        
    code += Mov_EAX_X(c_callback)
    code += Call_EAX()
    
    for i in range(len(callback.argtypes)):
        code += Pop_EBX()
         
    # Restore real return value
    code += Mov_EBX_DX(return_addr_save_addr)
    code += Push_EBX()
    
    # Save return value
    code += Push_EAX()
    code += Mov_EBX_DX(gstate_save_addr)
    code += Push_EBX()
    
    code += Mov_EAX_X(release)
    code += Call_EAX()
    
    # Discard `release` argument
    code += Pop_EAX()
    # Restore return value
    code += Pop_EAX()
    code += Mov_EBX_DX(save_ebx)
    code += Mov_ECX_DX(save_ecx)
    code += Mov_EDX_DX(save_edx)
    code += Mov_ESI_DX(save_esi)
    code += Mov_EDI_DX(save_edi)
    code += Ret()
    return code
 

def generate_callback_stub(callback, types):
    func_type = ctypes.CFUNCTYPE(*types)
    c_callable = func_type(callback)
    stub = generate_stub(c_callable)
    stub_addr = allocator.write_code(stub.get_code())
    generate_callback_stub.l.append((stub, c_callable))
    return stub_addr
    
generate_callback_stub.l = []

def create_function(code, types):
    func_type = ctypes.CFUNCTYPE(*types)
    addr = allocator.write_code(code)
    return func_type(addr)
    