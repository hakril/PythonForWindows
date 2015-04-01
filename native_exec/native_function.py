import ctypes
import mmap
import platform

import windows
import windows.k32testing as k32api

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
        addr = k32api.VirtualAlloc(0, size, 0x1000, 0x40)

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

    def reserve_int(self, nb_int=1):
        int_size = self.get_int_size()
        return self.reserve_size(int_size * nb_int)

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
    # Windows only with python27.dll | improve this ?
    import sys
    import windows

    PyGILState_Ensure = windows.utils.get_func_addr('python27', 'PyGILState_Ensure')
    PyObject_CallObject = windows.utils.get_func_addr('python27', 'PyObject_CallObject')
    PyGILState_Release = windows.utils.get_func_addr('python27', 'PyGILState_Release')
    return [PyGILState_Ensure, PyObject_CallObject, PyGILState_Release]

def analyse_callback(callback):
    if not callable(callback):
        raise ValueError("Need a callable object :)")
    obj_id = id(callback)
    if not hasattr(callback, '_objects'):
        raise ValueError("Need a ctypes PyCFuncPtr")
    return obj_id



# For windows 32 bits with stdcall
def generate_stub_32(callback):
    from simple_x86 import *
    obj_id = analyse_callback(callback)
    
    c_callback = ctypes.c_ulong.from_address(id(callback._objects['0']) + 3 * ctypes.sizeof(ctypes.c_void_p)).value
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

# For windows 32 bits with stdcall
def generate_stub_64(callback):
    import simple_x64 as x64
    from simple_x64 import *
    obj_id = analyse_callback(callback)

    REG_LEN = ctypes.sizeof(ctypes.c_void_p)

    c_callback = ctypes.c_ulong.from_address(id(callback._objects['0']) + 3 * ctypes.sizeof(ctypes.c_void_p)).value

    register_to_save = ("RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
    push_all_save_register = MultipleInstr([getattr(x64, "Push_" + reg)() for reg in register_to_save])
    pop_all_save_register = MultipleInstr([getattr(x64, "Pop_" + reg)() for reg in reversed(register_to_save)])
    # Reserve parallel `stack`
    save_register_space = allocator.reserve_int(len(register_to_save) + 1)
    save_register_space += REG_LEN # The + 1 is for the second-stack xchg
    save_register_space_end = save_register_space + (ctypes.sizeof(ctypes.c_void_p) * (len(register_to_save) ))


    save_rbx = save_register_space_end - REG_LEN
    save_rcx = save_register_space_end - REG_LEN - REG_LEN
    save_rdx = save_register_space_end - REG_LEN - (REG_LEN * 2)
    save_rsi = save_register_space_end - REG_LEN - (REG_LEN * 3)
    save_rdi = save_register_space_end - REG_LEN - (REG_LEN * 4)
    save_r8 = save_register_space_end - REG_LEN - (REG_LEN * 5)
    save_r9 = save_register_space_end - REG_LEN - (REG_LEN * 6)


    gstate_save_addr = allocator.reserve_int()
    return_addr_save_addr = allocator.reserve_int()
    return_value_save_addr = allocator.reserve_int()

    Reserve_space_for_call = MultipleInstr([Push_RDI()] * 4)
    Clean_space_for_call = MultipleInstr([Pop_RDI()] * 4)
    Do_stack_alignement = MultipleInstr([Push_RDI()] * 1)
    Remove_stack_alignement = MultipleInstr([Pop_RDI()] * 1)



    ensure, objcall, release = get_functions()

    ### Shellcode ###
    code = MultipleInstr()
    code += Mov_RAX_X(save_register_space_end)
    # A lazy working xchg RSP <-> RAX
    code += Push_RAX()
    code += Push_RSP()
    code += Pop_RAX()
    code += Pop_RSP()

    code += push_all_save_register

    # Re-set RSP to its real value
    code += Push_RAX()
    code += Pop_RSP()


    code += Pop_RAX() # Remove the Push_RAX of lazy xchg
    # GOOO
    code += Mov_RAX_X(ensure)
    code += Reserve_space_for_call
    code += Do_stack_alignement
    code += Call_RAX()
    code += Remove_stack_alignement
    code += Clean_space_for_call
    code += Mov_DX_RAX(gstate_save_addr)
     #Save real return addr (for good argument parsing by the callback)
    code += Pop_RAX()
    code += Mov_DX_RAX(return_addr_save_addr)
    # Restore parameters for real function call
    code += Mov_RAX_X(save_rcx)
    code += Mov_RCX_DRAX()
    code += Mov_RAX_X(save_rdx)
    code += Mov_RDX_DRAX()
    code += Mov_RAX_X(save_r8)
    code += Mov_R8_DRAX()
    code += Mov_RAX_X(save_r9)
    code += Mov_R9_DRAX()
    # Call python code
    code += Mov_RAX_X(c_callback)
    code += Reserve_space_for_call
    code += Call_RAX() # no need for stack alignement here as we poped the return addr
    
    code += Clean_space_for_call
    # Save return value
    code += Mov_DX_RAX(return_value_save_addr)
    code += Mov_RAX_DX(return_addr_save_addr)
    # Repush real return value
    code += Push_RAX()
    code += Mov_RAX_DX(gstate_save_addr)
    code += Push_RAX()
    code += Pop_RCX()
    code += Mov_RAX_X(release)
    code += Reserve_space_for_call
    code += Do_stack_alignement
    code += Call_RAX()
    code += Remove_stack_alignement
    code += Clean_space_for_call
    # Restore registers
    code += Mov_RAX_X(save_register_space)
    # A lazy working xchg RSP <-> RAX
    code += Push_RAX()
    code += Push_RSP()
    code += Pop_RAX()
    code += Pop_RSP()

    code += pop_all_save_register

    # Re-set RSP to its real value
    code += Push_RAX()
    code += Pop_RSP()
    code += Pop_RAX() # Remove the Push_RAX of lazy xchg

    # Restore return value
    code += Mov_RAX_DX(return_value_save_addr)
    code += Ret()
    return code


def generate_callback_stub(callback, types):
    func_type = ctypes.WINFUNCTYPE(*types)
    c_callable = func_type(callback)
    if windows.current_process.bitness == 32:
        stub = generate_stub_32(c_callable)
    else:
        stub = generate_stub_64(c_callable)
    stub_addr = allocator.write_code(stub.get_code())
    generate_callback_stub.l.append((stub, c_callable))
    return stub_addr

generate_callback_stub.l = []

def create_function(code, types):
    func_type = ctypes.CFUNCTYPE(*types)
    addr = allocator.write_code(code)
    return func_type(addr)
