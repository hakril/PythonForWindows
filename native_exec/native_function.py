import ctypes
import mmap
import platform
import sys

import windows
import windows.winproxy

from . import simple_x86 as x86
from . import simple_x64 as x64


class PyObj(ctypes.Structure):
    _fields_ = [("ob_refcnt", ctypes.c_size_t),
                ("ob_type", ctypes.c_void_p)]  # must be cast


class PyMmap(PyObj):
    _fields_ = [("ob_addr", ctypes.c_size_t), ("ob_size", ctypes.c_size_t)]


# Specific mmap class for code injection
class MyMap(mmap.mmap):
    """ A mmap that is never unmapped and that contains the page address """
    def __init__(self, *args, **kwarg):
        # Get the page address by 'introspection' of the C struct
        m = PyMmap.from_address(id(self))
        self.addr = m.ob_addr
        # Prevent garbage collection (so unmaping) of the page
        m.ob_refcnt += 1

    @classmethod
    def get_map(cls, size):
        """ Dispatch to the good mmap implem depending on the current system """
        systems = {'windows': Win32MyMap,
                   'linux': UnixMyMap}
        x = platform.system().lower()
        if x not in systems:
            raise ValueError("Unknow system {0}".format(x))
        return systems[x].get_map(size)


class Win32MyMap(MyMap):
    @classmethod
    def get_map(cls, size):
        addr = windows.winproxy.VirtualAlloc(0, size, 0x1000, 0x40)
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
    int_size = {'32bit': 4, '64bit': 8}

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
            self.get_new_page((size + 0x1000) & ~0xfff)
        addr = self.maps[-1].addr + self.cur_offset
        self.cur_offset += size
        return addr

    def reserve_int(self, nb_int=1):
        int_size = self.get_int_size()
        return self.reserve_size(int_size * nb_int)

    def write_code(self, code):
        size = len(code)
        if size + self.cur_offset > self.cur_page_size:
            self.get_new_page((size + 0x1000) & ~0xfff)
        self.maps[-1][self.cur_offset: self.cur_offset + size] = code
        addr = self.maps[-1].addr + self.cur_offset
        self.cur_offset += size
        return addr

allocator = CustomAllocator()


def get_functions():
    version = sys.version_info
    python_dll = "python" + str(version.major) + str(version.minor)

    PyGILState_Ensure = windows.utils.get_func_addr(python_dll, 'PyGILState_Ensure'.encode())
    PyObject_CallObject = windows.utils.get_func_addr(python_dll, 'PyObject_CallObject'.encode())
    PyGILState_Release = windows.utils.get_func_addr(python_dll, 'PyGILState_Release'.encode())
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
    c_callback = get_callback_address_32(callback)

    gstate_save_addr = x86.create_displacement(disp=allocator.reserve_int())
    return_addr_save_addr = x86.create_displacement(disp=allocator.reserve_int())
    save_ebx = x86.create_displacement(disp=allocator.reserve_int())
    save_ecx = x86.create_displacement(disp=allocator.reserve_int())
    save_edx = x86.create_displacement(disp=allocator.reserve_int())
    save_esi = x86.create_displacement(disp=allocator.reserve_int())
    save_edi = x86.create_displacement(disp=allocator.reserve_int())

    ensure, objcall, release = get_functions()

    code = x86.MultipleInstr()
    # ## Shellcode ## #
    code += x86.Mov(save_ebx, 'EBX')
    code += x86.Mov(save_ecx, 'ECX')
    code += x86.Mov(save_edx, 'EDX')
    code += x86.Mov(save_esi, 'ESI')
    code += x86.Mov(save_edi, 'EDI')

    code += x86.Mov('EAX', ensure)
    code += x86.Call('EAX')
    code += x86.Mov(gstate_save_addr, 'EAX')

    # Save real return addr (for good argument parsing by the callback)
    code += x86.Pop('EAX')
    code += x86.Mov(return_addr_save_addr, 'EAX')

    code += x86.Mov('EAX', c_callback)
    code += x86.Call('EAX')

    # Restore real return value
    code += x86.Mov('EBX', return_addr_save_addr)
    code += x86.Push('EBX')

    # Save return value
    code += x86.Push('EAX')
    code += x86.Mov('EBX', gstate_save_addr)
    code += x86.Push('EBX')

    code += x86.Mov('EAX', release)
    code += x86.Call('EAX')

    # Discard `release` argument
    code += x86.Pop('EAX')
    # Restore return value
    code += x86.Pop('EAX')
    code += x86.Mov('EBX', save_ebx)
    code += x86.Mov('ECX', save_ecx)
    code += x86.Mov('EDX', save_edx)
    code += x86.Mov('ESI', save_esi)
    code += x86.Mov('EDI', save_edi)
    code += x86.Ret()
    return code


def generate_stub_64(callback):
    c_callback = get_callback_address_64(callback)
    REG_LEN = ctypes.sizeof(ctypes.c_void_p)
    register_to_save = ("RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")

    push_all_save_register = x64.MultipleInstr([x64.Push(reg) for reg in register_to_save])
    pop_all_save_register = x64.MultipleInstr([x64.Pop(reg) for reg in reversed(register_to_save)])
    # Reserve parallel `stack`
    save_register_space = allocator.reserve_int(len(register_to_save))
    save_register_space_end = save_register_space + (ctypes.sizeof(ctypes.c_void_p) * (len(register_to_save)))

    save_rbx = save_register_space_end - REG_LEN
    save_rbx  # Fuck the linter :D
    save_rcx = save_register_space_end - REG_LEN - REG_LEN
    save_rdx = save_register_space_end - REG_LEN - (REG_LEN * 2)
    save_rsi = save_register_space_end - REG_LEN - (REG_LEN * 3)
    save_rsi  # Fuck the linter :D
    save_rdi = save_register_space_end - REG_LEN - (REG_LEN * 4)
    save_rdi  # Fuck the linter :D
    save_r8 = save_register_space_end - REG_LEN - (REG_LEN * 5)
    save_r9 = save_register_space_end - REG_LEN - (REG_LEN * 6)

    gstate_save_addr = x64.create_displacement(disp=allocator.reserve_int())
    return_addr_save_addr = x64.create_displacement(disp=allocator.reserve_int())
    return_value_save_addr = x64.create_displacement(disp=allocator.reserve_int())

    Reserve_space_for_call = x64.MultipleInstr([x64.Push('RDI')] * 4)
    Clean_space_for_call = x64.MultipleInstr([x64.Pop('RDI')] * 4)
    Do_stack_alignement = x64.MultipleInstr([x64.Push('RDI')] * 1)
    Remove_stack_alignement = x64.MultipleInstr([x64.Pop('RDI')] * 1)

    ensure, objcall, release = get_functions()

    # ## Shellcode ## #
    code = x64.MultipleInstr()
    # Save all registers
    code += x64.Mov('RAX', save_register_space_end)
    code += x64.Xchg('RAX', 'RSP')
    code += push_all_save_register
    code += x64.Xchg('RAX', 'RSP')
    # GOOO
    code += x64.Mov('RAX', ensure)
    code += Reserve_space_for_call
    code += Do_stack_alignement
    code += x64.Call('RAX')
    code += Remove_stack_alignement
    code += Clean_space_for_call
    code += x64.Mov(gstate_save_addr, 'RAX')
    # Save real return addr (for good argument parsing by the callback)
    code += x64.Pop('RAX')
    code += x64.Mov(return_addr_save_addr, 'RAX')
    # Restore parameters for real function call
    code += x64.Mov('RAX', save_rcx)
    code += x64.Mov('RCX', x64.mem('[RAX]'))
    code += x64.Mov('RAX', save_rdx)
    code += x64.Mov('RDX', x64.mem('[RAX]'))
    code += x64.Mov('RAX', save_r9)
    code += x64.Mov('R9', x64.mem('[RAX]'))
    code += x64.Mov('RAX', save_r8)
    code += x64.Mov('R8', x64.mem('[RAX]'))
    # Call python code
    code += x64.Mov('RAX', c_callback)
    # no need for stack alignement here as we poped the return addr
    # no need for Reserve_space_for_call as we must use the previous one for correct argument parsing
    code += x64.Call('RAX')
    # Save return value
    code += x64.Mov(return_value_save_addr, 'RAX')
    # Repush real return value
    code += x64.Mov('RAX', return_addr_save_addr)
    code += x64.Push('RAX')
    # Call release(gstate_save)
    code += x64.Mov('RAX', gstate_save_addr)
    code += x64.Mov('RCX', 'RAX')
    code += x64.Mov('RAX', release)
    code += Reserve_space_for_call
    code += Do_stack_alignement
    code += x64.Call('RAX')
    code += Remove_stack_alignement
    code += Clean_space_for_call
    # Restore registers
    code += x64.Mov('RAX', save_register_space)
    code += x64.Xchg('RAX', 'RSP')
    code += pop_all_save_register
    code += x64.Xchg('RAX', 'RSP')
    # Restore return value
    code += x64.Mov('RAX', return_value_save_addr)
    code += x64.Ret()
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
    """Create a python function that call raw machine code

   :param str code: Raw machine code that will be called
   :param list types: Return type and parameters type (see :mod:`ctypes`)
   :return: the created function
   :rtype: function
     """
    func_type = ctypes.CFUNCTYPE(*types)
    addr = allocator.write_code(code)
    return func_type(addr)


# Return First argument for 32 bits code
raw_code = x86.MultipleInstr()
raw_code += x86.Mov('EAX', x86.mem('[ESP + 4]'))
raw_code += x86.Ret()
get_callback_address_32 = create_function(raw_code.get_code(), [ctypes.c_void_p])


# Return First argument for 64 bits code
raw_code = x64.MultipleInstr()
raw_code += x64.Mov('RAX', 'RCX')
raw_code += x64.Ret()
get_callback_address_64 = create_function(raw_code.get_code(), [ctypes.c_void_p])
