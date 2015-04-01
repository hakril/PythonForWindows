import sys
import os
import utils
import windows


# 32 to 32 injection
def generate_python_exec_shellcode_32(PYDLL_addr, PyInit, PyRun, PYCODE_ADDR):
    from native_exec.simple_x86 import *
    LoadLibraryA = utils.get_func_addr('kernel32', 'LoadLibraryA')
    GetProcAddress = utils.get_func_addr('kernel32', 'GetProcAddress')
    code = MultipleInstr()
    # Load python27.dll
    code += Push_X(PYDLL_addr)
    code += Mov_EAX_X(LoadLibraryA)
    code += Call_EAX()
    # Get PyInit function into pythondll
    code += Push_EAX()
    code += Pop_EDI()
    code += Push_X(PyInit)
    code += Push_EDI()
    code += Mov_EBX_X(GetProcAddress)
    code += Call_EBX()
    # Call PyInit
    code += Call_EAX()
    # Get PyRun function into pythondll
    code += Push_X(PyRun)
    code += Push_EDI()
    code += Call_EBX()
    # Call PyRun with python code to exec
    code += Push_X(PYCODE_ADDR)
    code += Call_EAX()
    code += Pop_EDI()
    code += Ret()
    return code.get_code()

# 64 to 64 injection
def generate_python_exec_shellcode_64(PYDLL_addr, PyInit, PyRun, PYCODE_ADDR):
    from native_exec.simple_x64 import *
    LoadLibraryA = utils.get_func_addr('kernel32', 'LoadLibraryA')
    GetProcAddress = utils.get_func_addr('kernel32', 'GetProcAddress')

    Reserve_space_for_call = MultipleInstr([Push_RDI()] * 4)
    Clean_space_for_call = MultipleInstr([Pop_RDI()] * 4)

    code = MultipleInstr()
    # Do stack alignement
    code += Push_RAX()
    # Load python27.dll
    code += Mov_RCX_X(PYDLL_addr)
    code += Mov_RAX_X(LoadLibraryA)
    code += Reserve_space_for_call
    code += Call_RAX()
    code += Clean_space_for_call
    code += Push_RAX()
    code += Pop_RCX()
    # Save RCX
    code += Push_RCX()
    # Align stack
    code += Push_RDI()
    # Get PyInit function into pythondll
    code += Reserve_space_for_call
    code += Mov_RDX_X(PyInit)
    code += Mov_RBX_X(GetProcAddress)
    code += Call_RBX()
    # Call PyInit
    code += Call_RAX()
    code += Clean_space_for_call
    # Remove Stack align
    code += Pop_RDI()
    # Restore pythondll base into rcx
    code += Pop_RCX()
    # Get PyRun function into pythondll
    code += Mov_RDX_X(PyRun)
    code += Reserve_space_for_call
    code += Call_RBX()
    # Call PyInit with python code to exec
    code += Mov_RCX_X(PYCODE_ADDR)
    code += Call_RAX()
    code += Clean_space_for_call
    # Remove stack alignement
    code += Pop_RAX()
    code += Ret()
    return code.get_code()


def inject_python_command(process, code_injected, PYDLL="python27.dll\x00"):
    PyInitT = "Py_Initialize\x00"
    Pyrun = "PyRun_SimpleString\x00"
    PYCODE = code_injected + "\x00"
    remote_addr_base = process.virtual_alloc(len(code_injected) + 0x100)
    remote_addr = remote_addr_base

    PYDLL_addr = remote_addr
    process.write_memory(remote_addr, PYDLL)
    remote_addr += len(PYDLL)


    PyInitT_ADDR = remote_addr
    process.write_memory(remote_addr, PyInitT)
    remote_addr += len(PyInitT)

    Pyrun_ADDR = remote_addr
    process.write_memory(remote_addr, Pyrun)
    remote_addr += len(Pyrun)

    PYCODE_ADDR = remote_addr
    process.write_memory(remote_addr, PYCODE)
    remote_addr += len(PYCODE)

    SHELLCODE_ADDR = remote_addr
    if process.bitness == 32:
        shellcode = generate_python_exec_shellcode_32(PYDLL_addr, PyInitT_ADDR, Pyrun_ADDR, PYCODE_ADDR)
    else:
        shellcode = generate_python_exec_shellcode_64(PYDLL_addr, PyInitT_ADDR, Pyrun_ADDR, PYCODE_ADDR)
    process.write_memory(SHELLCODE_ADDR, shellcode)
    return SHELLCODE_ADDR



def execute_python_code(process, code):
    print("me = {0}".format(windows.current_process.bitness))
    print("him = {0}".format(process.bitness))
    if windows.current_process.bitness != process.bitness:
        raise NotImplementedError("Cannot perform 32 <-> 64 injection")
    shellcode_remote_addr = inject_python_command(process, code)
    return process.create_thread(shellcode_remote_addr, 0)
