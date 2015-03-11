import sys
import os

import utils
from native_exec.simple_x86 import *


RPython = os.getcwd() +  r'\..\RPython'
sys.path.append(RPython)
#import master

def generate_python_exec_shellcode(PYDLL_addr, PyInit, PyRun, PYCODE_ADDR):
    LoadLibraryA = utils.get_func_addr('kernel32', 'LoadLibraryA')
    GetProcAddress = utils.get_func_addr('kernel32', 'GetProcAddress')
    code = MultipleInstr()
    code += Push_X(PYDLL_addr)
    code += Mov_EAX_X(LoadLibraryA)
    code += Call_EAX()
    code += Push_EAX()
    code += Pop_EDI()
    code += Push_X(PyInit)
    code += Push_EDI()
    code += Mov_EBX_X(GetProcAddress)
    code += Call_EBX()
    code += Call_EAX()
    code += Push_X(PyRun)
    code += Push_EDI()
    code += Call_EBX()
    code += Push_X(PYCODE_ADDR)
    code += Call_EAX()
    code += Int3()
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
    shellcode = generate_python_exec_shellcode(PYDLL_addr, PyInitT_ADDR, Pyrun_ADDR, PYCODE_ADDR)
    process.write_memory(SHELLCODE_ADDR, shellcode)
    return SHELLCODE_ADDR

    
def execute_python_code(process, code):
    shellcode_remote_addr = inject_python_command(process, code)
    return process.create_thread(shellcode_remote_addr, 0)
  
remote_slave_launcher = """
import sys
import ctypes

sys.path.append(r'{0}')
import slave

sys.path.append(r'{1}')
import windows

name_pool = {{'ctypes' : ctypes, '__import__' : __import__, 'windows' : windows}}
s = slave.RemotePythonSlave.create(name_pool)
slave.debug_run(s)
""".format(RPython, os.getcwd())
  
  
def launch_remote_slave(process):
    import master
    execute_python_code(process, remote_slave_launcher)
    m = master.RemotePython.create()
    return m
    
    
    