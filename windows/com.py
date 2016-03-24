import struct
import ctypes
import functools
from ctypes.wintypes import HRESULT, byref, pointer

from windows import winproxy
from windows.generated_def import RPC_C_IMP_LEVEL_IMPERSONATE, CLSCTX_INPROC_SERVER
from windows.generated_def import interfaces
from windows.generated_def.interfaces import generate_IID, IID

# Simple Implem to create COM Interface in Python (COM -> Python)
def create_c_callable(func, types, keepalive=[]):
    func_type = ctypes.WINFUNCTYPE(*types)
    c_callable = func_type(func)
    # Dirty, but the other method require native code execution
    c_callback_addr = ctypes.c_ulong.from_address(id(c_callable._objects['0']) + 3 * ctypes.sizeof(ctypes.c_void_p)).value
    keepalive.append(c_callable)
    return c_callback_addr

def init():
    t = winproxy.CoInitializeEx()
    if t:
        return t
    return winproxy.CoInitializeSecurity(0, -1, None, 0, 0, RPC_C_IMP_LEVEL_IMPERSONATE, 0,0,0)

def create_instance(clsiid, targetinterface, custom_iid=None):
    if custom_iid is None:
        custom_iid = targetinterface.IID
    return winproxy.CoCreateInstance(byref(clsiid), None, CLSCTX_INPROC_SERVER, byref(custom_iid), byref(targetinterface))





class ComVtable(object):
    # Name, types
    _funcs_ = [("QueryInterface", [ctypes.HRESULT, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]),
               ("AddRef", [ctypes.HRESULT, ctypes.c_void_p]),
               ("Release", [ctypes.HRESULT, ctypes.c_void_p])
               ]

    def __init__(self, **implem_overwrite):
        self.implems = []
        self.vtable = self._create_vtable(**implem_overwrite)
        self.vtable_pointer = ctypes.pointer(self.vtable)
        self._as_parameter_ = ctypes.addressof(self.vtable_pointer)

    def _create_vtable(self, **implem_overwrite):
        vtables_names = [x[0] for x in self._funcs_]
        non_expected_args = [func_name for func_name in implem_overwrite if func_name not in vtables_names]
        if non_expected_args:
            raise ValueError("Non expected function : {0}".format(non_expected_args))

        for name, types in self._funcs_:
            func_implem = implem_overwrite.get(name)
            if func_implem is None:
                if hasattr(self, name):
                    func_implem = getattr(self, name)
                else:
                    raise ValueError("Missing implementation for function <{0}>".format(name))

            if isinstance(func_implem, (int, long)):
                self.implems.append(func_implem)
            else:
                self.implems.append(create_c_callable(func_implem, types))

        class Vtable(ctypes.Structure):
            _fields_ = [(name, ctypes.c_void_p) for name in vtables_names]
        return Vtable(*self.implems)

    def QueryInterface(self, *args):
        return 1

    def AddRef(self, *args):
        return 1

    def Release(self, *args):
        return 0