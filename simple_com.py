import struct
import ctypes
import functools
from ctypes.wintypes import HRESULT
from windows.generated_def.winstructs import *

# Simple Abstraction to call COM interface in Python (Python -> COM)
IID_PACK = "<I", "<H", "<H", "<B", "<B", "<B", "<B", "<B", "<B", "<B", "<B"


def get_IID_from_raw(raw):
    return "".join([struct.pack(i, j) for i, j in zip(IID_PACK, raw)])


class COMInterface(ctypes.c_void_p):
    _functions_ = {
        "QueryInterface": ctypes.WINFUNCTYPE(HRESULT, ctypes.c_void_p, ctypes.c_void_p)(0, "QueryInterface"),
        "AddRef": ctypes.WINFUNCTYPE(HRESULT)(1, "AddRef"),
        "Release": ctypes.WINFUNCTYPE(HRESULT)(2, "Release")
    }

    def __getattr__(self, name):
        if name in self._functions_:
            return functools.partial(self._functions_[name], self)
        return super(COMInterface, self).__getattribute__(name)


# Simple Implem to create COM Interface in Python (COM -> Python)

def create_c_callable(func, types, keepalive=[]):
    func_type = ctypes.WINFUNCTYPE(*types)
    c_callable = func_type(func)
    # Dirty, but the other method require native code execution
    c_callback_addr = ctypes.c_ulong.from_address(id(c_callable._objects['0']) + 3 * ctypes.sizeof(ctypes.c_void_p)).value
    keepalive.append(c_callable)
    return c_callback_addr


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