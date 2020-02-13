import sys
import ctypes

import windows
import windows.utils as utils
from . import native_exec
from .generated_def import winfuncs
from .generated_def.windef import PAGE_EXECUTE_READWRITE
from .generated_def.winstructs import *

# TODO Not a big fan of importing 'meta' every load
# Should do an Hook API that take the winproxy function (not generate every hook possible)
import windows.generated_def.meta


class Callback(object):
    """Give type information to hook callback"""
    def __init__(self, *types):
        self.types = types

    def __call__(self, func):
        func._types_info = self.types
        return func


class KnownCallback(object):
    types = ()

    def __call__(self, func):
        func._types_info = self.types
        return func


def add_callback_to_module(callback):
    setattr(sys.modules[__name__], type(callback).__name__, callback)

# Generate IATCallback decorator for all known functions



for func in windows.generated_def.meta.functions:
    prototype = getattr(winfuncs, func + "Prototype")
    callback_name = func + "Callback"

    class CallBackDeclaration(KnownCallback):
        types = (prototype._restype_,) + prototype._argtypes_

    CallBackDeclaration.__name__ = callback_name
    add_callback_to_module(CallBackDeclaration())


class IATHook(object):
    """Look at my hook <3"""

    def __init__(self, IAT_entry, callback, types=None):
        if types is None:
            if not hasattr(callback, "_types_info"):
                raise ValueError("Callback for IATHook has no type infomations")
            types = callback._types_info
        self.original_types = types
        self.callback_types = self.transform_arguments(self.original_types)
        self.entry = IAT_entry
        self.callback = callback
        ## No more circular ref -> but stub is destroyed -> segv :(
        self.stub = ctypes.WINFUNCTYPE(*self.callback_types)(self.hook_callback)
        # stub = ctypes.WINFUNCTYPE(*self.callback_types)(self.hook_callback)
        # self.stub_addr = ctypes.cast(stub, PVOID) # Same problem as keep stub... (GC..)
        self.stub_addr = ctypes.cast(self.stub, PVOID).value # Same problem as keep stub... (GC..)
        # IAT_entry.stub = stub
        self.realfunction = ctypes.WINFUNCTYPE(*types)(IAT_entry.nonhookvalue)
        self.is_enable = False

    def transform_arguments(self, types):
        res = []
        for type in types:
            if type in (ctypes.c_wchar_p, ctypes.c_char_p):
                res.append(ctypes.c_void_p)
            else:
                res.append(type)
        return res

    def enable(self):
        """Enable the IAT hook: you MUST keep a reference to the IATHook while the hook is enabled"""
        with utils.VirtualProtected(self.entry.addr, ctypes.sizeof(PVOID), PAGE_EXECUTE_READWRITE):
            self.entry.value = self.stub_addr
        self.is_enable = True
        self.entry.enabled = True

    def disable(self):
        """Disable the IAT hook"""
        with utils.VirtualProtected(self.entry.addr, ctypes.sizeof(PVOID), PAGE_EXECUTE_READWRITE):
            self.entry.value = self.entry.nonhookvalue
        self.is_enable = False
        self.entry.enabled = True

    def hook_callback(self, *args):
        adapted_args = []
        for value, type in zip(args, self.original_types[1:]):
            if type == ctypes.c_wchar_p:
                adapted_args.append(ctypes.c_wchar_p(value))
            elif type == ctypes.c_char_p:
                adapted_args.append(ctypes.c_char_p((value)))
            else:
                adapted_args.append(value)

        def real_function(*args):
            if args == ():
                args = adapted_args
            return self.realfunction(*args)
        return self.callback(*adapted_args, real_function=real_function)

## New simple hook API based on winproxy
def setup_hook(target, hook, dll_to_hook):
    "TODO: Test and doc :D"
    dll_name, api_name = windows.winproxy.get_target(target)
    prototype = target.prototype
    hook._types_info = (prototype._restype_,) + prototype._argtypes_

    if not dll_name.endswith(".dll"):
        dll_name += ".dll"
    # Get the peb of our process
    peb = windows.current_process.peb
    # Get the dll_to_hook
    module_to_hook = [m for m in peb.modules if m.name.lower() == dll_to_hook.lower()][0]
    # Get the iat entries for DLL dll_name
    adv_imports = module_to_hook.pe.imports[dll_name]
    # Get RegOpenKeyExA iat entry
    iat = [n for n in adv_imports if n.name == api_name][0]
    iat.set_hook(hook)
    return iat