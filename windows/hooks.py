import sys
import ctypes

import windows.utils as utils
from . import native_exec
from .generated_def import winfuncs
from .generated_def.windef import PAGE_EXECUTE_READWRITE
from .generated_def.winstructs import *


class Callback(object):
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
for func in winfuncs.functions:
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
        self.stub = native_exec.generate_callback_stub(self.hook_callback, self.callback_types)
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
        with utils.VirtualProtected(self.entry.addr, ctypes.sizeof(PVOID), PAGE_EXECUTE_READWRITE):
            self.entry.value = self.stub
        self.is_enable = True

    def disable(self):
        with utils.VirtualProtected(self.entry.addr, ctypes.sizeof(PVOID), PAGE_EXECUTE_READWRITE):
            self.entry.value = self.entry.nonhookvalue
        self.is_enable = False

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
