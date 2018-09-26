import ctypes
import functools

import windows.generated_def as gdef

# Utils
def is_implemented(apiproxy):
    """Return :obj:`True` if DLL/Api can be found"""
    try:
        apiproxy.force_resolution()
    except ExportNotFound:
        return False
    return True


def get_target(apiproxy):
    """POC for newshook"""
    return apiproxy.target_dll, apiproxy.target_func


def resolve(apiproxy):
    """Resolve the address of ``apiproxy``. Might raise if ``apiproxy`` is not implemented"""
    apiproxy.force_resolution()
    func = ctypes.WinDLL(dll_name)[func_name]
    return ctypes.cast(func, gdef.PVOID).value

# ApiProxy stuff
class ExportNotFound(RuntimeError):
        def __init__(self, func_name, api_name):
            self.func_name = func_name
            self.api_name = api_name
            super(ExportNotFound, self).__init__("Function {0} not found into {1}".format(func_name, api_name))


class NeededParameterType(object):
    _inst = None

    def __new__(cls):
        if cls._inst is None:
            cls._inst = super(NeededParameterType, cls).__new__(cls)
        return cls._inst

    def __repr__(self):
        return "NeededParameter"
NeededParameter = NeededParameterType()

class ApiProxy(object):
    APIDLL = None
    """Create a python wrapper around a kernel32 function"""
    def __init__(self, func_name=None, error_check=None, deffunc_module=None):
        self.deffunc_module = deffunc_module if deffunc_module is not None else gdef.winfuncs
        self.func_name = func_name
        if error_check is None:
            error_check = self.default_error_check
        self.error_check = functools.wraps(error_check)(functools.partial(error_check, func_name))
        self._cprototyped = None

    def __call__(self, python_proxy):
        # Use the name of the sub-function if None was given
        if self.func_name is None:
            self.func_name = python_proxy.__name__
        prototype = getattr(self.deffunc_module, self.func_name + "Prototype")
        params = getattr(self.deffunc_module, self.func_name + "Params")
        python_proxy.prototype = prototype
        python_proxy.params = params
        python_proxy.errcheck = self.error_check
        python_proxy.target_dll = self.APIDLL
        python_proxy.target_func = self.func_name
        # Give access to the 'ApiProxy' object from the function
        python_proxy.proxy = self
        params_name = [param[1] for param in params]
        if (self.error_check.__doc__):
            doc = python_proxy.__doc__
            doc = doc if doc else ""
            python_proxy.__doc__ = doc + "\nErrcheck:\n   " + self.error_check.__doc__

        def generate_ctypes_function():
            try:
                c_prototyped = prototype((self.func_name, getattr(ctypes.windll, self.APIDLL)), params)
            except (AttributeError, WindowsError):
                raise ExportNotFound(self.func_name, self.APIDLL)
            c_prototyped.errcheck = self.error_check
            self._cprototyped = c_prototyped

        def perform_call(*args):
            if len(params_name) != len(args):
                print("ERROR:")
                print("Expected params: {0}".format(params_name))
                print("Just Got params: {0}".format(args))
                raise ValueError("I do not have all parameters: how is that possible ?")
            for param_name, param_value in zip(params_name, args):
                if param_value is NeededParameter:
                    raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.func_name, param_name))
            if self._cprototyped is None:
                generate_ctypes_function()
            return self._cprototyped(*args)

        setattr(python_proxy, "ctypes_function", perform_call)
        setattr(python_proxy, "force_resolution", generate_ctypes_function)
        return python_proxy
