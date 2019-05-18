import ctypes

import windows.generated_def as gdef
from windows.generated_def.ntstatus import NtStatusException


# ApiProxy stuff
class ExportNotFound(RuntimeError):
        def __init__(self, func_name, api_name):
            self.func_name = func_name
            self.api_name = api_name
            super(ExportNotFound, self).__init__("Function {0} not found into {1}".format(func_name, api_name))


# PFW Winproxy Exception type
class WinproxyError(WindowsError):
    def __new__(cls, func_name, error_code=None):
        win_error = ctypes.WinError(error_code) #GetLastError by default
        api_error = super(WinproxyError, cls).__new__(cls)
        api_error.api_name = func_name
        api_error.winerror = win_error.winerror & 0xffffffff
        api_error.strerror = win_error.strerror
        api_error.args = (func_name, win_error.winerror, win_error.strerror)
        return api_error

    def __init__(self, func_name, error_code=None):
        super(WinproxyError, self).__init__(func_name)

    def __repr__(self):
        return "{0}: {1}".format(self.api_name, super(WinproxyError, self).__repr__())

    def __str__(self):
        return "{0}: {1}".format(self.api_name, super(WinproxyError, self).__str__())


# winproxy Error check
no_error_check = None

def fail_on_minus_one(func_name, result, func, args):
    """Raise WinproxyError if call result is -1"""
    if result == -1:
        raise WinproxyError(func_name)
    return args


def fail_on_zero(func_name, result, func, args):
    """raise WinproxyError if result is 0"""
    if not result:
        raise WinproxyError(func_name)
    return args


def succeed_on_zero(func_name, result, func, args):
    """raise WinproxyError if result is NOT 0"""
    if result:
        raise WinproxyError(func_name)
    return args


def result_is_error_code(func_name, result, func, args):
    """raise WinproxyError(result) if result is NOT 0"""
    if result:
        raise WinproxyError(func_name, error_code=result)
    return args


def result_is_ntstatus(func_name, result, func, args):
    """raise NtStatusException is result is not 0"""
    if result:
        raise NtStatusException(result & 0xffffffff)
    return args


def result_is_handle(func_name, result, func, args):
    """raise WinproxyError is result is INVALID_HANDLE_VALUE"""
    if result == gdef.INVALID_HANDLE_VALUE:
        raise WinproxyError(func_name)
    return args

