import functools
import ctypes


generate_IID = IID.from_raw

class COMInterface(ctypes.c_void_p):
    _functions_ = {
    }

    def __getattr__(self, name):
        if name in self._functions_:
            return functools.partial(self._functions_[name], self)
        return super(COMInterface, self).__getattribute__(name)

