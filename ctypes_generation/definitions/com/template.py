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

    def __repr__(self):
        description = "<NULL>" if not self.value else ""
        return "<{0}{1} at {2:#x}>".format(type(self).__name__, description, id(self))

    # Simplified API for QueryInterface for interface embeding there IID
    def query(self, interfacetype):
        interface = interfacetype()
        self.QueryInterface(interface.IID, interface)
        return interface

