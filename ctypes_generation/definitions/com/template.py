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

class COMImplementation(object):
    IMPLEMENT = None

    def get_index_of_method(self, method):
        # This code is horrible but not totally my fault
        # the PyCFuncPtrObject->index is not exposed to Python..
        # repr is: '<COM method offset 2: WinFunctionType at 0x035DDBE8>'
        rpr = repr(method)
        if not rpr.startswith("<COM method offset ") or ":" not in rpr:
            raise ValueError("Could not extract offset of {0}".format(rpr))
        return int(rpr[len("<COM method offset "): rpr.index(":")])

    def extract_methods_order(self, interface):
        index_and_method = sorted((self.get_index_of_method(m),name, m) for name, m in interface._functions_.items())
        return index_and_method

    def verify_implem(self, interface):
        for func_name in interface._functions_:
            implem = getattr(self, func_name, None)
            if implem is None:
                raise ValueError("<{0}> implementing <{1}> has no method <{2}>".format(type(self).__name__, self.IMPLEMENT.__name__, func_name))
            if not callable(implem):
                raise ValueError("{0} implementing <{1}>: <{2}> is not callable".format(type(self).__name__, self.IMPLEMENT.__name__, func_name))
        return True

    def _create_vtable(self, interface):
        implems = []
        names = []
        for index, name, method in self.extract_methods_order(interface):
            func_implem = getattr(self, name)
            #PVOID is 'this'
            types = [method.restype, PVOID] + list(method.argtypes)
            implems.append(ctypes.WINFUNCTYPE(*types)(func_implem))
            names.append(name)
        class Vtable(ctypes.Structure):
            _fields_ = [(name, ctypes.c_void_p) for name in names]
        return Vtable(*[ctypes.cast(x, ctypes.c_void_p) for x in implems]), implems

    def __init__(self):
        self.verify_implem(self.IMPLEMENT)
        vtable, implems = self._create_vtable(self.IMPLEMENT)
        self.vtable = vtable
        self.implems = implems
        self.vtable_pointer = ctypes.pointer(self.vtable)
        self._as_parameter_ = ctypes.addressof(self.vtable_pointer)

    def QueryInterface(self, this, piid, result):
        if piid[0] in (IUnknown.IID, self.IMPLEMENT.IID):
            result[0] = this
            return 1
        return E_NOINTERFACE

    def AddRef(self, *args):
        return 1

    def Release(self, *args):
        return 0
