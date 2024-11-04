import functools
import ctypes


generate_IID = IID.from_raw


class COMHRESULT(HRESULT):
    _type_ = HRESULT._type_
    def _check_retval_(self):
        # We CAN NOT try to adapt the self.value and transform it with flags
        # here, we need to do it with the errcheck
        # So we have the peer-interface callback system on errcheck :)
        return self.value # The value will be send to errcheck :)

class COMInterface(ctypes.c_void_p):
    _functions_ = {
    }

    # So COMInterface completely bypass the HRESULT
    # return value check on restype by setting the restype to COMHRESULT
    # But we add the 'errcheck' callback capacity for all COMInterface and subclasses
    # So the default implem of the callback must have the same behavior as
    # standard HRESULT restype.
    # This is why default errcheck callback call ctypes._check_HRESULT
    def _default_errcheck(self, result, func, args):
        ctypes._check_HRESULT(result)
        return args

    def __getattr__(self, name):
        if name in self._functions_:
            winfunc = self._functions_[name]
            # Hacking the HRESULT _check_retval_ and
            # letting COMInterface.errcheck do the work of validating / raising
            winfunc.restype = COMHRESULT
            effective_errcheck = getattr(self, "errcheck", self._default_errcheck)
            winfunc.errcheck = effective_errcheck
            return functools.partial(winfunc, self)
        return super(COMInterface, self).__getattribute__(name)

    def __repr__(self):
        description = "<NULL>" if not self.value else ""
        return "<{0}{1} at {2:#x}>".format(type(self).__name__, description, id(self))

    # Simplified API for QueryInterface for interface embeding their IID
    # Or for string/Obj
    def query(self, interface, target=None):
        if isinstance(interface, str): # We have a GUID
            interface_iid = IID.from_string(interface)
            if target is None:
                target = IUnknown()
        elif issubclass(interface, COMInterface): # We have a PFW COM interface
            interface_iid = interface.IID
            if target is None:
                target = interface() # Use an instance of the ComInterface as target of the QueryInterface
        else:
            # We have something else (A gdef.GUID probably)
            interface_iid = interface
            if target is None:
                target = IUnknown()
        self.QueryInterface(interface_iid, target)
        return target

    def marshal(self, target_iid=None, destination=MSHCTX_NOSHAREDMEM, flags=MSHLFLAGS_NORMAL):
        if target_iid is None:
            target_iid = self.IID
        mystream = windows.com.MemoryIStream.create()
        windows.winproxy.CoMarshalInterface(mystream, target_iid, self, destination, 0, flags)
        mystream.seek(0)
        buffer = mystream.read(0xffffffff) # Todo: release stuff
        return buffer








