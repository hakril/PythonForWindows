INITIAL_tagMInterfacePointer = tagMInterfacePointer

class tagMInterfacePointer(INITIAL_tagMInterfacePointer):
    @property
    def objref(self):
        return OBJREF.from_address(ctypes.addressof(self.abData))