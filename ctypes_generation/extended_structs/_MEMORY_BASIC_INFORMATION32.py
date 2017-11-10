INITIAL_MEMORY_BASIC_INFORMATION32 = _MEMORY_BASIC_INFORMATION32

class _MEMORY_BASIC_INFORMATION32(INITIAL_MEMORY_BASIC_INFORMATION32):
    STATE_MAPPER = {MEM_COMMIT: MEM_COMMIT, MEM_FREE: MEM_FREE, MEM_RESERVE:MEM_RESERVE}
    TYPE_MAPPER = {MEM_IMAGE: MEM_IMAGE, MEM_MAPPED: MEM_MAPPED, MEM_PRIVATE:MEM_PRIVATE}
    PROTECT_MAPPER = {x:x for x in [PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
                                    PAGE_WRITECOPY, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                                    PAGE_EXECUTE_WRITECOPY]}


    @property
    def State(self):
        raw_state = super(_MEMORY_BASIC_INFORMATION32, self).State
        # Finally make a chooser somewhere ?
        return self.STATE_MAPPER.get(raw_state, raw_state)

    @property
    def Type(self):
        raw_type = super(_MEMORY_BASIC_INFORMATION32, self).Type
        # Finally make a chooser somewhere ?
        return self.TYPE_MAPPER.get(raw_type, raw_type)

    @property
    def Protect(self):
        raw_protect = super(_MEMORY_BASIC_INFORMATION32, self).Protect
        # Finally make a chooser somewhere ?
        return self.PROTECT_MAPPER.get(raw_protect, raw_protect)

    def __repr__(self):
        return "<MEMORY_BASIC_INFORMATION32 BaseAddress={0:#08x} RegionSize={1:#08x} State={2} Type={3} Protect={4}>".format(
            self.BaseAddress, self.RegionSize, self.State, self.Type, self.Protect)