INITIAL_tagDUALSTRINGARRAY = tagDUALSTRINGARRAY

class tagDUALSTRINGARRAY(INITIAL_tagDUALSTRINGARRAY):
    @property
    def rawbuffer(self):
        array_size = self.wNumEntries
        array_type = self.aStringArray._type_
        new_buffer_type = (array_type * array_size)
        buffer = new_buffer_type.from_address(ctypes.addressof(self.aStringArray))
        return buffer



    @property
    def bidings(self):
        rawbuffer = self.rawbuffer
        rawarray = rawbuffer[:] # Allow to find 0 in USHORT without overlap
        rawbytes = bytearray(rawbuffer) # Allow to access to bytes to utf-16-le decode
        results = []
        next_start = 0

        # STRINGBINDING documentation says that it starts with a USHORT wTowerId
        # But i don't see it in our response.. (local response ?)
        # So ignore it for now
        for i in range(100):
            current_index = rawarray.index(0, next_start)
            new_entry = rawbytes[next_start * 2: current_index * 2]
            if not new_entry:
                return results
            results.append(new_entry.decode("utf-16-le")) # Does not handle full unicode I think but..
            next_start = current_index + 1
        # Should not happen
        raise ValueError("Could not parse DUALSTRINGARRAY")

    @property
    def security_bidings(self):
        rawbuffer = self.rawbuffer
        rawarray = rawbuffer[self.wSecurityOffset:]
        rawbytes = bytearray(rawbuffer)[self.wSecurityOffset * 2:]
        results = []
        next_start = 0

        for i in range(100):
            wAuthnSvc = rawarray[next_start]
            if wAuthnSvc == 0:
                return results
            reserved = rawarray[next_start + 1]
            current_index = rawarray.index(0, next_start + 2)
            new_entry = rawbytes[(next_start + 2) * 2:current_index * 2]
            results.append((wAuthnSvc, reserved, new_entry.decode("utf-16-le"))) # Does not handle full unicode I think but..
            next_start = current_index + 1
        # Should not happen
        raise ValueError("Could not parse DUALSTRINGARRAY security bidings")




