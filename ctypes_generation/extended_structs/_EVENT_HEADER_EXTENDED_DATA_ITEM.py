_OLD_EVENT_HEADER_EXTENDED_DATA_ITEM = _EVENT_HEADER_EXTENDED_DATA_ITEM
class _EVENT_HEADER_EXTENDED_DATA_ITEM(_OLD_EVENT_HEADER_EXTENDED_DATA_ITEM):
    @property
    def data(self):
        bdata = (ctypes.c_char * self.DataSize).from_address(self.DataPtr)
        return bdata[:]