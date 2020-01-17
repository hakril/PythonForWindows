INITIAL_GUID = _GUID
class _GUID(INITIAL_GUID):
    def __init__(self, Data1=None, Data2=None, Data3=None, Data4=None, name=None, strid=None):
        data_tuple = (Data1, Data2, Data3, Data4)
        self.name = name
        self.strid = strid
        if all(data is None for data in data_tuple):
            return super(_GUID, self).__init__()
        if any(data is None for data in data_tuple):
            raise ValueError("All or none of (Data1, Data2, Data3, Data4) should be None")
        super(_GUID, self).__init__(Data1, Data2, Data3, Data4)

    def __repr__(self):
        notpresent = object()
        # Handle IID created without '__init__' (like ctypes-ptr deref)
        if getattr(self, "strid", notpresent) is notpresent:
            self.strid = self.to_string()
        if self.strid is None:
            return super(_GUID, self).__repr__()

        if getattr(self, "name", notpresent) is notpresent:
            self.name = None
        if self.name is None:
            return '<GUID "{0}">'.format(self.strid.upper())
        return '<GUID "{0}({1})">'.format(self.strid.upper(), self.name)

    __sprint__ = __repr__


    def to_string(self):
        data4_format = "{0:02X}{1:02X}-" + "".join("{{{i}:02X}}".format(i=i + 2) for i in range(6))
        data4_str = data4_format.format(*self.Data4)
        return "{0:08X}-{1:04X}-{2:04X}-".format(self.Data1, self.Data2, self.Data3) + data4_str

    __str__ = to_string

    def update_strid(self):
       new_strid = self.to_string()
       self.strid = new_strid

    @classmethod
    def from_string(cls, iid):
        part_iid = iid.split("-")
        datas = [int(x, 16) for x in part_iid[:3]]
        datas.append(int(part_iid[3][:2], 16))
        datas.append(int(part_iid[3][2:], 16))
        for i in range(6):
            datas.append(int(part_iid[4][i * 2:(i + 1) * 2], 16))
        return cls.from_raw(*datas, strid=iid)


    @classmethod
    def from_raw(cls, Data1, Data2, Data3, Data41, Data42, Data43, Data44, Data45, Data46, Data47, Data48, **kwargs):
        return cls(Data1, Data2, Data3,  (BYTE*8)(Data41, Data42, Data43, Data44, Data45, Data46, Data47, Data48), **kwargs)

    def __eq__(self, other):
        if not isinstance(other, (_GUID, INITIAL_GUID)):
            return NotImplemented
        return (self.Data1, self.Data2, self.Data3, self.Data4[:]) == (other.Data1, other.Data2, other.Data3, other.Data4[:])
