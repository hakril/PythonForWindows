class _OBJECT_ATTRIBUTES(_OBJECT_ATTRIBUTES):
    @classmethod
    def from_string(cls, path, attributes=OBJ_CASE_INSENSITIVE): # Directly on constructor ?
        self = cls()
        self.Length = ctypes.sizeof(self)
        self.RootDirectory = 0
        self.ObjectName = ctypes.pointer(LSA_UNICODE_STRING.from_string(path))
        self.Attributes = attributes
        self.SecurityDescriptor = 0
        self.SecurityQualityOfService = 0
        return self

    def __repr__(self):
        if not self.ObjectName:
            return super(_OBJECT_ATTRIBUTES, self).__repr__()
        # .contents allow compatibility with remotectypes
        return """<{0} ObjectName="{1}">""".format(type(self).__name__, self.ObjectName.contents.str)