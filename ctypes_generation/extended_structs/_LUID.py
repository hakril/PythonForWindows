_INITIAL_LUID = _LUID
class _LUID(_INITIAL_LUID):
    def __int__(self):
        return (self.HighPart << 32) | self.LowPart

    def __eq__(self, other):
        return (self.HighPart, self.LowPart) == (other.HighPart, other.LowPart)

    def __repr__(self):
        return "<{0} HighPart={1} LowPart={2}>".format(type(self).__name__, self.HighPart, self.LowPart)