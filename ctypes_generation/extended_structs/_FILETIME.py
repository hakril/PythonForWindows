INITIAL_FILETIME = FILETIME

class _FILETIME(INITIAL_FILETIME):
    def __int__(self):
        return (self.dwHighDateTime << 32) + self.dwLowDateTime