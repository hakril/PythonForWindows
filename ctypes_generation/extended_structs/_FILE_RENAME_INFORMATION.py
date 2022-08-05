INITIAL_FILE_RENAME_INFORMATION = _FILE_RENAME_INFORMATION

class _FILE_RENAME_INFORMATION(INITIAL_FILE_RENAME_INFORMATION):
    @property
    def filename(self):
        filename_addr = ctypes.addressof(self) + type(self).FileName.offset
        if getattr(self, "_target", None) is not None: #remote ctypes :D -> TRICKS OF THE YEAR
            raw_data = self._target.read_memory(filename_addr, self.FileNameLength)
            return raw_data.decode("utf16")
        size = int(self.FileNameLength / 2)
        return (ctypes.c_wchar * size).from_address(filename_addr)[:]
