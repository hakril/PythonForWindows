import os.path

import windows
import windows.generated_def as gdef

from windows import security
from windows import utils


class WinFile(object):
    def __init__(self, filename=None, handle=None):
        if not filename and handle:
            raise ValueError("File constructor should be given a filename OR handle")
        self.filename = filename
        if handle:
            self._handle = handle
            self._file = utils.create_file_from_handle(self.handle)

    @utils.fixedproperty
    def file(self):
        assert not getattr(self, "_handle", None)
        return open(self.filename, "r")

    # We do not close the handle on __del__ -> the destructor of file will do it ?
    # BUt in this case handle without a file will NOT close it..
    @utils.fixedproperty
    def handle(self):
        if os.path.isdir(self.filename):
            return windows.utils.create_file(self.filename, share=gdef.FILE_SHARE_READ | gdef.FILE_SHARE_WRITE, flags=gdef.FILE_FLAG_BACKUP_SEMANTICS)
        else:
            file = self.file
            return utils.get_handle_from_file(file)


    def get_security_descriptor(self,  query_sacl=False, flags=security.SecurityDescriptor.DEFAULT_SECURITY_INFORMATION):
        return security.SecurityDescriptor.from_handle(self.handle, query_sacl=query_sacl, flags=flags, obj_type="file")

    def set_security_descriptor(self, sd):
        flags = 0
        if sd.owner:
            flags |= gdef.OWNER_SECURITY_INFORMATION
        if sd.group:
            flags |= gdef.GROUP_SECURITY_INFORMATION
        if sd.dacl:
            flags |= gdef.DACL_SECURITY_INFORMATION
        if sd.sacl:
            flags |= gdef.SACL_SECURITY_INFORMATION
        # Check Mandatory label ?

        handle = windows.utils.create_file(self.filename, access=gdef.GENERIC_READ|gdef.WRITE_DAC, share=gdef.FILE_SHARE_READ | gdef.FILE_SHARE_WRITE, flags=gdef.FILE_FLAG_BACKUP_SEMANTICS)
        return windows.winproxy.SetSecurityInfo(handle, gdef.SE_KERNEL_OBJECT, flags, sd.owner, sd.group, sd.dacl, sd.sacl)



    security_descriptor = property(get_security_descriptor, set_security_descriptor)

    @classmethod
    def from_file(cls):
        handle = utils.get_handle_from_file(file)
        self = cls(filename=file.name, handle=handle)
        self._file = file
        return self

