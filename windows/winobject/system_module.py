import ctypes

import windows
import windows.winproxy as winproxy
import windows.generated_def as gdef

class BaseSystemModule(object):
    """[ABSTRACT] A common base class for all system modules"""

    @property
    def name(self):
        """The name of the system module: alias for ``ImageName``"""
        return self.ImageName

    def __repr__(self):
        return """<{0} name="{1}" base={2:#x}>""".format(type(self).__name__, self.ImageName, self.Base)



class SystemModule(BaseSystemModule, gdef.SYSTEM_MODULE):
    """A system module.

    .. note::
        inherit from SYSTEM_MODULE[32/64] based on the current process bitness
    """
    pass


# Only useful / meaningful in Wow64 Process
class SystemModuleWow64(BaseSystemModule, gdef.SYSTEM_MODULE64):
    """An explicite 64b system module for SysWow64 processes"""
    pass


def enumerate_kernel_modules():
    if windows.current_process.is_wow_64:
        return enumerate_kernel_modules_syswow64()
    cbsize = gdef.DWORD()
    winproxy.NtQuerySystemInformation(gdef.SystemModuleInformation, None, 0, ctypes.byref(cbsize))
    raw_buffer = (cbsize.value * gdef.BYTE)()
    buffer = gdef.SYSTEM_MODULE_INFORMATION.from_address(ctypes.addressof(raw_buffer))
    winproxy.NtQuerySystemInformation(gdef.SystemModuleInformation, ctypes.byref(raw_buffer), ctypes.sizeof(raw_buffer), ctypes.byref(cbsize))
    modules = (SystemModule * buffer.ModulesCount).from_buffer(raw_buffer, gdef.SYSTEM_MODULE_INFORMATION.Modules.offset)
    return list(modules)

def enumerate_kernel_modules_syswow64():
    cbsize = gdef.DWORD()
    windows.syswow64.NtQuerySystemInformation_32_to_64(gdef.SystemModuleInformation, None, 0, ctypes.addressof(cbsize))
    raw_buffer = (cbsize.value * gdef.BYTE)()
    buffer = gdef.SYSTEM_MODULE_INFORMATION64.from_address(ctypes.addressof(raw_buffer))
    windows.syswow64.NtQuerySystemInformation_32_to_64(gdef.SystemModuleInformation, ctypes.byref(raw_buffer), ctypes.sizeof(raw_buffer), ctypes.byref(cbsize))
    modules = (SystemModuleWow64 * buffer.ModulesCount).from_buffer(raw_buffer, gdef.SYSTEM_MODULE_INFORMATION64.Modules.offset)
    return list(modules)