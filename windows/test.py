import windows
import windows.generated_def as gdef
from windows.utils import create_process, DisableWow64FsRedirection


test_binary_name = "notepad.exe"
DEFAULT_CREATION_FLAGS = gdef.CREATE_NEW_CONSOLE

if windows.system.bitness == 32:
    def pop_proc_32(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        return create_process(r"C:\Windows\system32\{0}".format(test_binary_name).encode(), dwCreationFlags=dwCreationFlags, show_windows=True)

    def pop_proc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        raise WindowsError("Cannot create calc64 in 32bits system")
else:
    def pop_proc_32(dwCreationFlags=DEFAULT_CREATION_FLAGS):
        return create_process(r"C:\Windows\syswow64\{0}".format(test_binary_name).encode(), dwCreationFlags=dwCreationFlags, show_windows=True)

    if windows.current_process.bitness == 32:
        def pop_proc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
            with DisableWow64FsRedirection():
                return create_process(r"C:\Windows\system32\{0}".format(test_binary_name).encode(), dwCreationFlags=dwCreationFlags, show_windows=True)
    else:
        def pop_proc_64(dwCreationFlags=DEFAULT_CREATION_FLAGS):
            return create_process(r"C:\Windows\system32\{0}".format(test_binary_name).encode(), dwCreationFlags=dwCreationFlags, show_windows=True)