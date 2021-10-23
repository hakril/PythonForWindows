import os
import ctypes

import windows
from windows import winproxy
from windows.generated_def import windef
import windows.generated_def as gdef

current_process_pid = os.getpid()

class BaseSystemHandle(object):
    # Big bypass to prevent missing reference at programm exit..
    _close_function = ctypes.WinDLL("kernel32").CloseHandle

    """A handle of the system"""
    @windows.utils.fixedpropety
    def process(self):
        """The process possessing the handle

        :type: :class:`WinProcess <windows.winobject.process.WinProcess>`"""
        # "TODO: something smart ? :D"
        # return [p for p in windows.system.processes if p.pid == self.dwProcessId][0]
        return windows.WinProcess(pid=self.dwProcessId)

    @property
    def pid(self):
        return self.dwProcessId

    @property
    def value(self):
        return self.wValue


    @windows.utils.fixedpropety
    def name(self):
        """The name of the handle

        :type: :class:`str`"""
        return self._get_object_name()

    @windows.utils.fixedpropety
    def type(self):
        """The type of the handle

        :type: :class:`str`"""
        return self._get_object_type()

    @property
    def infos(self):
        """TODO: DOC"""
        return self._get_object_basic_infos()

    def _get_object_name(self):
        lh = self.local_handle
        size_needed = gdef.DWORD()
        yyy = ctypes.c_buffer(0x1000)
        winproxy.NtQueryObject(lh, gdef.ObjectNameInformation, ctypes.byref(yyy), ctypes.sizeof(yyy), ctypes.byref(size_needed))
        return gdef.LSA_UNICODE_STRING.from_buffer_copy(yyy[:size_needed.value]).str

    def _get_object_type(self):
        lh = self.local_handle
        xxx = gdef.PUBLIC_OBJECT_TYPE_INFORMATION()
        size_needed = gdef.DWORD()
        try:
            winproxy.NtQueryObject(lh, gdef.ObjectTypeInformation, ctypes.byref(xxx), ctypes.sizeof(xxx), ctypes.byref(size_needed))
        except WindowsError as e:
            if e.code != gdef.STATUS_INFO_LENGTH_MISMATCH:
                raise
            size = size_needed.value
            buffer = ctypes.c_buffer(size)
            winproxy.NtQueryObject(lh, gdef.ObjectTypeInformation, buffer, size, ctypes.byref(size_needed))
            xxx = gdef.PUBLIC_OBJECT_TYPE_INFORMATION.from_buffer_copy(buffer)
        return xxx.TypeName.str

    def _get_object_basic_infos(self):
        pass
        lh = self.local_handle
        size_needed = gdef.DWORD()
        basic_infos = gdef.PUBLIC_OBJECT_BASIC_INFORMATION()
        winproxy.NtQueryObject(lh, gdef.ObjectBasicInformation, ctypes.byref(basic_infos), ctypes.sizeof(basic_infos), ctypes.byref(size_needed))
        return basic_infos

    @windows.utils.fixedpropety
    def local_handle(self):
        """A local copy of the handle, acquired with ``DuplicateHandle``

        :type: :class:`int`"""
        if self.dwProcessId == windows.current_process.pid:
            return self.wValue
        res = gdef.HANDLE()
        winproxy.DuplicateHandle(self.process.handle, self.wValue, windows.current_process.handle, ctypes.byref(res), dwOptions=gdef.DUPLICATE_SAME_ACCESS)
        return res.value

    def description(self):
        stype = self.type
        descr_func = getattr(self, "description_" + stype, None)
        if descr_func is None:
            return None
        return descr_func()

    def description_Process(self):
        proc = windows.WinProcess(handle=self.wValue)
        res = str(proc)
        del proc._handle
        return res

    def description_Thread(self):
        thread = windows.WinThread(handle=self.wValue)
        res = str(thread)
        del thread._handle
        return res

    def __repr__(self):
        return "<{0} value=<0x{1:x}> in process pid={2}>".format(type(self).__name__, self.wValue, self.dwProcessId)

    def __del__(self):
        if self.dwProcessId == current_process_pid:
            return
        if hasattr(self, "_local_handle"):
            return self._close_function(self._local_handle)

class Handle(gdef.SYSTEM_HANDLE, BaseSystemHandle):
    pass

class HandleWow64(gdef.SYSTEM_HANDLE64, BaseSystemHandle):
    pass # For wow64 process

def enumerate_handles():
    if windows.current_process.is_wow_64:
        return enumerate_handles_syswow64()
    size_needed = gdef.ULONG()
    # Should at least be sizeof(gdef.SYSTEM_HANDLE_INFORMATION)
    tmp_buffer = windows.utils.BUFFER(gdef.SYSTEM_HANDLE_INFORMATION)()
    try:
        winproxy.NtQuerySystemInformation(gdef.SystemHandleInformation, tmp_buffer, tmp_buffer.real_size, ReturnLength=ctypes.byref(size_needed))
    except WindowsError as e:
        pass
    size = size_needed.value + 0x1000 # In case we have some more handle created
    buf = windows.utils.BUFFER(gdef.SYSTEM_HANDLE_INFORMATION)(size=size)
    size_needed.value = 0
    winproxy.NtQuerySystemInformation(gdef.SystemHandleInformation, buf, buf.real_size, ReturnLength=ctypes.byref(size_needed))
    handle_array = windows.utils.resized_array(buf[0].Handles, buf[0].HandleCount, Handle)
    return list(handle_array)


def enumerate_handles_syswow64():
    size_needed = gdef.ULONG()
    # Should at least be sizeof(gdef.SYSTEM_HANDLE_INFORMATION)
    tmp_buffer = windows.utils.BUFFER(gdef.SYSTEM_HANDLE_INFORMATION64)()
    try:
        windows.syswow64.NtQuerySystemInformation_32_to_64(gdef.SystemHandleInformation, tmp_buffer, tmp_buffer.real_size, ReturnLength=ctypes.byref(size_needed))
    except WindowsError as e:
        pass
    size = size_needed.value + 0x1000 # In case we have some more handle created
    buf = windows.utils.BUFFER(gdef.SYSTEM_HANDLE_INFORMATION64)(size=size)
    size_needed.value = 0
    windows.syswow64.NtQuerySystemInformation_32_to_64(gdef.SystemHandleInformation, buf, buf.real_size, ReturnLength=ctypes.byref(size_needed))
    handle_array = windows.utils.resized_array(buf[0].Handles, buf[0].HandleCount, HandleWow64)
    return list(handle_array)


def enumerate_type():
        "WIP: DO NOT USE"
        size_needed = DWORD()
        fsize = 8
        fbuffer = ctypes.c_buffer(fsize)
        try:
            winproxy.NtQueryObject(None, gdef.ObjectTypesInformation, fbuffer, fsize, ctypes.byref(size_needed))
        except WindowsError as e:
            if e.code != STATUS_INFO_LENGTH_MISMATCH:
                raise
        else:
            # We had enought memory ?
            return

        # Looks like the Wow64 syscall emulation is broken :D
        # It write AFTER the buffer if we are a wow64 process :D
        # So better allocate a standalone buffer (triggering a ACCESS_VIOLATION) that corrupting the heap
        # This is a worst case scenario, as we allocation more space it should not happen !
        size = size_needed.value + 0x200
        size_needed.value = 0

        with windows.current_process.allocated_memory(size, gdef.PAGE_READWRITE) as buffer_base:
            winproxy.NtQueryObject(None, gdef.ObjectTypesInformation, buffer_base, size, ctypes.byref(size_needed))
            # Cache some exceptions ?
            # Parse the buffer data in-place as string are addr-dependant
            types_info = gdef.OBJECT_TYPES_INFORMATION.from_address(buffer_base)
            offset = ctypes.sizeof(gdef.PVOID) # Looks like the size of the struct is PTR aligned as the struct is follower by other stuff
            for i in range(types_info.NumberOfTypes):
                info = gdef.PUBLIC_OBJECT_TYPE_INFORMATION.from_address(buffer_base + offset)
                yield info
                offset += ctypes.sizeof(gdef.PUBLIC_OBJECT_TYPE_INFORMATION) + info.TypeName.MaximumLength
                if offset % ctypes.sizeof(gdef.PVOID):
                    offset += ctypes.sizeof(gdef.PVOID) - (offset % ctypes.sizeof(gdef.PVOID))
        # End-of ctx-manager
        return
