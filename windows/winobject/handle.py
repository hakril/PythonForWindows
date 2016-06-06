import ctypes

import windows
from windows import winproxy
from windows.generated_def import windef
from windows.winobject.process import WinUnicodeString

from windows.generated_def.winstructs import *


class ProcessHandle(SYSTEM_HANDLE):
    @windows.utils.fixedpropety
    def process(self):
        # Do better (open process / process by handle)
        return [p for p in windows.system.processes if p.pid == self.dwProcessId][0]


    def get_object_name(self):
        lh = self._get_local_handle()
        size_needed = DWORD()
        yyy = ctypes.c_buffer(0x1000)
        #print("Size = {0}".format(ctypes.sizeof(xxx)))
        size_needed = DWORD()
        #try:
        winproxy.NtQueryObject(lh, ObjectNameInformation, ctypes.byref(yyy), ctypes.sizeof(yyy), ctypes.byref(size_needed))
        return WinUnicodeString.from_buffer_copy(yyy[:size_needed.value]).str

    def _public_object_information(self):
        lh = self._get_local_handle()

        xxx = PUBLIC_OBJECT_TYPE_INFORMATION()
        #print("Size = {0}".format(ctypes.sizeof(xxx)))
        size_needed = DWORD()
        try:
            winproxy.NtQueryObject(lh, ObjectTypeInformation, ctypes.byref(xxx), ctypes.sizeof(xxx), ctypes.byref(size_needed))
        except Exception as e:
            #print(e)
            #print(size_needed)
            size = size_needed.value
            buffer = ctypes.c_buffer(size)
            winproxy.NtQueryObject(lh, ObjectTypeInformation, buffer, size, ctypes.byref(size_needed))
            xxx = PUBLIC_OBJECT_TYPE_INFORMATION.from_buffer_copy(buffer)
        return xxx

    def _get_local_handle(self):
        if self.dwProcessId == windows.current_process.pid:
            return self.wValue
        res = HANDLE()
        print("Duplicate <{0}> of {1}".format(self.wValue, self.process))
        winproxy.DuplicateHandle(self.process.handle, self.wValue, windows.current_process.handle, ctypes.byref(res), dwOptions=DUPLICATE_SAME_ACCESS)
        return res.value

    def _close_local_handle(self, h):
        if self.dwProcessId == windows.current_process.pid:
            return
        return winproxy.Closehandle(h)

    #def __repr__(self):
    #    return "YOLO" + object.__repr__(self)

def get_handle_list():
        size_needed = ULONG()
        size = 0x1000
        buffer = ctypes.c_buffer(size)

        try:
            winproxy.NtQuerySystemInformation(16, buffer, size, ReturnLength=ctypes.byref(size_needed))
        except WindowsError as e:
            pass

        size = size_needed.value + 0x1000
        buffer = ctypes.c_buffer(size)
        winproxy.NtQuerySystemInformation(16, buffer, size, ReturnLength=ctypes.byref(size_needed))

        x = SYSTEM_HANDLE_INFORMATION.from_buffer(buffer)

        class _GENERATED_SYSTEM_HANDLE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("HandleCount", ULONG),
                ("Handles", ProcessHandle * x.HandleCount),
            ]
        return list(_GENERATED_SYSTEM_HANDLE_INFORMATION.from_buffer_copy(buffer[:size_needed.value]).Handles)