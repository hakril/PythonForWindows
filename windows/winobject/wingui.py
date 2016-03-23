import ctypes

import windows
from windows.generated_def import *



callback_type = ctypes.WINFUNCTYPE(UINT, HWND, LPARAM)

class Window(object):
    def __init__(self, handle):
        self.handle = handle

    def name(self):
        size = 0x1024
        buffer = ctypes.c_buffer(size)

        res = windows.winproxy.GetWindowTextA(self.handle, buffer, size)
        return buffer[:res]

    # I don't understand the interest:
    # Either return "" or C:\Python27\python.exe
    #def module(self):
    #   size = 0x1024
    #   buffer = ctypes.c_buffer(size)
    #   res = windows.winproxy.GetWindowModuleFileNameA(self.handle, buffer, size)
    #   return buffer[:res]


def enumwindows():
    result = []
    def callback(handle, param):
        result.append(handle)
        return True

    try:
        x = windows.winproxy.EnumWindows(callback_type(callback), 0)
    except WindowsError:
        if not result:
            raise
    return result


v = enumwindows()

for i in v:
    w = Window(i)
    if w.name():
        print("{0} -> {1} ".format(i, w.name()))

raise "YOLO"
