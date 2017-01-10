import ctypes

import windows
from windows import winproxy
from windows.generated_def import *



callback_type = ctypes.WINFUNCTYPE(UINT, HWND, LPARAM)


class Point(POINT):
    def __repr__(self):
        return "<{0} x={1} y={2}>".format(type(self).__name__, self.x, self.y)
        #return "<{0} x={1:#x} y={2:#x}>".format(type(self).__name__, self.x, self.y)

class Rect(RECT):
    def __repr__(self):
        return "<{0} left={1} top={2} right={3} bottom={4}>".format(type(self).__name__, self.left, self.top, self.right, self.bottom)
        #return "<{0} x={1:#x} y={2:#x}>".format(type(self).__name__, self.x, self.y)


def get_cursor_pos():
    res = Point()
    winproxy.GetCursorPos(res)
    return res

class Window(object):
    def __init__(self, handle):
        self.handle = handle

    def name(self):
        size = 0x1024
        buffer = ctypes.c_buffer(size)

        res = windows.winproxy.GetWindowTextA(self.handle, buffer, size)
        return buffer[:res]

    def rect(self):
        res =  Rect()
        winproxy.GetWindowRect(self.handle, res)
        return res

    def size(self):
        rect = self.rect()
        width = rect.right - rect.left
        heigth = rect.bottom - rect.top
        return width, heigth

    @classmethod
    def at_point(cls, point):
        handle = winproxy.WindowFromPoint(point)
        return cls(handle)


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
