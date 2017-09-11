"""
Windows for Python
A lot of python object to help navigate windows stuff

Exported:

    system : :class:`windows.winobject.System`

    current_process : :class:`windows.winobject.CurrentProcess`

    current_thread : :class:`windows.winobject.CurrentThread`
"""


from windows import winproxy
from windows import winobject

from winobject.system import System
from winobject.process import CurrentProcess, CurrentThread, WinProcess, WinThread


system = System()
current_process = CurrentProcess()
current_thread = CurrentThread()

del System
del CurrentProcess
del CurrentThread

# Late import: other imports should go here
# Do not move it: risk of circular import

import windows.utils
import windows.debug
import windows.wintrust
import windows.syswow64
import windows.com

__all__ = ["system", 'current_process', 'current_thread']
