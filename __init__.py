"""
Windows for Python
A lot of python object to help navigate windows stuff

Exported:

    system : :class:`windows.winobject.System`

    current_process : :class:`windows.winobject.CurrentProcess`

    current_thread : :class:`windows.winobject.CurrentThread`
"""

import k32testing
from winobject import System, CurrentProcess, CurrentThread
from utils import  VirtualProtected

system = System()
current_process = CurrentProcess()
current_thread = CurrentThread()

__all__ = ["system", "VirtualProtected", 'current_process', 'current_thread']