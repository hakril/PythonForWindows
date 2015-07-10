"""
Windows for Python
A lot of python object to help navigate windows stuff

Exported:

    system : :class:`windows.winobject.System`

    current_process : :class:`windows.winobject.CurrentProcess`

    current_thread : :class:`windows.winobject.CurrentThread`
"""

import windows.k32testing
from .utils import  VirtualProtected
from .winobject import System, CurrentProcess, CurrentThread


system = System()
current_process = CurrentProcess()
current_thread = CurrentThread()

import windows.vectored_exception

__all__ = ["system", "VirtualProtected", 'current_process', 'current_thread']