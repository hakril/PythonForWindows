"""
Windows for Python
A lot of python object to help navigate windows stuff

Exported:

    system : :class:`windows.winobject.System`

    current_process : :class:`windows.winobject.CurrentProcess`

    current_thread : :class:`windows.winobject.CurrentThread`
"""

from . import winproxy
from .utils import VirtualProtected
from .winobject import System, CurrentProcess, CurrentThread

system = System()
current_process = CurrentProcess()
current_thread = CurrentThread()

# Late import: other imports should go here
# Do not move it: risk of circular import

__all__ = ["system", "VirtualProtected", 'current_process', 'current_thread', 'winproxy']
