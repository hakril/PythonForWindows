"""
Python for Windows
A lot of python object to help navigate windows stuff

Exported:

    system : :class:`windows.winobject.System`

    current_process : :class:`windows.winobject.CurrentProcess`

    current_thread : :class:`windows.winobject.CurrentThread`
"""

# check we are on windows
import sys
if sys.platform != "win32":
    raise NotImplementedError("It's called PythonForWindows not PythonFor{0}".format(sys.platform.capitalize()))

import warnings
warnings.filterwarnings('once', category=DeprecationWarning, module=__name__)

from windows import winproxy
from windows import winobject

from .winobject.system import System
from .winobject.process import CurrentProcess, CurrentThread, WinProcess, WinThread
from .winobject.file import WinFile


system = System()
current_process = CurrentProcess()
current_thread = CurrentThread()

del System
del CurrentProcess
del CurrentThread

# Late import: other imports should go here
# Do not move it: risk of circular import

import windows.utils
import windows.wintrust
import windows.syswow64
import windows.com

__all__ = ["system", 'current_process', 'current_thread']
