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

import windows.exception
import windows.wmi
import windows.utils
import windows.debug

__all__ = ["system", "VirtualProtected", 'current_process', 'current_thread', 'winproxy']

import os

if bool(os.environ.get("SPHINX_BUILD", 0)):
    # I know it's shameful
    # But it's the only way I can think of right know to get a full class
    # of PEFile for documentation purpose u_u

    ppe = windows.current_process.peb.modules[0].pe
    windows.pe_parse.PEFile = type(ppe)
    iat_entry = ppe.imports.values()[0][0]
    windows.pe_parse.IATEntry = type(iat_entry)

