import k32testing
from winobject import System, CurrentProcess
from utils import  VirtualProtected

system = System()
current_process = CurrentProcess()

__all__ = ["system", "VirtualProtected", 'current_process']