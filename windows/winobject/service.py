import ctypes
import windows

from collections import namedtuple
from contextlib import contextmanager

from windows import utils
import windows.generated_def as gdef
from windows.generated_def import *


SERVICE_TYPE = gdef.FlagMapper(SERVICE_KERNEL_DRIVER, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS, SERVICE_INTERACTIVE_PROCESS)
SERVICE_STATE = gdef.FlagMapper(SERVICE_STOPPED, SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_RUNNING, SERVICE_CONTINUE_PENDING, SERVICE_PAUSE_PENDING, SERVICE_PAUSED)
SERVICE_CONTROLE_ACCEPTED = gdef.FlagMapper()
SERVICE_FLAGS = gdef.FlagMapper(SERVICE_RUNS_IN_SYSTEM_PROCESS)


ServiceStatus = namedtuple("ServiceStatus", ["type", "state", "control_accepted", "flags"])
"""
``type`` might be one of:

    * ``SERVICE_KERNEL_DRIVER(0x1L)``
    * ``SERVICE_FILE_SYSTEM_DRIVER(0x2L)``
    * ``SERVICE_WIN32_OWN_PROCESS(0x10L)``
    * ``SERVICE_WIN32_SHARE_PROCESS(0x20L)``
    * ``SERVICE_INTERACTIVE_PROCESS(0x100L)``

``state`` might be one of:

    * ``SERVICE_STOPPED(0x1L)``
    * ``SERVICE_START_PENDING(0x2L)``
    * ``SERVICE_STOP_PENDING(0x3L)``
    * ``SERVICE_RUNNING(0x4L)``
    * ``SERVICE_CONTINUE_PENDING(0x5L)``
    * ``SERVICE_PAUSE_PENDING(0x6L)``
    * ``SERVICE_PAUSED(0x7L)``

``flags`` might be one of:

    * ``0``
    * ``SERVICE_RUNS_IN_SYSTEM_PROCESS(0x1L)``

"""

class Service(object):
    handle = None

    def __repr__(self):
        return '<{0} "{1}" {2}>'.format(type(self).__name__, self.name, self.status.state)

    @utils.fixedpropety
    def name(self):
        """The name of the service

        :type: :class:`str`
        """
        return self.lpServiceName

    @utils.fixedpropety
    def description(self):
        """The description of the service

        :type: :class:`str`
        """
        return self.lpDisplayName

    @property
    def status(self):
        """The status of the service

        :type: :class:`ServiceStatus`
        """
        status = self.ServiceStatusProcess
        stype = SERVICE_TYPE[status.dwServiceType]
        sstate = SERVICE_STATE[status.dwCurrentState]
        scontrol = status.dwControlsAccepted
        sflags = SERVICE_FLAGS[status.dwServiceFlags]
        return ServiceStatus(stype, sstate, scontrol, sflags)

    @utils.fixedpropety
    def process(self):
        """The process running the service (if any)

        :type: :class:`WinProcess <windows.winobject.process.WinProcess>` or ``None``
        """
        pid = self.ServiceStatusProcess.dwProcessId
        if not pid:
            return None
        l = windows.WinProcess(pid=pid)
        return l


class ServiceA(Service, ENUM_SERVICE_STATUS_PROCESSA):
    """A Service object with ascii data"""
    def start(self, args=None):
        if args is not None:
            raise NotImplementedError("Start service with args != None")
        with scmanagera(SC_MANAGER_CONNECT) as scm:
            # windows.winproxy.StartServiceA()
            servh = windows.winproxy.OpenServiceA(scm, self.name, SERVICE_START)
            windows.winproxy.StartServiceA(servh, 0, None)
            windows.winproxy.CloseServiceHandle(servh)


@contextmanager
def scmanagera(access):
    # scmanager = windows.winproxy.OpenSCManagerA(dwDesiredAccess=SC_MANAGER_ENUMERATE_SERVICE)
    scmanager = windows.winproxy.OpenSCManagerA(dwDesiredAccess=access)
    try:
        yield scmanager
    finally:
        windows.winproxy.CloseServiceHandle(scmanager)

def enumerate_services():
    with scmanagera(SC_MANAGER_ENUMERATE_SERVICE) as scm:
        size_needed = DWORD()
        nb_services = DWORD()
        counter = DWORD()
        try:
            windows.winproxy.EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, None, 0, ctypes.byref(size_needed), ctypes.byref(nb_services), byref(counter), None)
        except WindowsError:
            pass

        while True:
            size = size_needed.value
            buffer = (BYTE * size)()
            try:
                windows.winproxy.EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, buffer, size, ctypes.byref(size_needed), ctypes.byref(nb_services), byref(counter), None)
            except WindowsError as e:
                continue
            return_type = (ServiceA * nb_services.value)
            return list(return_type.from_buffer(buffer))