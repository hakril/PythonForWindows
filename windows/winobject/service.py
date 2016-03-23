import ctypes
import windows

from collections import namedtuple

from windows import utils
from windows.generated_def import *


SERVICE_TYPE = {x:x for x in [SERVICE_KERNEL_DRIVER, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS, SERVICE_INTERACTIVE_PROCESS]}
SERVICE_STATE = {x:x for x in [SERVICE_STOPPED, SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_RUNNING, SERVICE_CONTINUE_PENDING, SERVICE_PAUSE_PENDING, SERVICE_PAUSED]}
SERVICE_CONTROLE_ACCEPTED = {x:x for x in []}
SERVICE_FLAGS = {x:x for x in [SERVICE_RUNS_IN_SYSTEM_PROCESS]}


service_status = namedtuple("ServiceStatus", ["type", "state", "control_accepted", "flags"])

class Service(object):
    def __repr__(self):
        return '<{0} "{1}">'.format(type(self).__name__, self.name)

    @utils.fixedpropety
    def name(self):
        return self.lpServiceName

    @utils.fixedpropety
    def description(self):
        return self.lpDisplayName

    @utils.fixedpropety
    def status(self):
        status = self.ServiceStatusProcess
        stype = SERVICE_TYPE.get(status.dwServiceType, status.dwServiceType)
        sstate = SERVICE_STATE.get(status.dwCurrentState, status.dwCurrentState)
        scontrol = status.dwControlsAccepted
        sflags = SERVICE_FLAGS.get(status.dwServiceFlags, status.dwServiceFlags)
        return service_status(stype, sstate, scontrol, sflags)

    @utils.fixedpropety
    def process(self):
        pid = self.ServiceStatusProcess.dwProcessId
        if not pid:
            return None
        l = [p for p in windows.system.processes if p.pid == pid]
        if not l:
            return None # Other thing ?
        return l[0]


class ServiceA(Service, ENUM_SERVICE_STATUS_PROCESSA):
    pass

def enumerate_services():
    scmanager = windows.winproxy.OpenSCManagerA(dwDesiredAccess=SC_MANAGER_ENUMERATE_SERVICE)

    size_needed = DWORD()
    nb_services = DWORD()
    counter = DWORD()
    try:
        windows.winproxy.EnumServicesStatusExA(scmanager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_ACTIVE, None, 0, ctypes.byref(size_needed), ctypes.byref(nb_services), byref(counter), None)
    except WindowsError:
        pass

    while True:
        size = size_needed.value
        buffer = (ctypes.c_byte * size)()

        try:
            windows.winproxy.EnumServicesStatusExA(scmanager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_ACTIVE, buffer, size, ctypes.byref(size_needed), ctypes.byref(nb_services), byref(counter), None)
        except WindowsError as e:
            continue

        return_type = (ServiceA * nb_services.value)
        return list(return_type.from_buffer(buffer))