import ctypes
import windows

from collections import namedtuple
from contextlib import contextmanager

from windows import utils
import windows.generated_def as gdef
from windows.generated_def import *
from windows import security

# TODO: RM :)
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


class ServiceManager(utils.AutoHandle):
    _close_function = staticmethod(windows.winproxy.CloseServiceHandle)

    def _get_handle(self):
        return windows.winproxy.OpenSCManagerA(dwDesiredAccess=gdef.MAXIMUM_ALLOWED)

    def open_service(self, name, access=gdef.MAXIMUM_ALLOWED):
        return windows.winproxy.OpenServiceA(self.handle, name, access) # Check service exists :)

    def get_service(self, name, access=gdef.MAXIMUM_ALLOWED):
        handle = self.open_service(name, access)
        return NewService(name=name, handle=handle)

    __getitem__ = get_service

    def get_service_display_name(self, name):
        # This API is strange..
        # Why can't we retrieve the display name for a service handle ?
        BUFFER_SIZE = 0x1000
        result = (CHAR * BUFFER_SIZE)()
        size_needed = gdef.DWORD(BUFFER_SIZE)
        windows.winproxy.GetServiceDisplayNameA(self.handle, name, result, size_needed)
        return result.value

    def _enumerate_services_generator(self):
        size_needed = gdef.DWORD()
        nb_services =  gdef.DWORD()
        counter =  gdef.DWORD()
        try:
            windows.winproxy.EnumServicesStatusExA(self.handle, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, None, 0, ctypes.byref(size_needed), ctypes.byref(nb_services), byref(counter), None)
        except WindowsError:
            pass

        while True:
            size = size_needed.value
            buffer = (BYTE * size)()
            try:
                windows.winproxy.EnumServicesStatusExA(self.handle, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, buffer, size, ctypes.byref(size_needed), ctypes.byref(nb_services), byref(counter), None)
            except WindowsError as e:
                continue
            break
        services_array = (gdef.ENUM_SERVICE_STATUS_PROCESSA * nb_services.value).from_buffer(buffer)
        for service_info in services_array:
            shandle = self.open_service(service_info.lpServiceName)
            yield NewService(handle=shandle, name=service_info.lpServiceName, description=service_info.lpDisplayName)
        return

    __iter__ = _enumerate_services_generator

    def enumerate_services(self):
        return list(self._enumerate_services_generator())


class NewService(gdef.SC_HANDLE):
    # close_function = windows.winproxy.CloseServiceHandle

    def __init__(self, handle, name, description=None):
        super(NewService, self).__init__(handle)
        self.name = name
        """The name of the service

        :type: :class:`str`
        """
        if description is not None:
            self._description = description # Setup fixedpropety

    @property
    def description(self):
        """The description of the service

        :type: :class:`str`
        """
        return ServiceManager().get_service_display_name(self.name)

    @property
    def status(self):
        buffer = windows.utils.BUFFER(gdef.SERVICE_STATUS_PROCESS)()
        size_needed = gdef.DWORD()
        windows.winproxy.QueryServiceStatusEx(self, gdef.SC_STATUS_PROCESS_INFO, buffer.cast(gdef.LPBYTE), ctypes.sizeof(buffer), size_needed)
        return buffer[0]

    @utils.fixedpropety
    def process(self):
        """The process running the service (if any)

        :type: :class:`WinProcess <windows.winobject.process.WinProcess>` or ``None``
        """
        pid = self.status.dwProcessId
        if not pid:
            return None
        l = windows.WinProcess(pid=pid)
        return l

    @property
    def security_descriptor(self):
        return security.SecurityDescriptor.from_service(self.name)

    def start(self, args=None):
        nbelt = 0
        if args is not None:
            if isinstance(args, basestring):
                args = [args]
            nbelt = len(args)
            args = (gdef.LPCSTR * (nbelt))(*args)
        return windows.winproxy.StartServiceA(self, nbelt, args)

    def stop(self):
        status = SERVICE_STATUS()
        windows.winproxy.ControlService(self, gdef.SERVICE_CONTROL_STOP, status)
        return status

    def __repr__(self):
        return """<{0} "{1}" {2}>""".format(type(self).__name__, self.name, self.status.state)

    def __del__(self):
        return windows.winproxy.CloseServiceHandle(self)
