import ctypes
import windows

from collections import namedtuple
from contextlib import contextmanager

from windows import utils
from windows.pycompat import int_types
import windows.generated_def as gdef
from windows.generated_def import *
from windows import security
from windows.pycompat import basestring

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
    """An object to query, list and explore services"""
    def _get_handle(self):
        return windows.winproxy.OpenSCManagerW(dwDesiredAccess=gdef.MAXIMUM_ALLOWED)

    def open_service(self, name, access=gdef.MAXIMUM_ALLOWED):
        return windows.winproxy.OpenServiceW(self.handle, name, access) # Check service exists :)

    def get_service(self, key, access=gdef.MAXIMUM_ALLOWED):
        """Get a service by its name/index or a list of services via a slice

        :return: :class:`Service` or [:class:`Service`] -- A :class:`Service` or list of :class:`Service`
        """
        if isinstance(key, int_types):
            return self.enumerate_services()[key]
        if isinstance(key, slice):
            # Get service list
            servlist = self.enumerate_services()
            # Extract indexes matching the slice
            indexes = key.indices(len(servlist))
            return [servlist[idx] for idx in range(*indexes)]
        # Retrieve service by its name
        handle = self.open_service(key, access)
        return Service(name=key, handle=handle)

    __getitem__ = get_service
    """Get a service by its name/index or a list of services via a slice

    :return: :class:`Service` or [:class:`Service`] -- A :class:`Service` or list of :class:`Service`
    """

    def get_service_display_name(self, name):
        # This API is strange..
        # Why can't we retrieve the display name for a service handle ?
        BUFFER_SIZE = 0x1000
        result = (WCHAR * BUFFER_SIZE)()
        size_needed = gdef.DWORD(BUFFER_SIZE)
        windows.winproxy.GetServiceDisplayNameW(self.handle, name, result, size_needed)
        return result.value

    def _enumerate_services_generator(self):
        """The generator code behind __iter__.
        Allow to iter over the services on the system
        """
        size_needed = gdef.DWORD()
        nb_services =  gdef.DWORD()
        counter =  gdef.DWORD()
        try:
            windows.winproxy.EnumServicesStatusExW(self.handle, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, None, 0, ctypes.byref(size_needed), ctypes.byref(nb_services), byref(counter), None)
        except WindowsError:
            pass

        while True:
            size = size_needed.value
            buffer = (BYTE * size)()
            try:
                windows.winproxy.EnumServicesStatusExW(self.handle, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, buffer, size, ctypes.byref(size_needed), ctypes.byref(nb_services), byref(counter), None)
            except WindowsError as e:
                continue
            break
        services_array = (gdef.ENUM_SERVICE_STATUS_PROCESSW * nb_services.value).from_buffer(buffer)
        for service_info in services_array:
            shandle = self.open_service(service_info.lpServiceName)
            yield Service(handle=shandle, name=service_info.lpServiceName, description=service_info.lpDisplayName)
        return

    __iter__ = _enumerate_services_generator
    """Iter over the services on the system

    :yield: :class:`Service`
    """

    def enumerate_services(self):
        return list(self._enumerate_services_generator())


class Service(gdef.SC_HANDLE):
    """Represent a service on the system"""
    def __init__(self, handle, name, description=None):
        super(Service, self).__init__(handle)
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
        """The status of the service

        :type: :class:`~windows.generated_def.winstructs.SERVICE_STATUS_PROCESS`
        """
        buffer = windows.utils.BUFFER(gdef.SERVICE_STATUS_PROCESS)()
        size_needed = gdef.DWORD()
        windows.winproxy.QueryServiceStatusEx(self, gdef.SC_STATUS_PROCESS_INFO, buffer.cast(gdef.LPBYTE), ctypes.sizeof(buffer), size_needed)
        return buffer[0]

    @property # Can change if service is started/stopped when the object exist
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
        """The security descriptor of the service

        :type: :class:`~windows.security.SecurityDescriptor`
        """
        return security.SecurityDescriptor.from_service(self.name)

    def start(self, args=None):
        """Start the service

        :param args: a list of :class:`str`
        """
        nbelt = 0
        if args is not None:
            if isinstance(args, windows.pycompat.anybuff):
                args = [args]
            nbelt = len(args)
            args = (gdef.LPWSTR * (nbelt))(*args)
        return windows.winproxy.StartServiceW(self, nbelt, args)

    def stop(self):
        """Stop the service"""
        status = SERVICE_STATUS()
        windows.winproxy.ControlService(self, gdef.SERVICE_CONTROL_STOP, status)
        return status

    def __repr__(self):
        return """<{0} "{1}" {2!r}>""".format(type(self).__name__, self.name, self.status.state)

    def __del__(self):
        return windows.winproxy.CloseServiceHandle(self)
