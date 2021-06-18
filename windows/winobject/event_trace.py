import ctypes
import windows
import windows.generated_def as gdef
from windows.pycompat import basestring

# Renommer le fichier etw ?

MAX_ETW_SESSIONS  = 64
MAX_SESSION_NAME_LEN = 1024
MAX_LOGFILE_PATH_LEN  = 1024

MAX_SESSION_NAME_LEN_W = MAX_SESSION_NAME_LEN * 2
MAX_LOGFILE_PATH_LEN_W = MAX_LOGFILE_PATH_LEN * 2


class EventRecord(gdef.EVENT_RECORD):
    @property
    def tid(self):
        """Thread ID that provided the event"""
        return self.EventHeader.ThreadId

    @property
    def pid(self):
        """Process ID that provided the event"""
        return self.EventHeader.ProcessId

    @property
    def guid(self):
        """Guid of the Event"""
        # Well, this is called "ProviderId" but seems to be the Event GUID
        # As a provider can generated multiple event with differents GUID
        # And this value reflect EVENT_TRACE_HEADER.Guid passed to TraceEvent
        return self.EventHeader.ProviderId

    @property
    def id(self):
        """ID of the Event"""
        return self.EventHeader.EventDescriptor.Id

    @property
    def opcode(self):
        return self.EventHeader.EventDescriptor.Opcode

    @property
    def version(self):
        return self.EventHeader.EventDescriptor.Version

    @property
    def level(self):
        return self.EventHeader.EventDescriptor.Level

    @property
    def context(self):
        if self.UserContext is None:
            return None
        return ctypes.py_object.from_address(self.UserContext).value

    @property
    def user_data(self):
        """Event specific data

        :type: :class:`str`
        """
        if not (self.UserData and self.UserDataLength):
            return ""
        dbuf = (ctypes.c_char * self.UserDataLength).from_address(self.UserData)
        return dbuf[:]

    # def match(self, provider=None, id=None, opcode=None):

    def __repr__(self):
        guid = self.EventHeader.ProviderId
        return """<{0} provider="{1}" id={2}>""".format(type(self).__name__, guid, self.id)


PEventRecord = ctypes.POINTER(EventRecord)

class EventTraceProperties(gdef.EVENT_TRACE_PROPERTIES):
    """Represent an Event Trace session that may exist or now. (https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)

    This class is widly used by :class:`EtwTrace`
    """
    # Test: ascii / Use Wchar ?
    FULL_SIZE = ctypes.sizeof(gdef.EVENT_TRACE_PROPERTIES) + MAX_SESSION_NAME_LEN_W + MAX_LOGFILE_PATH_LEN_W

    # def alloc(cls, size) ?
    @classmethod
    def create(cls):
        """Initialize a new :class:`EventTraceProperties`"""
        buff = windows.utils.BUFFER(cls)(size=cls.FULL_SIZE)
        # ctypes.memset(buff, "\x00", cls.FULL_SIZE)
        self = buff[0]
        self.Wnode.BufferSize = cls.FULL_SIZE
        self.LoggerNameOffset = ctypes.sizeof(cls)
        self.LogFileNameOffset = ctypes.sizeof(cls) + MAX_SESSION_NAME_LEN
        return self

    def get_logfilename(self):
        assert self.LogFileNameOffset
        return windows.current_process.read_string(ctypes.addressof(self) + self.LogFileNameOffset)

    def set_logfilename(self, filename):
        assert self.LogFileNameOffset
        if not filename.endswith("\x00"):
            filename += "\x00"
        return windows.current_process.write_memory(ctypes.addressof(self) + self.LogFileNameOffset, filename)

    logfile = property(get_logfilename, set_logfilename) #: The logfile associated with the session

    def get_logger_name(self):
        assert self.LoggerNameOffset
        return windows.current_process.read_string(ctypes.addressof(self) + self.LoggerNameOffset)


    def set_logfilename(self, filename):
        assert self.LoggerNameOffset
        if not filename.endswith("\x00"):
            filename += "\x00"
        return windows.current_process.write_memory(ctypes.addressof(self) + self.LoggerNameOffset, filename)

    name = property(get_logger_name, set_logfilename) #: The name of the session

    @property
    def guid(self):
        """The GUID of the Event Trace session (see ``Wnode.Guid``)"""
        return self.Wnode.Guid

    @property
    def id(self):
        """The LoggerId if the session (see ``Wnode.HistoricalContext``)"""
        return self.Wnode.HistoricalContext


    def __repr__(self):
        return """<{0} name="{1}" guid={2}>""".format(type(self).__name__, self.name, self.guid)


    # GUID setter ?

class CtxProcess(object):
    def __init__(self, trace, func, stop=False):
        self.trace = trace
        self.func = func
        self.stop = stop
        self.timing = {}

    def _get_time(self):
        now = gdef.FILETIME()
        windows.winproxy.GetSystemTimeAsFileTime(now)
        return now

    def __enter__(self):
        self.timing["begin"] = self._get_time()
        return self.timing

    def __exit__(self, exc_type, exc_value, traceback):
        # bad_end = self._get_time()
        self.trace.flush()
        if self.stop:
            self.trace.stop()
        # End time after the flush is effective.
        self.timing["end"] = self._get_time()
        # print("Trace ctx: fake-end: {0:#x}".format(int(fake_end)))
        print("Trace ctx: begin={0:#x} | end={1:#x}".format(int(self.timing["begin"]), int(self.timing["end"])))
        self.trace.process(self.func, **self.timing)


class EtwTrace(object):
    """Represent an ETW Trace for tracing/processing events"""
    def __init__(self, name, logfile=None, guid=None):
        self.name = windows.pycompat.raw_encode(name) #: The name of the trace
        self.logfile = logfile #: The logging file of the trace (``None`` means real time trace)
        if guid and isinstance(guid, basestring):
            guid = gdef.GUID.from_string(guid)
        self.guid = guid #: The guid of the trace
        self.handle = 0

    def exists(self):
        """Return ``True`` if the trace already exist (based on its name)"""
        prop = EventTraceProperties.create()
        try:
            windows.winproxy.ControlTraceA(self.handle, self.name, prop, gdef.EVENT_TRACE_CONTROL_QUERY)
        except WindowsError as e:
            if e.winerror == gdef.ERROR_WMI_INSTANCE_NOT_FOUND:
                return False # Not found -> does not exists
            raise # Other error -> reraise
        return True

    def start(self, flags=0, mode=0):
        """Start the tracing"""
        prop = EventTraceProperties.create()
        prop.NumberOfBuffers = 42
        prop.EnableFlags = flags
        prop.LogFileMode = mode
        if self.guid:
            prop.Wnode.Guid = self.guid
        if self.logfile:
            prop.logfile = self.logfile
        if self.name: # Base REAL_TIME on option ? name presence ? logfile presence ?
            prop.LogFileMode |= gdef.EVENT_TRACE_REAL_TIME_MODE
        handle = gdef.TRACEHANDLE()
        windows.winproxy.StartTraceA(handle, self.name, prop)
        if not self.guid:
            self.guid = prop.Wnode.Guid
        self.handle = handle

    def stop(self, soft=False): # Change name
        """stop the tracing.

        ``soft`` will allow to stop a non-existing trace that do not exists/run.
        This allow for simpler script that stop/start some EtwTrace.
        """
        prop = EventTraceProperties.create()
        try:
            windows.winproxy.ControlTraceA(0, self.name, prop, gdef.EVENT_TRACE_CONTROL_STOP)
        except WindowsError as e:
            if soft and e.winerror == gdef.ERROR_WMI_INSTANCE_NOT_FOUND:
                return False
            raise
        return True

    def flush(self):
        """Flush the trace"""
        prop = EventTraceProperties.create()
        windows.winproxy.ControlTraceA(0, self.name, prop, gdef.EVENT_TRACE_CONTROL_FLUSH)


    def enable(self, guid, flags=0xff, level=0xff):
        """Enable the specified event trace provider."""
        if isinstance(guid, basestring):
            guid = gdef.GUID.from_string(guid)
        return windows.winproxy.EnableTrace(1, flags, level, guid, self.handle) # EnableTraceEx ?

    def enable_ex(self, guid, flags=0xff, level=0xff, any_keyword = 0xffffffff, all_keyword=0x00):
        """Enable the specified event trace provider."""
        if isinstance(guid, basestring):
            guid = gdef.GUID.from_string(guid)

        # TODO : implement EnableParameters
        EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1

        # EnableTraceEx only accept a UCHAR for the level param
        # TODO : maybe raise an Exception instead of silently masking the value ?
        level = gdef.UCHAR(chr(level & 0xff))

        return windows.winproxy.EnableTraceEx2(self.handle, guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, level , any_keyword, all_keyword, 0, None)


    def process(self, callback, begin=None, end=None, context=None):
        """Process the event retrieved by the trace.
        This function will call ``callback`` with any :class:`EventRecord` in the trace.
        ``begin/end`` allow to filter and only process events in a given timeframe.

        .. warning::

            If the trace if ``REALTIME`` (no logfile) this function will hang/process new event until the trace is stopped.

            Using ``logman -ets stop TRACE_NAME`` for exemple.

        """
        if end == "now":
            end = gdef.FILETIME()
            windows.winproxy.GetSystemTimeAsFileTime(end)
            windows.utils.sprint(end)

        logfile = gdef.EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = windows.pycompat.raw_decode(self.name)
        # logfile.ProcessTraceMode = gdef.PROCESS_TRACE_MODE_EVENT_RECORD | gdef.PROCESS_TRACE_MODE_RAW_TIMESTAMP
        logfile.ProcessTraceMode = gdef.PROCESS_TRACE_MODE_EVENT_RECORD
        if not self.logfile:
            logfile.ProcessTraceMode |= gdef.PROCESS_TRACE_MODE_REAL_TIME
        else:
            # logfile.ProcessTraceMode |= gdef.PROCESS_TRACE_MODE_REAL_TIME
            logfile.LogFileName = self.logfile

        if context:
            context_ptr = ctypes.pointer(ctypes.py_object(context))
            logfile.Context = ctypes.cast(context_ptr, ctypes.c_void_p)

        @ctypes.WINFUNCTYPE(gdef.PVOID, PEventRecord)
        def real_callback(record_ptr):
            try:
                x = callback(record_ptr[0])
            except Exception as e:
                print("CALLBACK ERROR: {0}".format(e))
                return 1
            if x is None:
                x = 1
            return x

        @ctypes.WINFUNCTYPE(gdef.PVOID, gdef.PEVENT_TRACE_LOGFILEW)
        def buffer_callback(trace):
            print("Buffer-callback: event-lost={0}".format(trace[0].LogfileHeader.EventsLost))
            print("Buffer-callback: buffer-lost={0}".format(trace[0].LogfileHeader.BuffersLost))
            return True

        logfile.EventRecordCallback  = ctypes.cast(real_callback, gdef.PVOID)
        # logfile.BufferCallback  = ctypes.cast(buffer_callback, gdef.PVOID)
        r = windows.winproxy.OpenTraceW(logfile)
        rh = gdef.TRACEHANDLE(r)
        return windows.winproxy.ProcessTrace(rh, 1, begin, end)

    def CtxProcess(self, func, stop=False):
        return CtxProcess(self, func, stop=stop)

    def __repr__(self):
        return """<{0} name={1!r} logfile={2!r}>""".format(type(self).__name__, self.name, self.logfile)

class TraceProvider(object):
    """Represent a ETW provider, which is just a GUID.
    Corresponding name for a provider may be available trhought WMI.
    """
    def __init__(self, guid):
        self.guid = guid

    @property
    def infos(self):
        """The :class:`TraceGuidInfo` associated with the provider.
        Main use is to retrieve the instances of the provider (directly available with ``instances``)

        :type: :class:`TraceGuidInfo`
        """
        size = gdef.DWORD()
        info_buffer = ctypes.c_buffer(0x1000)
        try:
            windows.winproxy.EnumerateTraceGuidsEx(gdef.TraceGuidQueryInfo, self.guid, ctypes.sizeof(self.guid), info_buffer, ctypes.sizeof(info_buffer), size)
        except WindowsError as e:
            if not e.winerror == gdef.ERROR_INSUFFICIENT_BUFFER:
                raise
            # Buffer to small
            info_buffer = ctypes.c_buffer(size.value)
            windows.winproxy.EnumerateTraceGuidsEx(gdef.TraceGuidQueryInfo, self.guid, ctypes.sizeof(self.guid), info_buffer, ctypes.sizeof(info_buffer), size)
        return TraceGuidInfo.from_raw_buffer(info_buffer)

    # We dont really care about the C struct layout
    # Our trace providers should be able to directly returns its instances
    @property
    def instances(self):
        """The instances of the provider.

        :type: [:class:`TraceProviderInstanceInfo`] -- A list of :class:`TraceProviderInstanceInfo`
        """
        return self.infos.instances

    def __repr__(self):
        return """<{0} for "{1}">""".format(type(self).__name__, self.guid)


class TraceGuidInfo(gdef.TRACE_GUID_INFO):
    """Defines the header to the list of sessions that enabled the provider
    (see https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_guid_info)
    """

    @classmethod
    def from_raw_buffer(cls, buffer):
        self = cls.from_buffer(buffer)
        self._raw_buffer_ = buffer
        return self

    def _instance_generator(self):
        if not self.InstanceCount:
            return
        abs_offset = ctypes.sizeof(self)
        for i in range(self.InstanceCount):
            instance = TraceProviderInstanceInfo.from_raw_buffer(self._raw_buffer_, abs_offset)
            abs_offset += instance.NextOffset
            yield instance

    @property
    def instances(self):
        """The instances of the provider.

        :type: [:class:`TraceProviderInstanceInfo`] -- A list of :class:`TraceProviderInstanceInfo`
        """
        return [x for x in self._instance_generator()]

    def __repr__(self):
        return "<{0} InstanceCount={1} Reserved={2}>".format(type(self).__name__, self.InstanceCount, self.Reserved)


class TraceProviderInstanceInfo(gdef.TRACE_PROVIDER_INSTANCE_INFO):
    """Defines an instance of the provider
    (see https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_provider_instance_info)
    """
    @classmethod
    def from_raw_buffer(cls, buffer, offset):
        self = cls.from_buffer(buffer, offset)
        self._offset = offset
        self._raw_buffer_ = buffer
        return self

    def _instance_generator(self):
        offset = self._offset + ctypes.sizeof(self)
        entry_size = ctypes.sizeof(gdef.TRACE_ENABLE_INFO)
        for i in range(self.EnableCount):
            yield gdef.TRACE_ENABLE_INFO.from_buffer(self._raw_buffer_, offset)
            offset += entry_size

    @property
    def sessions(self):
        """The sessions for the instance

        :type: [:class:`~windows.generated_def.winstructs.TRACE_ENABLE_INFO`] -- A list of session
        """
        return [x for x in self._instance_generator()]

    def __repr__(self):
        return "<{0} Pid={1} EnableCount={2}>".format(type(self).__name__, self.Pid, self.EnableCount)


class EtwManager(object):
    """An object to query ETW session/providers and open new trace"""

    @property
    def sessions(self):
        """The list of currently active ETW session.

        :type: [:class:`EventTraceProperties`] -- A list of :class:`EventTraceProperties`
        """
        # Create a tuple of MAX_ETW_SESSIONS EventTraceProperties ptr
        t = [EventTraceProperties.create() for _ in range(MAX_ETW_SESSIONS)]
        # Put this in a ctypes array
        array = (gdef.POINTER(EventTraceProperties) * MAX_ETW_SESSIONS)(*(ctypes.pointer(e) for e in t))
        # Cast as array/ptr does not handle subtypes very-well
        tarray = ctypes.cast(array, ctypes.POINTER(ctypes.POINTER(gdef.EVENT_TRACE_PROPERTIES)))
        count = gdef.DWORD()
        windows.winproxy.QueryAllTracesA(tarray, MAX_ETW_SESSIONS, count)
        return t[:count.value]


    @property
    def providers(self):
        """The list of currently existing ETW providers.

        :type: [:class:`TraceProvider`] -- A list of ETW providers
        """
        buffer = windows.utils.BUFFER(gdef.GUID, 0x1000)()
        size = gdef.DWORD()
        windows.winproxy.EnumerateTraceGuidsEx(gdef.TraceGuidQueryList, None, 0, buffer, buffer.real_size, size)
        return [TraceProvider(g) for g in buffer[:size.value // ctypes.sizeof(gdef.GUID)]]


    # Temp name / API ?
    def open_trace(self, name=None, logfile=None, guid=None):
        """Open a new ETW Trace

        :return: :class:`EtwTrace`
        """
        return EtwTrace(name, logfile, guid)