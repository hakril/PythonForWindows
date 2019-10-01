import ctypes
import windows
import windows.generated_def as gdef

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
        guid = self.EventHeader.ProviderId.to_string()
        return """<{0} provider="{1}" id={2}>""".format(type(self).__name__, guid, self.id)


PEventRecord = ctypes.POINTER(EventRecord)

class EventTraceProperties(gdef.EVENT_TRACE_PROPERTIES):
    # Test: ascii / Use Wchar ?
    FULL_SIZE = ctypes.sizeof(gdef.EVENT_TRACE_PROPERTIES) + MAX_SESSION_NAME_LEN_W + MAX_LOGFILE_PATH_LEN_W

    # def alloc(cls, size) ?
    @classmethod
    def create(cls):
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

    logfile = property(get_logfilename, set_logfilename)

    def get_logger_name(self):
        assert self.LoggerNameOffset
        return windows.current_process.read_string(ctypes.addressof(self) + self.LoggerNameOffset)


    def set_logfilename(self, filename):
        assert self.LoggerNameOffset
        if not filename.endswith("\x00"):
            filename += "\x00"
        return windows.current_process.write_memory(ctypes.addressof(self) + self.LoggerNameOffset, filename)

    name = property(get_logger_name, set_logfilename)

    @property
    def guid(self):
        return self.Wnode.Guid

    @property
    def id(self):
        """LoggerId"""
        return self.Wnode.HistoricalContext

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
    def __init__(self, name, logfile=None, guid=None):
        self.name = name
        self.logfile = logfile
        if guid and isinstance(guid, basestring):
            guid = gdef.GUID.from_string(guid)
        self.guid = guid
        self.handle = 0

    def exists(self):
        prop = EventTraceProperties.create()
        try:
            windows.winproxy.ControlTraceA(self.handle, self.name, prop, gdef.EVENT_TRACE_CONTROL_QUERY)
        except WindowsError as e:
            if e.winerror == gdef.ERROR_WMI_INSTANCE_NOT_FOUND:
                return False # Not found -> does not exists
            raise # Other error -> reraise
        return True

    def start(self, flags=0):
        prop = EventTraceProperties.create()
        prop.NumberOfBuffers = 42
        prop.EnableFlags = flags
        if self.guid:
            prop.Wnode.Guid = self.guid
        if self.logfile:
            prop.logfile = self.logfile
        if self.name: # Base REAL_TIME on option ? name presence ? logfile presence ?
            prop.LogFileMode = gdef.EVENT_TRACE_REAL_TIME_MODE
        handle = gdef.TRACEHANDLE()
        windows.winproxy.StartTraceA(handle, self.name, prop)
        if not self.guid:
            self.guid = prop.Wnode.Guid
        self.handle = handle

    def stop(self, soft=False): # Change name
        prop = EventTraceProperties.create()
        try:
            windows.winproxy.ControlTraceA(0, self.name, prop, gdef.EVENT_TRACE_CONTROL_STOP)
        except WindowsError as e:
            if soft and e.winerror == gdef.ERROR_WMI_INSTANCE_NOT_FOUND:
                return False
            raise
        return True

    def flush(self):
        prop = EventTraceProperties.create()
        windows.winproxy.ControlTraceA(0, self.name, prop, gdef.EVENT_TRACE_CONTROL_FLUSH)


    def enable(self, guid, flags=0xff, level=0xff):
        if isinstance(guid, basestring):
            guid = gdef.GUID.from_string(guid)
        return windows.winproxy.EnableTrace(1, flags, level, guid, self.handle) # EnableTraceEx ?

    def enable_ex(self, guid, flags=0xff, level=0xff, any_keyword = 0xffffffff, all_keyword=0x00):
        if isinstance(guid, basestring):
            guid = gdef.GUID.from_string(guid)

        # TODO : implement EnableParameters
        EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1

        # EnableTraceEx only accept a UCHAR for the level param
        # TODO : maybe raise an Exception instead of silently masking the value ?
        level = gdef.UCHAR(chr(level & 0xff))

        return windows.winproxy.EnableTraceEx2(self.handle, guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, level , any_keyword, all_keyword, 0, None) 


    def process(self, callback, begin=None, end=None):
        if end == "now":
            end = gdef.FILETIME()
            windows.winproxy.GetSystemTimeAsFileTime(end)
            windows.utils.sprint(end)

        logfile = gdef.EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = self.name
        # logfile.ProcessTraceMode = gdef.PROCESS_TRACE_MODE_EVENT_RECORD | gdef.PROCESS_TRACE_MODE_RAW_TIMESTAMP
        logfile.ProcessTraceMode = gdef.PROCESS_TRACE_MODE_EVENT_RECORD
        if not self.logfile:
            logfile.ProcessTraceMode |= gdef.PROCESS_TRACE_MODE_REAL_TIME
        else:
            # logfile.ProcessTraceMode |= gdef.PROCESS_TRACE_MODE_REAL_TIME
            logfile.LogFileName = self.logfile

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
    def __init__(self, guid):
        self.guid = guid

    @property
    def infos(self):
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
        return self.infos.instances

    def __repr__(self):
        return """<{0} for "{1}">""".format(type(self).__name__, self.guid.to_string())


class TraceGuidInfo(gdef.TRACE_GUID_INFO):
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
        return [x for x in self._instance_generator()]

    def __repr__(self):
        return "<{0} InstanceCount={1} Reserved={2}>".format(type(self).__name__, self.InstanceCount, self.Reserved)


class TraceProviderInstanceInfo(gdef.TRACE_PROVIDER_INSTANCE_INFO):
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
        return [x for x in self._instance_generator()]

    def __repr__(self):
        return "<{0} Pid={1} EnableCount={2}>".format(type(self).__name__, self.Pid, self.EnableCount)


class EtwManager(object):
    @property
    def sessions(self):
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
        buffer = windows.utils.BUFFER(gdef.GUID, 0x1000)()
        size = gdef.DWORD()
        windows.winproxy.EnumerateTraceGuidsEx(gdef.TraceGuidQueryList, None, 0, buffer, buffer.real_size, size)
        return [TraceProvider(g) for g in buffer[:size.value / ctypes.sizeof(gdef.GUID)]]


    # Temp name / API ?
    def open_trace(self, name=None, logfile=None, guid=None):
        return EtwTrace(name, logfile, guid)