import ctypes
import os.path
import xml.dom.minidom
from contextlib import contextmanager

import windows
import windows.generated_def as gdef
from windows import winproxy
from windows.pycompat import int_types, basestring


# Helpers


@contextmanager
def ClosingEvtHandle(handle):
    try:
        yield handle
    finally:
        winproxy.EvtClose(handle)


# low-level api helpers
def queryinfo(handle, propertyid):
    size = 0x1000
    buffer = ctypes.create_string_buffer(size)
    evt = ImprovedEVT_VARIANT.from_buffer(buffer)
    res = gdef.DWORD()
    windows.winproxy.EvtGetLogInfo(handle, propertyid, size, evt, res)
    return evt

def arrayproperty(handle, property, index, flags=0):
    size = 0x1000
    buffer = ctypes.create_string_buffer(size)
    evt = ImprovedEVT_VARIANT.from_buffer(buffer)
    res = gdef.DWORD()
    windows.winproxy.EvtGetObjectArrayProperty(handle, property, index, flags, size, evt, res)
    return evt

def generate_query_function(query_function):
    def generated_query_function(handle, propertyid, flags=0):
        size = 0x10000
        buffer = ctypes.create_string_buffer(size)
        evt = ImprovedEVT_VARIANT.from_buffer(buffer)
        res = gdef.DWORD()
        query_function(handle, propertyid, flags, size, evt, res)
        return evt
    return generated_query_function

chaninfo = generate_query_function(winproxy.EvtGetChannelConfigProperty)
eventinfo = generate_query_function(winproxy.EvtGetEventMetadataProperty)
publishinfo = generate_query_function(winproxy.EvtGetPublisherMetadataProperty)


class EvtHandle(gdef.EVT_HANDLE):
    # Class attribute function
    # Will pass (self) as first parameter (binding)
    # No need to pass any param to close ourself :)
    _close_function = windows.winproxy.EvtClose

    def __del__(self):
        if not bool(self):
            return
        self._close_function()

# Class high-level API
class EvtQuery(EvtHandle):
    """Represent an Event-log query"""
    DEFAULT_TIMEOUT = 0x1000

    def __init__(self, handle=0, channel=None, timeout=None):
        super(EvtQuery, self).__init__(handle)
        self.channel = channel
        self.timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT

    def __next__(self):
        """Return the next :class:`EvtEvent` matching the query"""
        try:
            event = EvtEvent(channel=self.channel)
            ret = gdef.DWORD()
            windows.winproxy.EvtNext(self, 1, event, self.timeout, 0, ret)
        except WindowsError as e:
            if e.winerror == gdef.ERROR_NO_MORE_ITEMS:
                raise StopIteration
            raise
        assert ret.value == 1
        return event

    def __iter__(self):
        return self

    def seek(self, position, seek_flags=None):
        """Seek to ``position``.
        ``seek_flags`` can be one of:

            * ``None``
            * ``EvtSeekRelativeToFirst``
            * ``EvtSeekRelativeToLast``
            * ``EvtSeekRelativeToBookmark``

        If ``seek_flags`` is None:

            * ``position >= 0`` will use ``EvtSeekRelativeToFirst``
            * ``position < 0`` will use ``EvtSeekRelativeToLast`` and with ``position+1``
                * This allow retrieve the ``position`` lasts events
        """

        if seek_flags is None:
            if position >= 0:
                seek_flags = gdef.EvtSeekRelativeToFirst
            else:
                # -1 + EvtSeekRelativeToLast will give us the last 2 events
                # So passing (-1, None) will give us the last event only
                # If user do not want this calcul it can directly pass seek_flags
                seek_flags = gdef.EvtSeekRelativeToLast
                position += 1
        windows.winproxy.EvtSeek(self, position, 0, 0, seek_flags)

    next = __next__ # Yep.. real name is 'next' in Py2 :D

    def all(self): # SqlAlchemy like :)
        """Return a list with all the query results

        :rtype: [:class:`EvtEvent`] -- A list of Event
        """
        return list(self)

    def first(self): # SqlAlchemy like :) -> allow testing in interactive console
        """Return the first query result

        :rtype: :class:`EvtEvent` -- An Event
        """
        return next(iter(self))




class EvtEvent(EvtHandle):
    """An Event log"""
    def __init__(self, handle=0, channel=None):
        super(EvtEvent, self).__init__(handle)
        self.channel = channel

    def render(self, ctx, rtype):
        size = 0x10000
        buffer = ctypes.c_buffer(size)
        rsize = gdef.DWORD()
        elementnb = gdef.DWORD()
        try:
            windows.winproxy.EvtRender(ctx, self, rtype, size, buffer, rsize, elementnb)
        except WindowsError as e:
            if e.winerror != gdef.ERROR_INSUFFICIENT_BUFFER:
                raise
            size = rsize.value
            buffer = ctypes.c_buffer(size)
            windows.winproxy.EvtRender(ctx, self, rtype, size, buffer, rsize, elementnb)
        # Adapting return value type
        if rtype != gdef.EvtRenderEventValues:
            # import pdb;pdb.set_trace()
            # assert elementnb.value == 1
            return buffer[:rsize.value]
        # print("Got <{0}> elt".format(elementnb.value))
        return list((ImprovedEVT_VARIANT * elementnb.value).from_buffer(buffer))

    def render_xml(self):
        xml = self.render(None, 1).decode("utf-16")
        assert xml[-1] == "\x00"
        return xml[:-1]

    def value(self, name, **kwargs):
        """Retrieve a value from the event.
        ``name`` is an XPath expressions that uniquely identify a node or attribute in the event.
        (see https://msdn.microsoft.com/en-us/library/windows/desktop/aa385352(v=vs.85).aspx)
        """
        values = self.get_values((name,), **kwargs)
        assert len(values) == 1
        return values[0]

    def get_values(self, values, flags=gdef.EvtRenderContextValues):
        nbelt = len(values)
        pwstr_values = tuple(gdef.LPWSTR(v) for v in values)
        pwstr_rarray = (gdef.LPWSTR * nbelt)(*pwstr_values)
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa385352(v=vs.85).aspx
        # An array of XPath expressions that uniquely identify a node or attribute in the event that you want to render.
        # Each value wil return 1 node :)
        ctx = windows.winproxy.EvtCreateRenderContext(nbelt, pwstr_rarray, gdef.EvtRenderContextValues)
        result = self.render(ctx, gdef.EvtRenderEventValues)
        windows.winproxy.EvtClose(ctx)
        return [r.value for r in result]

    def system_values(self): # POC: use this for all @property based on system data ?
        ctx = windows.winproxy.EvtCreateRenderContext(0, None, gdef.EvtRenderContextSystem)
        result = self.render(ctx, gdef.EvtRenderEventValues)
        windows.winproxy.EvtClose(ctx)
        return [r.value for r in result]

    def event_values(self):
        """The values of the event in a list"""
        ctx = windows.winproxy.EvtCreateRenderContext(0, None, gdef.EvtRenderContextUser)
        result = self.render(ctx, gdef.EvtRenderEventValues)
        windows.winproxy.EvtClose(ctx)
        return [r.value for r in result]

    def get_raw_values(self, values, flags=gdef.EvtRenderContextValues):
        nbelt = len(values)
        pwstr_values = tuple(gdef.LPWSTR(v) for v in values)
        pwstr_rarray = (gdef.LPWSTR * nbelt)(*pwstr_values)
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa385352(v=vs.85).aspx
        # An array of XPath expressions that uniquely identify a node or attribute in the event that you want to render.
        # Each value will return 1 node :)
        ctx = windows.winproxy.EvtCreateRenderContext(nbelt, pwstr_rarray, gdef.EvtRenderContextValues)
        result = self.render(ctx, gdef.EvtRenderEventValues)
        windows.winproxy.EvtClose(ctx)
        return list(result)


    # Properties arround common Event/System values
    @property
    def provider(self):
        """The provider of the event"""
        return self.system_values()[gdef.EvtSystemProviderName]

    @property
    def computer(self):
        """The computer that generated the event"""
        return self.system_values()[gdef.EvtSystemComputer]

    @property
    def id(self):
        """The ID of the Event"""
        return self.value("Event/System/EventID")

    @property
    def version(self):
        """The version of the Event"""
        return self.value("Event/System/Version")

    @property
    def level(self):
        """The level of the Event"""
        return self.value("Event/System/Level")

    @property
    def opcode(self):
        """The opcode of the Event"""
        return self.value("Event/System/Opcode")

    @property
    def time_created(self):
        """The creation time of the Event"""
        return self.value("Event/System/TimeCreated/@SystemTime")

    @property
    def pid(self):
        """The process ID of the Event"""
        return self.value("Event/System/Execution/@ProcessID")

    @property
    def tid(self):
        """The process ID of the Event"""
        return self.value("Event/System/Execution/@ThreadID")

    @property
    def error_payload(self):
        raw = self.value("Event/ProcessingErrorData/EventPayload")
        return bytearray(raw) if raw is not None else None

    @property
    def user(self):
        """The User ID associated with the Event"""
        return self.system_values()[gdef.EvtSystemUserID]

    @property
    def metadata(self):
        """The medata for the current Event

        :type: :class:`EventMetadata`
        """
        try:
            return self.channel.get_event_metadata(self.id)
        except KeyError as e:
            if not self.channel.config.classic:
                raise
        # id not found: try via the Provider in the event (classic channel)
        return self.channel.get_classic_event_metadata(self.id, self.provider)

    # Test
    @property
    def data(self): # user/event specifique data
        """A dict of EventData Name:Value for the current dict.

        :type: :class:`dict`
        """
        # What about classic channels where there is no event_metadata ?
        # Return a dict with [0-1-2-3-4] as key ? raise ?
        # Juste use the render_xml ?
        event_data_name = (i["name"] for i in self.metadata.event_data if i["type"] == "data")
        return {k:v for k,v in zip(event_data_name, self.event_values())}

    def xml_data(self):
        xmlevt = xml.dom.minidom.parseString(self.render_xml())
        res = {}

        eventdata = xmlevt.getElementsByTagName("EventData")
        if eventdata:
            # <Data Name='FIELD_NAME'>FIELD_VALUE</Data>
            for i, datanode in enumerate(xmlevt.getElementsByTagName("Data")):
                name = datanode.getAttribute("Name")
                if not name:
                    # Some Data in old EVTX have no name (Windows Powershell)
                    # Do the best we can by using the position of the event
                    name = str(i)

                if datanode.hasChildNodes():
                    value = datanode.firstChild.nodeValue
                else:
                    value = ""
                if not (name not in res):
                    import pdb;pdb.set_trace()
                res[name] = value
        userdata = xmlevt.getElementsByTagName("UserData")
        if userdata:
            # <UserData>
            #     <EventXML xmlns="Event_NS">
            #         <FIELD_NAME>FIELD_VALUE</FIELD_NAME>
            #     </EventXML>
            # </UserData>
            for datanode in userdata[0].firstChild.childNodes:
                name = datanode.tagName
                if datanode.hasChildNodes():
                    value = datanode.firstChild.nodeValue
                else:
                    value = ""
                assert name not in res
                res[name] = value
        return res


    @property
    def date(self):
        """``Event.time_created`` as a :class:``datetime``"""
        return windows.utils.datetime_from_filetime(self.time_created)

    def __repr__(self):
        creation_time = windows.utils.datetime_from_filetime(self.time_created)
        return '<{0} id="{self.id}" time="{creation_time}">'.format(type(self).__name__, self=self, creation_time=creation_time)


class ImprovedEVT_VARIANT(gdef.EVT_VARIANT):
    VALUE_MAPPER = {
        gdef.EvtVarTypeNull       : 'NoneValue',
        gdef.EvtVarTypeString     : 'StringVal',
        gdef.EvtVarTypeAnsiString : 'AnsiStringVal',
        gdef.EvtVarTypeSByte      : 'SByteVal',
        gdef.EvtVarTypeByte       : 'ByteVal',
        gdef.EvtVarTypeInt16      : 'Int16Val',
        gdef.EvtVarTypeUInt16     : 'UInt16Val',
        gdef.EvtVarTypeInt32      : 'Int32Val',
        gdef.EvtVarTypeUInt32     : 'UInt32Val',
        gdef.EvtVarTypeInt64      : 'Int64Val',
        gdef.EvtVarTypeUInt64     : 'UInt64Val',
        gdef.EvtVarTypeSingle     : 'SingleVal',
        gdef.EvtVarTypeDouble     : 'DoubleVal',
        gdef.EvtVarTypeBoolean    : 'BooleanVal',
        gdef.EvtVarTypeBinary     : 'BinaryVal',
        gdef.EvtVarTypeGuid       : 'GuidVal',
        gdef.EvtVarTypeSizeT      : 'SizeTVal',
        gdef.EvtVarTypeFileTime   : 'FileTimeVal',
        gdef.EvtVarTypeSysTime    : 'SysTimeVal',
        gdef.EvtVarTypeSid        : 'SidVal',
        gdef.EvtVarTypeHexInt32   : 'UInt32Val',
        gdef.EvtVarTypeHexInt64   : 'UInt64Val',
        gdef.EvtVarTypeEvtHandle  : 'EvtHandleVal',
        gdef.EvtVarTypeEvtXml     : 'XmlVal',
        # Array types: TODO: generic stuff
        gdef.EvtVarTypeString + gdef.EVT_VARIANT_TYPE_ARRAY : "StringArr",
        gdef.EvtVarTypeUInt16 + gdef.EVT_VARIANT_TYPE_ARRAY : "UInt16Arr",
        gdef.EvtVarTypeUInt32 + gdef.EVT_VARIANT_TYPE_ARRAY : "UInt32Arr",
        gdef.EvtVarTypeUInt64 + gdef.EVT_VARIANT_TYPE_ARRAY : "UInt64Arr",
    }
    NoneValue = None

    @property
    def Type(self):
        raw_type = super(ImprovedEVT_VARIANT, self).Type
        return gdef.EVT_VARIANT_TYPE.mapper.get(raw_type, raw_type)

    @property
    def value(self): # Prototype !!
        attrname = self.VALUE_MAPPER[self.Type]
        # print("Resolve type <{0}> -> {1}".format(self.Type, attrname))
        v =  getattr(self, attrname)
        if self.Type == gdef.EvtVarTypeBinary:
            v = v[:self.Count] # No need for a raw UBYTE ptr
        elif self.Type == gdef.EvtVarTypeGuid:
            v = v[0] # Deref LP_GUID
        elif self.Type & gdef.EVT_VARIANT_TYPE_ARRAY:
            # TODO: handle all array type
            v = v[:self.Count]
        return v

    @classmethod
    def from_value(cls, value, vtype=None):
        if vtype is None:
            # Guess type
            if isinstance(value, int_types):
                vtype = gdef.EvtVarTypeUInt64
            elif isinstance(value, basestring):
                vtype = gdef.EvtVarTypeString
            elif isinstance(value, bytes):
                # not basestring and bytes -> py3 bytes
                vtype = gdef.EvtVarTypeBinary
                value = windows.utils.BUFFER(gdef.BYTE).from_buffer_copy(value)
            else:
                raise NotImplementedError("LATER")
        self = cls()
        # import pdb;pdb.set_trace()
        # Yolo test :)
        super(ImprovedEVT_VARIANT, ImprovedEVT_VARIANT).Type.__set__(self, vtype)
        # super(ImprovedEVT_VARIANT, self).Type = vtype
        attrname = self.VALUE_MAPPER[self.Type]
        setattr(self, attrname, value)
        if self.Type in (gdef.EvtVarTypeBinary, gdef.EvtVarTypeString):
            self.Count = len(value)
        return self

    def __repr__(self):
        return "<{0} of type={1}>".format(type(self).__name__, self.Type)



class EvtChannel(object):
    """An Event Log channel"""
    DEFAULT_QUERY_FLAGS = gdef.EvtQueryChannelPath + gdef.EvtQueryForwardDirection

    def __init__(self, name):
        self.name = name
        self.event_metadata_by_id = {}
        self.classic_event_metadata_by_id = {} # For classic only

    def query(self, filter=None, ids=None, timeout=None):
        """Query the event with the ``ids`` or perform a query with the raw query ``filter``

        Both parameters are mutually exclusive.

        .. note:: Here are some query examples

            List all events with a event data attribute named 'RuleName':
                ``Event/EventData/Data[@Name='RuleName']``

            List all events with a event data value of 'C:\\\\WINDOWS\\\\System32\\\\svchost.exe':
                ``Event/EventData[Data='C:\\WINDOWS\\System32\\svchost.exe']``

            List all events with an EventID of 2006:
                ``Event/System[EventID=2006]``

            List all event with a given EventID while searching for a specific field value (Sysmon for the test here)
                ``Event/System[EventID=3] and Event/EventData/Data[@Name='DestinationIp'] and Event/EventData[Data='10.0.0.2']``

        :rtype: :class:`EvtQuery`
        """
        if ids and filter:
            raise ValueError("<ids> and <filter> are mutually exclusive")
        if ids is not None:
            if isinstance(ids, int_types):
                ids = (ids,)
            ids_filter = " or ".join("EventID={0}".format(id) for id in ids)
            filter = "Event/System[{0}]".format(ids_filter)
        query_handle = winproxy.EvtQuery(None, self.name, filter, self.DEFAULT_QUERY_FLAGS)
        return EvtQuery(query_handle, self, timeout=timeout)

    @property
    def events(self):
        """The list of all events in the channels, an alias for ``channel.query().all()``

        :type: [:class:`EvtEvent`] -- A list of :class:`EvtEvent`
        """
        return self.query().all()

    @property
    def config(self):
        """The configuration of the channel

        :type: :class:`ChannelConfig`
        """
        return ChannelConfig.from_channel_name(self.name)

    def get_event_metadata(self, id):
        """Return the metadata for the event ID ``id``

        :rtype: :class:`EventMetadata`
        """
        try:
            return self.event_metadata_by_id[id]
        except KeyError as e:
            pass

        pub_metada = self.config.publisher.metadata
        self.event_metadata_by_id = {evtm.id: evtm for evtm in pub_metada.events_metadata}
        return self.event_metadata_by_id[id]

    def get_classic_event_metadata(self, id, providername):
        if providername not in self.classic_event_metadata_by_id:
            # print("CALCUL FOR PROVIDER: <{0}> !!!!!!!!!!!!!!".format(providername))
            publisher = EvtPublisher(providername)
            events_metadata = {x.id: x for x in publisher.metadata.events_metadata}
            self.classic_event_metadata_by_id[providername] = events_metadata
        return self.classic_event_metadata_by_id[providername][id]


    def __repr__(self):
        return '<{0} "{1}">'.format(type(self).__name__, self.name)


class EvtFile(EvtChannel):
    """Represent an Evtx file"""
    DEFAULT_QUERY_FLAGS = gdef.EvtQueryFilePath + gdef.EvtQueryForwardDirection

    @property
    def config(self):
        """Not implemented for EvtFile

        :raise: :class:`NotImplementedError`
        """
        raise NotImplementedError("Cannot retrieve the configuration of an EvtFile")


class ChannelConfig(EvtHandle):
    """The configuration of a event channel"""
    def __init__(self, handle, name=None):
        super(ChannelConfig, self).__init__(handle)
        self.name = name

    @classmethod
    def from_channel_name(cls, name):
        """Return the :class:`ChannelConfig` for the channel ``name``"""
        return cls(winproxy.EvtOpenChannelConfig(None, name, 0), name)

    @property
    def publisher(self):
        """The :class:`EvtPublisher` for the channel"""
        return EvtPublisher(chaninfo(self, gdef.EvtChannelConfigOwningPublisher).value)

    def publishers(self):
        "TEST"
        return [EvtPublisher(pub) for pub in chaninfo(self, gdef.EvtChannelPublisherList).value]

    @property
    def keywords(self):
        return int(chaninfo(self, gdef.EvtChannelPublishingConfigKeywords).value)

    @property
    def enabled(self):
        return bool(chaninfo(self, gdef.EvtChannelConfigEnabled).value)


    @property
    def classic(self):
        """``True`` if the channel is a classic event channel (for example the Application or System log)"""
        return bool(chaninfo(self, gdef.EvtChannelConfigClassicEventlog).value)

    def __repr__(self):
        return '<{0} "{1}">'.format(type(self).__name__, self.name)


class PublisherMetadataChannel(object):
    """Represent a PublisherMetadataChannel (see https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_publisher_metadata_property_id)"""

    def __init__(self, pub_metadata, channel_id):
        super(PublisherMetadataChannel, self).__init__()
        self.pub_metadata = pub_metadata
        self._id = channel_id

    def _query_channel_metadata_property(self, propertyid):
        return self.pub_metadata.chanrefs.property(propertyid, self._id)

    @property
    def flags(self):
        """The flags of the ``PublisherMetadataChannel``"""
        return int(self._query_channel_metadata_property(gdef.EvtPublisherMetadataChannelReferenceFlags))

    @property
    def name(self):
        """The name of the ``PublisherMetadataChannel``"""
        return str(self._query_channel_metadata_property(gdef.EvtPublisherMetadataChannelReferencePath))

    @property
    def id(self):
        """The reference id of the ``PublisherMetadataChannel``"""
        return int(self._query_channel_metadata_property(gdef.EvtPublisherMetadataChannelReferenceID))

    @property
    def index(self):
        """The reference index of the ``PublisherMetadataChannel``"""
        return int(self._query_channel_metadata_property(gdef.EvtPublisherMetadataChannelReferenceIndex))

    @property
    def message_id(self):
        """The message id of the ``PublisherMetadataChannel``"""
        return int(self._query_channel_metadata_property(gdef.EvtPublisherMetadataChannelReferenceMessageID))


class PublisherMetadataLevel(object):
    """Represent a PublisherMetadataLevel (see https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_publisher_metadata_property_id)"""
    def __init__(self, pub_metadata, channel_id):
        super(PublisherMetadataLevel, self).__init__()
        self.pub_metadata = pub_metadata
        self._id = channel_id

    def _query_level_metadata_property(self, propertyid):
        return self.pub_metadata.levelrefs.property(propertyid, self._id)

    @property
    def name(self):
        return str(self._query_level_metadata_property(gdef.EvtPublisherMetadataLevelName))

    @property
    def value(self):
        return int(self._query_level_metadata_property(gdef.EvtPublisherMetadataLevelValue))

    @property
    def message_id(self):
        return int(self._query_level_metadata_property(gdef.EvtPublisherMetadataLevelMessageID))


class PublisherMetadataOpcode(object):
    """Represent a PublisherMetadataOpcode (see https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_publisher_metadata_property_id)"""
    def __init__(self, pub_metadata, channel_id):
        super(PublisherMetadataOpcode, self).__init__()
        self.pub_metadata = pub_metadata
        self._id = channel_id

    def _query_opcode_metadata_property(self, propertyid):
        return self.pub_metadata.opcoderefs.property(propertyid, self._id)

    @property
    def name(self):
        """The name of the ``PublisherMetadataOpcode``"""
        return str(self._query_opcode_metadata_property(gdef.EvtPublisherMetadataOpcodeName))

    @property
    def value(self):
        """The opcode value of the ``PublisherMetadataOpcode``"""
        return int(self._query_opcode_metadata_property(gdef.EvtPublisherMetadataOpcodeValue))

    @property
    def message_id(self):
        """The message id of the ``PublisherMetadataOpcode``"""
        return int(self._query_opcode_metadata_property(gdef.EvtPublisherMetadataOpcodeMessageID))


class PublisherMetadataKeyword(object):
    """Represent a PublisherMetadataKeyword (see https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_publisher_metadata_property_id)"""

    def __init__(self, pub_metadata, channel_id):
        super(PublisherMetadataKeyword, self).__init__()
        self.pub_metadata = pub_metadata
        self._id = channel_id

    def _query_keyword_metadata_property(self, propertyid):
        return self.pub_metadata.keywordrefs.property(propertyid, self._id)

    @property
    def name(self):
        """The name of the ``PublisherMetadataKeyword``"""
        return str(self._query_keyword_metadata_property(gdef.EvtPublisherMetadataKeywordName))

    @property
    def value(self):
        """The value of the ``PublisherMetadataKeyword``"""
        return int(self._query_keyword_metadata_property(gdef.EvtPublisherMetadataKeywordValue))

    @property
    def message_id(self):
        """The message id of the ``PublisherMetadataKeyword``"""
        return int(self._query_keyword_metadata_property(gdef.EvtPublisherMetadataKeywordMessageID))

class PublisherMetadataTask(object):
    """Represent a PublisherMetadataTask (see https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_publisher_metadata_property_id)"""
    def __init__(self, pub_metadata, channel_id):
        super(PublisherMetadataTask, self).__init__()
        self.pub_metadata = pub_metadata
        self._id = channel_id

    def _query_keyword_metadata_property(self, propertyid):
        return self.pub_metadata.taskrefs.property(propertyid, self._id)

    @property
    def name(self):
        """The name of the ``PublisherMetadataTask``"""
        return str(self._query_keyword_metadata_property(gdef.EvtPublisherMetadataTaskName))

    @property
    def value(self):
        """The value of the ``PublisherMetadataTask``"""
        return int(self._query_keyword_metadata_property(gdef.EvtPublisherMetadataTaskValue))

    @property
    def event_guid(self):
        """The event GUId of the ``PublisherMetadataTask``"""
        return self._query_keyword_metadata_property(gdef.EvtPublisherMetadataTaskEventGuid)

    @property
    def message_id(self):
        """The message ID GUId of the ``PublisherMetadataTask``"""
        return int(self._query_keyword_metadata_property(gdef.EvtPublisherMetadataTaskMessageID))

class EvtPublisher(object):
    """An Event provider"""
    def __init__(self, name):
        self.name = name

    @property
    def metadata(self):
        """Return the metadata for this publisher

        :type: :class:`PublisherMetadata`
        """
        return PublisherMetadata.from_publisher_name(self.name)

    def __repr__(self):
        return '<{0} "{1}">'.format(type(self).__name__, self.name)


class PublisherMetadata(EvtHandle):
    """The metadata about an event provider"""
    def __init__(self, handle, name=None):
        super(PublisherMetadata, self).__init__(handle)
        self.name = name

    @classmethod
    def from_publisher_name(cls, name):
        """The :class:`PublisherMetadata` for the publisher ``name``"""
        return cls(winproxy.EvtOpenPublisherMetadata(None, name, None, 0, 0), name)

    @property
    def guid(self):
        """The GUID associated with this provider

        :type:  [:class:`GUID`] -- the GUID in a XXXXXXXXXX-YYYY-ZZZZ-TTTT-VVVVVVVVVV form
        """
        return publishinfo(self, gdef.EvtPublisherMetadataPublisherGuid).value

    @property
    def chanrefs(self):
        """Identifies the channels child element of the provider.

        :type: :class:`PropertyArray`
        """
        return PropertyArray(publishinfo(self, gdef.EvtPublisherMetadataChannelReferences).value)

    @property
    def levelrefs(self):
        """Identifies the levels child element of the provider.

        :type: :class:`PropertyArray`
        """
        return PropertyArray(publishinfo(self, gdef.EvtPublisherMetadataLevels).value)

    @property
    def opcoderefs(self):
        """Identifies the opcodes child element of the provider.

        :type: :class:`PropertyArray`
        """
        return PropertyArray(publishinfo(self, gdef.EvtPublisherMetadataOpcodes).value)

    @property
    def keywordrefs(self):
        """The list of keywords defined by this provider

        :type: :class:`PropertyArray`
        """
        return PropertyArray(publishinfo(self, gdef.EvtPublisherMetadataKeywords).value)

    @property
    def taskrefs(self):
        """The list of tasks defined by this provider

        :type: :class:`PropertyArray`
        """
        return PropertyArray(publishinfo(self, gdef.EvtPublisherMetadataTasks).value)

    @property
    def channels_metadata(self):
        """The :class:`PublisherMetadataChannel` for each channel this provider defines

        :yield: :class:`PublisherMetadataChannel`
        """
        return [PublisherMetadataChannel(self, i) for i in range(self.chanrefs.size)]

    @property
    def levels_metadata(self):
        """The :class:`PublisherMetadataLevel` for each level this provider defines

        :yield: :class:`PublisherMetadataLevel`
        """
        return [PublisherMetadataLevel(self, i) for i in range(self.levelrefs.size)]

    @property
    def opcodes_metadata(self):
        """The :class:`PublisherMetadataOpcode` for each opcode this provider defines

        :yield: :class:`PublisherMetadataOpcode`
        """
        return [PublisherMetadataOpcode(self, i) for i in range(self.opcoderefs.size)]

    @property
    def tasks_metadata(self):
        """The :class:`PublisherMetadataTask` for each opcode this provider defines

        :yield: :class:`PublisherMetadataTask`
        """
        return [PublisherMetadataTask(self, i) for i in range(self.taskrefs.size)]

    @property
    def keywords_metadata(self):
        """The :class:`PublisherMetadataKeyword` for each opcode this provider defines

        :yield: :class:`PublisherMetadataKeyword`
        """
        return [PublisherMetadataKeyword(self, i) for i in range(self.keywordrefs.size)]

    @property
    def events_metadata(self):
        """The :class:`EventMetadata` for each event this provider defines

        :yield: :class:`EventMetadata`
        """
        eh = winproxy.EvtOpenEventMetadataEnum(self, 0)
        with ClosingEvtHandle(eh):
            while True:
                try:
                    nh = windows.winproxy.EvtNextEventMetadata(eh, 0)
                    yield EventMetadata(nh)
                except WindowsError as e:
                    if e.winerror != gdef.ERROR_NO_MORE_ITEMS:
                        raise
                    break

    @property
    def channel_name_by_id(self):
        """The dict of channel defined by this provider by their id

        :type: :class:`dict`
        """
        chansref = self.chanrefs
        channame_by_value_id = {}
        for i in range(chansref.size):
            value = chansref.property(gdef.EvtPublisherMetadataChannelReferenceID, i)
            name = chansref.property(gdef.EvtPublisherMetadataChannelReferencePath, i)
            channame_by_value_id[value] = name
        return channame_by_value_id

    @property
    def channels(self):
        """The list of :class:`EvtChannel` defined by this provider

        :type: [:class:`EvtChannel`] -- A list of :class:`EvtChannel`
        """
        chansref = self.chanrefs
        propertyid = gdef.EvtPublisherMetadataChannelReferencePath
        return [EvtChannel(chansref.property(propertyid, i)) for i in range(chansref.size)]

    def message(self, msgid):
        "TODO"
        size = 0x1000
        buffer = ctypes.c_buffer(size)
        sbuff = ctypes.cast(buffer, gdef.LPWSTR)
        outsize = gdef.DWORD()
        try:
            winproxy.EvtFormatMessage(self, None, msgid, 0, None, gdef.EvtFormatMessageId, size, sbuff, outsize)
        except WindowsError as e:
            if e.winerror != gdef.ERROR_EVT_UNRESOLVED_VALUE_INSERT:
                raise
        return sbuff.value

    @property
    def message_id(self):
        """
        """
        return publishinfo(self, gdef.EvtPublisherMetadataPublisherMessageID).value

    @property
    def message_filepath(self):
        """
        """
        return publishinfo(self, gdef.EvtPublisherMetadataMessageFilePath).value

    @property
    def message_resource_filepath(self):
        """
        """
        return publishinfo(self, gdef.EvtPublisherMetadataResourceFilePath).value

    @property
    def message_parameter_filepath(self):
        """
        """
        return publishinfo(self, gdef.EvtPublisherMetadataParameterFilePath).value


    def __repr__(self):
        return '<{0} "{1}">'.format(type(self).__name__, self.name)


class PropertyArray(gdef.EVT_OBJECT_ARRAY_PROPERTY_HANDLE):
    "TODO"
    @property
    def size(self):
        array_size = gdef.DWORD()
        windows.winproxy.EvtGetObjectArraySize(self, array_size)
        return array_size.value

    def property(self, type, index):
        return arrayproperty(self, type, index).value

class EventMetadata(EvtHandle):
    """The Metadata about a given Event type


    see: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385517(v=vs.85).aspx
    """

    @property
    def id(self):
        """The ID of the Event"""
        # https://docs.microsoft.com/en-us/windows/desktop/wes/eventschema-systempropertiestype-complextype
        # Qualifiers:
        # A legacy provider uses a 32-bit number to identify its events.
        # If the event is logged by a legacy provider, the value of EventID
        # element contains the low-order 16 bits of the event identifier and the
        # Qualifier attribute contains the high-order 16 bits of the event identifier.
        # [Question] Only true for legacy provider / channels ??
        return eventinfo(self, gdef.EventMetadataEventID).value & 0xffff

    @property
    def version(self):
        """The version of the Event"""
        return eventinfo(self, gdef.EventMetadataEventVersion).value

    @property
    def channel_id(self):
        """The Channel attribute of the Event definition"""
        return eventinfo(self, gdef.EventMetadataEventChannel).value

    @property
    def keyword(self):
        """The keyword attribute of the Event definition"""
        return eventinfo(self, gdef.EventMetadataEventKeyword).value

    @property
    def opcode(self):
        """The opcode attribute of the Event definition"""
        return eventinfo(self, gdef.EventMetadataEventOpcode).value

    @property
    def level(self):
        """The level attribute of the Event definition"""
        return eventinfo(self, gdef.EventMetadataEventLevel).value

    @property
    def task(self):
        """The task attribute of the Event definition"""
        return eventinfo(self, gdef.EventMetadataEventTask).value

    @property
    def message_id(self):
        """Identifies the message attribute of the event definition."""
        return eventinfo(self, gdef.EventMetadataEventMessageID).value

    @property
    def template(self):
        """Identifies the template attribute of the event definition which is an XML string"""
        return eventinfo(self, gdef.EventMetadataEventTemplate).value

    def _parse_event_template_data_element(self, element):
        res = {"type": "data"}
        res["name"] = element.attributes["name"].value
        res["inType"] = element.attributes["inType"].value
        res["outType"] = element.attributes["outType"].value
        count = element.attributes.get("count", None)
        if count:
            res["count"]  = count.value
        length = element.attributes.get("length", None)
        if length:
            res["length"]  = length.value
        return res

    def _parse_event_template_struct_element(self, element):
        res = {"type": "struct"}
        res["name"] = element.attributes["name"].value
        res["fields"] = [self._parse_event_template_data_element(elt) for elt in element.childNodes if elt.nodeType == elt.ELEMENT_NODE]
        return res

    def _event_data_generator(self, template):
        xmldoc = xml.dom.minidom.parseString(template)
        xmltemplate = xmldoc.getElementsByTagName("template")[0]
        for element in (n for n in xmltemplate.childNodes if n.nodeType == n.ELEMENT_NODE):
            if element.tagName == "data":
                yield self._parse_event_template_data_element(element)
            elif element.tagName == "struct":
                yield self._parse_event_template_struct_element(element)
            else:
                raise ValueError("Unexpected XML element <{0}> in event template".format(element.tagName))

    @property
    def event_data(self):
        """The list of attribute specifique for this event.
        Retrieved by parsing :data:`EventMetadata.template`
        """
        template = self.template
        if not template:
            return []
        return list(self._event_data_generator(template))

    def yolo(self):
        template = self.template
        if not template:
            return None
        xmltemplate = xml.dom.minidom.parseString(template)
        return xmltemplate


class EvtlogManager(object):
    """The main Evt class to open Evt channel/publisher and evtx file"""
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa385784(v=vs.85).aspx

    def is_implemented(self):
        """Return ``True`` if the new Evt-API is implemented on the current computer

        see: https://msdn.microsoft.com/en-us/library/windows/desktop/aa385784(v=vs.85).aspx
        """
        return windows.winproxy.is_implemented(windows.winproxy.EvtQuery)

    @property
    def channels(self):
        h = windows.winproxy.EvtOpenChannelEnum(None, 0)
        size = 0x1000
        buffer = ctypes.create_unicode_buffer(size)
        ressize = gdef.DWORD()
        with ClosingEvtHandle(h):
            while True:
                try:
                    windows.winproxy.EvtNextChannelPath(h, size, buffer, ressize)
                except WindowsError as e:
                    if e.winerror != gdef.ERROR_NO_MORE_ITEMS:
                        raise
                    return
                assert buffer[ressize.value - 1] == "\x00"
                name = buffer[:ressize.value - 1]
                chan = EvtChannel(name)
                yield chan

    @property
    def publishers(self):
        h = windows.winproxy.EvtOpenPublisherEnum(None, 0)
        size = 0x1000
        buffer = ctypes.create_unicode_buffer(size)
        ressize = gdef.DWORD()
        with ClosingEvtHandle(h):
            while True:
                try:
                    windows.winproxy.EvtNextPublisherId(h, size, buffer, ressize)
                except WindowsError as e:
                    if e.winerror != gdef.ERROR_NO_MORE_ITEMS:
                        raise
                    return
                assert buffer[ressize.value - 1] == "\x00"
                name = buffer[:ressize.value - 1]
                publisher = EvtPublisher(name)
                yield publisher



    def open_channel(self, name):
        """Open the Evt channel with ``name``

        :rtype: :class:`EvtChannel`
        """
        chan = EvtChannel(name)
        chan.config # Force to retrieve a handle (check channel exists)
        return chan

    def open_evtx_file(self, filename):
        """Open the evtx file with ``filename``

        :rtype: :class:`EvtFile`
        """
        with windows.utils.DisableWow64FsRedirection():
            if not os.path.exists(filename):
                raise WindowsError(gdef.ERROR_FILE_NOT_FOUND, "Could not find file <{0}>".format(filename))
        file = EvtFile(filename)
        return file

    def open_publisher(self, name):
        """Open the Evt publisher with ``name``

        :rtype: :class:`EvtPublisher`
        """
        publisher = EvtPublisher(name)
        publisher.metadata # Force to retrieve a handle (check channel exists)
        return publisher

    def __getitem__(self, name):
        """Open the Evt Channel/Publisher or Evtx file with ``name``

        :rtype: :class:`EvtChannel` or :class:`EvtPublisher` or :class:`EvtFile`
        """
        try:
            return self.open_channel(name)
        except WindowsError as e:
            if e.winerror == gdef.ERROR_ACCESS_DENIED:
                raise

        try:
            return self.open_publisher(name)
        except WindowsError as e:
            if e.winerror == gdef.ERROR_ACCESS_DENIED:
                raise
        # Raise FILE_NOT_FOUND if not found (last chance)
        return self.open_evtx_file(name)

