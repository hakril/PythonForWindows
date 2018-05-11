import ctypes
import os.path
import xml.dom.minidom
from contextlib import contextmanager

import windows
import windows.generated_def as gdef
from windows import winproxy


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


# Class high-level API
class EvtQuery(gdef.EVT_HANDLE):
    TIMEOUT = 0x1000

    def __init__(self, handle=0, channel=None):
        super(EvtQuery, self).__init__(handle)
        self.channel = channel

    def __next__(self):
        try:
            event = EvtEvent(channel=self.channel)
            ret = gdef.DWORD()
            windows.winproxy.EvtNext(self, 1, event, self.TIMEOUT, 0, ret)
        except WindowsError as e:
            if e.winerror == gdef.ERROR_NO_MORE_ITEMS:
                raise StopIteration
            raise
        assert ret.value == 1
        return  event

    def __iter__(self):
        return self

    next = __next__ # Yep.. real name is 'next' in Py2 :D

    def all(self): # SqlAlchemy like :)
        return list(self)


class EvtEvent(gdef.EVT_HANDLE):
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
        return [r.value for r in result]

    def system(self): # POC: use this for all @property based on system data ?
        ctx = windows.winproxy.EvtCreateRenderContext(0, None, gdef.EvtRenderContextSystem)
        result = self.render(ctx, gdef.EvtRenderEventValues)
        return [r.value for r in result]

    def user(self):
        ctx = windows.winproxy.EvtCreateRenderContext(0, None, gdef.EvtRenderContextUser)
        result = self.render(ctx, gdef.EvtRenderEventValues)
        return [r.value for r in result]

    # Properties arround common Event/System values
    @property
    def id(self):
        return self.value("Event/System/EventID")

    @property
    def version(self):
        return self.value("Event/System/Version")

    @property
    def level(self):
        return self.value("Event/System/Level")

    @property
    def opcode(self):
        return self.value("Event/System/Opcode")

    @property
    def time_created(self):
        return self.value("Event/System/TimeCreated/@SystemTime")

    @property
    def metadata(self):
        "HEAVY CALL"
        return self.channel.get_event_metadata(self.id)

    # Test
    @property
    def data(self): # user/event specifique data
        return {k:v for k,v in zip(self.metadata.user_data, self.user())}


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
        gdef.EvtVarTypeHexInt32   : 'BinaryVal',
        gdef.EvtVarTypeHexInt64   : 'BinaryVal',
        gdef.EvtVarTypeEvtHandle  : 'EvtHandleVal',
        gdef.EvtVarTypeEvtXml     : 'XmlVal',
    }
    NoneValue = None
    @property
    def Type(self):
        raw_type = super(ImprovedEVT_VARIANT, self).Type
        return gdef.EVT_VARIANT_TYPE.mapper[raw_type]

    @property
    def value(self): # Prototype !!
        attrname = self.VALUE_MAPPER[self.Type]
        # print("Resolve type <{0}> -> {1}".format(self.Type, attrname))
        return getattr(self, attrname)

    def __repr__(self):
        return "<{0} of type={1}>".format(type(self).__name__, self.Type)


def channels():
    h = windows.winproxy.EvtOpenChannelEnum(None, 0)
    size = 0x1000
    buffer = ctypes.create_unicode_buffer(size)
    ressize = gdef.DWORD()
    try:
        while True:
            try:
                windows.winproxy.EvtNextChannelPath(h, size, buffer, ressize)
            except WindowsError as e:
                if e.winerror != gdef.ERROR_NO_MORE_ITEMS:
                    raise
                return
            assert buffer[ressize.value - 1] == "\x00"
            yield buffer[:ressize.value - 1]
    finally: # TODO: ctx manager
        windows.winproxy.EvtClose(h)


def publishers():
    h = windows.winproxy.EvtOpenPublisherEnum(None, 0)
    size = 0x1000
    buffer = ctypes.create_unicode_buffer(size)
    ressize = gdef.DWORD()
    try:
        while True:
            try:
                windows.winproxy.EvtNextPublisherId(h, size, buffer, ressize)
            except WindowsError as e:
                if e.winerror != gdef.ERROR_NO_MORE_ITEMS:
                    raise
                return
            assert buffer[ressize.value - 1] == "\x00"
            yield buffer[:ressize.value - 1]
    finally: # TODO: ctx manager
        windows.winproxy.EvtClose(h)



# x = windows.winproxy.EvtQuery(None,
                # "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                # "Event/System[EventID=2004 or EventID=2006]",
                # gdef.EvtQueryChannelPath + gdef.EvtQueryForwardDirection)
# print(x)
# eq = EvtQuery(x)
# event = next(eq)

# xx = gdef.LPWSTR("ModifyingApplication")
# xx = gdef.LPWSTR("Event/System/Channel")
# xx = gdef.LPWSTR('Event/EventData/Data[@Name="ModifyingApplication"]')
# xx = gdef.LPWSTR('Event/System/EventID')

# event = next(eq)

# list(channels())

class EvtChannel(object):
    DEFAULT_QUERY_FLAGS = gdef.EvtQueryChannelPath + gdef.EvtQueryForwardDirection

    def __init__(self, name):
        self.name = name
        self.event_metadata_by_id = {}

    def query(self, ids=None, filter=None):
        if ids is not None:
            if isinstance(ids, (long, int)):
                ids = (ids,)
            ids_filter = " or ".join("EventID={0}".format(id) for id in ids)
            filter = "Event/System[{0}]".format(ids_filter)
        query_handle = winproxy.EvtQuery(None, self.name, filter, self.DEFAULT_QUERY_FLAGS)
        return EvtQuery(query_handle, self)

    @property
    def config(self):
        return ChannelConfig.from_channel_name(self.name)

    def get_event_metadata(self, id):
        try:
            return self.event_metadata_by_id[id]
        except KeyError as e:
            pass

        pub_metada = self.config.publisher.metadata
        self.event_metadata_by_id = {evtm.id: evtm for evtm in pub_metada.events_metadata}
        return self.event_metadata_by_id[id]


    def __repr__(self):
        return '<{0} "{1}">'.format(type(self).__name__, self.name)


class EvtFile(EvtChannel):
    DEFAULT_QUERY_FLAGS = gdef.EvtQueryFilePath + gdef.EvtQueryForwardDirection

    @property
    def config(self):
        raise NotImplementedError("Cannot retrieve the configuration of an EvtFile")


class ChannelConfig(gdef.EVT_HANDLE):
    def __init__(self, handle, name=None):
        super(ChannelConfig, self).__init__(handle)
        self.name = name

    @classmethod
    def from_channel_name(cls, channel_name):
        return cls(winproxy.EvtOpenChannelConfig(None, channel_name, 0), channel_name)

    @property
    def publisher(self):
        return EvtPublisher(chaninfo(self, gdef.EvtChannelConfigOwningPublisher).value)

    def __repr__(self):
        return '<{0} "{1}">'.format(type(self).__name__, self.name)


class EvtPublisher(object):
    def __init__(self, name):
        self.name = name

    @property
    def metadata(self):
        return PublisherMetadata.from_publisher_name(self.name)

    def __repr__(self):
        return '<{0} "{1}">'.format(type(self).__name__, self.name)


class PublisherMetadata(gdef.EVT_HANDLE):
    def __init__(self, handle, name=None):
        super(PublisherMetadata, self).__init__(handle)
        self.name = name

    @classmethod
    def from_publisher_name(cls, publisher_name):
        return cls(winproxy.EvtOpenPublisherMetadata(None, publisher_name, None, 0, 0), publisher_name)

    @property
    def chanrefs(self):
        return PropertyArray(publishinfo(self, gdef.EvtPublisherMetadataChannelReferences).value)

    @property
    def events_metadata(self):
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

    def channel_name_by_id(self):
        chansref = self.chanrefs
        channame_by_value_id = {}
        for i in range(chansref.size):
            value = chansref.propery(gdef.EvtPublisherMetadataChannelReferenceID, i)
            name = chansref.propery(gdef.EvtPublisherMetadataChannelReferencePath, i)
            channame_by_value_id[value] = name
        return channame_by_value_id

    def message(self, msgid):
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

    def __repr__(self):
        return '<{0} "{1}">'.format(type(self).__name__, self.name)


class PropertyArray(gdef.EVT_OBJECT_ARRAY_PROPERTY_HANDLE):
    @property
    def size(self):
        array_size = gdef.DWORD()
        windows.winproxy.EvtGetObjectArraySize(self, array_size)
        return array_size.value

    def propery(self, type, index):
        return arrayproperty(self, type, index).value

class EventMetadata(gdef.EVT_HANDLE):
    @property
    def id(self):
        return eventinfo(self, gdef.EventMetadataEventID).value

    @property
    def channel_id(self):
        return eventinfo(self, gdef.EventMetadataEventChannel).value

    @property
    def message_id(self):
        return eventinfo(self, gdef.EventMetadataEventMessageID).value

    @property
    def template(self):
        return eventinfo(self, gdef.EventMetadataEventTemplate).value

    @property
    def user_data(self):
        result = []
        xmltemplate = xml.dom.minidom.parseString(self.template)
        for data in xmltemplate.getElementsByTagName("data"):
            result.append(data.attributes["name"].value)
        return result


class EvtlogManager(object):
    "TODO: doc -> the frontend API object"
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa385784(v=vs.85).aspx

    def open_channel(self, channel_name):
        chan = EvtChannel(channel_name)
        chan.config # Force to retrieve a handle (check channel exists)
        return chan

    def open_evtx_file(self, filename):
        # We don't check if file exists because of 32->64 redirection
        # Do a check with FSRedirection disabled ?
        with windows.utils.DisableWow64FsRedirection():
            if not os.path.exists(filename):
                raise WindowsError(gdef.ERROR_FILE_NOT_FOUND, "Could not find file <{0}>".format(filename))
        file = EvtFile(filename)
        return file

    def open_publisher(self, publisher_name):
        publisher = EvtPublisher(publisher_name)
        publisher.metadata # Force to retrieve a handle (check channel exists)
        return publisher

    def __getitem__(self, name):
        try:
            return self.open_channel(name)
        except WindowsError as e:
            pass

        try:
            return self.open_publisher(name)
        except WindowsError as e:
            pass
        # Raise FILE_NOT_FOUND if not found (last chance)
        return self.open_evtx_file(name)




# CHANNAME = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
# CHANNAME = r"Microsoft-Windows-Windows Defender/Operational"

# print("Working of channel: <{0}>".format(CHANNAME))

# channel = EvtChannel(CHANNAME)
# chanconf = channel.config
# publisher = chanconf.publisher

# open publisher metadata

# print("Provider is <{0}>".format(publisher.name))

# pmd = publisher.metadata
# chansref = pmd.chanrefs

# channame_by_value_id  = pmd.channel_name_by_id()

# for event_metadata in pmd.events_metadata:
     # id = event_metadata.id
     # if id == 2004:
        # print("LOL")
     # chan = event_metadata.channel_id
     # channame = channame_by_value_id[chan]
     # print("   * {0}) {1}".format(id, channame))
     # if "unexpected" in pmd.message(event_metadata.message_id).lower():
        # print("UNEXPECTED in message :D")


# query = channel.query(ids=5008)
# evts = list(query)
