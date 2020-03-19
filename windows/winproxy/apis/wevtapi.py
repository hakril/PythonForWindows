import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import fail_on_zero

class WevtapiProxy(ApiProxy):
    APIDLL = "Wevtapi"
    default_error_check = staticmethod(fail_on_zero)


# Session

@WevtapiProxy()
def EvtOpenSession(LoginClass, Login, Timeout=0, Flags=0):
    return EvtOpenSession.ctypes_function(LoginClass, Login, Timeout, Flags)

# Event

@WevtapiProxy()
def EvtOpenLog(Session, Path, Flags):
    return EvtOpenLog.ctypes_function(Session, Path, Flags)

@WevtapiProxy()
def EvtClose(Object):
    return EvtClose.ctypes_function(Object)

@WevtapiProxy()
def EvtQuery(Session, Path, Query, Flags):
    return EvtQuery.ctypes_function(Session, Path, Query, Flags)

@WevtapiProxy()
def EvtNext(ResultSet, EventArraySize, EventArray, Timeout, Flags, Returned):
    return EvtNext.ctypes_function(ResultSet, EventArraySize, EventArray, Timeout, Flags, Returned)

@WevtapiProxy()
def EvtSeek(ResultSet, Position, Bookmark, Timeout, Flags):
    return EvtSeek.ctypes_function(ResultSet, Position, Bookmark, Timeout, Flags)


# Channel

@WevtapiProxy()
def EvtOpenChannelEnum(Session, Flags):
    return EvtOpenChannelEnum.ctypes_function(Session, Flags)


@WevtapiProxy()
def EvtNextChannelPath(ChannelEnum, ChannelPathBufferSize, ChannelPathBuffer, ChannelPathBufferUsed):
    return EvtNextChannelPath.ctypes_function(ChannelEnum, ChannelPathBufferSize, ChannelPathBuffer, ChannelPathBufferUsed)

@WevtapiProxy()
def EvtOpenChannelConfig(Session, ChannelPath, Flags):
    return EvtOpenChannelConfig.ctypes_function(Session, ChannelPath, Flags)

@WevtapiProxy()
def EvtGetChannelConfigProperty(ChannelConfig, PropertyId, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed):
    return EvtGetChannelConfigProperty.ctypes_function(ChannelConfig, PropertyId, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)

# Publisher

@WevtapiProxy()
def EvtOpenPublisherEnum(Session, Flags):
    return EvtOpenPublisherEnum.ctypes_function(Session, Flags)

@WevtapiProxy()
def EvtNextPublisherId(PublisherEnum, PublisherIdBufferSize, PublisherIdBuffer, PublisherIdBufferUsed):
    return EvtNextPublisherId.ctypes_function(PublisherEnum, PublisherIdBufferSize, PublisherIdBuffer, PublisherIdBufferUsed)

@WevtapiProxy()
def EvtOpenPublisherMetadata(Session, PublisherIdentity, LogFilePath, Locale, Flags):
    return EvtOpenPublisherMetadata.ctypes_function(Session, PublisherIdentity, LogFilePath, Locale, Flags)

@WevtapiProxy()
def EvtGetPublisherMetadataProperty(PublisherMetadata, PropertyId, Flags, PublisherMetadataPropertyBufferSize, PublisherMetadataPropertyBuffer, PublisherMetadataPropertyBufferUsed):
    return EvtGetPublisherMetadataProperty.ctypes_function(PublisherMetadata, PropertyId, Flags, PublisherMetadataPropertyBufferSize, PublisherMetadataPropertyBuffer, PublisherMetadataPropertyBufferUsed)


# Evt metadata

@WevtapiProxy()
def EvtOpenEventMetadataEnum(PublisherMetadata, Flags):
    return EvtOpenEventMetadataEnum.ctypes_function(PublisherMetadata, Flags)


@WevtapiProxy()
def EvtNextEventMetadata(EventMetadataEnum, Flags):
    return EvtNextEventMetadata.ctypes_function(EventMetadataEnum, Flags)


@WevtapiProxy()
def EvtGetEventMetadataProperty(EventMetadata, PropertyId, Flags, EventMetadataPropertyBufferSize, EventMetadataPropertyBuffer, EventMetadataPropertyBufferUsed):
    return EvtGetEventMetadataProperty.ctypes_function(EventMetadata, PropertyId, Flags, EventMetadataPropertyBufferSize, EventMetadataPropertyBuffer, EventMetadataPropertyBufferUsed)

# Render

@WevtapiProxy()
def EvtCreateRenderContext(ValuePathsCount, ValuePaths, Flags):
    return EvtCreateRenderContext.ctypes_function(ValuePathsCount, ValuePaths, Flags)


@WevtapiProxy()
def EvtRender(Context, Fragment, Flags, BufferSize, Buffer, BufferUsed, PropertyCount):
    return EvtRender.ctypes_function(Context, Fragment, Flags, BufferSize, Buffer, BufferUsed, PropertyCount)


@WevtapiProxy()
def EvtFormatMessage(PublisherMetadata, Event, MessageId, ValueCount, Values, Flags, BufferSize, Buffer, BufferUsed):
    return EvtFormatMessage.ctypes_function(PublisherMetadata, Event, MessageId, ValueCount, Values, Flags, BufferSize, Buffer, BufferUsed)

# Other

@WevtapiProxy()
def EvtGetLogInfo(Log, PropertyId, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed):
    return EvtGetLogInfo.ctypes_function(Log, PropertyId, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)

@WevtapiProxy()
def EvtGetObjectArraySize(ObjectArray, ObjectArraySize):
    return EvtGetObjectArraySize.ctypes_function(ObjectArray, ObjectArraySize)


@WevtapiProxy()
def EvtGetObjectArrayProperty(ObjectArray, PropertyId, ArrayIndex, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed):
    return EvtGetObjectArrayProperty.ctypes_function(ObjectArray, PropertyId, ArrayIndex, Flags, PropertyValueBufferSize, PropertyValueBuffer, PropertyValueBufferUsed)


####




