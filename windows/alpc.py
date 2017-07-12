import ctypes
from collections import namedtuple

import windows
from windows import winproxy
from windows import generated_def as gdef


class AlpcMessage(object):
    # PORT_MESSAGE + MessageAttribute
    def __init__(self, msg_or_size=None, attributes=None):
        # Init the PORT_MESSAGE
        if isinstance(msg_or_size, (long, int)):
            self.port_message_buffer_size = msg_or_size
            self.port_message_raw_buffer = ctypes.c_buffer(msg_or_size)
            self.port_message = AlpcMessagePort.from_buffer(self.port_message_raw_buffer)
            self.port_message.set_datalen(0)
        elif isinstance(msg_or_size, AlpcMessagePort):
            self.port_message = msg_or_size
            self.port_message_raw_buffer = self.port_message.raw_buffer
            self.port_message_buffer_size = len(self.port_message_raw_buffer)

        # Init the MessageAttributes
        if attributes is None:
            self.attributes = MessageAttribute.with_all_attributes()
        else:
            self.attributes = attributes

    # PORT_MESSAGE wrappers
    @property
    def type(self):
        return self.port_message.u2.s2.Type

    def get_port_message_data(self):
        return self.port_message.data

    def set_port_message_data(self, data):
        self.port_message.data = data

    data = property(get_port_message_data, set_port_message_data)

    # MessageAttributes wrappers

    ## Low level attributes access
    @property
    def security_attribute(self):
        return self.attributes.get_attribute(gdef.ALPC_MESSAGE_SECURITY_ATTRIBUTE)

    @property
    def view_attribute(self):
        return self.attributes.get_attribute(gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE)

    @property
    def context_attribute(self):
        return self.attributes.get_attribute(gdef.ALPC_MESSAGE_CONTEXT_ATTRIBUTE)

    @property
    def handle_attribute(self):
        return self.attributes.get_attribute(gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE)

    ## Low level validity check (Test)
    @property
    def view_is_valid(self): # Change the name ?
        return self.attributes.is_valid(gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE)


    ## High level setup (Test)
    def setup_view(self, size, section_handle=0, flags=None):
        raise NotImplementedError(self.setup_view)



class AlpcMessagePort(gdef.PORT_MESSAGE):
    # Constructeur
    @classmethod
    def from_buffer(self, buffer):
        # A sort of super(AlpcMessagePort).from_buffer
        # But from_buffer is from the Metaclass of AlpcMessagePort so we use 'type(AlpcMessagePort)'
        # To access the standard version of from_buffer.
        self = type(AlpcMessagePort).from_buffer(AlpcMessagePort, buffer)
        self.buffer_size = len(buffer)
        self.raw_buffer = buffer
        self.header_size = ctypes.sizeof(self)
        self.max_datasize = self.buffer_size - self.header_size
        return self

    @classmethod
    def from_buffer_size(cls, buffer_size):
        buffer = ctypes.c_buffer(buffer_size)
        return cls.from_buffer(buffer)

    def read_data(self):
        return self.raw_buffer[ctypes.sizeof(self):ctypes.sizeof(self) + self.u1.s1.DataLength]

    def write_data(self, data):
        if len(data) > self.max_datasize:
            raise ValueError("Cannot write data of len <{0}> (raw_buffer size == <{1}>)".format(len(data), self.buffer_size))
        self.raw_buffer[self.header_size: self.header_size + len(data)] = data
        self.set_datalen(len(data))

    data = property(read_data, write_data)

    def set_datalen(self, datalen):
        self.u1.s1.TotalLength = self.header_size + datalen
        self.u1.s1.DataLength = datalen

    def get_datalen(self):
        return self.u1.s1.DataLength

    datalen = property(get_datalen, set_datalen)



class MessageAttribute(gdef.ALPC_MESSAGE_ATTRIBUTES):
    ATTRIBUTE_BY_FLAG = [(gdef.ALPC_MESSAGE_SECURITY_ATTRIBUTE, gdef.ALPC_SECURITY_ATTR),
                            (gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE, gdef.ALPC_DATA_VIEW_ATTR),
                            (gdef.ALPC_MESSAGE_CONTEXT_ATTRIBUTE, gdef.ALPC_CONTEXT_ATTR),
                            (gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE, gdef.ALPC_HANDLE_ATTR)]

    @classmethod
    def with_attributes(cls, flags):
        size = cls._get_required_buffer_size(flags)
        buffer = ctypes.c_buffer(size)
        self = cls.from_buffer(buffer)
        self.raw_buffer = buffer
        res = gdef.DWORD()
        winproxy.AlpcInitializeMessageAttribute(flags, self, len(self.raw_buffer), res)
        return self

    @classmethod
    def with_all_attributes(cls):
        return cls.with_attributes(gdef.ALPC_MESSAGE_SECURITY_ATTRIBUTE |
                                                            gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE |
                                                            gdef.ALPC_MESSAGE_CONTEXT_ATTRIBUTE |
                                                            gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE)

    @staticmethod
    def _get_required_buffer_size(flags):
        res = gdef.DWORD()
        try:
            windows.winproxy.AlpcInitializeMessageAttribute(flags, None, 0, res)
        except windows.generated_def.ntstatus.NtStatusException as e:
            # Buffer too small: osef
            return res.value
        return res.value

    def is_allocated(self, value):
        return bool(self.AllocatedAttributes & value)

    def is_valid(self, value):
        return bool(self.ValidAttributes & value)

    def get_attribute(self, attribute):
        if not self.is_allocated(attribute):
            raise ValueError("Cannot get non-allocated attribute <{0}>".format(attribute))
        offset = ctypes.sizeof(self)
        for sflag, struct in self.ATTRIBUTE_BY_FLAG:
            if sflag == attribute:
                return struct.from_address(ctypes.addressof(self) + offset)
            elif self.is_allocated(sflag):
                offset += ctypes.sizeof(struct)
        raise ValueError("ALPC Attribute <{0}> not found :(".format(attribute))

AlpcSection = namedtuple("AlpcSection", ["handle", "size"])

class AlpcTransportBase(object):
    def send_receive(self, alpc_message, receive_msg=None, flags=gdef.ALPC_MSGFLG_SYNC_REQUEST):
        if isinstance(alpc_message, basestring):
            raw_alpc_message = alpc_message
            alpc_message = AlpcMessage(max(0x1000, len(alpc_message)))
            alpc_message.port_message.data = raw_alpc_message

        if receive_msg is None:
            receive_msg = AlpcMessage(0x1000)
        receive_size = gdef.SIZE_T(receive_msg.port_message_buffer_size)
        winproxy.NtAlpcSendWaitReceivePort(self.handle, flags, alpc_message.port_message, alpc_message.attributes, receive_msg.port_message, receive_size, receive_msg.attributes, None)
        return receive_msg

    def send(self, alpc_message, flags=0):
        if isinstance(alpc_message, basestring):
            raw_alpc_message = alpc_message
            alpc_message = AlpcMessage(max(0x1000, len(alpc_message)))
            alpc_message.port_message.data = raw_alpc_message
        winproxy.NtAlpcSendWaitReceivePort(self.handle, flags, alpc_message.port_message, alpc_message.attributes, None, None, None, None)

    def recv(self, receive_msg=None, flags=0):
        if receive_msg is None:
            receive_msg = AlpcMessage(0x1000)
        receive_size = gdef.SIZE_T(receive_msg.port_message_buffer_size)
        winproxy.NtAlpcSendWaitReceivePort(self.handle, flags, None, None, receive_msg.port_message, receive_size, receive_msg.attributes, None)
        return receive_msg



class AlpcClient(AlpcTransportBase):
    DEFAULT_MAX_MESSAGE_LENGTH = 0x1000

    def __init__(self, port_name=None):
        self.handle = None
        self.portname = None
        if port_name is not None:
            x = self.connect_to_port(port_name, "")

    def _alpc_port_to_unicode_string(self, name):
        utf16_len = len(name) * 2
        return gdef.UNICODE_STRING(utf16_len, utf16_len, name)

    def connect_to_port(self, port_name, connect_message=None, receive_message=None, port_attr=None, port_attr_flags=0x10000, obj_attr=None, flags=gdef.ALPC_MSGFLG_SYNC_REQUEST, timeout=None):
        # TODO raise on mutual exclusive parameter
        if self.handle is not None:
            raise ValueError("Client already connected")
        handle = gdef.HANDLE()
        port_name_unicode = self._alpc_port_to_unicode_string(port_name)

        if port_attr is None:
            port_attr = gdef.ALPC_PORT_ATTRIBUTES()
            port_attr.Flags = port_attr_flags # Flag qui fonctionne pour l'UAC
            port_attr.MaxMessageLength = self.DEFAULT_MAX_MESSAGE_LENGTH
            port_attr.MemoryBandwidth = 0
            port_attr.MaxPoolUsage = 0xffffffff
            port_attr.MaxSectionSize = 0xffffffff
            port_attr.MaxViewSize = 0xffffffff
            port_attr.MaxTotalSectionSize = 0xffffffff
            port_attr.DupObjectTypes = 0

            port_attr.SecurityQos.Length = ctypes.sizeof(port_attr.SecurityQos)
            port_attr.SecurityQos.ImpersonationLevel = gdef.SecurityImpersonation
            port_attr.SecurityQos.ContextTrackingMode = 0
            port_attr.SecurityQos.EffectiveOnly = 0

        if connect_message is None:
            send_msg = None
            send_msg_attr = None
            buffersize = None
        elif isinstance(connect_message, basestring):
            buffersize = gdef.DWORD(len(connect_message) + 0x1000)
            send_msg = AlpcMessagePort.from_buffer_size(buffersize.value)
            send_msg.data = connect_message
            send_msg_attr = MessageAttribute.with_all_attributes()
        else:
            raise NotImplementedError("TODO: connect_to_port with type(connect_message) == AlpcMessage")

        receive_attr = MessageAttribute.with_all_attributes()
        winproxy.NtAlpcConnectPort(handle, port_name_unicode, obj_attr, port_attr, flags, None, send_msg, buffersize, send_msg_attr, receive_attr, timeout)
        # If send_msg is not None, it contains the ClientId.UniqueProcess : PID of the server :)
        self.handle = handle.value
        self.portname = port_name
        return AlpcMessage(send_msg, receive_attr) if send_msg is not None else None

    def create_port_section(self, Flags, SectionHandle, SectionSize):
        AlpcSectionHandle = gdef.HANDLE()
        ActualSectionSize = gdef.SIZE_T()
        # RPCRT4 USE FLAGS 0x40000 ALPC_VIEWFLG_NOT_SECURE ?
        winproxy.NtAlpcCreatePortSection(self.handle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize)
        return AlpcSection(AlpcSectionHandle.value, ActualSectionSize.value)

    def map_section(self, section_handle, size, flags=0):
        view_attributes = gdef.ALPC_DATA_VIEW_ATTR()
        view_attributes.Flags = 0
        view_attributes.SectionHandle = section_handle
        view_attributes.ViewBase = 0
        view_attributes.ViewSize = size
        r = winproxy.NtAlpcCreateSectionView(self.handle, flags, view_attributes)
        return view_attributes


class AlpcServer(AlpcTransportBase):
    DEFAULT_MAX_MESSAGE_LENGTH = 0x1000

    def __init__(self, port_name=None):
        self.port_name = None
        if port_name is not None:
            self.create_port(port_name)

    def _alpc_port_to_unicode_string(self, name):
        utf16_len = len(name) * 2
        return gdef.UNICODE_STRING(utf16_len, utf16_len, name)

    def create_port(self, port_name, msglen=None, port_attr_flags=0, obj_attr=None, port_attr=None):
        # TODO raise on mutual exclusive parameter (port_attr + port_attr_flags | obj_attr + msglen)
        handle = gdef.HANDLE()
        raw_name =  port_name
        if not raw_name.startswith("\\"):
            raw_name = "\\" + port_name
        port_name = self._alpc_port_to_unicode_string(raw_name)

        if msglen is None:
            msglen = self.DEFAULT_MAX_MESSAGE_LENGTH
        if obj_attr is None:
            obj_attr = gdef.OBJECT_ATTRIBUTES()
            obj_attr.Length = ctypes.sizeof(obj_attr)
            obj_attr.RootDirectory = None
            obj_attr.ObjectName = ctypes.pointer(port_name)
            obj_attr.Attributes = 0
            obj_attr.SecurityDescriptor = None
            obj_attr.SecurityQualityOfService = None
        if port_attr is None:
            port_attr = gdef.ALPC_PORT_ATTRIBUTES()
            port_attr.Flags = 0
            port_attr.MaxMessageLength = msglen
            port_attr.MemoryBandwidth = 0
            port_attr.MaxPoolUsage = 0xffffffff
            port_attr.MaxSectionSize = 0xffffffff
            port_attr.MaxViewSize = 0xffffffff
            port_attr.MaxTotalSectionSize = 0xffffffff
            port_attr.DupObjectTypes = 0

        winproxy.NtAlpcCreatePort(handle, obj_attr, port_attr)
        self.port_name = raw_name
        self.handle = handle.value

    def accept_connection(self, msg, port_attr=None):
        rhandle = gdef.HANDLE()

        if port_attr is None:
            port_attr = gdef.ALPC_PORT_ATTRIBUTES()
            port_attr.Flags = gdef.ALPC_HANDLEFLG_DUPLICATE_INHERIT
            port_attr.Flags = 0 # Testing
            port_attr.DupObjectTypes = 4
            port_attr.MaxMessageLength = 0x1000
            port_attr.MemoryBandwidth = 0
            port_attr.MaxPoolUsage = 0xffffffff

        winproxy.NtAlpcAcceptConnectPort(rhandle, self.handle, 0, None, port_attr, None, msg.port_message, None, True)
        return rhandle.value, msg
