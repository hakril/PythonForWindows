import sys
import ctypes
from collections import namedtuple

import windows
from windows import winproxy
from windows import generated_def as gdef
import windows.pycompat


## For 64b python
# 0x1f: 0x80000000: ALPC_MESSAGE_SECURITY_ATTRIBUTE(0x80000000) : size=0x18?
# 0x1e: 0x40000000: ALPC_MESSAGE_VIEW_ATTRIBUTE(0x40000000): size=0x20
# 0x1d: 0x20000000: ALPC_MESSAGE_CONTEXT_ATTRIBUTE(0x20000000): size=0x20
# 0x1c: 0x10000000: ALPC_MESSAGE_HANDLE_ATTRIBUTE(0x10000000): size=0x18
# 0x1b: 0x8000000: ALPC_MESSAGE_TOKEN_ATTRIBUTE(0x8000000): size=0x18
# 0x1a: 0x4000000: ALPC_MESSAGE_DIRECT_ATTRIBUTE(0x4000000) size=0x8
# 0x19: 0x2000000: ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE(0x2000000) size=0x8

DEFAULT_MESSAGE_SIZE = 0x1000

class AlpcMessage(object):
    """Represent a full ALPC Message: a :class:`AlpcMessagePort` and a :class:`MessageAttribute`"""
    # PORT_MESSAGE + MessageAttribute
    def __init__(self, msg_or_size=DEFAULT_MESSAGE_SIZE, attributes=None):
        # Init the PORT_MESSAGE
        if isinstance(msg_or_size, windows.pycompat.int_types):
            self.port_message_buffer_size = msg_or_size
            self.port_message_raw_buffer = ctypes.c_buffer(msg_or_size)
            self.port_message = AlpcMessagePort.from_buffer(self.port_message_raw_buffer)
            self.port_message.set_datalen(0)
        elif isinstance(msg_or_size, AlpcMessagePort):
            self.port_message = msg_or_size
            self.port_message_raw_buffer = self.port_message.raw_buffer
            self.port_message_buffer_size = len(self.port_message_raw_buffer)
        else:
            raise NotImplementedError("Uneexpected type for <msg_or_size>: {0}".format(msg_or_size))

        # Init the MessageAttributes
        if attributes is None:
            # self.attributes = MessageAttribute.with_all_attributes()
            self.attributes = MessageAttribute.with_all_attributes() ## Testing
        else:
            self.attributes = attributes

    # PORT_MESSAGE wrappers
    @property
    def type(self):
        """The type of the message (``PORT_MESSAGE.u2.s2.Type``)"""
        return self.port_message.u2.s2.Type

    def get_port_message_data(self):
        return self.port_message.data

    def set_port_message_data(self, data):
        self.port_message.data = data

    data = property(get_port_message_data, set_port_message_data)
    "The data of the message (located after the PORT_MESSAGE header)"

    # MessageAttributes wrappers

    ## Low level attributes access
    @property
    def security_attribute(self):
        """The :data:`~windows.generated_def.ALPC_MESSAGE_SECURITY_ATTRIBUTE` of the message

            :type: :class:`ALPC_SECURITY_ATTR`
        """
        return self.attributes.get_attribute(gdef.ALPC_MESSAGE_SECURITY_ATTRIBUTE)

    @property
    def view_attribute(self):
        """The :data:`~windows.generated_def.ALPC_MESSAGE_VIEW_ATTRIBUTE` of the message:

            :type: :class:`ALPC_DATA_VIEW_ATTR`
        """
        return self.attributes.get_attribute(gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE)

    @property
    def context_attribute(self):
        """The :data:`~windows.generated_def.ALPC_MESSAGE_CONTEXT_ATTRIBUTE` of the message:

            :type: :class:`ALPC_CONTEXT_ATTR`
        """
        return self.attributes.get_attribute(gdef.ALPC_MESSAGE_CONTEXT_ATTRIBUTE)

    @property
    def handle_attribute(self):
        """The :data:`~windows.generated_def.ALPC_MESSAGE_HANDLE_ATTRIBUTE` of the message:

            :type: :class:`ALPC_HANDLE_ATTR`
        """
        return self.attributes.get_attribute(gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE)

    ## Low level validity check (Test)
    @property
    def view_is_valid(self): # Change the name ?
        """True if :data:`~windows.generated_def.ALPC_MESSAGE_VIEW_ATTRIBUTE` is a ValidAttributes"""
        return self.attributes.is_valid(gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE)

    @property
    def security_is_valid(self): # Change the name ?
        """True if :data:`~windows.generated_def.ALPC_MESSAGE_SECURITY_ATTRIBUTE` is a ValidAttributes"""
        return self.attributes.is_valid(gdef.ALPC_MESSAGE_SECURITY_ATTRIBUTE)

    @property
    def handle_is_valid(self): # Change the name ?
        """True if :data:`~windows.generated_def.ALPC_MESSAGE_HANDLE_ATTRIBUTE` is a ValidAttributes"""
        return self.attributes.is_valid(gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE)

    @property
    def context_is_valid(self): # Change the name ?
        """True if :data:`~windows.generated_def.ALPC_MESSAGE_CONTEXT_ATTRIBUTE` is a ValidAttributes"""
        return self.attributes.is_valid(gdef.ALPC_MESSAGE_CONTEXT_ATTRIBUTE)


    @property
    def valid_attributes(self):
        """The list of valid attributes

            :type: [:class:`~windows.generated_def.Flag`]
        """
        return self.attributes.valid_list

    @property
    def allocated_attributes(self):
        """The list of allocated attributes

            :type: [:class:`~windows.generated_def.Flag`]
        """
        return self.attributes.allocated_list

    ## High level setup (Test)
    def setup_view(self, size, section_handle=0, flags=None):
        raise NotImplementedError(self.setup_view)



class AlpcMessagePort(gdef.PORT_MESSAGE):
    """The effective ALPC Message composed of a ``PORT_MESSAGE`` structure followed by the data"""
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
            import pdb; pdb.set_trace()
            raise ValueError("Cannot write data of len <{0}> (raw_buffer size == <{1}>)".format(len(data), self.buffer_size))
        self.raw_buffer[self.header_size: self.header_size + len(data)] = data
        self.set_datalen(len(data))

    data = property(read_data, write_data)
    "The data of the message (located after the header)"

    def set_datalen(self, datalen):
        self.u1.s1.TotalLength = self.header_size + datalen
        self.u1.s1.DataLength = datalen

    def get_datalen(self):
        return self.u1.s1.DataLength

    datalen = property(get_datalen, set_datalen)
    """The length of the data"""

KNOWN_ALPC_ATTRIBUTES = (gdef.ALPC_MESSAGE_SECURITY_ATTRIBUTE,
                            gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE,
                            gdef.ALPC_MESSAGE_CONTEXT_ATTRIBUTE,
                            gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE,
                            gdef.ALPC_MESSAGE_TOKEN_ATTRIBUTE,
                            gdef.ALPC_MESSAGE_DIRECT_ATTRIBUTE,
                            gdef.ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE)

KNOWN_ALPC_ATTRIBUTES_MAPPING = gdef.FlagMapper(*KNOWN_ALPC_ATTRIBUTES)


class MessageAttribute(gdef.ALPC_MESSAGE_ATTRIBUTES):
    """The attributes of an ALPC message"""
    ATTRIBUTE_BY_FLAG = [(gdef.ALPC_MESSAGE_SECURITY_ATTRIBUTE, gdef.ALPC_SECURITY_ATTR),
                            (gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE, gdef.ALPC_DATA_VIEW_ATTR),
                            (gdef.ALPC_MESSAGE_CONTEXT_ATTRIBUTE, gdef.ALPC_CONTEXT_ATTR),
                            (gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE, gdef.ALPC_HANDLE_ATTR),
                            (gdef.ALPC_MESSAGE_TOKEN_ATTRIBUTE, gdef.ALPC_TOKEN_ATTR),
                            (gdef.ALPC_MESSAGE_DIRECT_ATTRIBUTE, gdef.ALPC_DIRECT_ATTR),
                            (gdef.ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE, gdef.ALPC_WORK_ON_BEHALF_ATTR),
                            ]

    @classmethod
    def with_attributes(cls, attributes):
        """Create a new :class:`MessageAttribute` with ``attributes`` allocated

            :returns: :class:`MessageAttribute`
        """
        size = cls._get_required_buffer_size(attributes)
        buffer = ctypes.c_buffer(size)
        self = cls.from_buffer(buffer)
        self.raw_buffer = buffer
        res = gdef.DWORD()
        winproxy.AlpcInitializeMessageAttribute(attributes, self, len(self.raw_buffer), res)
        return self

    @classmethod
    def with_all_attributes(cls):
        """Create a new :class:`MessageAttribute` with the following attributes allocated:

            - :class:`ALPC_MESSAGE_SECURITY_ATTRIBUTE`
            - :class:`ALPC_MESSAGE_VIEW_ATTRIBUTE`
            - :class:`ALPC_MESSAGE_CONTEXT_ATTRIBUTE`
            - :class:`ALPC_MESSAGE_HANDLE_ATTRIBUTE`
            - :class:`ALPC_MESSAGE_TOKEN_ATTRIBUTE`
            - :class:`ALPC_MESSAGE_DIRECT_ATTRIBUTE`
            - :class:`ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE`

            :returns: :class:`MessageAttribute`
        """
        return cls.with_attributes(gdef.ALPC_MESSAGE_SECURITY_ATTRIBUTE |
                                    gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE    |
                                    gdef.ALPC_MESSAGE_CONTEXT_ATTRIBUTE |
                                    gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE  |
                                    gdef.ALPC_MESSAGE_TOKEN_ATTRIBUTE   |
                                    gdef.ALPC_MESSAGE_DIRECT_ATTRIBUTE  |
                                    gdef.ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE)


    @staticmethod
    def _get_required_buffer_size(flags):
        res = gdef.DWORD()
        try:
            windows.winproxy.AlpcInitializeMessageAttribute(flags, None, 0, res)
        except windows.generated_def.ntstatus.NtStatusException as e:
            # Buffer too small: osef
            return res.value
        return res.value

    def is_allocated(self, attribute):
        """Return ``True`` if ``attribute`` is allocated"""
        return bool(self.AllocatedAttributes & attribute)

    def is_valid(self, attribute):
        """Return ``True`` if ``attribute`` is valid"""
        return bool(self.ValidAttributes & attribute)

    def get_attribute(self, attribute):
        if not self.is_allocated(attribute):
            raise ValueError("Cannot get non-allocated attribute <{0}>".format(attribute))
        offset = ctypes.sizeof(self)
        for sflag, struct in self.ATTRIBUTE_BY_FLAG:
            if sflag == attribute:
                # print("Attr {0:#x} was at offet {1:#x}".format(attribute, offset))
                return struct.from_address(ctypes.addressof(self) + offset)
            elif self.is_allocated(sflag):
                offset += ctypes.sizeof(struct)
        raise ValueError("ALPC Attribute <{0}> not found :(".format(attribute))

    def _extract_alpc_attributes_values(self, value):
        attrs = []
        for mask in (1 << i for i in range(64)):
            if value & mask:
                attrs.append(mask)
        return [KNOWN_ALPC_ATTRIBUTES_MAPPING[x] for x in attrs]

    @property
    def valid_list(self):
        """The list of valid attributes

            :type: [:class:`~windows.generated_def.Flag`]
        """
        return self._extract_alpc_attributes_values(self.ValidAttributes)

    @property
    def allocated_list(self):
        """The list of allocated attributes

            :type: [:class:`~windows.generated_def.Flag`]
        """
        return self._extract_alpc_attributes_values(self.AllocatedAttributes)


AlpcSection = namedtuple("AlpcSection", ["handle", "size"])

class AlpcTransportBase(object):
    def send_receive(self, alpc_message, receive_msg=None, flags=gdef.ALPC_MSGFLG_SYNC_REQUEST, timeout=None):
        """Send and receive a message with ``flags``.

            :param alpc_message: The message to send. If ``alpc_message`` is a :class:`str` it build an AlpcMessage with the message as data.
            :type alpc_message: AlpcMessage or str
            :param receive_msg: The message to send. If ``receive_msg`` is a ``None`` it create and return a simple :class:`AlpcMessage`
            :type receive_msg: AlpcMessage or None
            :param int flags: The flags for :func:`NtAlpcSendWaitReceivePort`
        """
        if isinstance(alpc_message, windows.pycompat.anybuff):
            raw_alpc_message = alpc_message
            alpc_message = AlpcMessage(max(0x1000, len(alpc_message) + 0x200))
            alpc_message.port_message.data = raw_alpc_message

        if receive_msg is None:
            receive_msg = AlpcMessage(DEFAULT_MESSAGE_SIZE)
        receive_size = gdef.SIZE_T(receive_msg.port_message_buffer_size)
        winproxy.NtAlpcSendWaitReceivePort(self.handle, flags, alpc_message.port_message, alpc_message.attributes, receive_msg.port_message, receive_size, receive_msg.attributes, timeout)
        return receive_msg

    def send(self, alpc_message, flags=0):
        """Send the ``alpc_message`` with ``flags``

            :param alpc_message: The message to send. If ``alpc_message`` is a :class:`str` it build an AlpcMessage with the message as data.
            :type alpc_message: AlpcMessage or str
            :param int flags: The flags for :func:`NtAlpcSendWaitReceivePort`
        """
        if isinstance(alpc_message, windows.pycompat.anybuff):
            raw_alpc_message = alpc_message
            alpc_message = AlpcMessage(max(0x1000, len(alpc_message) + 0x200))
            alpc_message.port_message.data = raw_alpc_message
        winproxy.NtAlpcSendWaitReceivePort(self.handle, flags, alpc_message.port_message, alpc_message.attributes, None, None, None, None)

    def recv(self, receive_msg=None, flags=0):
        """Receive a message into ``alpc_message`` with ``flags``.

            :param receive_msg: The message to send. If ``receive_msg`` is a ``None`` it create and return a simple :class:`AlpcMessage`
            :type receive_msg: AlpcMessage or None
            :param int flags: The flags for :func:`NtAlpcSendWaitReceivePort`
        """
        if receive_msg is None:
            receive_msg = AlpcMessage(DEFAULT_MESSAGE_SIZE)
        receive_size = gdef.SIZE_T(receive_msg.port_message_buffer_size)
        winproxy.NtAlpcSendWaitReceivePort(self.handle, flags, None, None, receive_msg.port_message, receive_size, receive_msg.attributes, None)
        return receive_msg

    def _close_port(self, port_handle):
        windows.winproxy.NtAlpcDisconnectPort(port_handle, 0)
        windows.winproxy.CloseHandle(port_handle)



class AlpcClient(AlpcTransportBase):
    "An ALPC client able to connect to a port and send/receive messages"

    def __init__(self, port_name=None):
        """Init the :class:`AlpcClient` automatically connect to ``port_name`` using default values if given"""
        self.handle = None
        self.port_name = None #: The name of the ALPC port the client is connect to.
        if port_name is not None:
            x = self.connect_to_port(port_name, "")

    def _alpc_port_to_unicode_string(self, name):
        return gdef.UNICODE_STRING.from_string(name)

    def connect_to_port(self, port_name, connect_message=None,
                                port_attr=None, port_attr_flags=0x10000, obj_attr=None,
                                flags=gdef.ALPC_MSGFLG_SYNC_REQUEST, timeout=None):
        """Connect to the ALPC port ``port_name``. Most of the parameters have defauls value is ``None`` is passed.

            :param AlpcMessage connect_message: The message send with the connection request, if not ``None`` the function will return an :class:`AlpcMessage`
            :param ALPC_PORT_ATTRIBUTES port_attr: The port attributes, one with default value will be used if this parameter is ``None``
            :param int port_attr_flags: ``ALPC_PORT_ATTRIBUTES.Flags`` used if ``port_attr`` is ``None`` (MUTUALY EXCLUSINVE WITH ``port_attr``)
            :param OBJECT_ATTRIBUTES obj_attr: The attributes of the port (can be None)
            :param int flags: The flags for :func:`NtAlpcConnectPort`
            :param int timeout: The timeout of the request
        """
        # TODO raise on mutual exclusive parameter
        if self.handle is not None:
            raise ValueError("Client already connected")
        handle = gdef.HANDLE()
        port_name_unicode = self._alpc_port_to_unicode_string(port_name)

        if port_attr is None:
            port_attr = gdef.ALPC_PORT_ATTRIBUTES()
            port_attr.Flags = port_attr_flags # Flag qui fonctionne pour l'UAC
            port_attr.MaxMessageLength = DEFAULT_MESSAGE_SIZE
            port_attr.MemoryBandwidth = 0
            port_attr.MaxPoolUsage = 0xffffffff
            port_attr.MaxSectionSize = 0xffffffff
            port_attr.MaxViewSize = 0xffffffff
            port_attr.MaxTotalSectionSize = 0xffffffff
            port_attr.DupObjectTypes = 0xffffffff

            port_attr.SecurityQos.Length = ctypes.sizeof(port_attr.SecurityQos)
            port_attr.SecurityQos.ImpersonationLevel = gdef.SecurityImpersonation
            port_attr.SecurityQos.ContextTrackingMode = 0
            port_attr.SecurityQos.EffectiveOnly = 0

        if connect_message is None:
            send_msg = None
            send_msg_attr = None
            buffersize = None
        elif isinstance(connect_message, windows.pycompat.anybuff):
            buffersize = gdef.DWORD(len(connect_message) + 0x1000)
            send_msg = AlpcMessagePort.from_buffer_size(buffersize.value)
            send_msg.data = connect_message
            send_msg_attr = MessageAttribute.with_all_attributes()
        elif isinstance(connect_message, AlpcMessage):
            send_msg = connect_message.port_message
            send_msg_attr = connect_message.attributes
            buffersize = gdef.DWORD(connect_message.port_message_buffer_size)
        else:
            raise ValueError("Don't know how to send <{0!r}> as connect message".format(connect_message))

        receive_attr = MessageAttribute.with_all_attributes()
        winproxy.NtAlpcConnectPort(handle, port_name_unicode, obj_attr, port_attr, flags, None, send_msg, buffersize, send_msg_attr, receive_attr, timeout)
        # If send_msg is not None, it contains the ClientId.UniqueProcess : PID of the server :)
        self.handle = handle.value
        self.port_name = port_name
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

    def disconnect(self):
        if self.handle:
            self._close_port(self.handle)

    def __del__(self):
        if sys.path is not None:
            self.disconnect()


class AlpcServer(AlpcTransportBase):
    """An ALPC server able to create a port, accept connections and send/receive messages"""

    def __init__(self, port_name=None):
        self.port_name = None
        self.communication_port_list = []
        self.handle = None
        if port_name is not None:
            self.create_port(port_name)

    def _alpc_port_to_unicode_string(self, name):
        return gdef.UNICODE_STRING.from_string(name)

    def create_port(self, port_name, msglen=None, port_attr_flags=0, obj_attr=None, port_attr=None):
        """Create the ALPC port ``port_name``. Most of the parameters have defauls value is ``None`` is passed.

            :param str port_name: The port's name to create.
            :param int msglen: ``ALPC_PORT_ATTRIBUTES.MaxMessageLength`` used if ``port_attr`` is ``None`` (MUTUALY EXCLUSINVE WITH ``port_attr``)
            :param int port_attr_flags: ``ALPC_PORT_ATTRIBUTES.Flags`` used if ``port_attr`` is ``None`` (MUTUALY EXCLUSINVE WITH ``port_attr``)
            :param OBJECT_ATTRIBUTES obj_attr: The attributes of the port, one with default value will be used if this parameter is ``None``
            :param ALPC_PORT_ATTRIBUTES port_attr: The port attributes, one with default value will be used if this parameter is ``None``
        """
        # TODO raise on mutual exclusive parameter (port_attr + port_attr_flags | obj_attr + msglen)
        handle = gdef.HANDLE()
        raw_name =  port_name
        if not raw_name.startswith("\\"):
            raw_name = "\\" + port_name
        port_name = self._alpc_port_to_unicode_string(raw_name)

        if msglen is None:
            msglen = DEFAULT_MESSAGE_SIZE
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
            port_attr.Flags = port_attr_flags
            # port_attr.Flags = 0x2080000
            # port_attr.Flags = 0x90000
            port_attr.MaxMessageLength = msglen
            port_attr.MemoryBandwidth = 0
            port_attr.MaxPoolUsage = 0xffffffff
            port_attr.MaxSectionSize = 0xffffffff
            port_attr.MaxViewSize = 0xffffffff
            port_attr.MaxTotalSectionSize = 0xffffffff
            port_attr.DupObjectTypes = 0xffffffff
            # windows.utils.print_ctypes_struct(port_attr, "   - PORT_ATTR", hexa=True)

        winproxy.NtAlpcCreatePort(handle, obj_attr, port_attr)
        self.port_name = raw_name
        self.handle = handle.value

    def accept_connection(self, msg, port_attr=None, port_context=None):
        """Accept the connection for a ``LPC_CONNECTION_REQUEST`` message.
            ``msg.MessageId`` must be the same as the connection requesting message.

            :param AlpcMessage msg: The response message.
            :param ALPC_PORT_ATTRIBUTES port_attr: The attributes of the port, one with default value will be used if this parameter is ``None``
            :param PVOID port_context: A value that will be copied in ``ALPC_CONTEXT_ATTR.PortContext`` of every message on this connection.

        """
        rhandle = gdef.HANDLE()

        if port_attr is None:
            port_attr = gdef.ALPC_PORT_ATTRIBUTES()
            port_attr.Flags = 0x80000
            # port_attr.Flags = 0x80000 + 0x2000000
            # port_attr.Flags =  0x2000000
            port_attr.MaxMessageLength = DEFAULT_MESSAGE_SIZE
            port_attr.MemoryBandwidth = 0
            port_attr.MaxPoolUsage = 0xffffffff
            port_attr.MaxSectionSize = 0xffffffff
            port_attr.MaxViewSize = 0xffffffff
            port_attr.MaxTotalSectionSize = 0xffffffff
            port_attr.DupObjectTypes = 0xffffffff
        # windows.utils.print_ctypes_struct(port_attr, "   - CONN_PORT_ATTR", hexa=True)
        winproxy.NtAlpcAcceptConnectPort(rhandle, self.handle, 0, None, port_attr, port_context, msg.port_message, None, True)
        self.communication_port_list.append(rhandle.value)
        return msg

    def disconnect(self):
        if self.handle:
            self._close_port(self.handle)
        for com_port_handle in self.communication_port_list:
            self._close_port(com_port_handle)

    # TODO: add an API to close a communication port ?

    def __del__(self):
        if sys.path is not None:
            self.disconnect()