import ctypes

import windows
from windows import winproxy
from windows import generated_def as gn

ALPC_MSGFLG_REPLY_MESSAGE = 0x1
ALPC_MSGFLG_LPC_MODE = 0x2
ALPC_MSGFLG_RELEASE_MESSAGE = 0x10000
ALPC_MSGFLG_SYNC_REQUEST = 0x20000
ALPC_MSGFLG_WAIT_USER_MODE = 0x100000
ALPC_MSGFLG_WAIT_ALERTABLE = 0x200000
ALPC_MSGFLG_WOW64_CALL = 0x80000000

ALPC_MESSAGE_SECURITY_ATTRIBUTE = 0x80000000
ALPC_MESSAGE_VIEW_ATTRIBUTE = 0x40000000
ALPC_MESSAGE_CONTEXT_ATTRIBUTE = 0x20000000
ALPC_MESSAGE_HANDLE_ATTRIBUTE = 0x10000000



class AlpcMessage(gn.PORT_MESSAGE):
    def __new__(cls, buffersize):
        size = ctypes.sizeof(cls) + buffersize
        buffer = ctypes.c_buffer(size)
        self = cls.from_buffer(buffer)
        self.raw_buffer = buffer
        return self

    def __init__(self, buffersize):
        self.u1.s1.TotalLength = buffersize + ctypes.sizeof(self)
        self.u1.s1.DataLength = buffersize
        return super(AlpcMessage, self).__init__()

    def read_data(self):
        return self.raw_buffer[ctypes.sizeof(self):ctypes.sizeof(self) + self.u1.s1.DataLength]

    def write_data(self, data):
        self.raw_buffer[ctypes.sizeof(self): ctypes.sizeof(self) + len(data)] = data

    data = property(read_data, write_data)

class MessageAttribute(gn.ALPC_MESSAGE_ATTRIBUTES):
    def __new__(cls, flags):
        size = cls._get_required_buffer_size(flags)
        buffer = ctypes.c_buffer(size)
        self = cls.from_buffer(buffer)
        self.raw_buffer = buffer
        return self

    def __init__(self, flags):
        res = gn.DWORD()
        winproxy.AlpcInitializeMessageAttribute(flags, self, len(self.raw_buffer), res)

    @staticmethod
    def _get_required_buffer_size(flags):
        res = gn.DWORD()
        try:
            windows.winproxy.AlpcInitializeMessageAttribute(flags, None, 0, res)
        except windows.generated_def.ntstatus.NtStatusException as e:
            # Buffer too small: osef
            return res.value
        return res.value


class AlpcPORT(object):
    def __init__(self, port_name, msglen=0x1000):
        self.port_name = port_name
        self.handle = self._create_port(port_name, msglen)

    def _create_port(self, port_name, msglen=0x1000):
        handle = gn.HANDLE()
        raw_name =  port_name
        if not raw_name.startswith("\\"):
            raw_name = "\\" + port_name
        utf16_len = len(raw_name) * 2
        port_name = gn.UNICODE_STRING(utf16_len, utf16_len, raw_name)

        obj_attr = gn.OBJECT_ATTRIBUTES()
        obj_attr.Length = ctypes.sizeof(obj_attr)
        obj_attr.RootDirectory = None
        obj_attr.ObjectName = ctypes.pointer(port_name)
        obj_attr.Attributes = 0
        obj_attr.SecurityDescriptor = None
        obj_attr.SecurityQualityOfService = None

        port_attr = gn.ALPC_PORT_ATTRIBUTES()
        port_attr.Flags = 0
        port_attr.MaxMessageLength = msglen
        port_attr.MemoryBandwidth = 0
        port_attr.MaxPoolUsage = 0

        winproxy.NtAlpcCreatePort(handle, obj_attr, port_attr)
        return handle.value

#class AlpcExchange(object):
#    def send_receive_data(port_handle, data):
#        raw_sendmsg = ctypes.c_buffer(0x1000)
#        size = gn.SIZE_T(0x1000)
#        sendmsg = ctypes.cast(raw_sendmsg, gn.PPORT_MESSAGE)
#        buffer = ctypes.c_buffer(0x200)
#        sendmsg_attr = ctypes.cast(buffer, gn.PALPC_MESSAGE_ATTRIBUTES)
#        res = gn.DWORD()
#        winproxy.AlpcInitializeMessageAttribute(ALPC_MESSAGE_CONTEXT_ATTRIBUTE + ALPC_MESSAGE_HANDLE_ATTRIBUTE + 1,  sendmsg_attr  , 0x200, res)
#
#        sendmsg = AlpcMessage(len(data))
#        sendmsg.data = data
#
#        size = gn.SIZE_T(0x1000)
#        receive = AlpcMessage(size.value)
#        buffer = ctypes.c_buffer(0x200)
#        receive_attr = ctypes.cast(buffer, gn.PALPC_MESSAGE_ATTRIBUTES)
#        res = gn.DWORD()
#
#        winproxy.NtAlpcSendWaitReceivePort(port_handle, ALPC_MSGFLG_SYNC_REQUEST, sendmsg, sendmsg_attr, receive, size, receive_attr, None)
#        return receive, receive_attr


def send_receive_data(port_handle, data):
    #sendmsg_attr = MessageAttribute(ALPC_MESSAGE_CONTEXT_ATTRIBUTE + ALPC_MESSAGE_HANDLE_ATTRIBUTE + 1)
    sendmsg_attr = MessageAttribute(0)
    sendmsg = AlpcMessage(len(data))
    sendmsg.data = data

    size = gn.SIZE_T(0x1000)
    receive = AlpcMessage(size.value)
    receive_attr = MessageAttribute(0)

    winproxy.NtAlpcSendWaitReceivePort(port_handle, ALPC_MSGFLG_SYNC_REQUEST, sendmsg, sendmsg_attr, receive, size, receive_attr, None)
    return receive_attr, receive

class AlpcClient(object):
    def __init__(self):
        self.portname = None
        self.handle = None

    def connect_to_port(self, port_name, connect_msg=None, maxmsglen=0x1000):
        if self.handle is not None:
            raise ValueError("Client already connected")
        handle = gn.HANDLE()

        #raw_name = "\\" + port_name
        raw_name = port_name
        utf16_len = len(raw_name) * 2

        port_name = gn.UNICODE_STRING(utf16_len, utf16_len, raw_name)

        # obj_attr = gn.OBJECT_ATTRIBUTES()
        # obj_attr.Length = ctypes.sizeof(obj_attr)
        # obj_attr.RootDirectory = None
        # obj_attr.ObjectName = None
        # obj_attr.Attributes = 0
        # obj_attr.SecurityDescriptor = None
        # obj_attr.SecurityQualityOfService = None

        obj_attr = None


        port_attr = gn.ALPC_PORT_ATTRIBUTES()
        port_attr.Flags = 0
        port_attr.MaxMessageLength = maxmsglen
        port_attr.MemoryBandwidth = 0
        port_attr.MaxPoolUsage = 0

        if True:
            port_attr.SecurityQos.Length = 12
            port_attr.SecurityQos.ImpersonationLevel = 2
            port_attr.SecurityQos.ContextTrackingMode = 0
            port_attr.SecurityQos.EffectiveOnly = 0


            #define ALPC_PORFLG_ALLOW_LPC_REQUESTS 0x20000 // rev
            #define ALPC_PORFLG_WAITABLE_PORT 0x40000 // dbg
            #define ALPC_PORFLG_SYSTEM_PROCESS 0x100000 // dbg

            #port_attr.MaxPoolUsage = 0
            port_attr.Flags = 0x10000 # Flag qui fonctionne pour l'UAC
            #  0x0010000 est le flag qui permet l'impersonation (en tout cas le pop UAC)
            #port_attr.MaxPoolUsage = 4294967295
            #port_attr.MaxSectionSize = 4294967295
            ##port_attr.MaxViewSize = 4294967295
            #port_attr.MaxTotalSectionSize = 4294967295
            #port_attr.DupObjectTypes = 4093

        # tst.Flags -> 34144256
        # tst.SecurityQos.Length -> 12
        # tst.SecurityQos.ImpersonationLevel -> SecurityImpersonation(0x2L)
        # tst.SecurityQos.ContextTrackingMode -> 0
        # tst.SecurityQos.EffectiveOnly -> 0
        # tst.MaxMessageLength -> 4096
        # tst.MemoryBandwidth -> 0
        # tst.MaxPoolUsage -> 4294967295
        # tst.MaxSectionSize -> 4294967295
        # tst.MaxViewSize -> 4294967295
        # tst.MaxTotalSectionSize -> 4294967295
        # tst.DupObjectTypes -> 4093


        if connect_msg is not None:
            size = len(connect_msg)
            send_msg = AlpcMessage(size)
            send_msg.data = connect_msg
            sendmsg_attr = MessageAttribute(0)
            receive_attr = MessageAttribute(0)
            receive_attr = None
            sendmsg_attr = None
            buffersize = gn.DWORD(len(send_msg.raw_buffer))
        else:
            size = None
            send_msg = None
            sendmsg_attr = None
            receive_attr = None
            buffersize = None

        #print(hex([0].AllocatedAttributes))
        #import pdb;pdb.set_trace()
        x = winproxy.NtAlpcConnectPort(handle, port_name,obj_attr, port_attr, ALPC_MSGFLG_SYNC_REQUEST, None, send_msg, buffersize, sendmsg_attr, receive_attr, None)

        self.handle = handle.value
        self.portname = port_name
        if connect_msg is not None:
            return send_msg

    def send_receive(self, data):
        return send_receive_data(self.handle, data)

class AlpcServer(object):
    def __init__(self, port_name):
        self.port = AlpcPORT(port_name)

    def wait_data(self):
        size = gn.SIZE_T(0x1000)
        receive = AlpcMessage(size.value)
        receive_attr = MessageAttribute(0)
        winproxy.NtAlpcSendWaitReceivePort(self.port.handle, 0, None, None, receive, size, receive_attr, None)
        return receive_attr, receive

    def accept_connection(self, msg):
        port_handle = self.port.handle
        rhandle = gn.HANDLE()

        ALPC_HANDLEFLG_DUPLICATE_INHERIT = 0x80000
        port_attr = gn.ALPC_PORT_ATTRIBUTES()
        port_attr.Flags = ALPC_HANDLEFLG_DUPLICATE_INHERIT
        port_attr.DupObjectTypes = 4
        port_attr.MaxMessageLength = 0x578
        port_attr.MemoryBandwidth = 0
        port_attr.MaxPoolUsage = 0x15E00

        winproxy.NtAlpcAcceptConnectPort(rhandle, port_handle, 0, None, port_attr, None, msg, None, 1)
        return rhandle.value, msg

    def send_receive(self, data):
        return send_receive_data(self.port.handle, data)

    def reply(self, reply_to_msg, reply_msg):
        port_handle = self.port.handle
        sendmsg = AlpcMessage(len(reply_msg))
        sendmsg.data = reply_msg
        sendmsg_attr = MessageAttribute(0)
        sendmsg.MessageId = reply_to_msg.MessageId
        winproxy.NtAlpcSendWaitReceivePort(port_handle, ALPC_MSGFLG_RELEASE_MESSAGE, sendmsg, None, None, None, None, None)
        return None, None

