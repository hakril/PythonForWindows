import windows
import windows.winproxy
import ctypes
import socket
import struct

from windows.generated_def.winstructs import *
from windows.generated_def.windef import *


class TCP4Connection(MIB_TCPROW_OWNER_PID):

    @property
    def established(self):
        return self.dwState == MIB_TCP_STATE_ESTAB

    @property
    def remote_port(self):
        return socket.ntohs(self.dwRemotePort)

    @property
    def local_port(self):
        return socket.ntohs(self.dwLocalPort)

    @property
    def local_addr(self):
        return socket.inet_ntoa(struct.pack("<I", self.dwLocalAddr))

    @property
    def remote_addr(self):
        return socket.inet_ntoa(struct.pack("<I", self.dwRemoteAddr))

    @property
    def remote_proto(self):
        try:
            return socket.getservbyport(self.remote_port, 'tcp')
        except socket.error:
            return self.remote_port

    @property
    def remote_host(self):
        try:
            return socket.gethostbyaddr(self.remote_addr)
        except socket.error:
            return self.remote_addr

    def close(self):
        closing = MIB_TCPROW()
        closing.dwState = MIB_TCP_STATE_DELETE_TCB
        closing.dwLocalAddr = self.dwLocalAddr
        closing.dwLocalPort = self.dwLocalPort
        closing.dwRemoteAddr = self.dwRemoteAddr
        closing.dwRemotePort = self.dwRemotePort
        return windows.winproxy.SetTcpEntry(ctypes.byref(closing))

    def __repr__(self):
        if not self.established:
            return "<TCP IPV4 Listening socket on {0}:{1}>".format(self.local_addr, self.local_port)
        return "<TCP IPV4 Connection {s.local_addr}:{s.local_port} -> {s.remote_addr}:{s.remote_port}>".format(s=self)


class TCP6Connection(MIB_TCP6ROW_OWNER_PID):
    @staticmethod
    def _str_ipv6_addr(addr):
        return ":".join(c.encode('hex') for c in addr)

    @property
    def established(self):
        return self.dwState == MIB_TCP_STATE_ESTAB

    @property
    def remote_port(self):
        return socket.ntohs(self.dwRemotePort)

    @property
    def local_port(self):
        return socket.ntohs(self.dwLocalPort)

    @property
    def local_addr(self):
        return self._str_ipv6_addr(self.ucLocalAddr)

    @property
    def remote_addr(self):
        return self._str_ipv6_addr(self.ucRemoteAddr)

    @property
    def remote_proto(self):
        return self.remote_port

    @property
    def remote_host(self):
        return self.remote_addr

    def close(self):
        raise NotImplementedError("Closing IPV6 connection non implemented")

    def __repr__(self):
        if not self.established:
            return "<TCP IPV6 Listening socket on {0}:{1}>".format(self.local_addr, self.local_port)
        return "<TCP IPV6 Connection {0}:{1} -> {2}:{3}>".format(self.local_addr, self.local_port, self.remote_addr, self.remote_port)


def get_MIB_TCPTABLE_OWNER_PID_from_buffer(buffer):
    x = windows.generated_def.winstructs.MIB_TCPTABLE_OWNER_PID.from_buffer(buffer)
    nb_entry = x.dwNumEntries

    class _GENERATED_MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
            _fields_ = [
                ("dwNumEntries", DWORD),
                ("table", TCP4Connection * nb_entry),
            ]

    return _GENERATED_MIB_TCPTABLE_OWNER_PID.from_buffer(buffer)


def get_MIB_TCP6TABLE_OWNER_PID_from_buffer(buffer):
    x = windows.generated_def.winstructs.MIB_TCP6TABLE_OWNER_PID.from_buffer(buffer)
    nb_entry = x.dwNumEntries

    # Struct _MIB_TCP6TABLE_OWNER_PID definitions
    class _GENERATED_MIB_TCP6TABLE_OWNER_PID(Structure):
            _fields_ = [
                ("dwNumEntries", DWORD),
                ("table", TCP6Connection * nb_entry),
            ]

    return _GENERATED_MIB_TCP6TABLE_OWNER_PID.from_buffer(buffer)




class Network(object):
    @staticmethod
    def _get_tcp_ipv4_sockets():
        size = ctypes.c_uint(0)
        try:
            windows.winproxy.GetExtendedTcpTable(None, ctypes.byref(size), ulAf=AF_INET)
        except windows.winproxy.IphlpapiError:
            pass  # Allow us to set size to the needed value
        buffer = (ctypes.c_char * size.value)()
        windows.winproxy.GetExtendedTcpTable(buffer, ctypes.byref(size), ulAf=AF_INET)
        t = get_MIB_TCPTABLE_OWNER_PID_from_buffer(buffer)
        return list(t.table)

    @staticmethod
    def _get_tcp_ipv6_sockets():
        size = ctypes.c_uint(0)
        try:
            windows.winproxy.GetExtendedTcpTable(None, ctypes.byref(size), ulAf=AF_INET6)
        except windows.winproxy.IphlpapiError:
            pass  # Allow us to set size to the needed value
        buffer = (ctypes.c_char * size.value)()
        windows.winproxy.GetExtendedTcpTable(buffer, ctypes.byref(size), ulAf=AF_INET6)
        t = get_MIB_TCP6TABLE_OWNER_PID_from_buffer(buffer)
        return list(t.table)


    ipv4 = property(lambda self: self._get_tcp_ipv4_sockets())
    ipv6 = property(lambda self: self._get_tcp_ipv6_sockets())
