import windows
from windows import winproxy
import ctypes
import socket
import struct

from windows.generated_def.winstructs import *
from windows.generated_def.windef import *


class TCP4Connection(MIB_TCPROW_OWNER_PID):

    @property
    def established(self):
        """``True`` if connection is established else it's a listening socket"""
        return self.dwState == MIB_TCP_STATE_ESTAB

    @property
    def remote_port(self):
        """:type: :class:`int`"""
        if not self.established:
            return None
        return socket.ntohs(self.dwRemotePort)

    @property
    def local_port(self):
        """:type: :class:`int`"""
        return socket.ntohs(self.dwLocalPort)

    @property
    def local_addr(self):
        """Local address IP (x.x.x.x)

        :type: :class:`str`"""
        return socket.inet_ntoa(struct.pack("<I", self.dwLocalAddr))

    @property
    def remote_addr(self):
        """remote address IP (x.x.x.x)

        :type: :class:`str`"""
        if not self.established:
            return None
        return socket.inet_ntoa(struct.pack("<I", self.dwRemoteAddr))

    @property
    def remote_proto(self):
        """Identification of the protocol associated with the remote port.
           Equals ``remote_port`` if no protocol is associated with it.

           :type: :class:`str` or :class:`int`
        """
        try:
            return socket.getservbyport(self.remote_port, 'tcp')
        except socket.error:
            return self.remote_port

    @property
    def remote_host(self):
        """Identification of the remote hostname.
           Equals ``remote_addr`` if the resolution fails

           :type: :class:`str` or :class:`int`
        """

        try:
            return socket.gethostbyaddr(self.remote_addr)
        except socket.error:
            return self.remote_addr

    def close(self):
        """Close the connection <require elevated process>"""
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
        """``True`` if connection is established else it's a listening socket"""
        return self.dwState == MIB_TCP_STATE_ESTAB

    @property
    def remote_port(self):
        """:type: :class:`int`"""
        if not self.established:
            return None
        return socket.ntohs(self.dwRemotePort)

    @property
    def local_port(self):
        """:type: :class:`int`"""
        return socket.ntohs(self.dwLocalPort)

    @property
    def local_addr(self):
        """Local address IP

        :type: :class:`str`"""
        return self._str_ipv6_addr(self.ucLocalAddr)

    @property
    def remote_addr(self):
        """remote address IP

        :type: :class:`str`"""
        if not self.established:
            return None
        return self._str_ipv6_addr(self.ucRemoteAddr)

    @property
    def remote_proto(self):
        """Equals to ``self.remote_port`` for Ipv6"""
        return self.remote_port

    @property
    def remote_host(self):
        """Equals to ``self.remote_addr`` for Ipv6"""
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
    """List of TCP IPv4 socket (connection and listening)

        :type: [:class:`TCP4Connection`]"""

    ipv6 = property(lambda self: self._get_tcp_ipv6_sockets())
    """List of TCP IPv6 socket (connection and listening)

      :type: [:class:`TCP6Connection`]
    """
