import windows
import ctypes
import socket
import struct

from windows import winproxy
import windows.generated_def as gdef
from windows.com import interfaces as cominterfaces
from windows.generated_def.winstructs import *
from windows.generated_def.windef import *


class TCP4Connection(MIB_TCPROW_OWNER_PID):
    """A TCP4 socket (connected or listening)"""
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
        return winproxy.SetTcpEntry(ctypes.byref(closing))

    def __repr__(self):
        if not self.established:
            return "<TCP IPV4 Listening socket on {0}:{1}>".format(self.local_addr, self.local_port)
        return "<TCP IPV4 Connection {s.local_addr}:{s.local_port} -> {s.remote_addr}:{s.remote_port}>".format(s=self)


class TCP6Connection(MIB_TCP6ROW_OWNER_PID):
    """A TCP6 socket (connected or listening)"""
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

class Firewall(cominterfaces.INetFwPolicy2):
    """The windows firewall"""
    @property
    def rules(self):
        """The rules of the firewall

        :type: [:class:`FirewallRule`] -- A list of rule
        """
        ifw_rules = cominterfaces.INetFwRules()
        self.get_Rules(ifw_rules)

        nb_rules = gdef.LONG()
        ifw_rules.get_Count(nb_rules)

        unknw = cominterfaces.IUnknown()
        ifw_rules.get__NewEnum(unknw)

        pVariant = cominterfaces.IEnumVARIANT()
        unknw.QueryInterface(pVariant.IID, pVariant)

        count = gdef.ULONG()
        var = windows.com.Variant()

        rules = []
        for i in range(nb_rules.value):
            pVariant.Next(1, var, count)
            if not count.value:
                break
            rule = FirewallRule()
            idisp = var.asdispatch
            idisp.QueryInterface(rule.IID, rule)
            rules.append(rule)
        return rules

    @property
    def current_profile_types(self):
        """Mask of the profiles currently enabled

        :type: :class:`long`
        """
        cpt = gdef.LONG()
        self.get_CurrentProfileTypes(cpt)
        return cpt.value

    @property
    def enabled(self):
        """A maping of the active firewall profiles

        {

        ``NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN(0x1L)``: ``True`` or ``False``,

        ``NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE(0x2L)``: ``True`` or ``False``,

        ``NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC(0x4L)``: ``True`` or ``False``,

        }


        :type: :class:`dict`
        """
        profiles = [gdef.NET_FW_PROFILE2_DOMAIN, gdef.NET_FW_PROFILE2_PRIVATE, gdef.NET_FW_PROFILE2_PUBLIC]
        return {prof: self.enabled_for_profile_type(prof) for prof in profiles}


    def enabled_for_profile_type(self, profile_type):
        enabled = gdef.VARIANT_BOOL()
        self.get_FirewallEnabled(profile_type, enabled)
        return enabled.value



class FirewallRule(cominterfaces.INetFwRule):
    """A rule of the firewall"""
    @property
    def name(self):
        """Name of the rule

        :type: :class:`unicode`
        """
        name = gdef.BSTR()
        self.get_Name(name)
        return name.value

    @property
    def description(self):
        """Description of the rule

        :type: :class:`unicode`
        """
        description = gdef.BSTR()
        self.get_Description(description)
        return description.value

    @property
    def application_name(self):
        """Name of the application to which apply the rule

        :type: :class:`unicode`
        """
        applicationname = gdef.BSTR()
        self.get_ApplicationName(applicationname)
        return applicationname.value

    @property
    def service_name(self):
        """Name of the service to which apply the rule

        :type: :class:`unicode`
        """
        servicename = gdef.BSTR()
        self.get_ServiceName(servicename)
        return servicename.value

    @property
    def protocol(self):
        """Protocol to which apply the rule

        :type: :class:`long`
        """
        protocol = gdef.LONG()
        self.get_Protocol(protocol)
        return protocol.value

    @property
    def local_address(self):
        """Local address of the rule

        :type: :class:`unicode`
        """
        local_address = gdef.BSTR()
        self.get_LocalAddresses(local_address)
        return local_address.value

    @property
    def remote_address(self):
        """Remote address of the rule

        :type: :class:`unicode`
        """
        remote_address = gdef.BSTR()
        self.get_RemoteAddresses(remote_address)
        return remote_address.value

    @property
    def direction(self):
        """Direction of the rule, values might be:

            * ``NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN(0x1L)``
            * ``NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT(0x2L)``

        subclass of :class:`long`
        """
        direction = gdef.NET_FW_RULE_DIRECTION()
        self.get_Direction(direction)
        return direction.value

    @property
    def interface_types(self):
        """Types of interface of the rule

        :type: :class:`unicode`
        """
        interface_type = gdef.BSTR()
        self.get_InterfaceTypes(interface_type)
        return interface_type.value

    @property
    def local_port(self):
        """Local port of the rule

        :type: :class:`unicode`
        """
        local_port = gdef.BSTR()
        self.get_LocalPorts(local_port)
        return local_port.value

    @property
    def remote_port(self):
        """Remote port of the rule

        :type: :class:`unicode`
        """
        remote_port = gdef.BSTR()
        self.get_RemotePorts(remote_port)
        return remote_port.value

    @property
    def action(self):
        """Action of the rule, values might be:

            * ``NET_FW_ACTION_.NET_FW_ACTION_BLOCK(0x0L)``
            * ``NET_FW_ACTION_.NET_FW_ACTION_ALLOW(0x1L)``

        subclass of :class:`long`
        """
        action = gdef.NET_FW_ACTION()
        self.get_Action(action)
        return action.value

    @property
    def enabled(self):
        """``True`` if rule is enabled"""
        enabled = gdef.VARIANT_BOOL()
        self.get_Enabled(enabled)
        return enabled.value

    @property
    def grouping(self):
        """Grouping of the rule

        :type: :class:`unicode`
        """
        grouping = gdef.BSTR()
        self.get_RemotePorts(grouping)
        return grouping.value

    @property
    def icmp_type_and_code(self):
        icmp_type_and_code = gdef.BSTR()
        self.get_RemotePorts(icmp_type_and_code)
        return icmp_type_and_code.value

    def __repr__(self):
        return u'<{0} "{1}">'.format(type(self).__name__, self.name).encode("ascii", errors='backslashreplace')

class Network(object):
    NetFwPolicy2 = windows.com.IID.from_string("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD")

    @property
    def firewall(self):
        """The firewall of the system

        :type: :class:`Firewall`
        """
        windows.com.init()
        firewall = Firewall()
        windows.com.create_instance(self.NetFwPolicy2, firewall)
        return firewall

    @staticmethod
    def _get_tcp_ipv4_sockets():
        size = ctypes.c_uint(0)
        try:
            winproxy.GetExtendedTcpTable(None, ctypes.byref(size), ulAf=AF_INET)
        except winproxy.WinproxyError:
            pass  # Allow us to set size to the needed value
        buffer = (ctypes.c_char * size.value)()
        winproxy.GetExtendedTcpTable(buffer, ctypes.byref(size), ulAf=AF_INET)
        t = get_MIB_TCPTABLE_OWNER_PID_from_buffer(buffer)
        return list(t.table)

    @staticmethod
    def _get_tcp_ipv6_sockets():
        size = ctypes.c_uint(0)
        try:
            winproxy.GetExtendedTcpTable(None, ctypes.byref(size), ulAf=AF_INET6)
        except winproxy.WinproxyError:
            pass  # Allow us to set size to the needed value
        buffer = (ctypes.c_char * size.value)()
        winproxy.GetExtendedTcpTable(buffer, ctypes.byref(size), ulAf=AF_INET6)
        t = get_MIB_TCP6TABLE_OWNER_PID_from_buffer(buffer)
        return list(t.table)


    ipv4 = property(lambda self: self._get_tcp_ipv4_sockets())
    """List of TCP IPv4 socket (connection and listening)

        :type: [:class:`TCP4Connection`]"""

    ipv6 = property(lambda self: self._get_tcp_ipv6_sockets())
    """List of TCP IPv6 socket (connection and listening)

      :type: [:class:`TCP6Connection`]
    """
