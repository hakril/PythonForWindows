import windows.generated_def as gdef
import windows.winproxy
import ctypes


WEBSITE = b"perdu.com"
MESSAGE = b"""GET / HTTP/1.1\r\nHost: perdu.com\r\n\r\n"""

x = gdef.WSADATA()
windows.winproxy.WSAStartup(0x0202, x)

print("=== WSADATA ===")
windows.utils.sprint(x)

hints = gdef.ADDRINFOA()
hints.ai_family = gdef.AF_UNSPEC
hints.ai_socktype = gdef.SOCK_STREAM
hints.ai_protocol = gdef.IPPROTO_TCP

result = gdef.PADDRINFOA()
windows.winproxy.getaddrinfo(WEBSITE, b"80", hints, result);

print("=== PADDRINFOA ===")
windows.utils.sprint(result)


connect_socket = windows.winproxy.socket(result[0].ai_family, result[0].ai_socktype, result[0].ai_protocol)
res =  windows.winproxy.connect(connect_socket, result[0].ai_addr, result[0].ai_addrlen)
windows.winproxy.send(connect_socket, MESSAGE)

buf = ctypes.create_string_buffer(10000)
windows.winproxy.recv(connect_socket, buf)
print("Received:\n{0}".format(buf.value))

windows.winproxy.closesocket(connect_socket)
windows.winproxy.WSACleanup()