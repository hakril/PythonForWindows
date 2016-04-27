import sys
import os.path
import socket
sys.path.append(os.path.abspath(__file__ + "\..\.."))

import windows

if not windows.utils.check_is_elevated():
    print("!!! Demo will fail because closing a connection require elevated process !!!")

print("Working on ipv4")
conns = windows.system.network.ipv4

print("== Listening ==")
print("Some listening connections: {0}".format([c for c in conns if not c.established][:3]))
print("Listening ports are : {0}".format([c.local_port for c in conns if not c.established]))

print("== Established ==")
print("Some established connections: {0}".format([c for c in conns if c.established][:3]))

TARGET_HOST = "localhost"
TARGET_PORT = 80
print("== connection to {0}:{1} ==".format(TARGET_HOST, TARGET_PORT))
s = socket.create_connection((TARGET_HOST, TARGET_PORT))

our_connection = [c for c in windows.system.network.ipv4 if c.established and c.remote_port == TARGET_PORT and c.remote_addr == s.getpeername()[0]]

print("Our connection is {0}".format(our_connection))
print("Sending YOP")
s.send("YOP")
print("Closing socket")
our_connection[0].close()
print("Sending LAIT")
s.send("LAIT")