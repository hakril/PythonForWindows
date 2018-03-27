import pytest
import threading
import time

import windows.alpc
import windows.generated_def as gdef

from pfwtest import *


def generate_client_server_test(client_function, server_function):
    def generated_test():
        th = threading.Thread(target=server_function, args=())
        th.start()
        time.sleep(0.5)
        client_function()
        th.join()
        return True
    return generated_test

PORT_NAME = r"\RPC Control\PythonForWindowsTestPort"
CLIENT_MESSAGE = "Message 1\x00\xffABCD"
SERVER_MESSAGE = "Message 2-" + "".join(chr(i) for i in range(256))

def alpc_simple_test_server():
    server = windows.alpc.AlpcServer(PORT_NAME)
    msg = server.recv()
    assert msg.type & 0xfff  == gdef.LPC_CONNECTION_REQUEST
    server.accept_connection(msg)
    msg = server.recv()
    assert msg.type & 0xfff  == gdef.LPC_REQUEST
    assert msg.data == CLIENT_MESSAGE
    msg.data = SERVER_MESSAGE
    server.send(msg)

def alpc_simple_test_client():
    client = windows.alpc.AlpcClient(PORT_NAME)
    response = client.send_receive(CLIENT_MESSAGE)
    assert response.data == SERVER_MESSAGE

test_simple_alpc = generate_client_server_test(alpc_simple_test_client, alpc_simple_test_server)


def send_message_with_view(client, message_data, view_data):
    # Create View
    section = client.create_port_section(0, 0, 0x4000)
    view = client.map_section(section[0], 0x4000)

    # New message with a View
    msg = windows.alpc.AlpcMessage(0x2000)
    msg.attributes.ValidAttributes |= gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE
    msg.view_attribute.Flags = 0
    msg.view_attribute.ViewBase = view.ViewBase
    msg.view_attribute.SectionHandle = view.SectionHandle
    msg.view_attribute.ViewSize = 0x4000
    msg.data = message_data
    windows.current_process.write_memory(view.ViewBase, view_data)
    return client.send_receive(msg)


CLIENT_VIEW_MESSAGE = "Message 1\x00\xffABCD"
CLIENT_VIEW_DATA = "Message Data-view" + "".join(chr(i) for i in range(256))


def alpc_view_test_server():
    server = windows.alpc.AlpcServer(PORT_NAME)
    msg = server.recv()
    assert msg.type & 0xfff  == gdef.LPC_CONNECTION_REQUEST
    server.accept_connection(msg)
    msg = server.recv()
    assert msg.type & 0xfff  == gdef.LPC_REQUEST
    assert msg.view_is_valid
    view_data = windows.current_process.read_memory(msg.view_attribute.ViewBase, len(CLIENT_VIEW_DATA))
    msg.attributes.ValidAttributes -= gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE
    assert view_data == CLIENT_VIEW_DATA
    assert msg.data == CLIENT_VIEW_MESSAGE
    msg.data = SERVER_MESSAGE
    server.send(msg)

def alpc_view_test_client():
    client = windows.alpc.AlpcClient(PORT_NAME)
    response = send_message_with_view(client, CLIENT_VIEW_MESSAGE, CLIENT_VIEW_DATA)
    assert response.data == SERVER_MESSAGE

test_view_alpc = generate_client_server_test(alpc_view_test_client, alpc_view_test_server)
