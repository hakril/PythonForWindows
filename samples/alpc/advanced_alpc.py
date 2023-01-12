import sys
import multiprocessing

import windows.alpc
from windows.generated_def import LPC_CONNECTION_REQUEST, LPC_REQUEST
import windows.generated_def as gdef

import ctypes
import tempfile

PORT_NAME = r"\RPC Control\PythonForWindowsPORT_2"
PORT_CONTEXT = 0x11223344


def full_alpc_server():
    print("server pid = {0}".format(windows.current_process.pid))
    server = windows.alpc.AlpcServer(PORT_NAME)
    print("[SERV] PORT <{0}> CREATED".format(PORT_NAME))
    msg = server.recv()
    print("[SERV] == Message received ==")
    if msg.type & 0xfff == LPC_CONNECTION_REQUEST:
        print(" * ALPC connection request: <{0}>".format(msg.data.decode()))
        msg.data = b"Connection message response"
        server.accept_connection(msg, port_context=PORT_CONTEXT)
    else:
        raise ValueError("Expected connection")

    while True:
        msg = server.recv()
        print("[SERV] == Message received ==")
        # print("       * Data: {0}".format(msg.data))
        # print("[SERV] RECV Message type = {0:#x}".format(msg.type))
        # print("[SERV] RECV Message Valid ATTRS = {0:#x}".format(msg.attributes.ValidAttributes))
        # print("[SERV] RECV Message ATTRS = {0:#x}".format(msg.attributes.AllocatedAttributes))
        if msg.type & 0xfff == LPC_REQUEST:
            print(" * ALPC request: <{0}>".format(msg.data.decode()))
            print(" * view_is_valid <{0}>".format(msg.view_is_valid))
            if msg.view_is_valid:
                print("   * message view attribute:")
                windows.utils.print_ctypes_struct(msg.view_attribute, "       - VIEW", hexa=True)
                view_data = windows.current_process.read_string(msg.view_attribute.ViewBase)
                print("   * Reading view content: <{0}>".format(view_data))
                # Needed in Win7 - TODO: why is there a different behavior ?
                msg.attributes.ValidAttributes -= gdef.ALPC_MESSAGE_VIEW_ATTRIBUTE
            print(" * security_is_valid <{0}>".format(msg.security_is_valid))
            print(" * handle_is_valid <{0}>".format(msg.handle_is_valid))
            if msg.handle_is_valid:
                if msg.handle_attribute.Handle:
                    print("   * message handle attribute:")
                    windows.utils.print_ctypes_struct(msg.handle_attribute, "       - HANDLE", hexa=True)
                    if msg.handle_attribute.ObjectType == 1:
                        f = windows.utils.create_file_from_handle(msg.handle_attribute.Handle)
                        print("   - File: {0}".format(f))
                        print("   - content: <{0}>".format(f.read()))
                    else:
                        print("  - unknow object type == {0}".format(msg.handle_attribute.ObjectType))
                msg.attributes.ValidAttributes -= gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE

            print(" * context_is_valid <{0}>".format(msg.context_is_valid))
            if msg.context_is_valid:
                print("   * message context attribute:")
                windows.utils.print_ctypes_struct(msg.context_attribute, "     - CTX", hexa=True)

            if msg.attributes.ValidAttributes & gdef.ALPC_MESSAGE_TOKEN_ATTRIBUTE:
                print(" * message token attribute:")
                token_struct = msg.attributes.get_attribute(gdef.ALPC_MESSAGE_TOKEN_ATTRIBUTE)
                windows.utils.print_ctypes_struct(token_struct, "   - TOKEN", hexa=True)

            # We can reply by to way:
            #    - Send the same message with modified data
            #    - Recreate a Message and copy the MessageId
            msg.data = "REQUEST '{0}' DONE".format(msg.data.decode()).encode()
            sys.stdout.flush()
            server.send(msg)
        else:
            print(ValueError("Unexpected message type <{0}>".format(msg.type & 0xfff)))


def send_message_with_handle(client):
    print("")
    print("[Client] == Sending a message with a handle ==")

    # Craft a file with some data
    f = tempfile.NamedTemporaryFile()
    f.write(b"Tempfile data <3")
    f.seek(0)

    # New message with a Handle
    msg = windows.alpc.AlpcMessage()
    msg.attributes.ValidAttributes |= gdef.ALPC_MESSAGE_HANDLE_ATTRIBUTE
    msg.handle_attribute.Flags = gdef.ALPC_HANDLEFLG_DUPLICATE_SAME_ACCESS
    msg.handle_attribute.Handle = windows.utils.get_handle_from_file(f)
    msg.handle_attribute.ObjectType = 0
    msg.handle_attribute.DesiredAccess = 0
    msg.data = b"some message with a file"
    client.send_receive(msg)

def send_message_with_view(client):
    print("")
    print("[Client] == Sending a message with a view ==")

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
    msg.data = b"some message with a view"
    windows.current_process.write_memory(view.ViewBase, b"The content of the view :)\x00")
    client.send_receive(msg)

def alpc_client():
    print("Client pid = {0}".format(windows.current_process.pid))
    client = windows.alpc.AlpcClient()

    # You can create a non-connected AlpcClient and send a custom
    # 'AlpcMessage' for complexe alpc port connection.
    connect_message = windows.alpc.AlpcMessage()
    connect_message.data = b"Connection request client message"
    print("[CLIENT] == Connecting to port ==")
    connect_response = client.connect_to_port(PORT_NAME, connect_message)
    print("[CLIENT] Connected with response: <{0}>".format(connect_response.data.decode()))

    # AlpcClient send/recv/send_receive methods accept both string or
    # AlpcMessage for complexe message.
    print("")
    print("[CLIENT] == Sending a message ==")
    msg = windows.alpc.AlpcMessage()
    msg.data = b"Complex Message 1"
    print(" * Sending Message <{0}>".format(msg.data.decode()))
    response = client.send_receive(msg)
    print("[CLIENT] Server response: <{0}>".format(response.data.decode()))
    print("[CLIENT] RESP Message Valid ATTRS = {0}".format(response.valid_attributes))

    send_message_with_handle(client)
    send_message_with_view(client)
    sys.stdout.flush()


if __name__ == "__main__":
    proc = multiprocessing.Process(target=full_alpc_server, args=())
    proc.start()
    import time; time.sleep(0.5)
    alpc_client()
    import time; time.sleep(0.5)
    print("BYE")
    proc.terminate()