import multiprocessing

import windows.alpc
from windows.generated_def import LPC_CONNECTION_REQUEST, LPC_REQUEST

PORT_NAME = r"\RPC Control\YOLOPORT"

def alpc_server():
    server = windows.alpc.AlpcServer(PORT_NAME) # NtAlpcCreatePort
    print("[SERV] PORT CREATED")
    msg = server.recv() # NtAlpcSendWaitReceivePort (send_msg = None)
    print("[SERV] Message type = {0:#x}".format(msg.u2.s2.Type))
    print("[SERV] Received data: <{0}>".format(msg.data))
    if msg.type & 0xfff & LPC_CONNECTION_REQUEST:
        print("[SERV] Connection request")
        msg.data = "WOKAY"
        server.accept_connection(msg) # NtAlpcAcceptConnectPort
    msg = server.recv() # NtAlpcSendWaitReceivePort (send_msg = None)
    print("[SERV] Received message")
    print("[SERV] Message type = {0:#x}".format(msg.u2.s2.Type))
    if msg.type & 0xfff & LPC_REQUEST:
        print("[SERV] ALPC request: <{0}>".format(msg.data))
        # We can reply by to way:
        #    - Send the same message with modified data
        #    - Recreate a Message and copy the MessageId
        msg.data = "REQUEST '{0}' DONE".format(msg.data)
        server.send(msg)


def alpc_client():
    client = windows.alpc.AlpcClient()
    connect_response = client.connect_to_port(PORT_NAME, "COUCOU") # NtAlpcConnectPort
    print("[CLIENT] Connected: {0}".format(connect_response.data))
    print("[CLIENT] Send Message <POUET>")
    response = client.send_receive("POUET") # NtAlpcSendWaitReceivePort
    print("[CLIENT] Server response: <{0}>".format(response.data))


if __name__ == "__main__":
    proc = multiprocessing.Process(target=alpc_server, args=())
    proc.start()
    import time; time.sleep(0.5)
    alpc_client()
    print("BYE")