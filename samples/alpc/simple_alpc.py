import multiprocessing

import windows.alpc
from windows.generated_def import LPC_CONNECTION_REQUEST, LPC_REQUEST

PORT_NAME = r"\RPC Control\PythonForWindowsPORT"


def alpc_server():
    server = windows.alpc.AlpcServer(PORT_NAME) # Create the ALPC Port
    print("[SERV] PORT <{0}> CREATED".format(PORT_NAME))

    msg = server.recv() # Wait for a message
    print("[SERV] Message type = {0:#x}".format(msg.type))
    print("[SERV] Received data: <{0}>".format(msg.data))
    assert msg.type & 0xfff  == LPC_CONNECTION_REQUEST # Check that message is a connection request
    print("[SERV] Connection request")
    server.accept_connection(msg)

    msg = server.recv() # Wait for a real message
    print ""
    print("[SERV] Received message: <{0}>".format(msg.data))
    print("[SERV] Message type = {0:#x}".format(msg.type))
    assert msg.type & 0xfff  == LPC_REQUEST
    # We can reply by two ways:
    #    - Send the same message with modified data
    #    - Recreate a Message and copy the MessageId
    msg.data = "REQUEST '{0}' DONE".format(msg.data)
    server.send(msg)



def alpc_client():
    print("Client pid = {0}".format(windows.current_process.pid))
    # Creation an 'AlpcClient' with a port name will connect to the port with an empty message
    client = windows.alpc.AlpcClient(PORT_NAME)
    print("[CLIENT] Connected: {0}".format(client))
    # Send a message / wait for the response
    response = client.send_receive("Hello world !")
    print("[CLIENT] Response: <{0}>".format(response.data))
    # You can also send message without waiting for a response with 'client.send'


if __name__ == "__main__":
    proc = multiprocessing.Process(target=alpc_server, args=())
    proc.start()
    import time; time.sleep(0.5)
    alpc_client()
    print("BYE")
    proc.terminate()