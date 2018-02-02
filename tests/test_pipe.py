import windows.pipe
from pfwtest import *

import time

PIPE_NAME = "PFW_Test_Pipe"

rcode_test_ipc_pipe = """
import windows
windows.pipe.send_object("{pipe}", {{'Hello': 2}})
"""

def test_ipc_pipe(proc32_64):
    with windows.pipe.create(PIPE_NAME) as np:
        proc32_64.execute_python(rcode_test_ipc_pipe.format(pipe=PIPE_NAME))
        obj = np.recv()
        assert obj == {'Hello': 2}


rcode_test_echo_pipe = """
import windows


with windows.pipe.create("{pipe}") as np:
    np.wait_connection()
    obj = np.recv()
    np.send(obj)
"""

def test_pipe_echo_server(proc32_64):
    t = proc32_64.execute_python_unsafe(rcode_test_echo_pipe.format(pipe=PIPE_NAME))
    time.sleep(0.5)
    assert not t.is_exit
    obj = {'MYPID': windows.current_process.pid}
    pipe = windows.pipe.connect(PIPE_NAME)
    pipe.send(obj)
    echoobj = pipe.recv()
    assert obj == echoobj

def test_pipe_recv_object(proc32_64):
    # not the good way to do the exchange (race possible)
    # Just for the sake of the test
    proc32_64.execute_python_unsafe(rcode_test_ipc_pipe.format(pipe=PIPE_NAME))
    obj = windows.pipe.recv_object(PIPE_NAME)
    assert obj == {'Hello': 2}

