import windows
from windows import winproxy
import windows.generated_def as gdef

import _multiprocessing

# Inspired from 'multiprocessing\connection.py'

def full_pipe_address(addr):
    """Return the full address of the pipe `addr`"""
    if addr.startswith("\\\\"):
        return addr
    return r"\\.\pipe\{addr}".format(addr=addr)

class PipeConnection(object): # Cannot inherit: crash the interpreter
    """A wrapper arround :class:`_multiprocessing.PipeConnection` able to work as a ContextManager"""
    BUFFER_SIZE = 0x2000

    def __init__(self, connection, name=None, server=False):
        self.handle = connection.fileno()
        self.connection = connection
        self.name = name
        self.server = server

    @classmethod
    def from_handle(cls, phandle, *args, **kwargs):
        """Create a :class:`PipeConnection` from pipe handle `phandle`"""
        connection = _multiprocessing.PipeConnection(phandle)
        return cls(connection, *args, **kwargs)

    @classmethod
    def create(cls, addr):
        """Create a namedpipe pipe ``addr``

        :returns type: :class:`PipeConnection`
        """
        addr = full_pipe_address(addr)
        pipehandle = winproxy.CreateNamedPipeA(
            addr, gdef.PIPE_ACCESS_DUPLEX,
            gdef.PIPE_TYPE_MESSAGE | gdef.PIPE_READMODE_MESSAGE |
            gdef.PIPE_WAIT,
            gdef.PIPE_UNLIMITED_INSTANCES, cls.BUFFER_SIZE, cls.BUFFER_SIZE,
            gdef.NMPWAIT_WAIT_FOREVER, None
            )
        return cls.from_handle(pipehandle, name=addr, server=True)

    @classmethod
    def connect(cls, addr):
        """Connect to the named pipe ``addr``

        :returns type: :class:`PipeConnection`
        """
        addr = full_pipe_address(addr)
        pipehandle = winproxy.CreateFileA(addr, gdef.GENERIC_READ | gdef.GENERIC_WRITE, 0, None, gdef.OPEN_EXISTING, 0, None)
        winproxy.SetNamedPipeHandleState(pipehandle, gdef.ULONG(gdef.PIPE_READMODE_MESSAGE), None, None)
        return cls.from_handle(pipehandle, name=addr, server=False)

    def send(self, *args, **kwargs):
        """Send an object on the pipe"""
        return self.connection.send(*args, **kwargs)

    def recv(self, *args, **kwargs):
        """Send an object from the pipe"""
        return self.connection.recv(*args, **kwargs)

    def wait_connection(self):
        """Wait for a client process to connect to the named pipe"""
        return winproxy.ConnectNamedPipe(self.handle, None)

    def close(self):
        """Close the handle of the pipe"""
        self.connection.close()
        self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.close()

    def __repr__(self):
        return """<{0} name="{1}" server={2}>""".format(type(self).__name__, self.name, self.server)


connect = PipeConnection.connect
create = PipeConnection.create

def send_object(addr, obj):
    """Send `obj` on pipe ``addr``"""
    with connect(addr) as np:
        np.send(obj)
    return None

def recv_object(addr):
    """Receive an object from pipe ``addr``"""
    with create(addr) as np:
        np.wait_connection()
        return np.recv()