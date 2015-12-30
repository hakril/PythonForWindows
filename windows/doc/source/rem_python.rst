Remote Python Injection
***********************

It's possible to inject the python interpreter into remote process. All you need to do is to use the method :func:`windows.winobject.WinProcess.execute_python`.

Calling this function will trigger the interpreter injection and the python code execution.

For simpler interaction interaction with the remote python, you can an RPC master linked to the remote interpreter.

RPython 101
'''''''''''

RPython is a very simple Pythonic (I hope so) RPC slave-master. It's goal is to allow easy manipulation of a remote interpreter.

The only action up to the `slave` is the creation of it's `name_pool`: a namespace of object accessible by the `master`.
After that the `slave` will just wait for request and return the desired object.

All slave object seen by the master are proxy that redirect operation to the slave.

RPython RPC to remote process
'''''''''''''''''''''''''''''

For easy manipulation of a remote Python interpreter, you can use the RPCInjection module::

    import windows
    import RPCInjection
    calc = [x for x in windows.system.processes if x.name == "calc.exe"][0]
    master = RPCInjection.launch_remote_slave(calc)
    # Master is a RPC-master to a python interpreter in calc.exe
    master['windows']
    # <RemoteObj |<module 'windows' from 'C:\Users\hakril\Documents\Work\PythonForWindows\windows\__init__.pyc'>|>

    # This is a way to get our own (python.exe) pid
    windows.current_process.pid
    3624
    # This is a way to get the pid of calc.exe
    master['windows'].current_process
    # <RemoteObj |<windows.winobject.CurrentProcess object at 0x055E6250>|>
    master['windows'].current_process.pid
    5052
    # We can also play with the peb of the remote process
    master['windows'].current_process.peb
    # <RemoteObj |<windows.winobject.PEB object at 0x054A3DF0>|>
    master['windows'].current_process.peb.commandline
    # <RemoteObj |<WinUnicodeString ""C:\Windows\SysWOW64\calc.exe" " at 0x55e9850>|>


    # we can import new stuff

    x['json']
    # ...
    # RPython.exchange.RemoteKeyError:
    # ....
    # KeyError: u'json'
    x.imp('json')
    # <RemoteObj |None|>
    x['json']
    # <RemoteObj |<module 'json' from 'C:\Python27\Lib\json\__init__.pyc'>|>


.. note::

    The slave `name_pool` in RPCInjection is filled with :mod:`windows`, :mod:`__import__`, :mod:`ctypes` and :mod:`self` (the RemotePythonSlave object)

The master.RemotePython
'''''''''''''''''''''''

.. autoclass:: RPython.master.RemotePython

    .. py:method:: __getitem__

        Alias to :func:`ask_by_name`

Remote IAT Hooking
''''''''''''''''''

See Examples directory