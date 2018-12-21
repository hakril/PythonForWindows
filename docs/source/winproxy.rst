``windows.winproxy`` -- Windows API
***********************************

.. module:: windows.winproxy

:mod:`windows.winproxy` tries to be a pythontic wrapper around windows API of various DLL.
It also heavily relies on :mod:`ctypes` and :mod:`windows.generated_def.winfuncs`

Here are the things to know about :mod:`windows.winproxy`
    * All of this is based on :mod:`windows.generated_def.winfuncs`
    * DLL is loaded the first time an API of it is called
    * All parameters can be passed by ordinal or keyword
    * The call will fail if an argument with default value ``NeededParamater`` have been called without another value.
    * The call will raise a subclass of :class:`WindowsError` if it fails.
    * Some functions are 'transparent proxy' it means that all parameters are mandatory

Example: ``VirtualAlloc``
"""""""""""""""""""""""""

Exemple with the function `VirtualAlloc` in :mod:`windows.winproxy`

Documentation:

.. code-block:: python

    import windows
    windows.winproxy.VirtualAlloc
    # <function VirtualAlloc at 0x02ED63F0>

    help(windows.winproxy.VirtualAlloc)
    # Help on function VirtualAlloc in module windows.winproxy:
    # VirtualAlloc(lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT(0x1000L), flProtect=PAGE_EXECUTE_READWRITE(0x40L))
    #     Errcheck:
    #     raise Kernel32Error if result is 0


Calling it

.. code-block:: python

    import windows

    # Ordinal arguments
    windows.winproxy.VirtualAlloc(0, 0x1000)
    34537472

    # Keyword arguments
    windows.winproxy.VirtualAlloc(dwSize=0x1000)
    34603008

    # NeededParameter must be provided
    windows.winproxy.VirtualAlloc()
    """
    Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
    File "windows\winproxy.py", line 264, in VirtualAlloc
        return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)
    File "windows\winproxy.py", line 130, in perform_call
        raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.func_name, param_name))
    TypeError: VirtualAlloc: Missing Mandatory parameter <dwSize>
    """

    # Error raises exception
    windows.winproxy.VirtualAlloc(dwSize=0xffffffff)
    """
    Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
    File "windows\winproxy.py", line 264, in VirtualAlloc
        return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)
    File "windows\winproxy.py", line 133, in perform_call
        return self._cprototyped(*args)
    File "windows\winproxy.py", line 59, in kernel32_error_check
        raise WinproxyError(func_name)
    windows.winproxy.error.WinproxyError: None: [Error 8] Not enough storage is available to process this command.
    """


Helper functions
""""""""""""""""

.. autofunction:: is_implemented

    Example:
        >>> windows.winproxy.is_implemented(windows.winproxy.NtWow64WriteVirtualMemory64)
        True


.. autofunction:: resolve

    Example:
        >>> hex(windows.winproxy.resolve(windows.winproxy.NtWow64WriteVirtualMemory64))
        '0x77340520'


WinproxyError
"""""""""""""

All errors raised by winproxy functions are instance of :class:`WinproxyError` (or subclasses)

.. autoclass:: WinproxyError
    :show-inheritance:

    .. attribute:: api_name

        The name of the API that raised the exception

Functions in :mod:`windows.winproxy`
""""""""""""""""""""""""""""""""""""

.. include:: winproxy_functions.rst

