:mod:`windows.debug` -- Debugging
=================================

.. module:: windows.debug

.. note::

    See sample :ref:`sample_debugger`

.. note::

    If you are interrested by symbols (PDB) handling, go to subsection :ref:`debug_symbols_module`

:class:`Debugger`
"""""""""""""""""

The :class:`Debugger` is the base class to perform the debugging of a remote process.
The :class:`Debugger` have some functions called on given event that can be implemented by subclasses.

All Memory-breakpoint are disabled when callind a public callback or a breakpoint ``trigger()`` function.

This means that those methods see the original ``current_process`` memory access rights.

.. autoclass:: Debugger
    :members:
    :member-order: bysource

    .. automethod:: __init__


:class:`SymbolDebugger`
"""""""""""""""""""""""

.. autoclass:: SymbolDebugger
    :members:
    :no-inherited-members:


:class:`LocalDebugger`
""""""""""""""""""""""

.. note::

    See sample :ref:`sample_local_debugger`

The :class:`Debugger` is the base class to perform the debugging the current process.
It is based on :func:`VectoredException` (see :ref:`sample_vectoredexception`)

There is not much documentation for now as the code might change soon.



.. autoclass:: LocalDebugger
    :members:


:class:`Breakpoint`
"""""""""""""""""""

Standard breakpoints types expect an address as argument.

An address can be:

    * An :class:`int`
    * A :class:`str` of form (breakpoint will be put when ``DLL`` is loaded):

        * ``"DLL!ApiName"``
        * ``"DLL!Offset"`` where offset is a int ("16", "0x10", ..)


When a breakpoint is hit, its ``trigger`` function is called with the debugger and a
``DEBUG_EXECEPTION_EVENT`` structure as argument.


.. autoclass:: Breakpoint
    :members:

.. autoclass:: HXBreakpoint
    :members:
    :inherited-members:

.. autoclass:: MemoryBreakpoint
    :members:
    :inherited-members:
    :special-members: __init__



.. note::

    MemoryBreakpoint are triggered based on the fault address only (as I don't know a way to get the size of the read/write causing the fault without embedding a disassembler).

    This means that a MEMBP at address ``X`` won't be triggered by a write of size 4 at address ``X - 1``. it's sad I know.


.. autoclass:: FunctionCallBP
    :members:
    :inherited-members:
    :special-members: __init__

.. note::

    See sample :ref:`sample_debugger_bp_functioncallbp`

.. autoclass:: FunctionBP
    :members:
    :inherited-members:
    :special-members: __init__

.. note::

    See sample :ref:`sample_debugger_bp_functionbp`


.. _debug_symbols_module:

:mod:`windows.debug.symbols` -- Using symbols
"""""""""""""""""""""""""""""""""""""""""""""

.. module:: windows.debug.symbols

The :mod:`windows.debug.symbols` module provide classes to load PDB and resolve name/address.
In its current state, this module does not handle types.

.. note::

    See sample <TODO>


Configuration
'''''''''''''

In order to be able to automatically download PDB and parse remote ``_NT_SYMBOL_PATH``, a debug version of the DLL `dbghelp.dll` must be used.
(See `MSDN: DbgHelp Versions <https://docs.microsoft.com/en-us/windows/win32/debug/dbghelp-versions>`_)

As it is NOT recommended to replace ``system32/dbghelp.dll``, its path must be provided to PythonForWindows.
This path must be provided before any call to the ``dbghelp.dll`` APIs.
Also, the ``symsrv.dll`` DLL should be present in the same directory as ``dbghelp.dll`` (See `SymSrv Installation <https://docs.microsoft.com/en-us/windows/win32/debug/using-symsrv#installation>`_)

There is 2 ways to pass this information to ``PythonForWindows``:

    * Using the function :func:`set_dbghelp_path`
    * Using the environment variable ``PFW_DBGHELP_PATH``
        * If this variable exists it will simply trigger a call to ``set_dbghelp_path(PFW_DBGHELP_PATH)``


If the given path is a directory, the final path will be computer as ``path\<current_process_bitness>\dbghelp.dll``.
This allow to use the same script (or environment variable) transparently in bot 32b & 64b python interpreters.

.. note::

    For example, on my computer my setup is done through the environment variable: ``PFW_DBGHELP_PATH=D:\pysym\bin``

    This directory have the following layout:

        | $ tree /A /F %PFW_DBGHELP_PATH%
        |     D:\\PYSYM\\BIN
        |     \| symsrv.yes
        |     \|
        |     +\\-\\-\\-32
        |     \| dbghelp.dll
        |     \| symsrv.dll
        |     \|
        |     \\\\-\\-\\-64
        |        dbghelp.dll
        |        symsrv.dll


Helpers
'''''''

.. autofunction:: set_dbghelp_path

.. autoclass:: SymbolEngine
    :members:


:class:`VirtualSymbolHandler`
'''''''''''''''''''''''''''''

.. autoclass:: VirtualSymbolHandler
    :show-inheritance:
    :members:
    :inherited-members:
    :special-members: __getitem__


:class:`ProcessSymbolHandler`
'''''''''''''''''''''''''''''

.. autoclass:: ProcessSymbolHandler
    :show-inheritance:
    :members:
    :inherited-members:
    :special-members: __getitem__


:class:`SymbolModule`
'''''''''''''''''''''

.. autoclass:: SymbolModule
    :show-inheritance:
    :members:
    :inherited-members:


:class:`SymbolInfo`
'''''''''''''''''''

.. autoclass:: SymbolInfo
    :members:


.. autoclass:: SymbolInfoA
    :members:
    :special-members: __str__, __int__
