:mod:`windows.debug` -- Debugging
=================================

.. module:: windows.debug

.. note::

    See sample :ref:`sample_debugger`

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

    MemoryBreakpoint are triggered based on the fault address only (as I don't know a way to get the size of the read/write causing the fault without embeding a disassembler).

    This means that a MEMBP at address ``X`` won't be triggered by a write of size 4 at address ``X - 1`` (it's sad I know :( )