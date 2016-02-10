:mod:`windows.debug` -- Debugging
=================================

.. module:: windows.debug

.. note::

    See sample :ref:`sample_debugger`

:class:`Debugger`
"""""""""""""""""

The :class:`Debugger` is the base class to perform the debugging of a remote process.
The :class:`Debugger` have some functions called on given event that can be implemented by subclasses.

.. autoclass:: Debugger
    :members:

    .. automethod:: __init__



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