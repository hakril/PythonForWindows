ETW -- Event Tracing for Windows
================================

.. module:: windows.winobject.event_trace

The :class:`EtwManager` instance is accessible via :py:attr:`windows.system.etw
<windows.winobject.system.System.etw>`

.. note::

    This code is the result of my research on ``ETW`` that lead to this presentation `ETW for the lazy reverser (FR) <https://www.rump.beer/2019/slides/etw_lazy_reverser.pdf>`_


.. note::

        See sample :ref:`sample_etw`


EtwManager
""""""""""


.. autoclass:: EtwManager
    :members:


Tracing Events
""""""""""""""

EtwTrace
''''''''

.. autoclass:: EtwTrace
    :members:


EventTraceProperties
''''''''''''''''''''

.. autoclass:: EventTraceProperties
    :members:

EventRecord
'''''''''''

.. autoclass:: EventRecord
    :members:

