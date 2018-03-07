``windows.pipe`` -- Inter-Process Communication
***********************************************

.. module:: windows.pipe


:mod:`windows.pipe` is wrapper around :class:`_multiprocessing.PipeConnection` simplifiying its use.

The main improvement are:

    - send/recv object from a pipe name in one line
    - Context manager around pipe connection

.. note::

    see sample :ref:`sample_pipe`

Helper functions
""""""""""""""""

.. autofunction:: create
.. autofunction:: connect
.. autofunction:: recv_object
.. autofunction:: send_object
.. autofunction:: full_pipe_address


PipeConnection
""""""""""""""

.. autoclass:: PipeConnection