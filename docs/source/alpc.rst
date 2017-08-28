``windows.alpc`` -- Advanced Local Procedure Call
*************************************************

.. module:: windows.alpc

The :mod:`windows.alpc` module regroups the classes that permits to send and receive
ALPC messages over an ALPC port and the classes representing these messages.


.. note::

    See samples:

        * :ref:`sample_alpc`
        * :ref:`sample_advanced_alpc`

ALPC Message
------------

.. autoclass:: AlpcMessage

.. autoclass:: AlpcMessagePort

.. autoclass:: MessageAttribute

ALPC client
-----------

.. autoclass:: AlpcClient

ALPC Server
-----------

.. autoclass:: AlpcServer