Registry
========

.. module:: windows.winobject.registry

.. note::

    See sample :ref:`sample_registry`

Registry
""""""""

.. autoclass:: Registry
    :special-members: __getitem__


PyHKey
""""""

.. autoclass:: PyHKey

    .. function:: __getitem__(name)

        Alias for :func:`open_subkey`

KeyValue
""""""""

.. autoclass:: KeyValue
    :exclude-members: count, index