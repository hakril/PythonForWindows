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

    .. function:: __call__(name)

        Alias for :func:`open_subkey`

    .. function:: __getitem__(name)

        Alias for :func:`get`

    .. function:: __setitem__(name)

        Wrapper for :func:`set`, accept ``value`` or ``(value, type)``

KeyValue
""""""""

.. autoclass:: KeyValue
    :exclude-members: count, index