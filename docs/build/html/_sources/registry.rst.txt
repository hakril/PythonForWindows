Registry
========

.. module:: windows.winobject.registry

The :class:`Registry` instance is accessible via :py:attr:`windows.system.registry
<windows.winobject.system.System.registry>`

.. note::

    See sample :ref:`sample_registry`

Registry
""""""""

.. autoclass:: Registry
    :special-members: __call__


PyHKey
""""""

.. autoclass:: PyHKey

    .. function:: __call__(name)

        Alias for :func:`open_subkey`

    .. function:: __getitem__(name)

        Alias for :func:`get`

    .. function:: __setitem__(name)

        Wrapper for :func:`set`, accept ``value`` or ``(value, type)``

    .. function:: __delitem__(name)

        Alias for :func:`delete_value`

KeyValue
""""""""

.. autoclass:: KeyValue
    :exclude-members: count, index