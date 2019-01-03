WMI -- Make request to WMI
==========================

.. module:: windows.winobject.wmi


The :class:`WmiManager` is accessible via :py:attr:`windows.system.wmi
<windows.winobject.system.System.wmi>`

.. note::

    See sample :ref:`wmi_samples`


WmiManager
""""""""""

.. autoclass:: WmiManager
    :no-inherited-members:
    :members: DEFAULT_NAMESPACE, select, query, namespaces


WmiNamespace
""""""""""""

.. autoclass:: WmiNamespace
    :members:
    :show-inheritance:

WmiObject
"""""""""

.. autoclass:: WmiObject
    :members:
    :special-members: __call__, __getitem__, __setitem__
    :show-inheritance:


WmiCallResult
"""""""""""""

.. autoclass:: WmiCallResult
    :members:
    :show-inheritance:

WmiEnumeration
""""""""""""""

.. autoclass:: WmiEnumeration
    :members:
    :special-members: __call__, __iter__
    :show-inheritance:
