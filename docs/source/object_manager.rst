Object Manager -- Kernel objects
================================

.. module:: windows.winobject.object_manager

The :class:`ObjectManager` instance is accessible via :py:attr:`windows.system.object_manager
<windows.winobject.system.System.object_manager>`


.. note::

    See sample at :ref:`sample_object_manager`


.. warning::

    This API have not been tested on real case yet and may be subject to changes.

ObjectManager
"""""""""""""

.. autoclass:: ObjectManager
   :members:
   :undoc-members:
   :special-members: __getitem__



KernelObject
""""""""""""

.. autoclass:: KernelObject
    :members:
    :undoc-members:
    :special-members: __getitem__, __iter__