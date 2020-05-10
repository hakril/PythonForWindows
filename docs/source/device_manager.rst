Device Manager
==============

.. module:: windows.winobject.device_manager

The :class:`DeviceManager` instance is accessible via :py:attr:`windows.system.device_manager
<windows.winobject.system.System.device_manager>`

.. note::

    See sample at :ref:`sample_device_manager`



DeviceManager
"""""""""""""


.. autoclass:: DeviceManager
   :members:


DeviceClass
"""""""""""


.. autoclass:: DeviceClass
   :members:
   :no-inherited-members:



DeviceInformationSet
""""""""""""""""""""


.. autoclass:: DeviceInformationSet
   :members:
   :special-members: __iter__



DeviceInstance
""""""""""""""


.. autoclass:: DeviceInstance
   :members:


LogicalConfiguration
""""""""""""""""""""

.. autoclass:: LogicalConfiguration
   :members:


ResourceDescriptor
""""""""""""""""""

.. autoclass:: ResourceDescriptor
   :members:


Concrete ResourceDescriptor
''''''''''''''''''''''''''

ResourceNoType
------------------

.. autoclass:: ResourceNoType

MemoryResource
--------------

.. autoclass:: MemoryResource

IoResource
----------

.. autoclass:: IoResource

DmaResource
-----------

.. autoclass:: DmaResource

IrqResource
-----------

.. autoclass:: IrqResource

BusNumberResource
-----------------

.. autoclass:: BusNumberResource

MemLargeResource
----------------

.. autoclass:: MemLargeResource

ClassSpecificResource
---------------------

.. autoclass:: ClassSpecificResource

DevicePrivateResource
---------------------

.. autoclass:: DevicePrivateResource

MfCardConfigResource
--------------------

.. autoclass:: MfCardConfigResource

PcCardConfigResource
--------------------

.. autoclass:: PcCardConfigResource