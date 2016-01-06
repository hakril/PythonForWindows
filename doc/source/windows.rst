The ``windows`` module
**********************

The ``windows`` module is the module installed by :file:`setup.py` (that does not exists right now).
This module export some object representing the current state of the system. It also offers some submodules aimed to help the interface with ``Windows`` and native code exection.

The defaults objects accessible in ``windows`` are:
    * ``system`` of type :class:`windows.winobject.System`
    * ``current_process`` of type :class:`windows.winobject.CurrentProcess`
    * ``current_thread`` of type :class:`windows.winobject.CurrentThread`

The submodules that you might use by themself are:
    * :mod:`windows.native_exec`
    * :mod:`windows.winproxy`
    * :mod:`windows.utils`

.. _object_system:

The ``system`` object
"""""""""""""""""""""

.. autoclass:: windows.winobject.System
    :no-show-inheritance:

    .. autoattribute:: windows.winobject.System.registry
        :annotation:

        Object of class :class:`windows.registry.Registry`

    .. autoattribute:: windows.winobject.System.network
        :annotation:

        Object of class :class:`windows.network.Network`