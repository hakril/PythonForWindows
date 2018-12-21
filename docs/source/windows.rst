The ``windows`` module
**********************

The ``windows`` module is the module installed by :file:`setup.py`.

This module exports some objects representing the current state of the system.
It also offers some submodules aimed to help the interfacing with ``Windows`` and native code execution.

The defaults objects accessible in ``windows`` are:
    * ``system`` of type :class:`windows.winobject.system.System`
    * ``current_process`` of type :class:`windows.winobject.process.CurrentProcess`
    * ``current_thread`` of type :class:`windows.winobject.process.CurrentThread`

The submodules that you might use by themself are:
    * :mod:`windows.generated_def`
    * :mod:`windows.native_exec`
    * :mod:`windows.winproxy`
    * :mod:`windows.wintrust`
    * :mod:`windows.security`
    * :mod:`windows.crypto`
    * :mod:`windows.utils`
    * :mod:`windows.debug`
    * :mod:`windows.alpc`
    * :mod:`windows.pipe`
    * :mod:`windows.rpc`
    * :mod:`windows.com`

.. _object_system:

The ``system`` object
"""""""""""""""""""""

.. note::

    See sample :ref:`sample_system`

.. currentmodule:: windows.winobject

.. autoclass:: windows.winobject.system.System
    :no-show-inheritance:

