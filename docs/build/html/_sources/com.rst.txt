:mod:`windows.com` - Component Object Model
""""""""""""""""""""""""""""""""""""""""""""

.. module:: windows.com

A module to call `COM` interfaces from `Python` or
`COM` vtable in python.

This code is only used in :mod:`windows.winobject.wmi` and :mod:`windows.winobject.network` for the firewall.
The ability to create `COM` vtable is used in the `LKD project <https://github.com/sogeti-esec-lab/LKD/>`_ .


Using a COM interface
'''''''''''''''''''''

It's possible to directly call `COM` interface from python. All you need is the definition of the `COM` interface.

There are three ways to get the definition of the code interface:

    * By using it from :mod:`windows.generated_def.interfaces`
    * By writing it yourself : <https://github.com/sogeti-esec-lab/LKD/blob/ba40727d7d257b00f89fc6ca7296c9833b7b75b2/dbginterface/remote.py#L56>`_
    * By generating it.

To generate a `COM` interface you need its definition from the ".c" file.
Then add thisit to ``PythonForWindows\ctypes_generation\com\MyInterface.txt``.
Finally re-generate the interface using ``generate.py``.

When you have the `COM` interface defintion you can create an instance of it.
Then you need to retrieve the interface by using an API returning an object or :func:`window.com.create_instance`.
You can then use the instance to call whatever method you need.

.. note::

    see sample :ref:`sample_com_firewall`

Implementing a COM interface
''''''''''''''''''''''''''''

To create `COM` object you need to:

    1. Create your ``COMImplementation`` with an ``IMPLEMENT`` attribute  that should be a cominterface `CODE 1 <https://github.com/sogeti-esec-lab/LKD/blob/efabf3cc38b94d4180ebe8d2c554da5d76b2fea1/lkd/dbginterface/base.py#L48>`_
    2. Implements the methods of the interface `CODE 2 <https://github.com/sogeti-esec-lab/LKD/blob/efabf3cc38b94d4180ebe8d2c554da5d76b2fea1/lkd/dbginterface/base.py#L55>`_
    3. Create an instance `CODE3 <https://github.com/sogeti-esec-lab/LKD/blob/efabf3cc38b94d4180ebe8d2c554da5d76b2fea1/lkd/dbginterface/base.py#L59>`_
    4. Pass it to whatever native function expects it `CODE4 <https://github.com/sogeti-esec-lab/LKD/blob/efabf3cc38b94d4180ebe8d2c554da5d76b2fea1/lkd/dbginterface/base.py#L272>`_