COM - Component Object Model
""""""""""""""""""""""""""""

A module to call `COM` interfaces from `Python` or
`COM` vtable in python.

This code is only used in :mod:`windows.wmi`.
The ability to create `COM` vtable is used in the `LKD project <https://github.com/sogeti-esec-lab/LKD/>`_ .


To call a `COM` interface you need to:

    1. Describe the `COM` interface `CODE1 <https://github.com/sogeti-esec-lab/LKD/blob/ba40727d7d257b00f89fc6ca7296c9833b7b75b2/dbginterface/remote.py#L56>`_
    2. Use an instance (which is a PVOID) to get the interface `CODE2 <https://github.com/sogeti-esec-lab/LKD/blob/ba40727d7d257b00f89fc6ca7296c9833b7b75b2/dbginterface/remote.py#L313>`_
    3. Use the object ! `CODE3 <https://github.com/sogeti-esec-lab/LKD/blob/ba40727d7d257b00f89fc6ca7296c9833b7b75b2/dbginterface/remote.py#L366>`_

To create `COM` object you need to:

    1. Describe your ComVtable `CODE4 <https://github.com/sogeti-esec-lab/LKD/blob/ba40727d7d257b00f89fc6ca7296c9833b7b75b2/simple_com.py#L89>`_
    2. Implement the python functions described `CODE5 <https://github.com/sogeti-esec-lab/LKD/blob/ba40727d7d257b00f89fc6ca7296c9833b7b75b2/dbginterface/remote.py#L233>`_
    3. Create an instance and pass it to whatever native function expects it `CODE6 <https://github.com/sogeti-esec-lab/LKD/blob/ba40727d7d257b00f89fc6ca7296c9833b7b75b2/dbginterface/remote.py#L438>`_