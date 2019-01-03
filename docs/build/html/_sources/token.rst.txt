Token
"""""

.. module:: windows.winobject.token

This module expose the :class:`Token` object that can be primarily  retrieved through:

    * :data:`windows.winobject.process.WinProcess.token`
    * :data:`windows.winobject.process.WinThread.token`
    * :data:`windows.current_process.token <windows.winobject.process.CurrentProcess.token>`
    * :data:`windows.current_thread.token <windows.winobject.process.CurrentThread.token>`
    * :class:`windows.security.Token`

.. note::

    If you need to directly access the :class:`Token` class, please use :class:`windows.security.Token` as the
    path of ``token.py`` may change.

    Indeed ``SecurityDescriptor`` & ``Token`` are deeply related and I may move ``token.py`` to a
    ``security/`` directory in the futur.

.. note::

    See sample :ref:`token_sample`


Token
'''''

.. autoclass:: Token
   :members:
   :inherited-members:


TokenGroups
'''''''''''

.. autoclass:: TokenGroups
    :show-inheritance:
    :members:
    :inherited-members:



TokenPrivileges
'''''''''''''''

.. autoclass:: TokenPrivileges
    :show-inheritance:
    :special-members: __getitem__, __setitem__
    :members:
    :inherited-members:


TokenSecurityAttributesInformation
''''''''''''''''''''''''''''''''''

.. autoclass:: TokenSecurityAttributesInformation
    :show-inheritance:
    :members:
    :inherited-members:


TokenSecurityAttributeV1
''''''''''''''''''''''''

.. autoclass:: TokenSecurityAttributeV1
    :show-inheritance:
    :members:
    :inherited-members: