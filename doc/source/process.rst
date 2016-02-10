Processes and Threads
"""""""""""""""""""""

.. module:: windows.winobject

CurrentProcess
''''''''''''''

.. note::

    See sample :ref:`sample_current_process`

.. autoclass:: CurrentProcess
   :members:
   :show-inheritance:
   :inherited-members:

CurrentThread
'''''''''''''

.. autoclass:: CurrentThread
   :members:
   :show-inheritance:
   :inherited-members:

WinProcess
''''''''''

.. note::

    See sample :ref:`sample_remote_process`

.. autoclass:: WinProcess
   :members:
   :show-inheritance:
   :inherited-members:


WinThread
'''''''''

.. autoclass:: WinThread
   :members:
   :show-inheritance:
   :inherited-members:


.. autoclass:: DeadThread
   :members:
   :show-inheritance:
   :inherited-members:

Token
'''''

.. autoclass:: Token
   :members:
   :inherited-members:


PEB Exploration
"""""""""""""""

The :mod:`windows` module is able to parse the PEB of the current process or remote process.
The :class:`PEB` is accessible via ``process.peb`` and is of type :class:`PEB`.

.. note::

    See sample :ref:`sample_peb_exploration`

PEB
'''

.. autoclass:: PEB
   :members:
   :inherited-members:

.. autoclass:: WinUnicodeString

LoadedModule
''''''''''''

.. autoclass:: LoadedModule


PEFile - Parsing loaded PE
""""""""""""""""""""""""""

:mod:`windows.pe_parse`
'''''''''''''''''''''''

.. module:: windows.pe_parse

.. autofunction:: windows.pe_parse.GetPEFile

PEFile
^^^^^^

.. autoclass:: PEFile

IATEntry
^^^^^^^^

.. autoclass:: IATEntry

    .. data:: addr

        :class:`int` : Address of the IAT Entry

    .. data:: ord

        :class:`int` : Ordinal of the imported function

    .. data:: name

        :class:`int` :  Name of the imported function

    .. data:: value

        :class:`int` :  The content (destination) of the IAT entry

        .. warning::

            `value` is a descriptor. Setting its value will actually CHANGE THE IAT ENTRY, resulting in a segfault if no VirtualProtect have been done.

        .. note::

            See: :class:`windows.utils.VirtualProtected`