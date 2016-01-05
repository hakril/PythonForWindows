Processes and Threads
"""""""""""""""""""""

.. module:: windows.winobject

CurrentProcess
''''''''''''''

.. note::

    See sample :ref:`sample_current_process`

.. autoclass:: CurrentProcess
   :members:
   :inherited-members:

CurrentThread
'''''''''''''

.. autoclass:: CurrentThread
   :members:
   :inherited-members:

WinProcess
''''''''''

.. note::

    See sample :ref:`sample_remote_process`

.. autoclass:: WinProcess
   :members:
   :inherited-members:


WinThread
'''''''''

.. autoclass:: WinThread
   :members:
   :inherited-members:


.. autoclass:: DeadThread
   :members:
   :inherited-members:


PEB Exploration
"""""""""""""""

The :mod:`windows` module is able to parse the PEB of the current process or remote process.
The :class:`PEB` is accessible via ``process.peb`` and is of type :class:`PEB`.

.. note::

    See sample :ref:`sample_peb_exploration`

.. autoclass:: PEB
   :members:
   :inherited-members:

.. autoclass:: WinUnicodeString

.. autoclass:: LoadedModule


.. warning::

    TODO: pe_parse.PEFile (sorry) but example at :ref:`sample_peb_exploration`


