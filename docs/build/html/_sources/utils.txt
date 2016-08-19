``windows.utils`` -- Windows Utilities
***********************************************

.. module:: windows.utils

Context Managers
""""""""""""""""

:mod:`windows.utils` provides some context managers wrapping `standard` contextual operations
like ``VirtualProtect`` or ``SysWow Redirection``

VirtualProtected
''''''''''''''''

.. autoclass:: windows.utils.VirtualProtected
    :no-show-inheritance:

DisableWow64FsRedirection
'''''''''''''''''''''''''

.. autoclass:: windows.utils.DisableWow64FsRedirection
    :no-show-inheritance:

Helper functions
""""""""""""""""

.. autofunction:: windows.utils.enable_privilege
.. autofunction:: windows.utils.check_is_elevated
.. autofunction:: windows.utils.check_debug
.. autofunction:: windows.utils.create_process
.. autofunction:: windows.utils.create_console
.. autofunction:: windows.utils.pop_shell
.. autofunction:: windows.utils.create_file_from_handle
.. autofunction:: windows.utils.get_handle_from_file