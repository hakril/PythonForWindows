IAT hooking
"""""""""""

.. note::

    See sample :ref:`sample_iat_hook`

Put a IAT hook
''''''''''''''

To setup your IAT hook you just need:

    * A callback that respect the :ref:`hook_protocol`
    * The :class:`windows.pe_parse.IATEntry` to hook


You just need to use the function :func:`windows.pe_parse.IATEntry.set_hook`

Putting a hook::

    import windows
    from windows.hooks import *

    @CreateFileACallback
    def createfile_callback(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, real_function):
        print("Trying to open {0}".format(lpFileName))
        if "secret" in lpFileName:
            return 0xffffffff
        return real_function()

    my_exe = windows.current_process.peb.modules[0]
    imp = my_exe.pe.imports

    iat_create_file = [entry for entry in imp['kernel32.dll'] if entry.name == "CreateFileA"]
    iat_create_file.set_hook(createfile_callback)


.. _hook_protocol:

Hook protocol
'''''''''''''

Callback arguments
------------------

A hook callback must have the same number of argument as the hooked API, PLUS a last argument ``real_function``.



The ``real_function`` argument is a callable that represent the hooked API, it can be called in two ways:

    * Without argument, the call will be done with the argument originaly passed to your callback. This allows simple redirection to the real API.

    * With arguments it will simply call the API with these.

Example::

    def createfile_callback(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, real_function):
        print("Trying to open {0}".format(lpFileName))
        if "secret" in lpFileName:
            return 0xffffffff
        # Perform the real call
        return real_function()


A hook callback must also embed some :ref:`Type Information <type_information>`


.. _type_information:

Callback type information
--------------------------

In order make the magic behind Python Hook Callback, :mod:`ctypes` need to have type information about the API parameters.

There is (again) two ways to give those informations to your hook callback. Both techniques use a decorator to setup type information to the callback.

    * Giving the type manualy using the decorator :class:`windows.hooks.Callback`::

        from windows.hooks import *
        # First type is return type, others are parameters types
        @Callback(ctypes.c_void_p, ctypes.c_ulong)
        def exit_callback(x, real_function):
            print("Try to quit with {0} | {1}".format(x, type(x)))
            if x == 3:
                print("TRYING TO REAL EXIT")
                return real_function(1234)
            return 0x4242424243444546

    * Using the `Callback` decorator generated from known functions::

        from windows.hooks import *
        # Decorator name is always API_NAME + "CallBack"
        @CreateFileACallback
        def createfile_callback(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, real_function):
            print("Trying to open {0}".format(lpFileName))
            if "secret" in lpFileName:
                return 0xffffffff
            return real_function()

    .. note::

        See the list of known functions


:mod:`windows.hooks`
''''''''''''''''''''

.. module:: windows.hooks

.. autoclass:: windows.hooks.Callback

.. autoclass:: windows.hooks.IATHook