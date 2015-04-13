Loaded DLL Exploration and IAT hooks
************************************

List of loaded modules
""""""""""""""""""""""

Accessible using::

    import windows
    windows.current_process.peb.modules[int].pe

..note::
    See: :class:`windows.winobject.PEB` and :class:`windows.winobject.LoadedModule`



DLL Import and IAT
""""""""""""""""""

.. py:class:: PEFile

    .. py:attribute:: imports

        The imports of the PE

        .. note::
            This is a :class:`dict` DLLName -> [:class:`IATEntry`]

        Example::

            import windows
            k32 = windows.current_process.peb.modules[2]
            # <LoadedModule "KERNEL32.DLL" at 0x2deca30>
            k32.pe.imports.keys()
            # ['kernelbase.dll', 'api-ms-win-core-profile-l1-1-0.dll', ...]
            k32.pe.imports['kernelbase.dll']
            # [<IATEntry "EnumLanguageGroupLocalesW" ordinal 58>, <IATEntry "GetNamedPipeAttribute" ordinal 93>, ...]
            [entry for entry in k32.pe.imports['kernelbase.dll'] if entry.name == "lstrcmpiW"][0]
            # <IATEntry "lstrcmpiW" ordinal 244>


.. py:class:: IATEntry

    | Reprensent An entry in the IAT of a module
    | Can be used to get resolved value and setup hook

    .. py:attribute:: name

        | :class:`int` : The name of the import


    .. py:attribute:: ord

        | :class:`int` : The ordinal of the import


    .. py:attribute:: addr

        | :class:`int` :  The address of the IAT entry

    .. py:attribute:: value

        | :class:`int` :  The destination of the IAT entry

        .. warning::

            `value` is a descriptor. Setting its value will actually CHANGE THE IAT ENTRY, resulting in a segfault if no VirtualProtect have been done.

        .. note::

            See: :class:`windows.utils.VirtualProtected`


    .. py:method:: set_hook(self, callback, types=None)

        Setup a hook, `callback` should respect the :ref:`hook_protocol`. If `callback` have no :ref:`type_information`, `types` should provide them.


IAT Hooking
"""""""""""

.. _hook_protocol:

The hook protocol
-----------------

Callback arguments
''''''''''''''''''

A hook callback must have the same number of argument as the hooked API, PLUS a last argument `real_function`.

The `real_function` argument is a callable that represent the hooked API, it can be called in two ways:

    * Without argument, the call will be done with the argument originaly passed to your callback. This allow simple redirection to the real API.

    * With arguments it will simply call the API with these.

    Example::

        def createfile_callback(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, real_function):
            print("Trying to open {0}".format(lpFileName))
            if "secret" in lpFileName:
                return 0xffffffff
            # Perform the real call
            return real_function()


.. _type_information:

Type information
''''''''''''''''

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


Put the hook
------------

To setup your IAT hook you just need:

    * A callback that respect the :ref:`hook_protocol`
    * The :class:`IATEntry` to hook


You just need to use the function :func:`IATEntry.set_hook`


    Full Example::

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






