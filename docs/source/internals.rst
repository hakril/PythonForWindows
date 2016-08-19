Internals
=========

Because some horrible hacks of ``PythonForWindows`` are hidden and I wanted to talk about it.

remotectypes.py
'''''''''''''''

.. module:: windows.remotectypes

Performing parsing of PEB / PE in remote process may be painful and i didn't want
to have two versions of all my parsing code.

So I made a wrapper around :mod:`ctypes` that is able to do two things:

    - Transform a 32bits ctypes structure into a 64bits one and reverse

    This is done by replacing the ``c_void_p``/``c_char_p`` by ``DWORD`` or
    ``QWORD`` and rewriting a wrapper around the :mod:`ctypes` ``POINTER`` and other stuff.
    It might not works for every structure by i didn't have any problem for now.

    - Read the memory in another process

    For this one I rewrote a class that use the standard :mod:`ctypes` structure
    offset-size calculation, extracts those information when asked for a field and read it from the target process.
    We just need to take care of special cases:  ``POINTER`` / ``ARRAY`` / ``STRING`` / ..

We also need to be carreful about the inheritance, we need to inherit from "hidden"
:class:`ctypes` classes to keep the magic working.


This module exports the following API:

.. autofunction:: transform_type_to_remote32bits

.. autofunction:: transform_type_to_remote64bits

Both functions return a class that represent the structure in a remote process.
The class.__init__ accept two arguments:

    * ``base_addr``: the address of the object in the remote process
    * ``target``: an object with a method ``read_memory`` (so a :class:`windows.winobject.WinProcess` in our case)

Example ``WinProcess.peb``::

    def peb(self):
        if windows.current_process.bitness == 32 and self.bitness == 64:
            return RemotePEB64(self.peb_addr, self)
        if windows.current_process.bitness == 64 and self.bitness == 32:
            return RemotePEB32(self.peb_addr, self)
        return RemotePEB(self.peb_addr, self)

I am pretty sure that this code does NOT handle all the cases, so it might break some day.

syswow64.py -- Crossing the heaven gate
'''''''''''''''''''''''''''''''''''''''

.. module:: windows.syswow64

One of my goal with ``PythonForWindows`` is to have some abstraction of the bitness of the processes.
It means being able to work on a ``32bits Python`` or a ``64bits Python``.

In the case of a 32bits python on a ``64bits`` system (``SysWow64``) it's not trivial to perform operation on
other ``64bits`` processes. For example directly calling :func:`CreateRemoteThread` will not work.

To be able to perform those operation we must be able to execute code in the ``64bits`` part of our
``SysWow64`` process.

.. note::

    See `Knockin’ on Heaven’s Gate – Dynamic Processor Mode Switching <http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/>`_


For that we need to jump to the 64bits segment of our process, execute some code then return.
To do so, we need to use some ``far jump`` / ``far ret`` with the segments selector ``0x23`` (CS_32bits) and ``0x33`` (CS_64bits).

The generation of this is quite ugly in my case.
This code is in:

.. function:: execute_64bits_code_from_syswow

Once we are able to execute some code in the ``64bits`` part we need to create the code that will call our API (in NTDLL).
To do that, I rely on the type information already present in the function of :mod:`windows.winproxy`.
With these information we are able to know

    * The name of the API
    * The number of arguments

Then I generate the correct x64 stub (using :mod:`windows.native_exec.simple_x64`) with the function:

.. function:: generate_syswow64_call

One problem I encountered is that our function must be able to pass values of 64bits, so passing arguments by register is not possible.

For now I allocate a buffer where a python wrapper copy the parameters and the x64 stub retrieves them from here.

(It might be possible to do something by creating a WINCFUNC with only ULONG64 parameters).

.. function:: try_generate_stub_target

The final result is a ``Python`` function like the one in :mod:`windows.winproxy`

    * It copies the arguments in the buffer
    * Jumps on the 32->64 stub
    * X64 bits code retrieves the arguments in the buffer and setup the registers and the stack for the call
    * Calls the API
    * Returns to 32bits mode.

.. class:: Syswow64ApiProxy

Existing function are:

.. function:: NtCreateThreadEx_32_to_64

.. function:: NtQueryInformationProcess_32_to_64

.. function:: NtQueryInformationThread_32_to_64

.. function:: NtQueryVirtualMemory_32_to_64

.. function:: NtGetContextThread_32_to_64

.. function:: NtSetContextThread_32_to_64

.. function:: LdrLoadDll_32_to_64