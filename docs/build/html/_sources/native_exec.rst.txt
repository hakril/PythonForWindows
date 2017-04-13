.. module:: windows.native_exec

``windows.native_exec`` -- Native Code Execution
************************************************


:mod:`windows.native_exec` allows to create `Python` functions calling native code.
it also provides a simple assembler for x86 and x64.

:mod:`windows.native_exec` provides those functions:

.. autofunction:: windows.native_exec.create_function

The :mod:`windows.native_exec` also contains some submodules:
    * :mod:`windows.native_exec.cpuid`
    * :mod:`windows.native_exec.simple_x86`
    * :mod:`windows.native_exec.simple_x64`

:mod:`windows.native_exec.cpuid` -- Interface to native CPUID
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. automodule:: windows.native_exec.cpuid
    :no-show-inheritance:
    :no-members: bitness

Demo::

    >>> import windows.native_exec.cpuid
    >>> windows.native_exec.cpuid.do_cpuid(0)
    <windows.native_exec.cpuid.X86CpuidResult object at 0x0330D990>
    >>> x = windows.native_exec.cpuid.do_cpuid(0)
    >>> x.EAX
    13L
    >>> x.EBX
    1970169159L
    >>> windows.native_exec.cpuid.get_vendor_id()
    'GenuineIntel'
    >>> windows.native_exec.cpuid.get_proc_family_model()
    (6L, 58L)


:mod:`windows.native_exec.simple_x86` -- X86 Assembler
""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. module:: windows.native_exec.simple_x86

The :mod:`windows.native_exec.simple_x86` module allows to create simple x86 code.

Its features are:
    * Forward - Backward jump (using labels)
    * Non-string interface for conditional/context dependent generation


.. note::
    The assembler DOES NOT handle every instruction at all.


The assembler instructions are `Python` object that may accept arguments representing
the mnemonic operands.

These parameters can be of type:
    * :class:`str` (register)
    * :class:`int` (int)
    * :class:`mem_access` (memory access)

.. autoclass:: windows.native_exec.simple_x86.mem_access
    :members: prefix, base, index, scale, disp
    :exclude-members: count

The :class:`mem_access` object can be created:
    * By hand
    * Using :func:`create_displacement`
    * Using :func:`mem`

.. autofunction:: windows.native_exec.simple_x86.create_displacement
.. autofunction:: windows.native_exec.simple_x86.deref
.. autofunction:: windows.native_exec.simple_x86.mem

Instruction assembling::

    >>> import windows.native_exec.simple_x86 as x86
    >>> import random
    >>> x86.Mov
    <class 'windows.native_exec.simple_x86.Mov'>
    >>> instr = x86.Mov("EAX", "EBX")
    >>> instr
    <windows.native_exec.simple_x86.Mov object at 0x03243770>
    >>> instr.get_code()
    '\x89\xd8'
    >>> x86.Mov("EAX", 0x42424242).get_code()
    '\xc7\xc0BBBB'
    >>> x86.Mov("EAX", x86.create_displacement(base="EAX", disp=random.randint(0, 0xffffffff))).get_code()
    '\x8b\x80\x977\n&'
    >>> x86.Mov(x86.mem("[EBX + EDI * 2 + 0x11111111]"), "EAX").get_code()
    '\x89\x84{\x11\x11\x11\x11'
    >>> x86.Mov(x86.mem("gs:[EBX + EDI * 2 + 0x11111111]"), "EAX").get_code()
    'e\x89\x84{\x11\x11\x11\x11'

:mod:`windows.native_exec.simple_x86` also provides an interface to complex shellcode assembling
including jump and label via the :class:`MultipleInstr` class.

Shellcode assembling::

    import windows.native_exec.simple_x86 as x86

    code = x86.MultipleInstr()
    code += x86.Label(":BEGIN")
    code += x86.Jmp(":BEGIN")
    print(repr(code.get_code()))
    # '\xeb\xfe'

Another example from a project::

        IO_STACK_INPUT_BUFFER_LEN = x86.mem('[ESI + 8]')
        IO_STACK_INPUT_BUFFER =     x86.mem('[ESI + 0x10]')

        INPUT_BUFFER_SIZE =  x86.mem('[ECX]')
        INPUT_BUFFER_PORT =  x86.mem('[ECX + 4]')
        INPUT_BUFFER_VALUE = x86.mem('[ECX + 8]')

        out_ioctl = x86.MultipleInstr()
        out_ioctl += x86.Cmp(IO_STACK_INPUT_BUFFER_LEN, 0xc)  # size indicator / port / value
        out_ioctl += x86.Jnz(":FAIL")
        out_ioctl +=    x86.Mov('ECX', IO_STACK_INPUT_BUFFER)
        out_ioctl +=    x86.Mov('EDX', INPUT_BUFFER_PORT)
        out_ioctl +=    x86.Mov('EAX', INPUT_BUFFER_VALUE)
        out_ioctl +=    x86.Mov('ECX', INPUT_BUFFER_SIZE)
        out_ioctl +=    x86.Cmp('ECX', 0x1)
        out_ioctl +=    x86.Jnz(":OUT_2_OR_4")
        out_ioctl +=    x86.Out('DX', 'AL')
        out_ioctl +=    x86.Jmp(':SUCCESS')
        out_ioctl +=    x86.Label(":OUT_2_OR_4")
        out_ioctl +=    x86.Cmp('ECX', 0x2)
        out_ioctl +=    x86.Jnz(":OUT_4")
        out_ioctl +=    x86.Out('DX', 'AX')
        out_ioctl +=    x86.Jmp(':SUCCESS')
        out_ioctl +=    x86.Label(":OUT_4")
        out_ioctl +=    x86.Out('DX', 'EAX')
        out_ioctl +=    x86.Label(":SUCCESS")
        out_ioctl +=    x86.Xor('EAX', 'EAX')
        out_ioctl +=    x86.Ret()
        out_ioctl += x86.Label(":FAIL")
        out_ioctl += x86.Mov('EAX', 0x0C000000D)
        out_ioctl += x86.Ret()

        out_ioctl.get_code()
        '\x81~\x08\x0c\x00\x00\x00u&\x8bN\x10\x8bQ\x04\x8bA\x08\x8b\t\x81\xf9\x01\x00\x00\x00u\x03\xee\xeb\r\x81\xf9\x02\x00\x00\x00u\x04f\xef\xeb\x01\xef1\xc0\xc3\xc7\xc0\r\x00\x00\xc0\xc3'


:mod:`windows.native_exec.simple_x64` -- X64 Assembler
""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. module:: windows.native_exec.simple_x64

Same things as :mod:`windows.native_exec.simple_x86`

The only things that change are:
    * The registers name

:mod:`windows.native_exec.simple_x64` handles 32 and 64 bits operations.

Demo::

    >>> import windows.native_exec.simple_x64 as x64
    >>> x64.Mov("RAX", "R13").get_code()
    'L\x89\xe8'
    >>> x64.Mov("EAX", "EDI").get_code()
    '\x89\xf8'
    >>> x64.Mov("RAX", "EDI").get_code()
    """
    ValueError: Size mismatch
    """
    >>> x64.Mov("RAX", x64.mem("[EAX]")).get_code()
    'gH\x8b\x00'
    >>> x64.Mov("RAX", x64.mem("[RAX]")).get_code()
    'H\x8b\x00'
    >>> x64.Mov("EAX", x64.mem("[RAX]")).get_code()
    '\x8b\x00'
    >>> x64.Mov("EAX", x64.mem("[EAX]")).get_code()
    'g\x8b\x00'



:mod:`windows.native_exec.nativeutils` -- Native utility functions
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. module:: windows.native_exec.nativeutils

This module contains some native-code functions that can be used for various purposes.
Each function export a label that allow another :class:`MultipleInstr` to call the code of the function.

The current functions are:

    * ``StrlenW64`` A 64bits wide-string STRLEN (``Label(":FUNC_STRLENW64")``)
    * ``StrlenA64`` A 64bits ASCII STRLEN (``Label(":FUNC_STRLENA64")``)
    * ``GetProcAddress64`` A 64bits export resolver (``Label(":FUNC_GETPROCADDRESS64")``)

        * Arg1: The DLL (wstring)
        * Arg2: The API (string)
        * Return value:

            * 0xfffffffffffffffe if the DLL is not found
            * 0xffffffffffffffff if the API is not found
            * The address of the function

    * ``StrlenW32`` A 32bits wide-string STRLEN (``Label(":FUNC_STRLENW32")``)
    * ``StrlenA32`` A 32bits ASCII STRLEN (``Label(":FUNC_STRLENA32")``)
    * ``GetProcAddress32`` A 32bits export resolver (``Label(":FUNC_GETPROCADDRESS32")``)

        * Arg1: The DLL (wstring)
        * Arg2: The API (string)
        * Return value:

            * 0xfffffffe if the DLL is not found
            * 0xffffffff if the API is not found
            * The address of the function

To use those functions in a :class:`MultipleInstr` just call the label in your code and append the function at
the end of your :class:`MultipleInstr`


Example::

        RemoteManualLoadLibray = x86.MultipleInstr()

        RemoteManualLoadLibray += x86.Mov("ECX", x86.mem("[ESP + 4]"))
        RemoteManualLoadLibray += x86.Push(x86.mem("[ECX + 4]"))
        RemoteManualLoadLibray += x86.Push(x86.mem("[ECX]"))
        RemoteManualLoadLibray += x86.Call(":FUNC_GETPROCADDRESS32")
        RemoteManualLoadLibray += x86.Push(x86.mem("[ECX + 8]"))
        RemoteManualLoadLibray += x86.Call("EAX") # LoadLibrary
        RemoteManualLoadLibray += x86.Pop("ECX")
        RemoteManualLoadLibray += x86.Pop("ECX")
        RemoteManualLoadLibray += x86.Ret()

        RemoteManualLoadLibray += GetProcAddress32