``windows.native_exec`` -- Native Code Execution
************************************************

.. currentmodule:: windows.native_exec

The  :mod:`windows.native_exec` allows to create `Python` functions calling native code.
it also provide a simple assembler for x86 and x64.

The :mod:`windows.native_exec` provides those functions:

.. automodule:: windows.native_exec

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
    * Forward - Backward jump (using label)
    * Non-string interface for conditional/context dependent generation


.. note::
    The assembler DOES NOT handle every instruction at all.


The assembler instructions are `Python` object that may accept arguments representing
the mnemonic operands.

These parameters can be of type:
    * str (register)
    * int (int)
    * mem_access (memory access)

.. autoclass:: windows.native_exec.simple_x86.mem_access
    :members: prefix, base, index, scale, disp

The :class:`mem_access` object can be created:
    * By hand
    * Using :func:`create_displacement`
    * Using :func:`mem`

.. autofunction:: windows.native_exec.simple_x86.create_displacement
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

.. note::

    TODO: prefix

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



