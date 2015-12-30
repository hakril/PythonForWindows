Native code execution
***********************

.. automodule:: windows.native_exec
    :members: generate_callback_stub, create_function


The native_function submodule
"""""""""""""""""""""""""""""

.. automodule:: windows.native_exec.native_function
    :members: create_function


Simple machine code generation
""""""""""""""""""""""""""""""

These modules allow you to write some simple x86 / x64 shellcode. This is useful to use in adequation to :func:`create_function`.
The instruction name are as explicit as possible with the following convention:

    * This is `intel syntax` so `dest, src`
    * X specify a value passed as parameters::

        Mov_EAX_X(0x42) # mov eax, 0x42

    * D is for `dereference`::

        Mov_EAX_DX(0x42424242) # mov EAX, [0x42424242]
        Mov_DEAX_EDI() # mov [EAX], EDI

All instructions follow this interface:

.. py:class:: Instruction

    .. py:method:: get_code(self)

        :returns: :class:`str`: The raw code of the instruction

    .. py:method:: get_mnemo(self)

        :returns: :class:`str`: The mnemonic of the instruction

Example::

    import windows.native_exec.simple_x86 as x86

    i = x86.Mov_EAX_X(0x42434445)
    i.get_code()
    # '\xb8EDCB'
    i.get_mnemo()
    # 'mov EAX, 0x42434445'


You can also use a :class:`MultipleInstr` instance to merge instructions

Example::

    import windows.native_exec.simple_x86 as x86

    code = x86.MultipleInstr()
    code += x86.Mov_EAX_X(0x42434445)
    code += x86.Push_EAX()
    code += x86.Ret()
    code.get_code()
    # '\xb8EDCBP\xc3'
    print(code.get_mnemo())
    # mov EAX, 0x42434445
    # push    EAX
    # ret

simple_x86 instructions
-----------------------

.. automodule:: windows.native_exec.simple_x86

simple_x64 instructions
-----------------------

.. automodule:: windows.native_exec.simple_x64