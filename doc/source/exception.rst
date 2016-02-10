Exception and Context related structures
========================================

.. module:: windows.exception


This module regroups all the Exception/Context related structures and functions.
Most of the structures are the Windows structure with a prefix ``E`` (For enhanced)

Those structure have the same fields that the normal windows ones but their types might vary for a simpler use.


This module also define the decorator :func:`VectoredException` which allows to play with ``Vectored Exception Handler`` in Python

.. note::

    See sample :ref:`sample_vectoredexception` samples

Exception Records
'''''''''''''''''

.. autoclass:: EEXCEPTION_RECORD
    :members:
    :inherited-members:

.. autoclass:: EEXCEPTION_RECORD32
    :inherited-members:

.. autoclass:: EEXCEPTION_RECORD64
    :members:
    :inherited-members:

EXCEPTION DEBUG INFO
''''''''''''''''''''

.. autoclass:: EEXCEPTION_DEBUG_INFO32
    :members:
    :inherited-members:

    .. data:: ExceptionRecord

        :type: :class:`EEXCEPTION_RECORD32`


.. autoclass:: EEXCEPTION_DEBUG_INFO64
    :members:
    :inherited-members:

    .. data:: ExceptionRecord

        :type: :class:`EEXCEPTION_RECORD64`

Context
'''''''

.. autoclass:: ECONTEXT32
    :members:
    :inherited-members:

.. autoclass:: ECONTEXTWOW64
    :members:
    :inherited-members:

.. autoclass:: ECONTEXT64
    :members:
    :inherited-members:

.. autoclass:: EEflags
    :members:

.. autoclass:: EDr7
    :members:

EXCEPTION POINTERS
''''''''''''''''''

.. autoclass:: EEXCEPTION_POINTERS
    :members:

    .. data:: ExceptionRecord

        :type: POINTER to :class:`EEXCEPTION_RECORD`

    .. data:: ContextRecord

        :type: POINTER to :class:`ECONTEXT32` or :class:`ECONTEXT64`


.. _vectoredexception:

Vectored Exception
''''''''''''''''''

.. note::

    See sample :ref:`sample_vectoredexception`

.. autoclass:: VectoredException
    :members: