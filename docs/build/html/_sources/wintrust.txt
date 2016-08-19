``windows.wintrust`` -- Checking signature
******************************************

.. module:: windows.wintrust

.. note::

    See sample :ref:`sample_wintrust`

The :mod:`wintrust` module offers wrapper around ``wintrust.dll``.
It allows to check the signature of a file.

The signature of a file can be at two differents place:

    * In the file itself (:func:`check_signature`)
    * In a catalog file  (:func:`full_signature_information`)

.. note::

    `Explanation about catalog files <https://msdn.microsoft.com/en-us/library/windows/hardware/ff537872(v=vs.85).aspx>`_


API
"""

.. autofunction:: is_signed

.. autofunction:: full_signature_information

.. autofunction:: check_signature


SignatureData
'''''''''''''

.. autoclass:: SignatureData
    :exclude-members: count, index



