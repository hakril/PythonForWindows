``windows.crypto`` -- CryptoAPI
*******************************

.. module:: windows.crypto

The :mod:`windows.crypto` module offers some wrappers arround the CryptoAPI_.

The main goal of this module (for now) is providing simple encryption/decryption methods.

Encryption
""""""""""

.. note::

    See sample :ref:`sample_crypto_encryption`

encrypt
'''''''

.. autofunction:: encrypt

decrypt
'''''''

.. autofunction:: decrypt

import_pfx
''''''''''

.. autofunction:: import_pfx



Certificate
"""""""""""

.. warning::

    The classes described here are still under test and possible rewrite/refactor.

    The classes, methods and properties described here will problably change as I haven't yet had the time
    to try it out in real cases and figure out the final look of the API I want to do.

.. note::

    See sample :ref:`sample_crypto_certificate`

Certificate
''''''''''''''''''

.. autoclass:: Certificate
    :show-inheritance:


CertificateStore
''''''''''''''''

.. autoclass:: CertificateStore


CryptObject
'''''''''''

.. autoclass:: CryptObject


CryptMessage
''''''''''''

.. autoclass:: CryptMessage


CryptContext
''''''''''''

.. autoclass:: CryptContext


Generating componants
"""""""""""""""""""""

.. module:: windows.crypto.generation

This module is used to generate selfsigned-certificates / keypair and pfx file.

.. note::

    See ``genkeys()`` in the sample :ref:`sample_crypto_encryption`


generate_selfsigned_certificate
'''''''''''''''''''''''''''''''

.. autofunction:: generate_selfsigned_certificate


generate_key
''''''''''''

.. autofunction:: generate_key


generate_pfx
''''''''''''

.. autofunction:: generate_pfx




.. _CryptoAPI: https://msdn.microsoft.com/en-us/library/windows/desktop/aa380252(v=vs.85).aspx