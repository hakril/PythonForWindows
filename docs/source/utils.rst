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

.. autofunction:: windows.utils.sprint

    Example:
        >>> cert
        <Certificate "YOLO2" serial="6f 1d 3e 7d d9 77 59 a9 4c 1c 53 dc 80 db 0c fe">
        >>> windows.utils.sprint(cert)
        struct.dwCertEncodingType -> 0x1L
        struct.pbCertEncoded<deref> -> 0x30
        struct.cbCertEncoded -> 0x1a7L
        struct.pCertInfo<deref>.dwVersion -> 0x2L
        struct.pCertInfo<deref>.SerialNumber.cbData -> 0x10L
        struct.pCertInfo<deref>.SerialNumber.pbData<deref> -> 0xfe
        struct.pCertInfo<deref>.SignatureAlgorithm.pszObjId -> '1.2.840.113549.1.1.5'
        struct.pCertInfo<deref>.SignatureAlgorithm.Parameters.cbData -> 0x2L
        struct.pCertInfo<deref>.SignatureAlgorithm.Parameters.pbData<deref> -> 0x5
        struct.pCertInfo<deref>.Issuer.cbData -> 0x12L
        struct.pCertInfo<deref>.Issuer.pbData<deref> -> 0x30
        struct.pCertInfo<deref>.NotBefore.dwLowDateTime -> 0x718ddc00L
        struct.pCertInfo<deref>.NotBefore.dwHighDateTime -> 0x1d249bbL
        struct.pCertInfo<deref>.NotAfter.dwLowDateTime -> 0x34ef0c00L
        struct.pCertInfo<deref>.NotAfter.dwHighDateTime -> 0x1d368bfL
        ...

.. autofunction:: windows.utils.enable_privilege
.. autofunction:: windows.utils.check_is_elevated
.. autofunction:: windows.utils.check_debug
.. autofunction:: windows.utils.create_process
.. autofunction:: windows.utils.create_console
.. autofunction:: windows.utils.pop_shell
.. autofunction:: windows.utils.create_file_from_handle
.. autofunction:: windows.utils.get_handle_from_file
.. autofunction:: windows.utils.get_short_path
.. autofunction:: windows.utils.get_long_path