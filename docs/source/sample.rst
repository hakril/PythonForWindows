.. _sample_of_code:

Samples of code
===============

Processes
"""""""""

.. _sample_current_process:

``windows.current_process``
'''''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\process\current_process.py

Output

.. literalinclude:: samples_output\process_current_process.txt


.. _sample_remote_process:

Remote process : :class:`WinProcess`
''''''''''''''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\process\remote_process.py


Output

.. literalinclude:: samples_output\process_remote_process.txt



.. _sample_peb_exploration:

:class:`PEB` exploration
''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\process\peb.py

Output

.. literalinclude:: samples_output\process_peb.txt

.. _sample_apisetmap:

ApiSetMap
'''''''''

.. literalinclude:: ..\..\samples\process\apisetmap.py

Output

.. literalinclude:: samples_output\process_apisetmap.txt


.. _sample_iat_hook:

IAT hooking
'''''''''''

.. literalinclude:: ..\..\samples\process\iat_hook.py

Output

.. literalinclude:: samples_output\process_iat_hook.txt


.. _sample_system:


``windows.system``
""""""""""""""""""

.. literalinclude:: ..\..\samples\system.py

Output

.. literalinclude:: samples_output\system.txt


.. _sample_network_exploration:

:class:`Network` - socket exploration
"""""""""""""""""""""""""""""""""""""

.. literalinclude:: ..\..\samples\network\network.py

Output-New

.. literalinclude:: samples_output\network_network.txt


.. _sample_registry:

:class:`Registry`
"""""""""""""""""

.. literalinclude:: ..\..\samples\registry\registry.py

Output

.. literalinclude:: samples_output\registry_registry.txt


.. _sample_scheduled_task:

Scheduled tasks
"""""""""""""""

.. literalinclude:: ..\..\samples\scheduled_tasks\scheduled_task.py

Output

.. literalinclude:: samples_output\scheduled_task_scheduled_task.txt


.. _sample_event_log:

Event Log
"""""""""

.. literalinclude:: ..\..\samples\event_log\eventlog.py

Output

.. literalinclude:: samples_output\event_log_eventlog.txt


.. _sample_object_manager:

Object manager
""""""""""""""

.. literalinclude:: ..\..\samples\object_manager\object_manager.py

Output

.. literalinclude:: samples_output\object_manager_object_manager.txt

find objects
''''''''''''


.. literalinclude:: ..\..\samples\object_manager\findobj.py

Output

.. literalinclude:: samples_output\object_manager_findobj.txt


.. _sample_wintrust:

``windows.wintrust``
""""""""""""""""""""

.. literalinclude:: ..\..\samples\crypto\wintrust.py

Output

.. literalinclude:: samples_output\crypto_wintrust.txt


.. _sample_vectoredexception:

:func:`VectoredException`
"""""""""""""""""""""""""

In local process
''''''''''''''''

.. literalinclude:: ..\..\samples\process\veh_segv.py

Output

.. literalinclude:: samples_output\process_veh_segv.txt



In remote process
'''''''''''''''''

.. literalinclude:: ..\..\samples\process\remote_veh_segv.py

Output::

    (cmd λ) python.exe process\remote_veh_segv.py
    (In another console)

    Tracing execution in module: <gdi32.dll>
    Protected page is at 0x7ffa3c700000L

    Instr at 0x7ffa3c70f0f0L accessed to addr 0x7ffa3c70f0f0L (gdi32.dll)
    Exception of type EXCEPTION_SINGLE_STEP(0x80000004L)
    Resetting page protection to <PAGE_READWRITE>

    Instr at 0x7ffa3c70f0f5L accessed to addr 0x7ffa3c70f0f5L (gdi32.dll)
    Exception of type EXCEPTION_SINGLE_STEP(0x80000004L)
    Resetting page protection to <PAGE_READWRITE>

    Instr at 0x7ffa3c70f0faL accessed to addr 0x7ffa3c70f0faL (gdi32.dll)
    Exception of type EXCEPTION_SINGLE_STEP(0x80000004L)
    Resetting page protection to <PAGE_READWRITE>

    Instr at 0x7ffa3c70f0ffL accessed to addr 0x7ffa3c70f0ffL (gdi32.dll)
    Exception of type EXCEPTION_SINGLE_STEP(0x80000004L)
    Resetting page protection to <PAGE_READWRITE>

    Instr at 0x7ffa3c70f100L accessed to addr 0x7ffa3c70f100L (gdi32.dll)
    No more tracing !


.. _sample_debugger:

Debugging
"""""""""

:class:`Debugger`
'''''''''''''''''

.. literalinclude:: ..\..\samples\debug\debugger_print_LdrLoaddll.py


Output

.. literalinclude:: samples_output\debug_debugger_print_LdrLoaddll.txt



Single stepping
~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\debug\debugger_membp_singlestep.py

Output

.. literalinclude:: samples_output\debug_debugger_membp_singlestep.txt


:class:`windows.debug.FunctionBP`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\debug\debug_functionbp.py

Output

.. literalinclude:: samples_output\debug_debug_functionbp.txt


.. _sample_debugger_attach:

:func:`Debugger.attach <windows.debug.Debugger.attach>`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\debug\attach.py

Output

.. literalinclude:: samples_output\debug_attach.txt



Native code tester
~~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\test_code.py


Ouput

.. literalinclude:: samples_output\test_code.txt


.. _sample_local_debugger:


:class:`LocalDebugger`
''''''''''''''''''''''

In current process
~~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\debug\local_debugger.py

Output

.. literalinclude:: samples_output\debug_local_debugger.txt


In remote process
~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\debug\local_debugger_remote_process.py


Ouput::

    (cmd λ) python.exe debug\local_debugger_remote_process.py
    (In another console)
    I AM LOADING <C:\Windows\system32\uxtheme.dll>
    I AM LOADING <C:\Windows\system32\uxtheme.dll>
    I AM LOADING <C:\Windows\system32\uxtheme.dll>
    I AM LOADING <C:\Windows\system32\uxtheme.dll>
    I AM LOADING <kernel32.dll>
    I AM LOADING <C:\Windows\WinSxS\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.9600.17415_none_dad8722c5bcc2d8f\gdiplus.dll>
    I AM LOADING <comctl32.dll>
    I AM LOADING <comctl32.dll>
    I AM LOADING <comctl32.dll>
    I AM LOADING <comctl32.dll>
    I AM LOADING <comctl32.dll>
    I AM LOADING <comctl32>
    I AM LOADING <C:\Windows\SysWOW64\oleacc.dll>
    I AM LOADING <OLEAUT32.DLL>
    I AM LOADING <C:\Windows\system32\ole32.dll>
    I AM LOADING <C:\Windows\system32\MSCTF.dll>
    I AM LOADING <C:\Windows\SysWOW64\msxml6.dll>
    I AM LOADING <C:\Windows\system32\shell32.dll>
    I AM LOADING <C:\Windows\SYSTEM32\WINMM.dll>
    I AM LOADING <C:\Windows\system32\ole32.dll>


.. _wmi_samples:

WMI
"""

WMI requests
''''''''''''


.. literalinclude:: ..\..\samples\wmi\wmi_request.py

Output

.. literalinclude:: samples_output\wmi_wmi_request.txt

WMI Create Process
''''''''''''''''''

.. literalinclude:: ..\..\samples\wmi\create_process.py

Output

.. literalinclude:: samples_output\wmi_create_process.txt


.. _sample_com:

:mod:`windows.com`
""""""""""""""""""

.. _sample_com_firewall:

``INetFwPolicy2``
'''''''''''''''''

.. literalinclude:: ..\..\samples\com\com_inetfwpolicy2.py

Output

.. literalinclude:: samples_output\com_com_inetfwpolicy2.txt


.. _sample_com_icallinterceptor:

``ICallInterceptor``
''''''''''''''''''''

.. literalinclude:: ..\..\samples\com\icallinterceptor.py

Output

.. literalinclude:: samples_output\com_icallinterceptor.txt



:mod:`windows.crypto`
"""""""""""""""""""""


.. _sample_crypto_encryption:

Encryption demo
'''''''''''''''

This sample is a working POC able to generate key-pair, encrypt and decrypt file.

.. literalinclude:: ..\..\samples\crypto\encryption_demo.py

Ouput::

    (cmd λ) python crypto\encryption_demo.py genkey YOLOCERTIF mykey --pfxpassword MYPASSWORD
    <CertificatContext "YOLOCERTIF" serial="1b a4 3e 17 f7 ed ec ab 4f f8 11 46 48 e9 29 25">

    (cmd λ) ls
    mykey.cer  mykey.pfx

    (cmd λ) echo|set /p="my secret message" > message.txt

    (cmd λ) python crypto\encryption_demo.py crypt message.txt message.crypt mykey.cer
    Encryption done. Result:
    bytearray(b'0\x82\x01\x19\x06\t*\x86H\x86\xf7\r\x01\x07\x03\xa0\x82\x01\n0\x82\x01\x06\x02\x01\x001\x81\xc30\x81
    \xc0\x02\x01\x000)0\x151\x130\x11\x06\x03U\x04\x03\x13\nYOLOCERTIF\x02\x10\x1b\xa4>\x17\xf7\xed\xec\xabO\xf8\x11
    FH\xe9)%0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x04\x81\x80V\x89)\xf5\xaaM\x99cEA\x17^\xa2D~\x94\xe3\xf2\x1f
    \x05Y\xc2\xbb\xb2\xbbYBpU6\x870\xce\xe7\xd2M{\xbb\xb9K\xa0\xf5\xe5\x93\xca\xedF\x80.x\xdc\xf2\x0c\xa6UO\x01\r\xaf
    \xd0Z\xd9\xabnzR\xd4j=\xca\xc2RG\xcd\x11u\x82\x7f\x8c\xd8t\xb9\xf9\xe8%\xfal\xaaHPj;\xecKk]\t%\xfd\x91\xcc\xe0lWf
    \xc6\x12x\x1am\xc8\x01t\xac\xa6\xf3#\x02\xd4J \x8eZ\xbb\x10W\xe1 0;\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x14\x06\x08*
    \x86H\x86\xf7\r\x03\x07\x04\x08\x14F\x04\xad\xed9\xed<\x80\x18\x80]6\xccTV\xbc\xb8*\x84QY!~\xb3\n\x1aV\xd4\rf\xd1n:')

    (cmd λ) python crypto\encryption_demo.py decrypt decrypt --password BADPASS message.crypt mykey.pfx
    Traceback (most recent call last):
    File "..\samples\encryption_demo.py", line 103, in <module>
        res.func(**res.__dict__)
    File "..\samples\encryption_demo.py", line 26, in decrypt
        pfx = crypto.import_pfx(pfxfile.read(), password)
    File "c:\users\hakril\documents\work\pythonforwindows\windows\crypto\certificate.py", line 153, in import_pfx
        cert_store = winproxy.PFXImportCertStore(pfx, password, flags)
    File "c:\users\hakril\documents\work\pythonforwindows\windows\winproxy.py", line 1065, in PFXImportCertStore
        return PFXImportCertStore.ctypes_function(pPFX, szPassword, dwFlags)
    File "c:\users\hakril\documents\work\pythonforwindows\windows\winproxy.py", line 148, in perform_call
        return self._cprototyped(*args)
    File "c:\users\hakril\documents\work\pythonforwindows\windows\winproxy.py", line 69, in kernel32_error_check
        raise Kernel32Error(func_name)
    windows.winproxy.Kernel32Error: PFXImportCertStore: [Error 86] The specified network password is not correct.

    (cmd λ) python crypto\encryption_demo.py decrypt --password MYPASSWORD message.crypt mykey.pfx
    Result = <my secret message>


.. _sample_crypto_certificate:

Certificate demo
''''''''''''''''

.. literalinclude:: ..\..\samples\crypto\certificate.py

Output

.. literalinclude:: samples_output\crypto_certificate.txt



:mod:`windows.alpc`
"""""""""""""""""""

.. _sample_alpc:

simple alpc communication
'''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\alpc\simple_alpc.py

Output

.. literalinclude:: samples_output\alpc_simple_alpc.txt


.. _sample_advanced_alpc:


advanced alpc communication
'''''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\alpc\advanced_alpc.py

Output

.. literalinclude:: samples_output\alpc_advanced_alpc.txt


:mod:`windows.rpc`
""""""""""""""""""

.. _sample_rpc_uac:

Manual UAC
''''''''''

.. literalinclude:: ..\..\samples\rpc\uac.py


Output::

    (cmd λ) python rpc\uac.py
    Namespace(cmdline='', creationflags=CREATE_UNICODE_ENVIRONMENT(0x400L), target='C:\\Python27\\python.exe', uacflags=17)
    # UAC pop - asking to execute python.exe | Clicking Yes
    Return value = 0x6
    Created process is <WinProcess "python.exe" pid 19304 at 0x455f7d0>
    * bitness is 32
    * integrity: SECURITY_MANDATORY_HIGH_RID(0x3000L)
    * elevated: True

    # The new python.exe in another window
    >>> windows.current_process.token.integrity
    SECURITY_MANDATORY_HIGH_RID(0x3000L)
    >>> windows.current_process.token.is_elevated
    True

.. _sample_rpc_lsass:

Manual ``LsarEnumeratePrivileges``
''''''''''''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\rpc\lsass.py

Output

.. literalinclude:: samples_output\rpc_lsass.txt


.. _sample_pipe:

:mod:`windows.pipe`
"""""""""""""""""""

Communication with an injected process
''''''''''''''''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\pipe\child_send_object.py

Output

.. literalinclude:: samples_output\pipe_child_send_object.txt

