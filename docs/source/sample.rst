Samples of code
===============

.. _sample_current_process:

``windows.current_process``
"""""""""""""""""""""""""""

.. literalinclude:: ..\..\samples\current_process.py

Output::

    (cmd λ) python32.exe current_process.py
    current process is <windows.winobject.process.CurrentProcess object at 0x030A2590>
    current process is a <32> bits process
    current process is a SysWow64 process ? <True>
    current process pid <8264>  and ppid <4100>
    Here are the current process threads: <[<WinThread 13540 owner "python.exe" at 0x32d3210>]>
    Let's execute some native code ! (0x41 + 1)
    Native code returned <0x42>
    Allocating memory in current process
    Allocated memory is at <0xd60000>
    Writing 'SOME STUFF' in allocation memory
    Reading memory : <'SOME STUFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'>

.. _sample_remote_process:

Remote process : :class:`WinProcess`
""""""""""""""""""""""""""""""""""""

.. literalinclude:: ..\..\samples\remote_calc.py

Output::

    (cmd λ) python.exe remote_calc.py
    Creating a calc
    Looking for calcs in the processes
    They are currently <1> calcs running on the system
    Let's play with our calc: <<WinProcess "calc.exe" pid 8052 at 0x27bd5d0>>
    Our calc pid is 8052
    Our calc is a <32> bits process
    Our calc is a SysWow64 process ? <True>
    Our calc have threads ! <[<WinThread 8552 owner "calc.exe" at 0x27f7f30>, <WinThread 3464 owner "calc.exe" at 0x27f7f80>, <WinThread 3840 owner "calc.exe" at 0x27fa030>]>
    Exploring our calc PEB ! <windows.winobject.RemotePEB object at 0x026DDD00>
    Command line is <RemoteWinUnicodeString ""C:\windows\system32\calc.exe"" at 0x26ddee0>
    Here are 3 loaded modules: [<RemoteLoadedModule "calc.exe" at 0x26dde40>, <RemoteLoadedModule "ntdll.dll" at 0x26ddf30>, <RemoteLoadedModule "kernel32.dll" at 0x26ddc60>]
    Allocating memory in our calc
    Allocated memory is at <0x5c90000>
    Writing 'SOME STUFF' in allocated memory
    Reading allocated memory : <'SOME STUFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'>
    Execution some native code in our calc (write 0x424242 at allocated address + return 0x1337
    Executing native code !
    Return code = 0x1337L
    Reading allocated memory : <'BBBB STUFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'>
    Executing python code !
    Reading allocated memory : <'HELLO FROM CALC\x00\x00\x00\x00\x00'>
    Trying to import in remote module 'FAKE_MODULE'
    Remote ERROR !
    Traceback (most recent call last):
    File "<string>", line 3, in <module>
    File "<string>", line 2, in func
    ImportError: No module named FAKE_MODULE

    That's all ! killing the calc


.. _sample_peb_exploration:

:class:`PEB` exploration
""""""""""""""""""""""""

.. literalinclude:: ..\..\samples\peb.py

Output::

    (cmd λ) python.exe  peb.py
    Exploring the current process PEB
    PEB is <<windows.winobject.PEB object at 0x02649B70>>
    Commandline object is <WinUnicodeString "python.exe   peb.py " at 0x2649c60>
    Commandline string is u'python.exe   peb.py '
    Imagepath  <WinUnicodeString "C:\Python27\python.exe" at 0x2649d50>
    Printing some modules: <LoadedModule "python.exe" at 0x272a030>
    <LoadedModule "ntdll.dll" at 0x272a080>
    <LoadedModule "kernel32.dll" at 0x272acb0>
    <LoadedModule "kernelbase.dll" at 0x272ad00>
    <LoadedModule "python27.dll" at 0x272ad50>
    <LoadedModule "msvcr90.dll" at 0x272ada0>
    === K32  ===
    Looking for kernel32.dll
    Kernel32 module: <LoadedModule "kernel32.dll" at 0x272acb0>
    Module name = <kernel32.dll> | Fullname = <C:\Windows\SYSTEM32\KERNEL32.DLL>
    Kernel32 is loaded at address 0x774c0000
    === K32 PE ===
    PE Representation of k32: <windows.pe_parse.PEFile object at 0x0272D350>
    Here are some exports {0: 2001566688L, u'CreateFileA': 2001635616L, 42: 2001647872L, u'VirtualAlloc': 2001570704L}
    Import DLL dependancies are (without api-*): [u'ntdll.dll', u'kernelbase.dll']
    IAT Entry for ntdll!NtCreateFile = <IATEntry "NtCreateFile" ordinal 253> | addr = 0x77541128L
    Sections: [<PESection ".text">, <PESection ".rdata">, <PESection ".data">, <PESection ".rsrc">, <PESection ".reloc">]



.. _sample_system:


``windows.system``
""""""""""""""""""

.. literalinclude:: ..\..\samples\system.py

Output::

    (cmd λ) python system.py
    Basic system infos:
        version = (6, 3)
        bitness = 64
        computer_name = HAKRIL-PC
        product_type = VER_NT_WORKSTATION(0x1L)
        version_name = Windows 8.1

    There is 117 processes
    There is 1246 threads

    Dumping first logical drive:
        <LogicalDrive "C:\" (DRIVE_FIXED)>
            name = C:\
            type = DRIVE_FIXED(0x3L)
            path = \Device\HarddiskVolume2

    Dumping first service:
        <ServiceA "ACPI">
            name = ACPI
            description = Microsoft ACPI Driver
            status = ServiceStatus(type=SERVICE_KERNEL_DRIVER(0x1L), state=SERVICE_RUNNING(0x4L), control_accepted=1L, flags=0L)
            process = None

    Finding a service in a user process:
        <ServiceA "Appinfo">
            name = Appinfo
            description = Application Information
            status = ServiceStatus(type=SERVICE_WIN32_SHARE_PROCESS(0x20L), state=SERVICE_RUNNING(0x4L), control_accepted=129L, flags=0L)
            process = <WinProcess "svchost.exe" pid 988 at 0x2e64750>

    Enumerating handles:
        There are 40664 handles:
        First handle is: <Handle value=<0x4> in process pid=4>
        Enumerating handles of the current process:
            There are 255 handles for this process
        Looking for a File handle:
            Handle is <Handle value=<0x4> in process pid=14340>
            Name is <\Device\ConDrv>

.. _sample_iat_hook:

IAT hooking
"""""""""""

.. literalinclude:: ..\..\samples\iat_hook.py

Output::

    (cmd λ) python iat_hook.py
    Asking for <MY_SECRET_KEY>
    <in hook> Hook called | hKey = 0x12d687 | lpSubKey = <MY_SECRET_KEY>
    <in hook> Secret key asked, returning magic handle 0x12345678
    Result = 0x12345678

    Asking for <MY_FAIL_KEY>
    <in hook> Hook called | hKey = 0x12d687 | lpSubKey = <MY_FAIL_KEY>
    <in hook> Asked for a failing key: returning 0x2a
    WindowsError(42, 'Windows Error 0x2A')

    Asking for <HKEY_CURRENT_USER/Software>
    <in hook> Hook called | hKey = 0x80000001L | lpSubKey = <Software>
    <in hook> Non-secret key : calling normal function
    Result = 0x108

.. _sample_network_exploration:

:class:`Network` - socket exploration
"""""""""""""""""""""""""""""""""""""

.. literalinclude:: ..\..\samples\network.py

Output::

    (cmd λ) python.exe  network.py
    Working on ipv4
    == Listening ==
    Some listening connections: [<TCP IPV4 Listening socket on 0.0.0.0:80>, <TCP IPV4 Listening socket on 0.0.0.0:135>, <TCP IPV4 Listening socket on 0.0.0.0:443>]
    Listening ports are : [80, 135, 443, 445, 902, 912, 5357, 49152, 49153, 49154, 49155, 49157, 49159, 8307, 25340, 139, 139]
    == Established ==
    Some established connections: [<TCP IPV4 Connection 127.0.0.1:25340 -> 127.0.0.1:49472>, <TCP IPV4 Connection 127.0.0.1:49173 -> 127.0.0.1:49174>, <TCP IPV4 Connection 127.0.0.1:49174 -> 127.0.0.1:49173>]
    == connection to localhost:80 ==
    Our connection is [<TCP IPV4 Connection 127.0.0.1:49616 -> 127.0.0.1:80>]
    Sending YOP
    Closing socket
    Sending LAIT
    Traceback (most recent call last):
    File ".\network.py", line 45, in <module>
        s.send("LAIT")
    socket.error: [Errno 10054] An existing connection was forcibly closed by the remote host


.. _sample_registry:

:class:`Registry`
"""""""""""""""""

.. literalinclude:: ..\..\samples\registry.py

Output::

    (cmd λ) python.exe registry.py
    Registry is <<windows.registry.Registry object at 0x02941290>>
    HKEY_CURRENT_USER is <<PyHKey "HKEY_CURRENT_USER">>
    HKEY_CURRENT_USER subkeys names are:
    ['AppEvents',
    'AppXBackupContentType',
    'Console',
    'Control Panel',
    'Environment',
    'EUDC',
    'Identities',
    'Keyboard Layout',
    'Network',
    'Printers',
    'Software',
    'System',
    'Volatile Environment']
    Opening 'Software' in HKEY_CURRENT_USER: <PyHKey "HKEY_CURRENT_USER\Software">
    We can also open it in one access: <PyHKey "HKEY_CURRENT_USER\Sofware">
    Looking at CurrentVersion
    Key is <PyHKey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion">
    values are:
    [KeyValue(name='SoftwareType', value=u'System', type=1),
    KeyValue(name='RegisteredOwner', value=u'hakril', type=1),
    KeyValue(name='InstallDate', value=0, type=4),
    ...
    KeyValue(name='PathName', value=u'C:\\Windows', type=1)]
    registered owner = <KeyValue(name='RegisteredOwner', value=u'hakril', type=1)>


.. _sample_wintrust:

``windows.wintrust``
""""""""""""""""""""

.. literalinclude:: ..\..\samples\wintrust.py

Output::

    (cmd λ) python .\wintrust.py
    Checking signature of <C:\windows\system32\ntdll.dll>
    is_signed: <True>
    check_signature: <0>
    full_signature_information:
        * signed <True>
        * catalog <C:\Windows\system32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Package_35_for_KB3128650~31bf3856ad364e35~amd64~~6.3.1.2.cat>
        * catalogsigned <True>
        * additionalinfo <0>
    Checking signature of some loaded DLL
    <c:\python27\python.exe> : False (TRUST_E_NOSIGNATURE(0x800b0100L))
    <c:\windows\system32\ntdll.dll> : True
    <c:\windows\system32\kernel32.dll> : True
    <c:\windows\system32\kernelbase.dll> : True
    <c:\windows\system32\python27.dll> : False (TRUST_E_NOSIGNATURE(0x800b0100L))

.. _sample_vectoredexception:

:func:`VectoredException`
"""""""""""""""""""""""""

In local process
''''''''''''''''

.. literalinclude:: ..\..\samples\veh_segv.py

Output::

    (cmd λ) python.exe veh_segv.py
    Protected page is at <0x1db0000>
    Setting page protection to <PAGE_NOACCESS>

    ==Entry of VEH handler==
    Instr at 0x1d1ab574 accessed to addr 0x1db0000
    Resetting page protection to <PAGE_READWRITE>
    ==Entry of VEH handler==
    Exception of type EXCEPTION_SINGLE_STEP(0x80000004L)
    Resetting page protection to <PAGE_NOACCESS>
    Value 1 read

    ==Entry of VEH handler==
    Instr at 0x1d1ab574 accessed to addr 0x1db0010
    Resetting page protection to <PAGE_READWRITE>
    ==Entry of VEH handler==
    Exception of type EXCEPTION_SINGLE_STEP(0x80000004L)
    Resetting page protection to <PAGE_NOACCESS>
    Value 2 read


In remote process
'''''''''''''''''

.. literalinclude:: ..\..\samples\remote_veh_segv.py

Output::

    (cmd λ) python .exe.\samples\remote_veh_segv.py
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

.. literalinclude:: ..\..\samples\debugger_print_LdrLoaddll.py

Ouput::

    (cmd λ) python.exe .\samples\debugger_print_LdrLoaddll.py
    Loading <KERNEL32.DLL>
    Got exception EXCEPTION_BREAKPOINT(0x80000003L) at 0x77a73bad
    Loading <C:\Windows\system32\IMM32.DLL>
    Loading <C:\Windows\system32\uxtheme.dll>
    Loading <C:\Windows\system32\uxtheme.dll>
    Loading <C:\Windows\system32\uxtheme.dll>
    Loading <C:\Windows\system32\uxtheme.dll>
    Loading <kernel32.dll>
    Loading <C:\Windows\WinSxS\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.9600.17415_none_dad8722c5bcc2d8f\gdiplus.dll>
    Loading <comctl32.dll>
    Loading <comctl32.dll>
    Loading <comctl32.dll>
    Loading <C:\Windows\system32\shell32.dll>
    Loading <C:\Windows\SYSTEM32\WINMM.dll>
    Loading <C:\Windows\system32\ole32.dll>
    Ask to load <ole32.dll>: exiting process


Single stepping
~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\debugger_membp_singlestep.py

Ouput::

    (cmd λ) python.exe .\samples\debugger_membp_singlestep.py
    Got exception EXCEPTION_BREAKPOINT(0x80000003L) at 0x77ae3c7d
    Instruction at <0x8d0006> wrote at <0x8e0000>
    Got single_step EXCEPTION_SINGLE_STEP(0x80000004L) at 0x8d000c
    Got single_step EXCEPTION_SINGLE_STEP(0x80000004L) at 0x8d0011
    Instruction at <0x8d0011> wrote at <0x8e0004>
    Got single_step EXCEPTION_SINGLE_STEP(0x80000004L) at 0x8d0017
    Got single_step EXCEPTION_SINGLE_STEP(0x80000004L) at 0x8d001c
    Got single_step EXCEPTION_SINGLE_STEP(0x80000004L) at 0x8d0022
    Got single_step EXCEPTION_SINGLE_STEP(0x80000004L) at 0x8d0023
    No more single step: exiting


:class:`windows.debug.FunctionBP`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\debug_functionbp.py

Ouput::

    (cmd λ) python.exe .\samples\debug_functionbp.py
    NtCreateFile of <\??\C:\Windows\syswow64\en-US\calc.exe.mui>: handle = 0xac
    Handle manually found! typename=<File>, name=<\Device\HarddiskVolume2\Windows\SysWOW64\en-US\calc.exe.mui>

    NtCreateFile of <\Device\DeviceApi\CMApi>: handle = 0x108
    Handle manually found! typename=<File>, name=<\Device\DeviceApi>

    NtCreateFile of <\??\C:\Windows\Fonts\staticcache.dat>: handle = 0x154
    Handle manually found! typename=<File>, name=<\Device\HarddiskVolume2\Windows\Fonts\StaticCache.dat>

    Exiting process

.. _sample_local_debugger:


:class:`LocalDebugger`
''''''''''''''''''''''

In current process
~~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\local_debugger.py

Ouput::

    (cmd λ) python.exe .\samples\local_debugger.py
    Code addr = 0xcf0002
    GOT AN HXBP at 0xcf0002
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0xcf0003
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0xcf0004
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0xcf0005
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0x770d7c04
    Done!


In remote process
~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\local_debugger_remote_process.py

Ouput::

    (cmd λ) python.exe .\samples\local_debugger_remote_process.py
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


.. _wmi_request:

Make WMI requests
"""""""""""""""""


.. literalinclude:: ..\..\samples\wmi_request.py


Ouput::

    (cmd λ) python .\samples\wmi_request.py
    WMI requester is <windows.winobject.wmi.WmiRequester object at 0x02B37EF0>
    Selecting * from 'Win32_Process'
    They are <92> processes
    Looking for ourself via pid
    Some info about our process:
        * Name -> python.exe
        * ProcessId -> 7968
        * OSName -> Microsoft Windows 8.1 Pro|C:\Windows|\Device\Harddisk0\Partition2
        * UserModeTime -> 2812500
        * WindowsVersion -> 6.3.9600
        * CommandLine -> python.exe  .\samples\wmi_request.py
    <Select Caption,FileSystem,FreeSpace from Win32_LogicalDisk>:
        * {'Caption': u'C:', 'FreeSpace': u'43991547904', 'FileSystem': u'NTFS'}
        * {'Caption': u'E:', 'FreeSpace': u'82776027136', 'FileSystem': u'NTFS'}
        * {'Caption': u'F:', 'FreeSpace': u'5711265792', 'FileSystem': u'FAT32'}
        * {'Caption': u'G:', 'FreeSpace': None, 'FileSystem': None}

.. _sample_com_firewall:

using COM: ``INetFwPolicy2``
""""""""""""""""""""""""""""

.. literalinclude:: ..\..\samples\com_inetfwpolicy2.py

Output::

    (cmd λ) python .\samples\com_inetfwpolicy2.py
    Initialisation of COM
    Creating INetFwPolicy2 variable
    <INetFwPolicy2 object at 0x02DC8210> (value = None)

    Generating CLSID
    <IID "E2B3C97F-6AE1-41AC-817A-F6F92166D7DD">

    Creating COM instance
    <INetFwPolicy2 object at 0x02DC8210> (value = 0x8984848)

    Checking for enabled profiles
    * NET_FW_PROFILE2_DOMAIN(0x1L) -> True
    * NET_FW_PROFILE2_PRIVATE(0x2L) -> True
    * NET_FW_PROFILE2_PUBLIC(0x4L) -> True


``windows.crypto``
""""""""""""""""""


.. _sample_crypto_encryption:

Encryption demo
'''''''''''''''

This sample is a working POC able to generate key-pair, encrypt and decrypt file.

.. literalinclude:: ..\..\samples\encryption_demo.py

Ouput::

    (cmd λ) python samples\encryption_demo.py genkey YOLOCERTIF mykey --pfxpassword MYPASSWORD
    <CertificatContext "YOLOCERTIF" serial="1b a4 3e 17 f7 ed ec ab 4f f8 11 46 48 e9 29 25">

    (cmd λ) ls
    mykey.cer  mykey.pfx

    (cmd λ) echo|set /p="my secret message" > message.txt

    (cmd λ) python samples\encryption_demo.py crypt message.txt message.crypt mykey.cer
    Encryption done. Result:
    bytearray(b'0\x82\x01\x19\x06\t*\x86H\x86\xf7\r\x01\x07\x03\xa0\x82\x01\n0\x82\x01\x06\x02\x01\x001\x81\xc30\x81
    \xc0\x02\x01\x000)0\x151\x130\x11\x06\x03U\x04\x03\x13\nYOLOCERTIF\x02\x10\x1b\xa4>\x17\xf7\xed\xec\xabO\xf8\x11
    FH\xe9)%0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x04\x81\x80V\x89)\xf5\xaaM\x99cEA\x17^\xa2D~\x94\xe3\xf2\x1f
    \x05Y\xc2\xbb\xb2\xbbYBpU6\x870\xce\xe7\xd2M{\xbb\xb9K\xa0\xf5\xe5\x93\xca\xedF\x80.x\xdc\xf2\x0c\xa6UO\x01\r\xaf
    \xd0Z\xd9\xabnzR\xd4j=\xca\xc2RG\xcd\x11u\x82\x7f\x8c\xd8t\xb9\xf9\xe8%\xfal\xaaHPj;\xecKk]\t%\xfd\x91\xcc\xe0lWf
    \xc6\x12x\x1am\xc8\x01t\xac\xa6\xf3#\x02\xd4J \x8eZ\xbb\x10W\xe1 0;\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x14\x06\x08*
    \x86H\x86\xf7\r\x03\x07\x04\x08\x14F\x04\xad\xed9\xed<\x80\x18\x80]6\xccTV\xbc\xb8*\x84QY!~\xb3\n\x1aV\xd4\rf\xd1n:')

    (cmd λ) python samples\encryption_demo.py decrypt message.crypt mykey.pfx BADPASS
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

    (cmd λ) python samples\encryption_demo.py decrypt message.crypt mykey.pfx MYPASSWORD
    Result = <my secret message>


.. _sample_crypto_certificate:

Certificate demo
''''''''''''''''

.. literalinclude:: ..\..\samples\certificate.py


Ouput::


    (cmd λ) python .\samples\certificate.py
    Analysing certificate: <CertificateContext "Microsoft Windows" serial="33 00 00 01 06 6e c3 25 c4 31 c9 18 0e 00 00 00 00 01 06">
    * name: <Microsoft Windows>
    * issuer: <Microsoft Windows Production PCA 2011>
    * raw_serial: <[51, 0, 0, 1, 6, 110, 195, 37, 196, 49, 201, 24, 14, 0, 0, 0, 0, 1, 6]>
    * serial: <33 00 00 01 06 6e c3 25 c4 31 c9 18 0e 00 00 00 00 01 06>
    * encoded start: <bytearray(b'0\x82\x05\x040\x82\x03\xec\xa0\x03\x02\x01\x02\x02\x133\x00\x00\x01\x06')>

    This certificate has 1 certificate chain
    Chain 0:
    <CertificateContext "Microsoft Windows" serial="33 00 00 01 06 6e c3 25 c4 31 c9 18 0e 00 00 00 00 01 06">:
        * issuer: <Microsoft Windows Production PCA 2011>
    <CertificateContext "Microsoft Windows Production PCA 2011" serial="61 07 76 56 00 00 00 00 00 08">:
        * issuer: <Microsoft Root Certificate Authority 2010>
    <CertificateContext "Microsoft Root Certificate Authority 2010" serial="28 cc 3a 25 bf ba 44 ac 44 9a 9b 58 6b 43 39 aa">:
        * issuer: <Microsoft Root Certificate Authority 2010>

    Looking for <Microsoft Root Certificate Authority 2010> in trusted certificates
    matches = [<CertificateContext "Microsoft Root Certificate Authority 2010" serial="28 cc 3a 25 bf ba 44 ac 44 9a 9b 58 6b 43 39 aa">]
    Found it !