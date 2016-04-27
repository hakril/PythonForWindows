Samples of code
===============

.. _sample_current_process:

``windows.current_process``
"""""""""""""""""""""""""""

.. literalinclude:: ..\..\samples\current_process.py

Output::

    (cmd λ) python32.exe current_process.py
    current process is <windows.winobject.CurrentProcess object at 0x026CD190>
    current process is a <32> bits process
    current process is a SysWow64 process ? <True>
    current process pid <7432>  and ppid <5412>
    Here are the current process threads: <[<WinThread 5264 owner "python.exe" at 0x28563f0>]>
    Let's execute some native code ! (0x41 + 1)
    Waiting for execution to finish !
    Native code returned <0x42L>
    Allocating memory in current process
    Allocated memory is at <0x3f0000>
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

    There is 95 processes
    There is 1021 threads

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
            process = <WinProcess "svchost.exe" pid 944 at 0x29d5290>


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

.. literalinclude:: ..\..\samples\debugger.py

Ouput::

    (cmd λ) python.exe .\samples\debugger.py
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


.. _sample_local_debugger:

:class:`LocalDebugger`
''''''''''''''''''''''

In current process
^^^^^^^^^^^^^^^^^^

.. literalinclude:: ..\..\samples\local_debugger.py

Ouput::

    (cmd λ) python.exe .\samples\local_debugger.py
    Your main thread is 3864
    Code addr = 0x46000b
    GOT AN HXBP <3 at 0x46000b
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0x46000c
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0x46000d
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0x46000e
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0x46000f
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0x460010
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0x460011


In remote process
^^^^^^^^^^^^^^^^^

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
'''''''''''''''''

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
''''''''''''''''''''''''''''

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