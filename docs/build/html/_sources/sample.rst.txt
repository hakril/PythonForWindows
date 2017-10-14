Samples of code
===============

Processes
"""""""""

.. _sample_current_process:

``windows.current_process``
'''''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\process\current_process.py

Output::

    (cmd λ) python32.exe process\current_process.py
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
''''''''''''''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\process\remote_process.py

Output::

    (cmd λ) python.exe process\remote_process.py
    Creating a notepad
    Looking for notepads in the processes
    They are currently <1> notepads running on the system
    Let's play with our notepad: <<WinProcess "notepad.exe" pid 2044 at 0x40ce850>>
    Our notepad pid is 2044
    Our notepad is a <32> bits process
    Our notepad is a SysWow64 process ? <True>
    Our notepad have threads ! <[<WinThread 7700 owner "notepad.exe" at 0x41faee0>, <WinThread 7264 owner "notepad.exe" at 0x41faf30>, ...]>
    Exploring our notepad PEB ! <windows.winobject.process.RemotePEB object at 0x03F6CDA0>
    Command line is <RemoteWinUnicodeString ""C:\windows\system32\notepad.exe"" at 0x3f6cf80>
    Here are 3 loaded modules: [<RemoteLoadedModule "notepad.exe" at 0x3f6cf30>, <RemoteLoadedModule "ntdll.dll" at 0x3f6ce40>, <RemoteLoadedModule "kernel32.dll" at 0x3f6cee0>]
    Allocating memory in our notepad
    Allocated memory is at <0x6f80000>
    Writing 'SOME STUFF' in allocated memory
    Reading allocated memory : <'SOME STUFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'>
    Execution some native code in our notepad (write 0x424242 at allocated address + return 0x1337)
    Executing native code !
    Return code = 0x1337L
    Reading allocated memory : <'BBBB STUFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'>
    Executing python code !
    Reading allocated memory : <'HELLO FROM notepad\x00\x00'>
    Trying to import in remote module 'FAKE_MODULE'
    Remote ERROR !
    Traceback (most recent call last):
    File "<string>", line 3, in <module>
    File "<string>", line 2, in func
    ImportError: No module named FAKE_MODULE

    That's all ! killing the notepad


.. _sample_peb_exploration:

:class:`PEB` exploration
''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\process\peb.py

Output::

    (cmd λ) python.exe  process\peb.py
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

.. _sample_iat_hook:

IAT hooking
'''''''''''

.. literalinclude:: ..\..\samples\process\iat_hook.py

Output::

    (cmd λ) python process\iat_hook.py
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



.. _sample_network_exploration:

:class:`Network` - socket exploration
"""""""""""""""""""""""""""""""""""""

.. literalinclude:: ..\..\samples\network\network.py

Output::

    (cmd λ) python.exe  network\network.py
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

.. literalinclude:: ..\..\samples\registry\registry.py

Output::

    (cmd λ) python.exe registry\registry.py
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

.. literalinclude:: ..\..\samples\crypto\wintrust.py

Output::

    (cmd λ) python crypto\wintrust.py
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

.. literalinclude:: ..\..\samples\process\veh_segv.py

Output::

    (cmd λ) python.exe process\veh_segv.py
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

Ouput::

    (cmd λ) python.exe debug\debugger_print_LdrLoaddll.py
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

.. literalinclude:: ..\..\samples\debug\debugger_membp_singlestep.py

Ouput::

    (cmd λ) python.exe debug\debugger_membp_singlestep.py
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

.. literalinclude:: ..\..\samples\debug\debug_functionbp.py

Ouput::

    (cmd λ) python.exe debug\debug_functionbp.py
    NtCreateFile of <\??\C:\Windows\syswow64\en-US\calc.exe.mui>: handle = 0xac
    Handle manually found! typename=<File>, name=<\Device\HarddiskVolume2\Windows\SysWOW64\en-US\calc.exe.mui>

    NtCreateFile of <\Device\DeviceApi\CMApi>: handle = 0x108
    Handle manually found! typename=<File>, name=<\Device\DeviceApi>

    NtCreateFile of <\??\C:\Windows\Fonts\staticcache.dat>: handle = 0x154
    Handle manually found! typename=<File>, name=<\Device\HarddiskVolume2\Windows\Fonts\StaticCache.dat>

    Exiting process

.. _sample_debugger_attach:

:func:`Debugger.attach <windows.debug.Debugger.attach>`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\debug\attach.py

Ouput::

    (cmd λ) python.exe debug\attach.py
    Finding process with pid <11392>
    Target is <WinProcess "notepad.exe" pid 11392 at 0x471a750>
    Debugger attached: <windows.debug.debugger.Debugger object at 0x04707EF0>

    NtCreateFile of <\??\C:\Windows\Fonts\staticcache.dat>: handle = 0x288
    Handle manually found! typename=<File>, name=<\Device\HarddiskVolume4\Windows\Fonts\StaticCache.dat>

    NtCreateFile of <\??\C:\WINDOWS\Registration\R000000000015.clb>: handle = 0x320
    Handle manually found! typename=<File>, name=<\Device\HarddiskVolume4\Windows\Registration\R000000000015.clb>

    NtCreateFile of <\??\C:\WINDOWS\Globalization\Sorting\sortdefault.nls>: handle = 0x334
    Handle manually found! typename=<File>, name=<\Device\HarddiskVolume4\Windows\Globalization\Sorting\SortDefault.nls>

    Exiting process





Native code tester
~~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\test_code.py


Ouput::

    (cmd λ) python.exe test_code.py "mov eax, 0x42424242" "eax=0x11223344"
    Testing x86 code
    Startup context is:
    Eip -> 0x3f0000L
    Esp -> 0x3bfae4L
    Eax -> 0x11223344L
    Ebx -> 0x5a6000L
    Ecx -> 0x0L
    Edx -> 0x0L
    Ebp -> 0x0L
    Edi -> 0x0L
    Esi -> 0x0L
    EFlags -> 0x202L
    EEflags(0x202L:IF)
    ==Post-exec context==
    Eip -> 0x3f0007L
    Esp -> 0x3bfae4L
    Eax -> 0x42424242L
    Ebx -> 0x5a6000L
    Ecx -> 0x0L
    Edx -> 0x0L
    Ebp -> 0x0L
    Edi -> 0x0L
    Esi -> 0x0L
    EFlags -> 0x202L
    EEflags(0x202L:IF)
    <Normal terminaison>
    ==DIFF==
    Eip: 0x3f0000 -> 0x3f0007 (+0x7)
    Eax: 0x11223344 -> 0x42424242 (+0x31200efe)


    (cmd λ) python64 test_code.py --x64 "mov r15, 0x11223344; push r14; call r15" "rcx=1; r14=0x4242424243434343"
    Testing x64 code
    Startup context is:
    Rip -> 0x205a1d60000L
    Rsp -> 0xe24a88fa88L
    Rax -> 0x0L
    Rbx -> 0x0L
    Rcx -> 0x1L
    Rdx -> 0xe24aaf9000L
    Rbp -> 0x0L
    Rdi -> 0x0L
    Rsi -> 0x0L
    R8 -> 0x0L
    R9 -> 0x0L
    R10 -> 0x0L
    R11 -> 0x0L
    R12 -> 0x0L
    R13 -> 0x0L
    R14 -> 0x4242424243434343L
    R15 -> 0x0L
    EFlags -> 0x200L
    EEflags(0x200L:IF)
    ==Post-exec context==
    Rip -> 0x11223344L
    Rsp -> 0xe24a88fa78L
    Rax -> 0x0L
    Rbx -> 0x0L
    Rcx -> 0x1L
    Rdx -> 0xe24aaf9000L
    Rbp -> 0x0L
    Rdi -> 0x0L
    Rsi -> 0x0L
    R8 -> 0x0L
    R9 -> 0x0L
    R10 -> 0x0L
    R11 -> 0x0L
    R12 -> 0x0L
    R13 -> 0x0L
    R14 -> 0x4242424243434343L
    R15 -> 0x11223344L
    EFlags -> 0x10202L
    EEflags(0x10202L:IF|RF)
    <EXCEPTION_ACCESS_VIOLATION(0xc0000005L)> at <0x11223344>
    ==DIFF==
    Rip: 0x205a1d60000 -> 0x11223344 (-0x20590b3ccbc)
    Rsp: 0xe24a88fa88 -> 0xe24a88fa78 (-0x10)
    R15: 0x0 -> 0x11223344 (+0x11223344)
    EFlags: 0x200 -> 0x10202 (+0x10002)
    Negative Stack: dumping:
    E24A88FA88 0C 00 D6 A1 05 02 00 00  43 43 43 43 42 42 42 42 ........CCCCBBBB


.. _sample_local_debugger:


:class:`LocalDebugger`
''''''''''''''''''''''

In current process
~~~~~~~~~~~~~~~~~~

.. literalinclude:: ..\..\samples\debug\local_debugger.py

Ouput::

    (cmd λ) python.exe debug\local_debugger.py
    Code addr = 0xcf0002
    GOT AN HXBP at 0xcf0002
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0xcf0003
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0xcf0004
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0xcf0005
    EXCEPTION !!!! Got a EXCEPTION_SINGLE_STEP(0x80000004L) at 0x770d7c04
    Done!


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


.. _wmi_request:

WMI requests
""""""""""""


.. literalinclude:: ..\..\samples\wmi\wmi_request.py


Ouput::

    (cmd λ) python wmi\wmi_request.py
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

.. literalinclude:: ..\..\samples\com\com_inetfwpolicy2.py

Output::

    (cmd λ) python com\com_inetfwpolicy2.py
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

    (cmd λ) python crypto\encryption_demo.py decrypt message.crypt mykey.pfx BADPASS
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

    (cmd λ) python crypto\encryption_demo.py decrypt message.crypt mykey.pfx MYPASSWORD
    Result = <my secret message>


.. _sample_crypto_certificate:

Certificate demo
''''''''''''''''

.. literalinclude:: ..\..\samples\crypto\certificate.py


Ouput::


    (cmd λ) python crypto\certificate.py
    Analysing certificate: <CertificateContext "Microsoft Windows" serial="33 00 00 01 06 6e c3 25 c4 31 c9 18 0e 00 00 00 00 01 06">
        * name: <Microsoft Windows>
        * issuer: <Microsoft Windows Production PCA 2011>
        * raw_serial: <[51, 0, 0, 1, 6, 110, 195, 37, 196, 49, 201, 24, 14, 0, 0, 0, 0, 1, 6]>
        * serial: <33 00 00 01 06 6e c3 25 c4 31 c9 18 0e 00 00 00 00 01 06>
        * encoded start: <bytearray(b'0\x82\x05\x040\x82\x03\xec\xa0\x03\x02\x01\x02\x02\x133\x00\x00\x01\x06')>

    This certificate has 1 certificate chain(s)
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

    == PE Analysis ==
    Target sha1 = <eb90bc0e33f3e62b0eac4afa8bfcf42a5d4e7bbb>
    Analysing <CryptObject "C:\windows\system32\ntdll.dll" content_type=CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED(0xaL)>
    File has 1 signer(s):
    Signer 0:
    * Issuer: bytearray(b'0\x81\x841\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nWashington1\x100\x0e\x06\x03U\x04\x07\x13\x07Redmond1\x1e0\x1c\x06\x03U\x04\n\x13\x15Microsoft Corporation1.0,\x06\x03U\x04\x03\x13%Microsoft Windows Production PCA 2011')
    * HashAlgorithme: 2.16.840.1.101.3.4.2.1
    * Certificate: <CertificateContext "Microsoft Windows" serial="33 00 00 01 06 6e c3 25 c4 31 c9 18 0e 00 00 00 00 01 06">

    File embdeds 2 certificate(s):
    * 0) <CertificateContext "Microsoft Windows" serial="33 00 00 01 06 6e c3 25 c4 31 c9 18 0e 00 00 00 00 01 06">
    * 1) <CertificateContext "Microsoft Windows Production PCA 2011" serial="61 07 76 56 00 00 00 00 00 08">



:mod:`windows.alpc`
"""""""""""""""""""

.. _sample_alpc:

simple alpc communication
'''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\alpc\simple_alpc.py

Ouput::

    (cmd λ) python alpc\simple_alpc.py
    [SERV] PORT <\RPC Control\PythonForWindowsPORT> CREATED
    Client pid = 15044
    [SERV] Message type = 0x300a
    [SERV] Received data: <>
    [SERV] Connection request
    [CLIENT] Connected: <windows.alpc.AlpcClient object at 0x0377FDB0>

    [SERV] Received message: <Hello world !>
    [SERV] Message type = 0x3001
    [CLIENT] Response: <REQUEST 'Hello world !' DONE>
    BYE

.. _sample_advanced_alpc:


advanced alpc communication
'''''''''''''''''''''''''''

.. literalinclude:: ..\..\samples\alpc\advanced_alpc.py


Output::

    (cmd λ) python alpc\advanced_alpc.py
    server pid = 13000
    [SERV] PORT <\RPC Control\PythonForWindowsPORT_2> CREATED
    Client pid = 2100
    [CLIENT] == Connecting to port ==
    [SERV] == Message received ==
    * ALPC connection request: <Connection request client message>
    [CLIENT] Connected with response: <Connection message response>

    [CLIENT] == Sending a message ==
    * Sending Message <Complex Message 1>
    [SERV] == Message received ==
    * ALPC request: <Complex Message 1>
    * view_is_valid <False>
    * security_is_valid <False>
    * handle_is_valid <False>
    * context_is_valid <True>
    * message context attribute:
        - CTX.PortContext -> 0x11223344
        - CTX.MessageContext -> None
        - CTX.Sequence -> 0x1L
        - CTX.MessageId -> 0x0L
        - CTX.CallbackId -> 0x0L
    * message token attribute:
    - TOKEN.TokenId -> 0x1e4ecaccL
    - TOKEN.AuthenticationId -> 0x48989L
    - TOKEN.ModifiedId -> 0x48995L
    [CLIENT] Server response: <REQUEST 'Complex Message 1' DONE>
    [CLIENT] RESP Message Valid ATTRS = [ALPC_MESSAGE_CONTEXT_ATTRIBUTE(0x20000000L)]

    [Client] == Sending a message with a handle ==
    [SERV] == Message received ==
    * ALPC request: <some message with a file>
    * view_is_valid <False>
    * security_is_valid <False>
    * handle_is_valid <True>
    * message handle attribute:
        - HANDLE.Flags -> 0x0L
        - HANDLE.Handle -> 0x260
        - HANDLE.ObjectType -> 0x1L
        - HANDLE.DesiredAccess -> 0x13019fL
    - File: <open file '<fdopen>', mode 'r' at 0x02D529C0>
    - content: <Tempfile data <3>
    * context_is_valid <True>
    * message context attribute:
        - CTX.PortContext -> 0x11223344
        - CTX.MessageContext -> None
        - CTX.Sequence -> 0x2L
        - CTX.MessageId -> 0x0L
        - CTX.CallbackId -> 0x0L
    * message token attribute:
    - TOKEN.TokenId -> 0x1e4ecaccL
    - TOKEN.AuthenticationId -> 0x48989L
    - TOKEN.ModifiedId -> 0x48995L

    [Client] == Sending a message with a view ==
    [SERV] == Message received ==
    * ALPC request: <some message with a view>
    * view_is_valid <True>
    * message view attribute:
        - VIEW.Flags -> 0x0L
        - VIEW.SectionHandle -> None
        - VIEW.ViewBase -> 0x2770000
        - VIEW.ViewSize -> 0x4000
    * Reading view content: <The content of the view :)>
    * security_is_valid <False>
    * handle_is_valid <False>
    * context_is_valid <True>
    * message context attribute:
        - CTX.PortContext -> 0x11223344
        - CTX.MessageContext -> None
        - CTX.Sequence -> 0x3L
        - CTX.MessageId -> 0x0L
        - CTX.CallbackId -> 0x0L
    * message token attribute:
    - TOKEN.TokenId -> 0x1e4ecaccL
    - TOKEN.AuthenticationId -> 0x48989L
    - TOKEN.ModifiedId -> 0x48995L
    BYE




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

Output::

    (cmd λ) python rpc\lsass.py
    (2, u'SeCreateTokenPrivilege')
    (3, u'SeAssignPrimaryTokenPrivilege')
    (4, u'SeLockMemoryPrivilege')
    (5, u'SeIncreaseQuotaPrivilege')
    (6, u'SeMachineAccountPrivilege')
    (7, u'SeTcbPrivilege')
    (8, u'SeSecurityPrivilege')
    (9, u'SeTakeOwnershipPrivilege')
    (10, u'SeLoadDriverPrivilege')
    (11, u'SeSystemProfilePrivilege')
    (12, u'SeSystemtimePrivilege')
    (13, u'SeProfileSingleProcessPrivilege')
    (14, u'SeIncreaseBasePriorityPrivilege')
    (15, u'SeCreatePagefilePrivilege')
    (16, u'SeCreatePermanentPrivilege')
    (17, u'SeBackupPrivilege')
    (18, u'SeRestorePrivilege')
    (19, u'SeShutdownPrivilege')
    (20, u'SeDebugPrivilege')
    (21, u'SeAuditPrivilege')
    (22, u'SeSystemEnvironmentPrivilege')
    (23, u'SeChangeNotifyPrivilege')
    (24, u'SeRemoteShutdownPrivilege')
    (25, u'SeUndockPrivilege')
    (26, u'SeSyncAgentPrivilege')
    (27, u'SeEnableDelegationPrivilege')
    (28, u'SeManageVolumePrivilege')
    (29, u'SeImpersonatePrivilege')
    (30, u'SeCreateGlobalPrivilege')
    (31, u'SeTrustedCredManAccessPrivilege')
    (32, u'SeRelabelPrivilege')
    (33, u'SeIncreaseWorkingSetPrivilege')
    (34, u'SeTimeZonePrivilege')
    (35, u'SeCreateSymbolicLinkPrivilege')
    (36, u'SeDelegateSessionUserImpersonatePrivilege')

