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