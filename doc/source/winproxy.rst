``windows.winproxy`` -- Windows API
***********************************

.. module:: windows.winproxy

:mod:`windows.winproxy` tries to be a pythontic wrapper around windows API of various DLL.
It also heavily relies on :mod:`ctypes` and :mod:`windows.generated_def.winfuncs`

Here are the things to know about :mod:`windows.winproxy`
    * All of this is based on :mod:`windows.generated_def.winfuncs`
    * DLL is loaded the first time an API of it is called
    * All parameters can be passed by ordinal or keyword
    * The call will fail if an argument with default value ``NeededParamater`` have been called without another value.
    * The call will raise a subclass of :class:`WindowsError` if it fails.
    * Some functions are 'transparent proxy' it means that all parameters are mandatory

Example: ``VirtualAlloc``
"""""""""""""""""""""""""

Exemple with the function `VirtualAlloc` in :mod:`windows.winproxy`

Documentation:

.. code-block:: python

    import windows
    windows.winproxy.VirtualAlloc
    # <function VirtualAlloc at 0x02ED63F0>

    help(windows.winproxy.VirtualAlloc)
    # Help on function VirtualAlloc in module windows.winproxy:
    # VirtualAlloc(lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT(0x1000L), flProtect=PAGE_EXECUTE_READWRITE(0x40L))
    #     Errcheck:
    #     raise Kernel32Error if result is 0


Calling it

.. code-block:: python

    import windows

    # Ordinal arguments
    windows.winproxy.VirtualAlloc(0, 0x1000)
    34537472

    # Keyword arguments
    windows.winproxy.VirtualAlloc(dwSize=0x1000)
    34603008

    # NeededParameter must be provided
    windows.winproxy.VirtualAlloc()
    """
    Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
    File "windows\winproxy.py", line 264, in VirtualAlloc
        return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)
    File "windows\winproxy.py", line 130, in perform_call
        raise TypeError("{0}: Missing Mandatory parameter <{1}>".format(self.func_name, param_name))
    TypeError: VirtualAlloc: Missing Mandatory parameter <dwSize>
    """

    # Error raises exception
    windows.winproxy.VirtualAlloc(dwSize=0xffffffff)
    """
    Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
    File "windows\winproxy.py", line 264, in VirtualAlloc
        return VirtualAlloc.ctypes_function(lpAddress, dwSize, flAllocationType, flProtect)
    File "windows\winproxy.py", line 133, in perform_call
        return self._cprototyped(*args)
    File "windows\winproxy.py", line 59, in kernel32_error_check
        raise Kernel32Error(func_name)
    windows.winproxy.Kernel32Error: VirtualAlloc: [Error 8] Not enough storage is available to process this command.
    """


Functions in :mod:`windows.winproxy`
""""""""""""""""""""""""""""""""""""

Transparent proxies:

* AllocConsole()
* CloseHandle(hObject)
* ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus)
* DebugActiveProcess(dwProcessId)
* DebugActiveProcessStop(dwProcessId)
* DebugBreak()
* DebugBreakProcess(Process)
* DebugSetProcessKillOnExit(KillOnExit)
* ExitProcess(uExitCode)
* ExitThread(dwExitCode)
* FreeConsole()
* GetCurrentProcess()
* GetCurrentProcessorNumber()
* GetCurrentThread()
* GetCurrentThreadId()
* GetExitCodeProcess(hProcess, lpExitCode)
* GetExitCodeThread(hThread, lpExitCode)
* GetLastError()
* GetProcAddress(hModule, lpProcName)
* GetProcessId(Process)
* GetSidSubAuthority(pSid, nSubAuthority)
* GetSidSubAuthorityCount(pSid)
* GetStdHandle(nStdHandle)
* GetThreadId(Thread)
* LoadLibraryA(lpFileName)
* LoadLibraryW(lpFileName)
* ResumeThread(hThread)
* SetStdHandle(nStdHandle, hHandle)
* SetTcpEntry(pTcpRow)
* SuspendThread(hThread)
* TerminateProcess(hProcess, uExitCode)
* TerminateThread(hThread, dwExitCode)
* VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength)
* Wow64DisableWow64FsRedirection(OldValue)
* Wow64EnableWow64FsRedirection(Wow64FsEnableRedirection)
* Wow64GetThreadContext(hThread, lpContext)
* Wow64RevertWow64FsRedirection(OldValue)
Functions:

* AddVectoredContinueHandler::

    AddVectoredContinueHandler(FirstHandler=1, VectoredHandler=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* AddVectoredExceptionHandler::

    AddVectoredExceptionHandler(FirstHandler=1, VectoredHandler=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* AdjustTokenPrivileges::

    AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges=False, NewState=NeededParameter, BufferLength=None, PreviousState=None, ReturnLength=None)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateFileA::

    CreateFileA(lpFileName, dwDesiredAccess=GENERIC_READ(0x80000000L), dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=OPEN_EXISTING(0x3L), dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL(0x80L), hTemplateFile=None)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* CreateFileW::

    CreateFileW(lpFileName, dwDesiredAccess=GENERIC_READ(0x80000000L), dwShareMode=0, lpSecurityAttributes=None, dwCreationDisposition=OPEN_EXISTING(0x3L), dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL(0x80L), hTemplateFile=None)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* CreateProcessA::

    CreateProcessA(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateProcessW::

    CreateProcessW(lpApplicationName, lpCommandLine=None, lpProcessAttributes=None, lpThreadAttributes=None, bInheritHandles=False, dwCreationFlags=0, lpEnvironment=None, lpCurrentDirectory=None, lpStartupInfo=None, lpProcessInformation=None)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateRemoteThread::

    CreateRemoteThread(hProcess=NeededParameter, lpThreadAttributes=None, dwStackSize=0, lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateThread::

    CreateThread(lpThreadAttributes=None, dwStackSize=0, lpStartAddress=NeededParameter, lpParameter=NeededParameter, dwCreationFlags=0, lpThreadId=None)
    Errcheck:
       raise Kernel32Error if result is 0

* CreateToolhelp32Snapshot::

    CreateToolhelp32Snapshot(dwFlags, th32ProcessID=0)
    Errcheck:
       raise Kernel32Error if result is 0

* DeviceIoControl::

    DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize=None, lpOutBuffer=NeededParameter, nOutBufferSize=None, lpBytesReturned=None, lpOverlapped=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetExtendedTcpTable::

    GetExtendedTcpTable(pTcpTable, pdwSize=None, bOrder=True, ulAf=NeededParameter, TableClass=5, Reserved=0)
    Errcheck:
       raise IphlpapiError if result is NOT 0

* GetMappedFileNameA::

    GetMappedFileNameA(hProcess, lpv, lpFilename, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetMappedFileNameW::

    GetMappedFileNameW(hProcess, lpv, lpFilename, nSize=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetThreadContext::

    GetThreadContext(hThread, lpContext=None)
    Errcheck:
       raise Kernel32Error if result is 0

* GetTokenInformation::

    GetTokenInformation(TokenHandle=NeededParameter, TokenInformationClass=NeededParameter, TokenInformation=None, TokenInformationLength=0, ReturnLength=None)
    Errcheck:
       raise Kernel32Error if result is 0

* LdrLoadDll::

    LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle)

* LookupPrivilegeValueA::

    LookupPrivilegeValueA(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* LookupPrivilegeValueW::

    LookupPrivilegeValueW(lpSystemName=None, lpName=NeededParameter, lpLuid=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* NtCreateThreadEx::

    NtCreateThreadEx(ThreadHandle=None, DesiredAccess=2097151, ObjectAttributes=0, ProcessHandle=NeededParameter, lpStartAddress=NeededParameter, lpParameter=NeededParameter, CreateSuspended=0, dwStackSize=0, Unknown1=0, Unknown2=0, Unknown=0)

* NtGetContextThread::

    NtGetContextThread(hThread, lpContext)

* NtQueryInformationProcess::

    NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength=0, ReturnLength=None)

* NtQueryInformationThread::

    NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength=0, ReturnLength=None)

* NtQuerySystemInformation::

    NtQuerySystemInformation(SystemInformationClass, SystemInformation=None, SystemInformationLength=0, ReturnLength=NeededParameter)

* NtQueryVirtualMemory::

    NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation=NeededParameter, MemoryInformationLength=0, ReturnLength=None)

* NtSetContextThread::

    NtSetContextThread(hThread, lpContext)

* NtWow64ReadVirtualMemory64::

    NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None)

* OpenProcess::

    OpenProcess(dwDesiredAccess=PROCESS_ALL_ACCESS(0x1f0fffL), bInheritHandle=0, dwProcessId=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* OpenProcessToken::

    OpenProcessToken(ProcessHandle=None, DesiredAccess=NeededParameter, TokenHandle=NeededParameter)
    If ProcessHandle is None: take the current process
    Errcheck:
       raise Kernel32Error if result is 0

* OpenThread::

    OpenThread(dwDesiredAccess=THREAD_ALL_ACCESS(0x1f03ffL), bInheritHandle=0, dwThreadId=NeededParameter)
    Errcheck:
       raise Kernel32Error if result is 0

* Process32First::

    Process32First(hSnapshot, lpte)
    Set byref(lpte) if needed
    Errcheck:
       Nothing special

* Process32Next::

    Process32Next(hSnapshot, lpte)
    Set byref(lpte) if needed
    Errcheck:
       Nothing special

* ReadProcessMemory::

    ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None)
    Errcheck:
       raise Kernel32Error if result is 0

* RegCloseKey::

    RegCloseKey(hKey)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegGetValueA::

    RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegGetValueW::

    RegGetValueW(hkey, lpSubKey=None, lpValue=NeededParameter, dwFlags=0, pdwType=None, pvData=None, pcbData=None)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegOpenKeyExA::

    RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RegOpenKeyExW::

    RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult)
    Errcheck:
       raise Kernel32Error if result is NOT 0

* RemoveVectoredExceptionHandler::

    RemoveVectoredExceptionHandler(Handler)
    Errcheck:
       raise Kernel32Error if result is 0

* SetThreadAffinityMask::

    SetThreadAffinityMask(hThread=None, dwThreadAffinityMask=NeededParameter)
    If hThread is not given, it will be the current thread
    Errcheck:
       raise Kernel32Error if result is 0

* SetThreadContext::

    SetThreadContext(hThread, lpContext)
    Errcheck:
       raise Kernel32Error if result is 0

* Thread32First::

    Thread32First(hSnapshot, lpte)
    Set byref(lpte) if needed
    Errcheck:
       Nothing special

* Thread32Next::

    Thread32Next(hSnapshot, lpte)
    Set byref(lpte) if needed
    Errcheck:
       Nothing special

* VirtualAlloc::

    VirtualAlloc(lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT(0x1000L), flProtect=PAGE_EXECUTE_READWRITE(0x40L))
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualAllocEx::

    VirtualAllocEx(hProcess, lpAddress=0, dwSize=NeededParameter, flAllocationType=MEM_COMMIT(0x1000L), flProtect=PAGE_EXECUTE_READWRITE(0x40L))
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualFree::

    VirtualFree(lpAddress, dwSize=0, dwFreeType=MEM_RELEASE(0x8000L))
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualFreeEx::

    VirtualFreeEx(hProcess, lpAddress, dwSize=0, dwFreeType=MEM_RELEASE(0x8000L))
    Errcheck:
       raise Kernel32Error if result is 0

* VirtualProtect::

    VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect=None)
    Errcheck:
       raise Kernel32Error if result is 0

* WaitForDebugEvent::

    WaitForDebugEvent(lpDebugEvent, dwMilliseconds=INFINITE(0xffffffffL))
    Errcheck:
       raise Kernel32Error if result is 0

* WaitForSingleObject::

    WaitForSingleObject(hHandle, dwMilliseconds=INFINITE(0xffffffffL))
    Errcheck:
       raise Kernel32Error if result is NOT 0

* WinVerifyTrust::

    WinVerifyTrust(hwnd, pgActionID, pWVTData)
    Errcheck:
       Nothing special

* Wow64SetThreadContext::

    Wow64SetThreadContext(hThread, lpContext)
    Errcheck:
       raise Kernel32Error if result is 0

* WriteFile::

    WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite=None, lpNumberOfBytesWritten=None, lpOverlapped=None)
    Errcheck:
       raise Kernel32Error if result is 0

* WriteProcessMemory::

    WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize=None, lpNumberOfBytesWritten=None)
    Computer nSize with len(lpBuffer) if not given
    Errcheck:
       raise Kernel32Error if result is 0