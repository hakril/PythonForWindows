import ctypes
import windows.generated_def as gdef

from ..apiproxy import ApiProxy, NeededParameter
from ..error import WinproxyError, result_is_ntstatus, fail_on_zero

class NtdllProxy(ApiProxy):
    APIDLL = "ntdll"
    default_error_check = staticmethod(result_is_ntstatus)


# Process

@NtdllProxy()
def NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId):
    return NtOpenProcess.ctypes_function(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId)

@NtdllProxy()
def NtTerminateProcess(ProcessHandle, ExitStatus):
    return NtTerminateProcess.ctypes_function(ProcessHandle, ExitStatus)

# Memory

@NtdllProxy()
def NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead):
    return NtReadVirtualMemory.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

@NtdllProxy()
def NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten):
    return NtWriteVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)

# Wow64

@NtdllProxy()
def NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead=None):
    return NtWow64ReadVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

@NtdllProxy()
def NtWow64WriteVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten=None):
    return NtWow64WriteVirtualMemory64.ctypes_function(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)

# File

@NtdllProxy()
def NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength):
    return NtCreateFile.ctypes_function(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength)

@NtdllProxy()
def NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions):
    return NtOpenFile.ctypes_function(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions)


@NtdllProxy()
def NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass):
    return NtSetInformationFile.ctypes_function(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)

@NtdllProxy()
def NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length=None, FileInformationClass=NeededParameter):
    if Length is None:
        Length = ctypes.sizeof(FileInformation)
    return NtQueryInformationFile.ctypes_function(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)

@NtdllProxy()
def NtQueryDirectoryFile(FileHandle, Event=None, ApcRoutine=None, ApcContext=None, IoStatusBlock=NeededParameter, FileInformation=NeededParameter, Length=None, FileInformationClass=NeededParameter, ReturnSingleEntry=NeededParameter, FileName=None, RestartScan=NeededParameter):
    if Length is None:
        Length = ctypes.sizeof(FileInformation)
    return NtQueryDirectoryFile.ctypes_function(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan)

@NtdllProxy()
def NtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FsInformation, Length=None, FsInformationClass=NeededParameter):
    if Length is None:
        Length = ctypes.sizeof(FsInformation)
    return NtQueryVolumeInformationFile.ctypes_function(FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass)

@NtdllProxy()
def NtQueryEaFile(FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan):
    return NtQueryEaFile.ctypes_function(FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan)

@NtdllProxy()
def NtSetEaFile(FileHandle, IoStatusBlock, Buffer, Length):
    return NtSetEaFile.ctypes_function(FileHandle, IoStatusBlock, Buffer, Length)


# Process

@NtdllProxy()
def NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength=0, ReturnLength=None):
    if ProcessInformation is not None and ProcessInformationLength == 0:
        ProcessInformationLength = ctypes.sizeof(ProcessInformation)
    if type(ProcessInformation) == gdef.PROCESS_BASIC_INFORMATION:
        ProcessInformation = ctypes.byref(ProcessInformation)
    if ReturnLength is None:
        ReturnLength = ctypes.byref(gdef.ULONG())
    return NtQueryInformationProcess.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)

@NtdllProxy()
def NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength=0):
    if not ProcessInformationLength:
        ProcessInformationLength = ctypes.sizeof(ProcessInformation)
    return NtSetInformationProcess.ctypes_function(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength)


@NtdllProxy()
def LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle):
    return LdrLoadDll.ctypes_function(PathToFile, Flags, ModuleFileName, ModuleHandle)

@NtdllProxy()
def RtlGetUnloadEventTraceEx(ElementSize, ElementCount, EventTrace):
    return RtlGetUnloadEventTraceEx.ctypes_function(ElementSize, ElementCount, EventTrace)


# Thread

@NtdllProxy()
def NtGetContextThread(hThread, lpContext):
    return NtGetContextThread.ctypes_function(hThread, lpContext)

@NtdllProxy()
def NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = ctypes.byref(gdef.ULONG())
    if ThreadInformation is not None and ThreadInformationLength == 0:
        ThreadInformationLength = ctypes.sizeof(ThreadInformation)
    return NtQueryInformationThread.ctypes_function(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)


@NtdllProxy()
def NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes=None, ParentProcess=NeededParameter, Flags=NeededParameter, SectionHandle=NeededParameter, DebugPort=None, ExceptionPort=None, InJob=False):
    return NtCreateProcessEx.ctypes_function(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob)

@NtdllProxy()
def NtCreateThreadEx(ThreadHandle=None, DesiredAccess=0x1fffff, ObjectAttributes=0, ProcessHandle=NeededParameter, lpStartAddress=NeededParameter, lpParameter=NeededParameter, CreateSuspended=0, dwStackSize=0, Unknown1=0, Unknown2=0, Unknown=0):
    if ThreadHandle is None:
        ThreadHandle = ctypes.byref(gdef.HANDLE())
    return NtCreateThreadEx.ctypes_function(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, dwStackSize, Unknown1, Unknown2, Unknown3)


@NtdllProxy()
def NtSetContextThread(hThread, lpContext):
    return NtSetContextThread.ctypes_function(hThread, lpContext)

@NtdllProxy()
def NtDelayExecution(Alertable, DelayInterval):
    return NtDelayExecution.ctypes_function(Alertable, DelayInterval)


# Memory

@NtdllProxy()
def NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect):
    return NtAllocateVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)


@NtdllProxy()
def NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType):
    return NtFreeVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, RegionSize, FreeType)

@NtdllProxy()
def NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection=None):
    if OldAccessProtection is None:
        OldAccessProtection = gdef.DWORD()
    return NtProtectVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection)

@NtdllProxy()
def NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation=NeededParameter, MemoryInformationLength=0, ReturnLength=None):
    if ReturnLength is None:
        ReturnLength = ctypes.byref(gdef.ULONG())
    if MemoryInformation is not None and MemoryInformationLength == 0:
        ProcessInformationLength = ctypes.sizeof(MemoryInformation)
    if type(MemoryInformation) == gdef.MEMORY_BASIC_INFORMATION64:
        MemoryInformation = ctypes.byref(MemoryInformation)
    return NtQueryVirtualMemory.ctypes_function(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation=NeededParameter, MemoryInformationLength=0, ReturnLength=None)


# System

def ntquerysysteminformation_error_check(func_name, result, func, args):
    if result == 0:
        return args
    # Ignore STATUS_INFO_LENGTH_MISMATCH if SystemInformation is None
    if result == gdef.STATUS_INFO_LENGTH_MISMATCH and args[1] is None:
        return args
    raise WinproxyError("{0} failed with NTStatus {1}".format(func_name, hex(result)))


@NtdllProxy(error_check=ntquerysysteminformation_error_check)
def NtQuerySystemInformation(SystemInformationClass, SystemInformation=None, SystemInformationLength=0, ReturnLength=NeededParameter):
    if SystemInformation is not None and SystemInformationLength == 0:
        SystemInformationLength = ctypes.sizeof(SystemInformation)
    return NtQuerySystemInformation.ctypes_function(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength)

# path

@NtdllProxy(error_check=fail_on_zero)
def RtlDosPathNameToNtPathName_U(DosName, NtName=None, PartName=None, RelativeName=None):
    return RtlDosPathNameToNtPathName_U.ctypes_function(DosName, NtName, PartName, RelativeName)



# kernel Object

@NtdllProxy()
def NtQueryObject(Handle, ObjectInformationClass, ObjectInformation=None, ObjectInformationLength=0, ReturnLength=NeededParameter):
    return NtQueryObject.ctypes_function(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength)

@NtdllProxy()
def NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes):
    return NtOpenDirectoryObject.ctypes_function(DirectoryHandle, DesiredAccess, ObjectAttributes)


@NtdllProxy()
def NtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength):
    return NtQueryDirectoryObject.ctypes_function(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength)


@NtdllProxy()
def NtCreateSymbolicLinkObject(pHandle, DesiredAccess, ObjectAttributes, DestinationName):
    return NtCreateSymbolicLinkObject.ctypes_function(pHandle, DesiredAccess, ObjectAttributes, DestinationName)


@NtdllProxy()
def NtOpenSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes):
    return NtOpenSymbolicLinkObject.ctypes_function(LinkHandle, DesiredAccess, ObjectAttributes)


@NtdllProxy()
def NtQuerySymbolicLinkObject(LinkHandle, LinkTarget, ReturnedLength):
    return NtQuerySymbolicLinkObject.ctypes_function(LinkHandle, LinkTarget, ReturnedLength)


# Event

@NtdllProxy()
def NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes):
    return NtOpenEvent.ctypes_function(EventHandle, DesiredAccess, ObjectAttributes)


# LPC

@NtdllProxy()
def NtConnectPort(PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength, ConnectionInformation, ConnectionInformationLength):
    return NtConnectPort.ctypes_function(PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength, ConnectionInformation, ConnectionInformationLength)


# ALPC

@NtdllProxy()
def NtAlpcCreatePort(PortHandle, ObjectAttributes, PortAttributes):
    return NtAlpcCreatePort.ctypes_function(PortHandle, ObjectAttributes, PortAttributes)


@NtdllProxy()
def NtAlpcConnectPort(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout):
    return NtAlpcConnectPort.ctypes_function(PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)


@NtdllProxy()
def NtAlpcConnectPortEx(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout):
    return NtAlpcConnectPortEx.ctypes_function(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)


@NtdllProxy()
def NtAlpcAcceptConnectPort(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection):
    return NtAlpcAcceptConnectPort.ctypes_function(PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection)


@NtdllProxy()
def NtAlpcQueryInformation(PortHandle, PortInformationClass, PortInformation, Length, ReturnLength):
    return NtAlpcQueryInformation.ctypes_function(PortHandle, PortInformationClass, PortInformation, Length, ReturnLength)

@NtdllProxy()
def NtAlpcDisconnectPort(PortHandle, Flags):
    return NtAlpcDisconnectPort.ctypes_function(PortHandle, Flags)

@NtdllProxy()
def NtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout):
    return NtAlpcSendWaitReceivePort.ctypes_function(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout)

@NtdllProxy()
def AlpcInitializeMessageAttribute(AttributeFlags, Buffer, BufferSize, RequiredBufferSize):
    return AlpcInitializeMessageAttribute.ctypes_function(AttributeFlags, Buffer, BufferSize, RequiredBufferSize)

@NtdllProxy()
def AlpcGetMessageAttribute(Buffer, AttributeFlag):
    return AlpcGetMessageAttribute.ctypes_function(Buffer, AttributeFlag)

@NtdllProxy()
def NtAlpcCreatePortSection(PortHandle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize):
    return NtAlpcCreatePortSection.ctypes_function(PortHandle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize)

@NtdllProxy()
def NtAlpcDeletePortSection(PortHandle, Flags, SectionHandle):
    return NtAlpcDeletePortSection.ctypes_function(PortHandle, Flags, SectionHandle)

@NtdllProxy()
def NtAlpcCreateSectionView(PortHandle, Flags, ViewAttributes):
    return NtAlpcCreateSectionView.ctypes_function(PortHandle, Flags, ViewAttributes)

@NtdllProxy()
def NtAlpcDeleteSectionView(PortHandle, Flags, ViewBase):
    return NtAlpcDeleteSectionView.ctypes_function(PortHandle, Flags, ViewBase)

@NtdllProxy()
def NtAlpcQueryInformationMessage(PortHandle, PortMessage, MessageInformationClass, MessageInformation, Length, ReturnLength):
    return NtAlpcQueryInformationMessage.ctypes_function(PortHandle, PortMessage, MessageInformationClass, MessageInformation, Length, ReturnLength)

@NtdllProxy()
def TpCallbackSendAlpcMessageOnCompletion(TpHandle, PortHandle, Flags, SendMessage):
    return TpCallbackSendAlpcMessageOnCompletion.ctypes_function(TpHandle, PortHandle, Flags, SendMessage)

@NtdllProxy()
def NtAlpcImpersonateClientOfPort(PortHandle, Message, Flags):
    return NtAlpcImpersonateClientOfPort.ctypes_function(PortHandle, Message, Flags)


# Compression

@NtdllProxy()
def RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize=None, FinalUncompressedSize=NeededParameter):
    if CompressedBufferSize is None:
        CompressedBufferSize = len(CompressedBuffer)
    return RtlDecompressBuffer.ctypes_function(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize)

@NtdllProxy()
def RtlDecompressBufferEx(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize=None, FinalUncompressedSize=NeededParameter, WorkSpace=NeededParameter):
    if CompressedBufferSize is None:
        CompressedBufferSize = len(CompressedBuffer)
    # TODO: automatic 'WorkSpace' size calc + allocation ?
    return RtlDecompressBufferEx.ctypes_function(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize, WorkSpace)

@NtdllProxy()
def RtlGetCompressionWorkSpaceSize(CompressionFormatAndEngine, CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize):
    return RtlGetCompressionWorkSpaceSize.ctypes_function(CompressionFormatAndEngine, CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize)

@NtdllProxy()
def RtlCompressBuffer(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, UncompressedChunkSize=4096, FinalCompressedSize=NeededParameter, WorkSpace=NeededParameter):
    return RtlCompressBuffer.ctypes_function(CompressionFormatAndEngine, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, UncompressedChunkSize, FinalCompressedSize, WorkSpace)


# Section

@NtdllProxy()
def NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle):
    return NtCreateSection.ctypes_function(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle)


@NtdllProxy()
def NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes):
    return NtOpenSection.ctypes_function(SectionHandle, DesiredAccess, ObjectAttributes)


@NtdllProxy()
def NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect):
    return NtMapViewOfSection.ctypes_function(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect)


@NtdllProxy()
def NtUnmapViewOfSection(ProcessHandle, BaseAddress):
    return NtUnmapViewOfSection.ctypes_function(ProcessHandle, BaseAddress)

# Registry

@NtdllProxy()
def NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes):
    return NtOpenKey.ctypes_function(KeyHandle, DesiredAccess, ObjectAttributes)

@NtdllProxy()
def NtCreateKey(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition):
    return NtCreateKey.ctypes_function(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition)

@NtdllProxy()
def NtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize):
    return NtSetValueKey.ctypes_function(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize)

@NtdllProxy()
def NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength):
    return NtQueryValueKey.ctypes_function(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)

@NtdllProxy()
def NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength):
    return NtEnumerateValueKey.ctypes_function(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)

@NtdllProxy()
def NtDeleteValueKey(KeyHandle, ValueName):
    return NtDeleteValueKey.ctypes_function(KeyHandle, ValueName)

@NtdllProxy()
def NtQueryLicenseValue(Name, Type, Buffer, Length=None, DataLength=NeededParameter):
    if Length is None and Buffer:
        Length = len(buffer)
    return NtQueryLicenseValue.ctypes_function(Name, Type, Buffer, Length, DataLength)

@NtdllProxy()
def NtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength):
    return NtQueryKey.ctypes_function(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength)

# Other

@NtdllProxy()
def RtlEqualUnicodeString(String1, String2, CaseInSensitive):
   return RtlEqualUnicodeString.ctypes_function(String1, String2, CaseInSensitive)

@NtdllProxy(error_check=None)
def RtlMoveMemory(Destination, Source, Length):
    return RtlMoveMemory.ctypes_function(Destination, Source, Length)


# Firmware
@NtdllProxy()
def NtEnumerateSystemEnvironmentValuesEx(InformationClass, Buffer, BufferLength):
    return NtEnumerateSystemEnvironmentValuesEx.ctypes_function(InformationClass, Buffer, BufferLength)


# Pipe
@NtdllProxy()
def NtCreateNamedPipeFile(NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, WriteModeMessage, ReadModeMessage, NonBlocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTimeOut):
    return NtCreateNamedPipeFile.ctypes_function(NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, WriteModeMessage, ReadModeMessage, NonBlocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTimeOut)


#########





