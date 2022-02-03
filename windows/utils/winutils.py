import ctypes
import msvcrt
import os
import sys
import code
import math
import datetime
import warnings
from collections import namedtuple

import windows
from windows.dbgprint import dbgprint
import windows.generated_def as gdef

from .. import winproxy
from ..generated_def.winstructs import *


# Function resolution !
# should be in winproxy ?
def get_func_addr(dll_name, func_name):
        # Load the DLL
        ctypes.WinDLL(dll_name)
        modules = windows.current_process.peb.modules
        if not dll_name.lower().endswith(".dll"):
            dll_name += ".dll"
        mod = [x for x in modules if x.name == dll_name][0]
        return mod.pe.exports[func_name]


def get_remote_func_addr(target, dll_name, func_name):
        name_modules = [m for m in target.peb.modules if m.name == dll_name]
        if not len(name_modules):
            raise ValueError("Module <{0}> not loaded in target <{1}>".format(dll_name, target))
        mod = name_modules[0]
        return mod.pe.exports[func_name]


def is_wow_64(hProcess):
    try:
        fnIsWow64Process = get_func_addr("kernel32.dll", "IsWow64Process")
    except winproxy.WinproxyError:
        return False
    IsWow64Process = ctypes.WINFUNCTYPE(BOOL, HANDLE, ctypes.POINTER(BOOL))(fnIsWow64Process)
    Wow64Process = BOOL()
    res = IsWow64Process(hProcess, ctypes.byref(Wow64Process))
    if res:
        return bool(Wow64Process)
    raise ctypes.WinError()


def create_file_from_handle(handle, mode="r"):
    """Return a Python :class:`file` around a ``Windows`` HANDLE"""
    flags = os.O_BINARY if "b" in mode else os.O_TEXT
    fd = msvcrt.open_osfhandle(handle, flags)
    kwargs = {}
    if windows.pycompat.is_py3 and flags == os.O_TEXT:
        # Buffering, encoding
        args = (100, "ascii")
    else:
        # Buffering
        args = (0,)
    # In py2 os.fdopen do not accept kwargs
    return os.fdopen(fd, mode, *args)


def get_handle_from_file(f):
    """Get the ``Windows`` HANDLE of a python :class:`file`"""
    return msvcrt.get_osfhandle(f.fileno())


def create_console():
    """Create a new console displaying STDOUT.
       Useful in injection of GUI process"""
    winproxy.AllocConsole()
    stdout_handle = winproxy.GetStdHandle(gdef.STD_OUTPUT_HANDLE)
    console_stdout = create_file_from_handle(stdout_handle, "w")
    sys.stdout = console_stdout

    stdin_handle = winproxy.GetStdHandle(gdef.STD_INPUT_HANDLE)
    console_stdin = create_file_from_handle(stdin_handle, "r")
    sys.stdin = console_stdin

    stderr_handle = winproxy.GetStdHandle(gdef.STD_ERROR_HANDLE)
    console_stderr = create_file_from_handle(stderr_handle, "w")
    sys.stderr = console_stderr


def create_process(path, args=None, dwCreationFlags=0, show_windows=True):
    """A convenient wrapper arround :func:`windows.winproxy.CreateProcessA`"""
    proc_info = PROCESS_INFORMATION()
    lpStartupInfo = None
    if show_windows:
        StartupInfo = STARTUPINFOW()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        StartupInfo.dwFlags = 0
        lpStartupInfo = ctypes.byref(StartupInfo)
    lpCommandLine = None
    if isinstance(path, bytes):
        path = path.decode()
    if args:
        unicode_args = []
        for arg in args:
            if isinstance(arg, bytes):
                arg = arg.decode()
            unicode_args.append(arg)
        lpCommandLine = (" ".join(unicode_args))
    windows.winproxy.CreateProcessW(path, lpCommandLine=lpCommandLine, dwCreationFlags=dwCreationFlags, lpProcessInformation=ctypes.byref(proc_info), lpStartupInfo=lpStartupInfo)
    dbgprint("CreateProcessW new process handle {:#x}".format(proc_info.hProcess), "HANDLE")
    dbgprint("CreateProcessW new thread handle {:#x}".format(proc_info.hThread), "HANDLE")
    dbgprint("Automatic close of thread handle {:#x}".format(proc_info.hThread), "HANDLE")
    windows.winproxy.CloseHandle(proc_info.hThread)  # Give access to a WinThread in addition of the WinProcess ?
    return windows.winobject.process.WinProcess(pid=proc_info.dwProcessId, handle=proc_info.hProcess)


def device_io_control(handle, iocode, buffer):
    outbuffer = ctypes.c_buffer(0x1000)
    returned_size = gdef.DWORD()
    windows.winproxy.DeviceIoControl(handle, iocode, buffer, lpOutBuffer=outbuffer, lpBytesReturned=returned_size)
    return outbuffer[:returned_size.value]



def tmp_cp_as(path, token):
    proc_info = PROCESS_INFORMATION()
    windows.winproxy.CreateProcessAsUserA(token, path, lpCommandLine=None, dwCreationFlags=gdef.CREATE_NEW_CONSOLE, lpProcessInformation=ctypes.byref(proc_info), lpStartupInfo=None)
    return windows.winobject.process.WinProcess(pid=proc_info.dwProcessId, handle=proc_info.hProcess)

def find_handle(proc, value):
    return [h for h in windows.system.handles if h.dwProcessId == proc.pid and h.wValue == value]

def lookup_privilege_value(privilege_name):
    luid = LUID()
    winproxy.LookupPrivilegeValueA(None, privilege_name, byref(luid))
    return luid

def lookup_privilege_name(privilege_value):
    if isinstance(privilege_value, tuple):
        luid = LUID(privilege_value[1], privilege_value[0])
        privilege_value = luid
    size = DWORD(0x100)
    buff = ctypes.c_buffer(size.value)
    winproxy.LookupPrivilegeNameA(None, privilege_value, buff, size)
    return buff[:size.value]


def lookup_sid(psid):
    """Retrieves the name of the Computer/Domain and the name of the Account for a given SID

    :returns: (:class:`unicode`, :class:`unicode`) - A tuple of two unicode strings
    """
    usernamesize = gdef.DWORD(0x1000)
    computernamesize = gdef.DWORD(0x1000)
    username = ctypes.create_unicode_buffer(usernamesize.value)
    computername = ctypes.create_unicode_buffer(computernamesize.value)
    peUse = gdef.SID_NAME_USE()
    winproxy.LookupAccountSidW(None, psid, username, usernamesize, computername, computernamesize, peUse)
    return computername[:computernamesize.value], username[:usernamesize.value]

def enable_privilege(lpszPrivilege, bEnablePrivilege):
    """
    Enable or disable a privilege::

        enable_privilege(SE_DEBUG_NAME, True)
    """
    tp = TOKEN_PRIVILEGES()
    luid = LUID()
    hToken = HANDLE()

    winproxy.OpenProcessToken(winproxy.GetCurrentProcess(), TOKEN_ALL_ACCESS, byref(hToken))
    winproxy.LookupPrivilegeValueA(None, lpszPrivilege, byref(luid))
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    if bEnablePrivilege:
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    else:
        tp.Privileges[0].Attributes = 0
    winproxy.AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(TOKEN_PRIVILEGES))
    winproxy.CloseHandle(hToken)
    if winproxy.GetLastError() == gdef.ERROR_NOT_ALL_ASSIGNED:
        raise ValueError("Failed to get privilege {0}".format(lpszPrivilege))
    return True


def check_is_elevated():
    """Return ``True`` if process is Admin"""
    hToken = HANDLE()
    elevation = TOKEN_ELEVATION()
    cbsize = DWORD()

    winproxy.OpenProcessToken(winproxy.GetCurrentProcess(), TOKEN_ALL_ACCESS, byref(hToken))
    winproxy.GetTokenInformation(hToken, TokenElevation, byref(elevation), sizeof(elevation), byref(cbsize))
    winproxy.CloseHandle(hToken)
    return elevation.TokenIsElevated


def check_debug():
    """Check that kernel is in debug mode (beware of NOUMEX):

       https://msdn.microsoft.com/en-us/library/windows/hardware/ff556253(v=vs.85).aspx#_______noumex______
    """
    options = windows.system.registry(r'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control')['SystemStartOptions']
    control = options.value
    if "DEBUG" not in control:
        # print "[-] Enable debug boot!"
        # print "> bcdedit /debug on"
        return False
    if "DEBUG=NOUMEX" not in control:
        pass
        # print "[*] Warning noumex not set!"
        # print "> bcdedit /set noumex on"
    return True

UNIX_EPOCH = datetime.datetime(1970, 1, 1, 0, 0)
WINDOWS_EPOCH = datetime.datetime(1601, 1, 1, 0, 0)
# https://docs.microsoft.com/en-us/cpp/atl-mfc-shared/date-type?view=vs-2019
# Why keep it simple and have only one epoch ? :D
# I don't want to name this "DATE_EPOCH" as everything is a DATE
# So let's go with COMDATE as this structure seems very related to COM/AUTOMATION
COMDATE_EPOCH = datetime.datetime(1899, 12, 30, 0, 0)

WIN_TO_UNIX_EPOCH_SECOND = int((UNIX_EPOCH - WINDOWS_EPOCH).total_seconds())
WIN_TICK_PER_SECOND_INT = 10**7
WIN_TICK_PER_SECOND_FLOAT = 10.0**7
WIN_TO_UNIX_EPOCH_WIN_TICKS = WIN_TO_UNIX_EPOCH_SECOND * WIN_TICK_PER_SECOND_INT

# TODO: look in python stblib how filetime -> unix timestamp translation is down (os.stat code ?)

def unix_timestamp_from_filetime(filetime):
    # Round the filetime
    last_number = (filetime % 10)
    # We do some sort of "manual rounding cause of py2 vs py3
    # PY2: round(0.5) == 1
    # PY3: round(0.5) == 0
    if last_number == 5:
        rounding = 1
    else:
        rounding = round(last_number / 10.0)
    round_win_ticks = ((filetime // 10) + int(rounding)) * 10
    return round((round_win_ticks - WIN_TO_UNIX_EPOCH_WIN_TICKS) / WIN_TICK_PER_SECOND_FLOAT, 7)

def datetime_from_filetime(filetime):
    """return a :class:`datetime.datetime` from a ``windows`` FILETIME int"""
    # Manual non-approx rounding as filetime will not have a perfect representation as Python float
    # We do some sort of "manual rounding cause of py2 vs py3
    # PY2: round(0.5) == 1
    # PY3: round(0.5) == 0
    last_number = (filetime % 10)
    if last_number == 5:
        rounding = 1
    else:
        rounding = round(last_number / 10.0)
    round_microsecond = (filetime // 10) + int(rounding)
    return WINDOWS_EPOCH + datetime.timedelta(microseconds=round_microsecond)

def filetime_from_datetime(dtime):
    """Return the FILETIME value from a :class:`datetime.datetime` in a python :class:`int`"""
    return int((dtime - WINDOWS_EPOCH).total_seconds()) * WIN_TICK_PER_SECOND_INT

def datetime_from_comdate(comtime):
    # Hour values are expressed as the absolute value of the fractional part of the number.
    if comtime < 0:
        # The date timeline becomes discontinuous for date values less than 0 (before 30 December 1899). This is because the whole-number portion of the date value is treated as signed, while the fractional part is treated as unsigned.
        # other words, the whole-number part of the date value may be positive or negative, while the fractional part of the date value is always added to the overall logical date.
        # WTF :D
        dec, nb = math.modf(comtime)
        final_delta = nb + abs(dec)
        return COMDATE_EPOCH + datetime.timedelta(final_delta)
    return COMDATE_EPOCH + datetime.timedelta(comtime)

def datetime_from_systemtime(systime):
    return datetime.datetime(
            year=systime.wYear,
            month=systime.wMonth,
            day=systime.wDay,
            hour=systime.wHour,
            minute=systime.wMinute,
            second=systime.wSecond,
            microsecond=systime.wMilliseconds * 1000,
    )

class FixedInteractiveConsole(code.InteractiveConsole):
    def raw_input(self, prompt=">>>"):
        sys.stdout.write(prompt)
        return raw_input("")


def pop_shell(locs=None):
    """Pop a console with an InterativeConsole"""
    if locs is None:
        locs = globals()
    create_console()
    FixedInteractiveConsole(locs).interact()

def get_kernel_modules():
    warnings.warn("get_kernel_modules() will be removed: use windows.system.modules instead", DeprecationWarning)
    return windows.system.modules

class FileStreamInformation(gdef.FILE_STREAM_INFORMATION):
    @property
    def name(self):
        return gdef.LPWSTR(ctypes.addressof(self) + type(self).StreamName.offset).value

    @property
    def next(self):
        if not self.NextEntryOffset:
            return None
        return type(self).from_address(ctypes.addressof(self) + self.NextEntryOffset)


    def all(self):
        return list(self)

    def __iter__(self):
        while self:
            yield self
            self = self.next

    def __repr__(self):
        return "<ADS name='{0}'>".format(self.name)


ntqueryinformationfile_info_structs = {
    gdef.FileAccessInformation: gdef.FILE_ACCESS_INFORMATION,
    gdef.FileAlignmentInformation: gdef.FILE_ALIGNMENT_INFORMATION,
    gdef.FileAllInformation: gdef.FILE_ALL_INFORMATION,
    gdef.FileAttributeTagInformation: gdef.FILE_ATTRIBUTE_TAG_INFORMATION,
    gdef.FileBasicInformation: gdef.FILE_BASIC_INFORMATION,
    gdef.FileEaInformation: gdef.FILE_EA_INFORMATION ,
    gdef.FileInternalInformation: gdef.FILE_INTERNAL_INFORMATION,
    gdef.FileIoPriorityHintInformation: gdef.FILE_IO_PRIORITY_HINT_INFORMATION,
    gdef.FileModeInformation: gdef.FILE_MODE_INFORMATION,
    gdef.FileNetworkOpenInformation: gdef.FILE_NETWORK_OPEN_INFORMATION,
    gdef.FileNameInformation: gdef.FILE_NAME_INFORMATION,
    gdef.FilePositionInformation: gdef.FILE_POSITION_INFORMATION,
    gdef.FileStandardInformation: gdef.FILE_STANDARD_INFORMATION,
    gdef.FileIsRemoteDeviceInformation: gdef.FILE_IS_REMOTE_DEVICE_INFORMATION,
    gdef.FileStreamInformation: FileStreamInformation,
}

def query_file_information(file_or_handle, file_info_class):
    if not isinstance(file_or_handle, windows.pycompat.int_types):
        file_or_handle = windows.utils.get_handle_from_file(file_or_handle)
    handle = file_or_handle
    io_status = gdef.IO_STATUS_BLOCK()
    info = ntqueryinformationfile_info_structs[file_info_class]()
    # Do helper for 'is_pointer' / get pointed_size & co ? (useful for winproxy)
    pinfo = ctypes.pointer(info)
    try:
        windows.winproxy.NtQueryInformationFile(handle, io_status, pinfo, ctypes.sizeof(info), FileInformationClass=file_info_class)
    except Exception as e:
        if not (e.winerror & 0xffffffff) == gdef.STATUS_BUFFER_OVERFLOW:
            raise
        # STATUS_BUFFER_OVERFLOW -> Guess we have a FILE_NAME_INFORMATION somewhere that need a bigger buffer
        if file_info_class == gdef.FileNameInformation:
            file_name_length = pinfo[0].FileNameLength
        elif file_info_class == gdef.FileAllInformation:
            file_name_length = pinfo[0].NameInformation.FileNameLength
        elif file_info_class == gdef.FileStreamInformation:
            file_name_length = 0x10000
        else:
            raise
        full_size = ctypes.sizeof(info) + file_name_length # We add a little too much size for the sake of simplicity
        buffer = ctypes.c_buffer(full_size)
        windows.winproxy.NtQueryInformationFile(handle, io_status, buffer, full_size, FileInformationClass=file_info_class)
        pinfo = ctypes.cast(buffer,  ctypes.POINTER(ntqueryinformationfile_info_structs[file_info_class]))
        info = pinfo[0]
    # return list of ADS if FileStreamInformation ?
    return info


class EAInfo(gdef.FILE_FULL_EA_INFORMATION):
    @property
    def name(self):
        return gdef.LPCSTR(ctypes.addressof(self) + type(self).EaName.offset).value

    @property
    def value(self):
        value_addr = ctypes.addressof(self) + type(self).EaName.offset + self.EaNameLength + 1 # +1 -> Name \x00
        return (ctypes.c_char * self.EaValueLength).from_address(value_addr)[:]

    @property
    def next(self):
        # NextEntryOffset is Relative to our current offset
        if not self.NextEntryOffset:
            return None
        try: # First entry
            raw_buffer = self._b_base_._raw_buffer_
        except AttributeError as e:
            raw_buffer = self._raw_buffer_
        curoffset = getattr(self, "_raw_buffer_offset_", 0)
        new = type(self).from_buffer(raw_buffer, curoffset + self.NextEntryOffset)
        # Keep the underlying buffer easily accessible
        new._raw_buffer_ = raw_buffer
        new._raw_buffer_offset_ = curoffset + self.NextEntryOffset
        return new


    def __iter__(self):
        while self:
            yield self
            self = self.next

    def __repr__(self):
        return '<{0} name="{1}">'.format(type(self).__name__, self.name)


MAXIMUM_EA_SIZE = 0x0000ffff

def query_extended_attributes(file_or_handle):
    if isinstance(file_or_handle, file):
        file_or_handle = windows.utils.get_handle_from_file(file_or_handle)
    # Check EaSize
    x = windows.utils.query_file_information(file_or_handle, gdef.FileEaInformation)
    if not x.EaSize:
        return
    io_status = gdef.IO_STATUS_BLOCK()
    # Handle Win10 / Win7
    # Saw on Win10 -> EaSize > MAXIMUM_EA_SIZE
    # Saw on Win7 -> EaSize not enought (STATUS_BUFFER_OVERFLOW)
    buffsize = max(MAXIMUM_EA_SIZE, x.EaSize)
    buffer = windows.utils.BUFFER(EAInfo)(size=buffsize)
    windows.winproxy.NtQueryEaFile(file_or_handle, io_status, buffer, buffsize, False, None, 0, None, True)
    return buffer[0]




ntqueryvolumeinformationfile_info_structs = {
    gdef.FileFsAttributeInformation: gdef.FILE_FS_ATTRIBUTE_INFORMATION,
    gdef.FileFsControlInformation: gdef.FILE_FS_CONTROL_INFORMATION,
    gdef.FileFsDeviceInformation: gdef.FILE_FS_DEVICE_INFORMATION,
    gdef.FileFsDriverPathInformation: gdef.FILE_FS_DRIVER_PATH_INFORMATION,
    gdef.FileFsFullSizeInformation: gdef.FILE_FS_FULL_SIZE_INFORMATION,
    gdef.FileFsObjectIdInformation: gdef.FILE_FS_OBJECTID_INFORMATION,
    gdef.FileFsSizeInformation: gdef.FILE_FS_SIZE_INFORMATION,
    gdef.FileFsVolumeInformation: gdef.FILE_FS_VOLUME_INFORMATION,
    gdef.FileFsSectorSizeInformation: gdef.FILE_FS_SECTOR_SIZE_INFORMATION,
}


# TODO: FileFsDriverPathInformation
# TODO: Extended FILE_FS_VOLUME_INFORMATION that can read the real value of 'VolumeLabel'
def query_volume_information(file_or_handle, volume_info_class):
    if not isinstance(file_or_handle, windows.pycompat.int_types):
        file_or_handle = get_handle_from_file(file_or_handle)
    handle = file_or_handle
    io_status = gdef.IO_STATUS_BLOCK()
    info = ntqueryvolumeinformationfile_info_structs[volume_info_class]()
    # Do helper for 'is_pointer' / get pointed_size & co ? (useful for winproxy)
    pinfo = ctypes.pointer(info)
    try:
        windows.winproxy.NtQueryVolumeInformationFile(handle, io_status, pinfo, ctypes.sizeof(info), FsInformationClass=volume_info_class)
    except WindowsError as e:
        # import pdb;pdb.set_trace()
        if not (e.winerror & 0xffffffff) == gdef.STATUS_BUFFER_OVERFLOW:
            raise
        if volume_info_class == gdef.FileFsAttributeInformation:
            file_name_length = pinfo[0].FileSystemNameLength
        elif volume_info_class == gdef.FileFsVolumeInformation:
            # Well VolumeLabelLength is clearly broken (after testing..) so we are adding some bytes to it..
            file_name_length = pinfo[0].VolumeLabelLength + 0x100 # I have seen cases where the VolumeLabelLength is not even enough..
        else:
            raise
        full_size = ctypes.sizeof(info) + file_name_length # We add a little too much size for the sake of simplicity
        buffer = ctypes.c_buffer(full_size)
        windows.winproxy.NtQueryVolumeInformationFile(handle, io_status, buffer, full_size, FsInformationClass=volume_info_class)
        pinfo = ctypes.cast(buffer,  ctypes.POINTER(ntqueryvolumeinformationfile_info_structs[volume_info_class]))
        info = pinfo[0]
    return info
    return info

# String stuff
def ntstatus(code):
    return windows.generated_def.ntstatus.NtStatusException(code)


_WINERROR_BY_VALUE = None
def winerror(code):
    global _WINERROR_BY_VALUE
    if not _WINERROR_BY_VALUE: # Lazy init
        _WINERROR_BY_VALUE = gdef.FlagMapper(*(getattr(gdef, error) for error in gdef.meta.errors))
    val = _WINERROR_BY_VALUE[code]
    if val is code: # Not found
        val = _WINERROR_BY_VALUE[code & 0xffff] # Hresult: extract code (https://en.wikipedia.org/wiki/HRESULT)
    return val



def get_long_path(path):
    """Return the long path form for ``path``.

        :raise: :class:`~windows.winproxy.WinproxyError` if ``path`` does not exists
        :param path: a valid Windows path
        :type path: :class:`str` | :obj:`unicode`
        :returns: :class:`str` | :obj:`unicode` -- same type as ``path`` parameter
    """
    size = 0x1000
    buffer = ctypes.create_unicode_buffer(size)
    rsize = winproxy.GetLongPathNameW(path, buffer, size)
    return buffer[:rsize]


def get_short_path(path):
    """Return the short path form for ``path``

        :raise: :class:`~windows.winproxy.WinproxyError` if ``path`` does not exists
        :param path: a valid Windows path
        :type path: :class:`str` | :obj:`unicode`
        :returns: :class:`str` | :obj:`unicode` -- same type as ``path`` parameter
    """
    size = 0x1000
    buffer = ctypes.create_unicode_buffer(size)
    rsize = winproxy.GetShortPathNameW(path, buffer, size)
    return buffer[:rsize]

def dospath_to_ntpath(dospath):
    ustring = gdef.UNICODE_STRING()
    windows.winproxy.RtlDosPathNameToNtPathName_U(dospath, ustring, None, None)
    return ustring.str


def get_shared_mapping(name=None, handle=INVALID_HANDLE_VALUE, size=0x1000):
    # TODO: real code
    h = windows.winproxy.CreateFileMappingA(handle, dwMaximumSizeLow=size, lpName=name)
    addr = windows.winproxy.MapViewOfFile(h, dwNumberOfBytesToMap=size)
    return addr


def create_file(name, access=gdef.GENERIC_READ, share=gdef.FILE_SHARE_READ, security=None, creation=gdef.OPEN_EXISTING, flags=gdef.FILE_ATTRIBUTE_NORMAL):
    return windows.winproxy.CreateFileA(name, access, share, security, creation, flags, 0)

#def mapfile(file):
#    fhandle = get_handle_from_file(file)
#    h = windows.winproxy.CreateFileMappingA(fhandle, None, PAGE_READONLY, 0, 1, None)
#    addr = windows.winproxy.MapViewOfFile(h, dwDesiredAccess=FILE_MAP_READ, dwNumberOfBytesToMap=1)
#    return addr

def decompress_buffer(buffer, comptype=gdef.COMPRESSION_FORMAT_LZNT1, uncompress_size=None):
    if uncompress_size is None:
        uncompress_size = len(buffer) * 10
    result_size = DWORD()
    uncompressed = ctypes.c_buffer(uncompress_size)
    windows.winproxy.RtlDecompressBuffer(comptype, uncompressed, uncompress_size, buffer, len(buffer), result_size)
    return uncompressed[:result_size.value]

def compress_buffer(buffer, comptype=gdef.COMPRESSION_FORMAT_LZNT1):
    uncompress_size = len(buffer)
    CompressedBufferSize = uncompress_size + 0x1000
    CompressedBuffer = ctypes.c_buffer(CompressedBufferSize)
    chunk = 4096
    final_size = gdef.DWORD()
    work_space_size = gdef.ULONG()
    ignore_data = gdef.ULONG()

    windows.winproxy.RtlGetCompressionWorkSpaceSize(comptype, work_space_size, ignore_data)
    work_space = ctypes.c_buffer(work_space_size.value)
    windows.winproxy.RtlCompressBuffer(comptype, buffer, uncompress_size, CompressedBuffer, CompressedBufferSize, chunk, final_size, work_space)
    return CompressedBuffer[:final_size.value]


# sid.py + real SID type ?

def get_known_sid(sid_type):
    size = DWORD()
    try:
        windows.winproxy.CreateWellKnownSid(sid_type, None, None, size)
    except WindowsError:
        pass
    buffer = ctypes.c_buffer(size.value)
    windows.winproxy.CreateWellKnownSid(sid_type, None, buffer, size)
    return ctypes.cast(buffer, PSID)

UnloadEventTraceInfo = namedtuple("UnloadEventTraceInfo", ["size", "nb_elt", "array_ptr"])

def get_unload_event_trace():
    x = PULONG()
    y = PULONG()
    z = PVOID()
    windows.winproxy.RtlGetUnloadEventTraceEx(x, y, z)
    return UnloadEventTraceInfo(x[0], y[0], z.value)

class VirtualProtected(object):
    """
    A context manager usable like `VirtualProtect` that will restore the old protection at exit ::

        with utils.VirtualProtected(IATentry.addr, ctypes.sizeof(PVOID), gdef.PAGE_EXECUTE_READWRITE):
            IATentry.value = 0x42424242
    """
    def __init__(self, addr, size, new_protect):
        if (addr % 0x1000):
            addr = addr - addr % 0x1000
        self.addr = addr
        self.size = size
        self.new_protect = new_protect

    def __enter__(self):
        self.old_protect = DWORD()
        winproxy.VirtualProtect(self.addr, self.size, self.new_protect, ctypes.byref(self.old_protect))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        winproxy.VirtualProtect(self.addr, self.size, self.old_protect.value, ctypes.byref(self.old_protect))
        return False


class DisableWow64FsRedirection(object):
    """
    A context manager that disable the SysWow64 Filesystem Redirection ::

        if is_process_32_bits:
            def pop_calc_64():
                with windows.utils.DisableWow64FsRedirection():
                    return windows.utils.create_process(r"C:\Windows\system32\calc.exe", True)
    """
    def __enter__(self):
        if windows.current_process.bitness == 64 or windows.system.bitness == 32:
            return self
        self.OldValue = PVOID()
        winproxy.Wow64DisableWow64FsRedirection(ctypes.byref(self.OldValue))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if windows.current_process.bitness == 64 or windows.system.bitness == 32:
            return False
        winproxy.Wow64RevertWow64FsRedirection(self.OldValue)
        return False
