import ctypes
import struct
import windows
from windows.generated_def.winstructs import *

IID_PACK = "<I", "<H", "<H", "<B", "<B", "<B", "<B", "<B", "<B", "<B", "<B"
def get_IID_from_raw(raw):
    s = "".join([struct.pack(i, j) for i, j in zip(IID_PACK, raw)])
    return ctypes.create_string_buffer(s)


WINTRUST_ACTION_GENERIC_VERIFY_V2_RAW = (0xaac56b, 0xcd44,  0x11d0,
                    0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee)

WINTRUST_ACTION_GENERIC_VERIFY_V2 = get_IID_from_raw(WINTRUST_ACTION_GENERIC_VERIFY_V2_RAW)

WTD_UI_ALL    = 1
WTD_UI_NONE   = 2
WTD_UI_NOBAD  = 3
WTD_UI_NOGOOD = 4

WTD_REVOKE_NONE         = 0x00000000
WTD_REVOKE_WHOLECHAIN   = 0x00000001

WTD_CHOICE_FILE    = 1
WTD_CHOICE_CATALOG = 2
WTD_CHOICE_BLOB    = 3
WTD_CHOICE_SIGNER  = 4
WTD_CHOICE_CERT    = 5

WTD_STATEACTION_IGNORE           = 0x00000000
WTD_STATEACTION_VERIFY           = 0x00000001
WTD_STATEACTION_CLOSE            = 0x00000002
WTD_STATEACTION_AUTO_CACHE       = 0x00000003
WTD_STATEACTION_AUTO_CACHE_FLUSH = 0x00000004

def check_signature(filename):
    print("Filename is <{0}>".format(repr(filename)))
    file_data = WINTRUST_FILE_INFO()
    file_data.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_data.pcwszFilePath = filename
    file_data.hFile = None
    file_data.pgKnownSubject = None

    WVTPolicyGUID =  WINTRUST_ACTION_GENERIC_VERIFY_V2

    win_trust_data = WINTRUST_DATA()

    win_trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    win_trust_data.pPolicyCallbackData = None
    win_trust_data.pSIPClientData = None
    win_trust_data.dwUIChoice = WTD_UI_NONE
    win_trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    win_trust_data.dwUnionChoice = WTD_CHOICE_FILE
    win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    win_trust_data.hWVTStateData = None
    win_trust_data.pwszURLReference = None
    win_trust_data.dwUIContext = 0
    win_trust_data.tmp_union.pFile = ctypes.pointer(file_data)

    WinVerifyTrust = ctypes.WinDLL("wintrust").WinVerifyTrust

    x = WinVerifyTrust(None, ctypes.byref(WVTPolicyGUID), ctypes.byref(win_trust_data))

    win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE

    WinVerifyTrust(None, ctypes.byref(WVTPolicyGUID), ctypes.byref(win_trust_data))

    return x & 0xffffffff