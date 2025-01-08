import platform
from .flag import make_flag

bits = platform.architecture()[0]
bitness =  int(bits[:2])

NATIVE_WORD_MAX_VALUE = 0xffffffff if bitness == 32 else 0xffffffffffffffff

# python implementation of CTL_CODE (macro to compute IOCTL code from param.
# The python implem simplify the code parsing define (macro) by not handling macro functions

# Original MACRO:
#
#    #define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
#        ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
#    )

def CTL_CODE(DeviceType, Function, Method, Access):
    return (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

# https://learn.microsoft.com/en-us/windows/win32/api/winerror/nf-winerror-hresult_facility
# Original MACRO:
#   #define HRESULT_FACILITY(hr)  (((hr) >> 16) & 0x1fff)

def HRESULT_FACILITY(hr):
    return (((hr) >> 16) & 0x1fff)


BROKEN