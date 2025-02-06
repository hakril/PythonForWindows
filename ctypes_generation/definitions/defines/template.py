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

# https://github.com/microsoft/win32metadata/blob/6af96d8470751e13a4e3f579f84b7b8b3ca398e1/generation/WinSDK/RecompiledIdlHeaders/um/WinBase.h#L3562
# Original MACRO:

#define ProcThreadAttributeValue(Number, Thread, Input, Additive) \
#      (((Number) & PROC_THREAD_ATTRIBUTE_NUMBER) | \
#       ((Thread != FALSE) ? PROC_THREAD_ATTRIBUTE_THREAD : 0) | \
#       ((Input != FALSE) ? PROC_THREAD_ATTRIBUTE_INPUT : 0) | \
#       ((Additive != FALSE) ? PROC_THREAD_ATTRIBUTE_ADDITIVE : 0))

def ProcThreadAttributeValue(Number, Thread, Input, Additive):
    return ((Number & PROC_THREAD_ATTRIBUTE_NUMBER) |
             (Thread and PROC_THREAD_ATTRIBUTE_THREAD) |
             (Input and PROC_THREAD_ATTRIBUTE_INPUT) |
             (Additive and PROC_THREAD_ATTRIBUTE_ADDITIVE))

