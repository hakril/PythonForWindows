import platform
from .flag import make_flag

bits = platform.architecture()[0]
bitness =  int(bits[:2])

NATIVE_WORD_MAX_VALUE = 0xffffffff if bitness == 32 else 0xffffffffffffffff
