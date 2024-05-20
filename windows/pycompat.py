import sys
import locale

is_py3 = (sys.version_info.major >= 3)

# retrieve info about current encoding output
# Provite a warning if sys.stdout.encoding do not match GetConsoleOutputCP() ?



if is_py3:
    def str_from_ascii_function(s):
        return s.decode("ascii")

    int_types = int
    basestring = str
    anybuff = (str, bytes)

    def raw_encode(s):
        if isinstance(s, str):
            return s.encode("latin1")
        return s

    def raw_decode(s):
        if isinstance(s, bytes):
            return s.decode("latin1")
        return s

    # No encoding of unicode repr
    # Python3 handle unicode natively in string and console output
    def urepr_encode(s):
        return s

else: # py2.7
    def str_from_ascii_function(s):
        return s

    int_types = (int, long)
    basestring = basestring
    anybuff = basestring

    def raw_encode(s):
        if isinstance(s, unicode):
            return s.encode("latin1")
        return s

    def raw_decode(s):
        # No unicode for now on py2
        return s

    # sys.stdout.encoding may be None if not a tty
    # Use sys.stdout.isatty() ?
    repr_encoding = sys.stdout.encoding or locale.getpreferredencoding()

    def urepr_encode(ustr):
        # assert isinstance(s, unicode) # Make the check explicitly ?
        return ustr.encode(repr_encoding, "backslashreplace")