import sys

is_py3 = (sys.version_info.major >= 3)

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
