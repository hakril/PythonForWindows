import sys

is_py3 = (sys.version_info.major >= 3)

if is_py3:
    def str_from_ascii_function(s):
        return s.decode("ascii")

    int_types = int
    basestring = str
    anybuff = (str, bytes)

else: # py2.7
    def str_from_ascii_function(s):
        return s

    int_types = (int, long)
    basestring = basestring
    anybuff = basestring
