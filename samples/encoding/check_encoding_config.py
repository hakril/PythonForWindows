import sys
import os
import windows

WINDOWS_UTF8_CODEPAGE = 65001


var_ioencode = os.environ.get("PYTHONIOENCODING", None)
stdout_encode = sys.stdout.encoding
if var_ioencode is not None:
    assert var_ioencode == stdout_encode
    repr_encoding = var_ioencode
repr_encoding = var_ioencode or stdout_encode

def encode_for_repr(ustr):
    if sys.version_info.major >= 3:
        return ustr
    return ustr.encode(repr_encoding, "backslashreplace")


class MyUtf8Object(object):
    def __init__(self):
        self.name = u"\u304a\u524d\u306f\u3082\u3046\u6b7b\u3093\u3067\u3044-\u043a\u0430\u043a\u0438\u0435_\u0444\u0436\u044e\u0449\u0434\u0444\u044f"

    def __repr__(self):
        print("__repr__")
        return encode_for_repr(u'<{0} name="{1}">'.format(type(self).__name__, self.name))

    def __unicode__(self):
        print("__unicode__")
        return u'<{0} name="{1}">'.format(type(self).__name__, self.name)

    def __str__(self):
        print("__str__")
        return encode_for_repr(u'<{0} name="{1}">'.format(type(self).__name__, self.name))


tstobj = MyUtf8Object()

def check_encoding_config_py3():
    # Easy case: everything should be already full utf-8 for Py3
    # Its passed throught a windows console object and transformed as wide-string
    # Its cool as windows console API handle Wide-string well
    print("Py3: everything should work as-is")
    stdout_encoding = sys.stdout.encoding
    print(" [*] sys.stdout.encoding = {0}".format(stdout_encoding))
    if stdout_encoding != "utf-8":
        print("[-] Stdout encoding is not utf-8 ! (please explain me your setup)")
    print("")
    print("Unicode string print: <{0}>".format(tstobj.name))
    print("Unicode object repr: {0}".format(tstobj))


def check_encoding_config_py2():
    # The hard case
    # We want to have the ability to print unicode to the console
    # But we go through sys.stdout encoding that depend on environ[PYTHONIOENCODING]
    # and current console codepage
    # Best case for py2 is:
    #   - PYTHONIOENCODING == utf-8
    #   - codepage == "65001" (utf-8 codepage)

    # Retrieve the infos we need
    var_ioencode = os.environ.get("PYTHONIOENCODING", None)
    stdout_encode = sys.stdout.encoding
    current_console_output_codepage = windows.winproxy.GetConsoleOutputCP()

    print("Py2 python/console configuration analysis:")
    print(" [*] env[PYTHONIOENCODING] = {0}".format(var_ioencode))

    if var_ioencode is None:
        print("     [-] No env variable <PYTHONIOENCODING>.")
        print("         sys.stdout encoding will only depends on your console codepage. Leading to high probability of EncodingError if printing unicode string")
    elif var_ioencode != "utf-8":
        print("     [-] env variable <PYTHONIOENCODING> != utf-8")
        print("         Recommended setting is PYTHONIOENCODING == utf-8 (I have no idea how PFW will react)")
    else:
        print("     [+] Optimal PYTHONIOENCODING")

    print(" [*] sys.stdout.encoding = {0}".format(stdout_encode))

    # Not even sur if we can have (var_ioencode == None and sys.stdout.encoding == "utf-8")
    if var_ioencode is None and sys.stdout.encoding != "utf-8":
        print("     [-] Unoptimal stdout encoding")
        print("         Recommended fix is setting PYTHONIOENCODING == utf-8")

    print(" [*] Console Codepage = {0}".format(current_console_output_codepage))

    if current_console_output_codepage != WINDOWS_UTF8_CODEPAGE:
        print("     [-] Non UTF-8 codepage for the current console")
        print("         Setting codepage to UTF8 (chcp 65001) will ensure currect output with PYTHONIOENCODING UTF-8")

    try:
        print(u"Unicode string print: <{0}>".format(tstobj.name))
    except Exception as e:
        print(" [-] Error printing unicode string: {0}".format(e))

    try:
        print(u"Unicode string print: <{0}>".format(tstobj))
    except Exception as e:
        print(" [-] Error printing unicode object str: {0}".format(e))

    try:
        print("Unicode object repr: {0!r}".format(tstobj))
    except Exception as e:
        print(" [-] Error printing unicode object repr: {0}".format(e))

if __name__ == "__main__":
    print("Python version is <{0}>".format(sys.version))
    if sys.version_info.major == 2:
        check_encoding_config_py2()
    else:
        check_encoding_config_py3()
