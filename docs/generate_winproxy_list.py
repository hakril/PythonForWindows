import sys
import os.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "\\..")
print(sys.path[-1])
import pydoc
import re
import windows


winprox = windows.winproxy
all_in_module = [getattr(winprox, x) for x in dir(winprox)]
transp = [f for f in all_in_module if isinstance(f, winprox.TransparentApiProxy)]
functions = [f for f in all_in_module if hasattr(f, "prototype") and f not in transp]


print ("Transparent proxies:")
print("")
for f in transp:
    print("* {0}({1})".format(f.func_name, ", ".join([x[1] for x in f.args])))

print ("Functions:")
print("")
for f in functions:
    doc = pydoc.text.document(f)
    doc = re.sub("\x08." , "", doc)
    print("* {0}::\n\n    {1}".format(f.func_name, doc))
    #print("* {0}::\n\n    {1}".format(f.func_name, pydoc.plain(pydoc.render_doc(f))))

