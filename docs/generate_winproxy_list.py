import sys
import os.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "\\..")
print(sys.path[-1])
import pydoc
import re
import windows


winprox = windows.winproxy
all_in_module = [getattr(winprox, x) for x in dir(winprox)]
functions = [f for f in all_in_module if hasattr(f, "prototype")]

import pdb;pdb.set_trace()

print ("Functions:")
print("")
for f in functions:
    doc = pydoc.text.document(f)
    doc = re.sub("\x08." , "", doc)
    print("* {0}::\n\n    {1}".format(f.func_name, doc))
    #print("* {0}::\n\n    {1}".format(f.func_name, pydoc.plain(pydoc.render_doc(f))))

