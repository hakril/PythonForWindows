import windows
import windows.test
import windows.pipe

p = windows.test.pop_proc_32()
print("Child is {0}".format(p))

PIPE_NAME = "PFW_Pipe"

rcode = """
import windows
import windows.pipe

f = open('tst.txt', "w+")
fh = windows.utils.get_handle_from_file(f)
hm = windows.winproxy.CreateFileMappingA(fh, dwMaximumSizeLow=0x1000, lpName=None)
addr = windows.winproxy.MapViewOfFile(hm, dwNumberOfBytesToMap=0x1000)

windows.pipe.send_object("{pipe}", addr)
"""

with windows.pipe.create(PIPE_NAME) as np:
    print("Created pipe is {0}".format(np))
    p.execute_python(rcode.format(pipe=PIPE_NAME))
    print("Receiving object from injected process")
    addr = np.recv()

print("Remote Address = {0:#x}".format(addr))
print("Querying memory in target at <{0:#x}>".format(addr))
print("    * {0}".format(p.query_memory(addr)))
print("Querying mapped file in target at <{0:#x}>".format(addr))
print("    * {0}".format(p.get_mapped_filename(addr)))
p.exit()