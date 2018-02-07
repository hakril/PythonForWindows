import windows
import windows.test

p = windows.test.pop_proc_32()
print("Child is {0}".format(p))

PIPE_NAME = "PFW_Pipe"

rcode = """
import windows

f = open('tst.txt', "w+")
fh = windows.utils.get_handle_from_file(f)
hm = windows.winproxy.CreateFileMappingA(fh, dwMaximumSizeLow=0x1000, lpName=None)
addr = windows.winproxy.MapViewOfFile(hm, dwNumberOfBytesToMap=0x1000)

windows.pipe.send_object("{pipe}", addr)
"""

with windows.pipe.create(PIPE_NAME) as np:
    print(np)
    p.execute_python(rcode.format(pipe=PIPE_NAME))
    addr = np.recv()

print("Remote Address = {0:#x}".format(addr))
print(p.query_memory(addr))
print(p.get_mapped_filename(addr))
p.exit()


# python samples\pipe\child_send_object.py
# Child is <WinProcess "notepad.exe" pid 16724 at 0x63455d0>
# <PipeConnection name="\\.\pipe\PFW_Pipe" server=True>
# Remote Address = 0x6fa0000
# <MEMORY_BASIC_INFORMATION32 BaseAddress=0x6fa0000 RegionSize=0x001000 State=MEM_COMMIT(0x1000L) Type=MEM_MAPPED(0x40000L) Protect=PAGE_READWRITE(0x4L)>
# \Device\HarddiskVolume2\Users\hakril\Documents\projets\PythonForWindows\tst.txt