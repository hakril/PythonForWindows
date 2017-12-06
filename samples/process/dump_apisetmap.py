import argparse
import windows

def read_apisetmap():
    cp = windows.current_process
    apisetmap_addr = cp.peb.ApiSetMap
    print("ApiSetMap address <{0:#x}>".format(apisetmap_addr))
    apisetmap_version = cp.read_dword(apisetmap_addr)
    print("ApiSetMap version <{0}>".format(apisetmap_version))
    meminfo = cp.query_memory(apisetmap_addr)
    print(meminfo)
    data = cp.read_memory(meminfo.BaseAddress, meminfo.RegionSize)
    return data



parser = argparse.ArgumentParser(prog=__file__)
parser.add_argument('--filename', default="apisetmap.dmp", help='The filename in which the ApiSetMap is dumped')
res = parser.parse_args()

with open(res.filename, "wb") as f:
    f.write(read_apisetmap().encode("base64"))
print("<{0}> generated".format(res.filename))