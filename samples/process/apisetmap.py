import windows

print("Computer is a <{0}>".format(windows.system.version_name))

cp = windows.current_process
apism = cp.peb.apisetmap

print("ApiSetMap: {0} (version = {1})".format(apism, apism.version))

# Find the current version of "api-ms-win-core-processthreads" used by windows
dll_demos_fullname = [x for x in windows.current_process.peb.apisetmap.apisetmap_dict if "api-ms-win-core-processthreads" in x][0]
dll_demos_utilname = 'api-ms-win-core-processthreads-l1-1-'

print("Entries in 'apisetmap_dict' are the full api-dll path extracted")
print(" * apisetmap.apisetmap_dict['{0}'] -> {1}".format(dll_demos_fullname, apism.apisetmap_dict[dll_demos_fullname]))
print("Entries in 'resolution_dict' are the contains the util-part check by windows")
print(" * apisetmap.resolution_dict['{0}'] -> {1}".format(dll_demos_utilname, apism.resolution_dict[dll_demos_utilname]))

print("ApiSetMap.resolve resolve a api-dll based on the util part")
for suffix in ["1", "2", "PART_IS_IGNORED"]:
    testname = dll_demos_utilname + suffix
    print(" * apisetmap.resolve('{0}') -> {1}".format(testname, apism.resolve(testname)))

testname = "BAD_DLL-3.dll"
try:
    print(" * apisetmap.resolve('{0}') -> {1}".format(testname, apism.resolve(testname)))
except KeyError as e:
    print(" * apisetmap.resolve('{0}') -> raised: {1!r}".format(testname, e))
