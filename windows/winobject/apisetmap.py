import windows
import windows.generated_def as gdef

from windows import utils


def get_api_set_map_for_current_process(base):
    base = windows.current_process.peb.ApiSetMap
    version = windows.current_process.read_dword(base)
    if version not in API_SET_MAP_BY_VERSION:
        raise NotImplementedError("ApiSetMap version <{0}> not implemented, please contact me, I need a sample to implem it ;)")
    return API_SET_MAP_BY_VERSION[version](base)


class ApiSetMap(object):
    def __init__(self, base):
        self.base = base
        self.target = windows.current_process

    # helpers
    def read_apiset_wstring(self, offset, length):
        return self.target.read_memory(self.base + offset, length).decode("utf-16")

    # Low-level version-dependent parsing function
    def entries_array(self):
        raise NotImplementedError("Should be implemented by subclasses")

    def get_entry_name(self, entry):
        raise NotImplementedError("Should be implemented by subclasses")

    def get_entry_name_basicimpl(self, entry):
        return self.read_apiset_wstring(entry.NameOffset, entry.NameLength)

    def values_for_entry(self, entry):
        raise NotImplementedError("Should be implemented by subclasses")

    @utils.fixedpropety
    def resolution_dict(self):
        res = {}
        for entry in self.entries_array():
            values = self.values_for_entry(entry)
            if not values:
                final_value = None
            else:
                final_value = values[-1]
            res[self.get_entry_name(entry)] = final_value
        return res

    def resolve(self, dllname):
        return self.resolution_dict[dllname]



class ApiSetMapVersion2(ApiSetMap):
    def namespace(self):
        return gdef.API_SET_NAMESPACE_ARRAY_V2.from_address(self.base)

    def entries_array(self):
        namespace = self.namespace()
        array_addr = ctypes.addressof(namespace.Array)
        array_size = namespace.Count
        return (gdef.API_SET_NAMESPACE_ENTRY_V2 *  array_size).from_address(array_addr)

    get_entry_name = ApiSetMap.get_entry_name_basicimpl

    def values_for_entry(self, entry):
        values_array_v2 = (gdef.API_SET_VALUE_ARRAY_V2).from_address(self.base + entry.DataOffset)
        array_size = values_array_v2.Count
        array_addr = ctypes.addressof(values_array_v2.Array)
        values_array = (gdef.API_SET_VALUE_ENTRY_V2 * array_size).from_address(array_addr)
        res = []
        for value in values_array:
            if value.ValueLength:
                v = self.read_apiset_wstring(value.ValueOffset, value.ValueLength)
                res.append(v)
        return res


class ApiSetMapVersion4(ApiSetMap):
    def namespace(self):
        return gdef.API_SET_NAMESPACE_ARRAY_V4.from_address(self.base)

    def entries_array(self):
        namespace = self.namespace()
        array_addr = ctypes.addressof(namespace.Array)
        array_size = namespace.Count
        return (gdef.API_SET_NAMESPACE_ENTRY_V4 *  array_size).from_address(array_addr)

    get_entry_name = ApiSetMap.get_entry_name_basicimpl

    def values_for_entry(self, entry):
        values_array_v2 = (gdef.API_SET_VALUE_ARRAY_V4).from_address(self.base + entry.DataOffset)
        array_size = values_array_v2.Count
        array_addr = ctypes.addressof(values_array_v2.Array)
        values_array = (gdef.API_SET_VALUE_ENTRY * array_size).from_address(array_addr)
        res = []
        for value in values_array:
            if value.ValueLength:
                v = self.read_apiset_wstring(value.ValueOffset, value.ValueLength)
                res.append(v)
        return res

class ApiSetMapVersion6(ApiSetMap):
    def namespace(self):
        return gdef.API_SET_NAMESPACE_V6.from_address(self.base)

    get_entry_name = ApiSetMap.get_entry_name_basicimpl

    def entries_array(self):
        namespace = self.namespace()
        array_offset = namespace.EntryOffset
        array_size = namespace.Count
        return (gdef.API_SET_NAMESPACE_ENTRY_V6 *  array_size).from_address(self.base + array_offset)

    def values_for_entry(self, entry):
        values_array = (gdef.API_SET_VALUE_ENTRY * entry.ValueCount).from_address(self.base + entry.ValueOffset)
        res = []
        for value in values_array:
            if value.ValueLength:
                v = self.read_apiset_wstring(value.ValueOffset, value.ValueLength)
                res.append(v)
        return res

API_SET_MAP_BY_VERSION = {
    2: ApiSetMapVersion2,
    4: ApiSetMapVersion4,
    6: ApiSetMapVersion6,
}