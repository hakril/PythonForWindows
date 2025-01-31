# From: ctypes_generation\extended_structs\_LIST_ENTRY.py
# _LIST_ENTRY is a self referencing structure
# Currently ctypes generation does not support extending self referencing structures
# Ass the _fields_ assignement should happen after the extended structure definition
# So we just redefine fully _LIST_ENTRY without inheriting the real one

class _LIST_ENTRY(Structure):
    def get_real_struct(self, targetcls, target_field):
        # >>> gdef.LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks
        # <Field type=_LIST_ENTRY, ofs=16, size=16>
        # This field object does not allow to retrieve the type..
        # So we need to basse the target class AND the target field..
        return targetcls.from_address(ctypes.addressof(self) - target_field.offset)

_LIST_ENTRY._fields_ = [
    ("Flink", POINTER(_LIST_ENTRY)),
    ("Blink", POINTER(_LIST_ENTRY)),
]