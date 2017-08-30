import windows.rpc
from windows.rpc import ndr


# Ndr stuff
class NdrContext(ndr.NdrStructure):
    MEMBERS = [ndr.NdrLong, ndr.NdrLong, ndr.NdrLong, ndr.NdrLong, ndr.NdrLong]


class PLSAPR_OBJECT_ATTRIBUTES(ndr.NdrStructure):
    MEMBERS = [ndr.NdrLong,
                ndr.NdrUniquePTR(ndr.NdrWString),
                ndr.NdrUniquePTR(ndr.NdrLong), # We dont care if the subtype as we will pass None
                ndr.NdrLong,
                ndr.NdrUniquePTR(ndr.NdrLong), # We dont care if the subtype as we will pass None
                ndr.NdrUniquePTR(ndr.NdrLong)] # We dont care if the subtype as we will pass None


class LsarOpenPolicy2Parameter(ndr.NdrParameters):
    MEMBERS = [ndr.NdrUniquePTR(ndr.NdrWString),
                PLSAPR_OBJECT_ATTRIBUTES,
                ndr.NdrLong]


class LsarEnumeratePrivilegesParameter(ndr.NdrParameters):
    MEMBERS = [NdrContext,
                ndr.NdrLong,
                ndr.NdrLong]


class LSAPR_POLICY_PRIVILEGE_DEF(object):
    @classmethod
    def unpack(cls, stream):
        size1 = ndr.NdrShort.unpack(stream)
        ptr = ndr.NdrShort.unpack(stream)
        size2 = ndr.NdrLong.unpack(stream)
        luid = ndr.NdrHyper.unpack(stream)
        return ptr, luid


class LSAPR_PRIVILEGE_ENUM_BUFFER(object):
    @classmethod
    def unpack(cls, stream):
        entries = ndr.NdrLong.unpack(stream)
        array_size = ndr.NdrLong.unpack(stream)
        array_ptr = ndr.NdrLong.unpack(stream)
        # Unpack pointed array
        array_size2 = ndr.NdrLong.unpack(stream)
        assert array_size == array_size2
        x = []
        # unpack each elements LSAPR_POLICY_PRIVILEGE_DEF
        for i in range(array_size2):
            ptr, luid = LSAPR_POLICY_PRIVILEGE_DEF.unpack(stream)
            if ptr:
                x.append(luid)
        # unpack pointed strings
        result = []
        for luid in x:
            name = ndr.NdrWcharConformantVaryingArrays.unpack(stream)
            result.append((luid, name))
        return result


# Actual code

## LSASS alpc endpoints is fixed, no need for the epmapper
client = windows.rpc.RPCClient(r"\RPC Control\lsasspirpc")
## Bind to the desired interface
iid = client.bind('12345778-1234-abcd-ef00-0123456789ab', version=(0,0))

## Craft parameters and call 'LsarOpenPolicy2'
params = LsarOpenPolicy2Parameter.pack([None, (0, None, None, 0, None, None), 0x20000000])
res = client.call(iid, 44, params)
## Unpack the resulting handle
handle = NdrContext.unpack(ndr.NdrStream(res))

## Craft parameters and call 'LsarEnumeratePrivileges'
x = LsarEnumeratePrivilegesParameter.pack([handle, 0, 10000]);
res = client.call(iid, 2, x)

## Unpack the resulting 'LSAPR_PRIVILEGE_ENUM_BUFFER'
priviledges = LSAPR_PRIVILEGE_ENUM_BUFFER.unpack(ndr.NdrStream(res))
for priv in priviledges:
    print priv