import windows
import windows.generated_def as gdef

import struct

# http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_07

## Array
# A conformant array is an array in which the maximum number of elements is not known beforehand and therefore is included in the representation of the array.
# A varying array is an array in which the actual number of elements passed in a given call varies and therefore is included in the representation of the array.

## Pointers

# NDR defines two classes of pointers that differ both in semantics and in representation
# - reference pointers, which cannot be null and cannot be aliases
# - full pointers, which can be null and can be an aliases
# - unique pointers, which can be null and cannot be aliases, and are transmitted as full pointers.


def pack_dword(x):
     return struct.pack("<I", x)


def dword_pad(s):
    if (len(s) % 4) == 0:
        return s
    return s + ("P" * (4 - len(s) % 4))


class NdrUniquePTR(object):
    """Create a UNIQUE PTR around a given Ndr type"""
    def __init__(self, subcls):
        self.subcls = subcls

    def pack(self, data):
        subpack = self.subcls.pack(data)
        if subpack is None:
            return pack_dword(0)
        return pack_dword(0x02020202) + subpack

    def unpack(self, stream):
        ptr = NdrLong.unpack(stream)
        if not ptr:
            return None
        return self.subcls.unpack(stream)

    def pack_in_struct(self, data, id):
        if data is None:
            return pack_dword(0), None
        subpack = self.subcls.pack(data)
        if subpack is None:
            return pack_dword(0), None
        return pack_dword(0x01010101 * (id + 1)), subpack

    def unpack_in_struct(self, stream):
        ptr = NdrLong.unpack(stream)
        if not ptr:
            return 0, None
        return ptr, self.subcls

    def parse(self, stream):
        data = stream.partial_unpack("<I")
        if data[0] == 0:
            return None
        return self.subcls.parse(stream)

class NdrFixedArray(object):
    def __init__(self, subcls, size):
        self.subcls = subcls
        self.size = size

    def pack(self, data):
        data = list(data)
        assert len(data) == self.size
        return dword_pad("".join([self.subcls.pack(elt) for elt in data]))


    def unpack(self, stream):
        return [self.subcls.unpack(stream) for i in range(self.size)]


class NdrSID(object):
    @classmethod
    def pack(cls, psid):
        """Pack a PSID

        :param PSID psid:
        """
        subcount = windows.winproxy.GetSidSubAuthorityCount(psid)
        size = windows.winproxy.GetLengthSid(psid)
        sid_data = windows.current_process.read_memory(psid.value, size)
        return pack_dword(subcount[0]) + dword_pad(sid_data)

    @classmethod
    def unpack(cls, stream):
        """Unpack a PSID, partial implementation that returns a :class:`str` and not a PSID"""
        subcount = NdrLong.unpack(stream)
        return stream.read(8 + (subcount * 4))

class NdrVaryingCString(object):
    @classmethod
    def pack(cls, data):
        """Pack string ``data``. append ``\\x00`` if not present at the end of the string"""
        if data is None:
            return None
        if not data.endswith('\x00'):
            data += '\x00'
        l = len(data)
        result = struct.pack("<2I", 0, l)
        result += data
        return dword_pad(result)

class NdrWString(object):
    @classmethod
    def pack(cls, data):
        """Pack string ``data``. append ``\\x00`` if not present at the end of the string"""
        if data is None:
            return None
        if not data.endswith('\x00'):
            data += '\x00'
        data = data.encode("utf-16-le")
        l = (len(data) / 2)
        result = struct.pack("<3I", l, 0, l)
        result += data
        return dword_pad(result)

    @classmethod
    def unpack(cls, stream):
        stream.align(4)
        size1, zero, size2 = stream.partial_unpack("<3I")
        assert size1 == size2
        assert zero == 0
        s = stream.read(size1 * 2)
        return s.decode("utf-16-le")

class NdrCString(object):
    @classmethod
    def pack(cls, data):
        """Pack string ``data``. append ``\\x00`` if not present at the end of the string"""
        if data is None:
            return None
        if not data.endswith('\x00'):
            data += '\x00'
        l = len(data)
        result = struct.pack("<3I", l, 0, l)
        result += data
        return dword_pad(result)

    # @classmethod
    # def unpack(self, stream):
    #     maxcount, offset, count = stream.partial_unpack("<3I")
    #     return maxcount, offset, count

NdrUniqueCString = NdrUniquePTR(NdrCString)
NdrUniqueWString = NdrUniquePTR(NdrWString)

class NdrLong(object):
    @classmethod
    def pack(cls, data):
        return struct.pack("<I", data)

    @classmethod
    def unpack(self, stream):
        stream.align(4)
        return stream.partial_unpack("<I")[0]

class NdrHyper(object):
    @classmethod
    def pack(cls, data):
        return struct.pack("<Q", data)

    @classmethod
    def unpack(self, stream):
        stream.align(8)
        return stream.partial_unpack("<Q")[0]

class NdrShort(object):
    @classmethod
    def pack(cls, data):
        return struct.pack("<H", data)

    @classmethod
    def unpack(self, stream):
        return stream.partial_unpack("<H")[0]


class NdrByte(object):
    @classmethod
    def pack(self, data):
        return struct.pack("<B", data)

    @classmethod
    def unpack(self, stream):
        return stream.partial_unpack("<B")[0]


class NdrGuid(object):
    @classmethod
    def pack(cls, data):
        if not isinstance(data, gdef.IID):
            data = gdef.IID.from_string(data)
        return str(bytearray(data))

    @classmethod
    def unpack(self, stream):
        rawguid = stream.partial_unpack("16s")[0]
        return gdef.IID.from_buffer_copy(rawguid)

class NdrContextHandle(object):
    @classmethod
    def pack(cls, data):
        if not isinstance(data, gdef.IID):
            data = gdef.IID.from_string(data)
        return struct.pack("<I", 0) + str(bytearray(data))

    @classmethod
    def unpack(self, stream):
        attributes, rawguid = stream.partial_unpack("<I16s")
        return gdef.IID.from_buffer_copy(rawguid)


class NdrStructure(object):
    """a NDR structure that tries to respect the rules of pointer packing, this class should be subclassed with
    an attribute ``MEMBERS`` describing the members of the class
    """
    @classmethod
    def pack(cls, data):
        """Pack data into the struct, ``data`` size must equals the number of members in the structure"""
        if not (len(data) == len(cls.MEMBERS)):
            print("Size mistach:")
            print("   * data size = {0}".format(len(data)))
            print("   * members size = {0}".format(len(cls.MEMBERS)))
            print("   * data {0}".format(data))
            print("   * members = {0}".format(cls.MEMBERS))
            raise ValueError("NdrStructure packing number elements mismatch: structure has <{0}> members got <{1}>".format(len(cls.MEMBERS), len(data)))
        conformant_size = []
        res = []
        pointed = []
        for i, (member, memberdata) in enumerate(zip(cls.MEMBERS, data)):
            if hasattr(member, "pack_in_struct"):
                x, y = member.pack_in_struct(memberdata, i)
                res.append(x)
                if y is not None:
                    pointed.append(y)
            elif hasattr(member, "pack_conformant"):
                size, data = member.pack_conformant(memberdata)
                conformant_size.append(size)
                res.append(data)
            else:
                packed_member = member.pack(memberdata)
                res.append(packed_member)
        return dword_pad("".join(conformant_size)) + dword_pad("".join(res)) + dword_pad("".join(pointed))

    @classmethod
    def unpack(cls, stream):
        """Unpack the structure from the stream"""
        conformant_members = [hasattr(m, "pack_conformant") for m in cls.MEMBERS]
        is_conformant = any(conformant_members)
        assert(conformant_members.count(True) <= 1), "Unpack conformant struct with more that one conformant MEMBER not implem"

        data = []
        if is_conformant:
            conformant_size = NdrLong.unpack(stream)
        post_subcls = []
        for i, member in enumerate(cls.MEMBERS):
            if conformant_members[i]:
                data.append(member.unpack_conformant(stream, conformant_size))
            else:
                if hasattr(member, "unpack_in_struct"):
                    # print("[{0}] Dereferenced unpacking".format(i))
                    ptr, subcls = member.unpack_in_struct(stream)
                    if not ptr:
                        data.append(None)
                    else:
                        data.append(ptr)
                    post_subcls.append((i, subcls))
                    # print(post_subcls)
                else:
                    data.append(member.unpack(stream))
        # print("Applying deref unpack")
        for i, entry in post_subcls:
            data[i] = entry.unpack(stream)
        return cls.post_unpack(data)

    @classmethod
    def post_unpack(cls, data):
        return data



class NdrParameters(object):
    """a class to pack NDR parameters together to performs RPC call, this class should be subclassed with
    an attribute ``MEMBERS`` describing the members of the class
    """
    @classmethod
    def pack(cls, data):
        if not (len(data) == len(cls.MEMBERS)):
            print("Size mistach:")
            print("   * data size = {0}".format(len(data)))
            print("   * members size = {0}".format(len(cls.MEMBERS)))
            print("   * data {0}".format(data))
            print("   * members = {0}".format(cls.MEMBERS))
            raise ValueError("NdrParameters packing number elements mismatch: structure has <{0}> members got <{1}>".format(len(cls.MEMBERS), len(data)))
        res = []
        for (member, memberdata) in zip(cls.MEMBERS, data):
            packed_member = member.pack(memberdata)
            res.append(packed_member)
        return "".join(dword_pad(elt) for elt in res)

    @classmethod
    def unpack(cls, stream):
        res = []
        for member in cls.MEMBERS:
            unpacked_member = member.unpack(stream)
            res.append(unpacked_member)
        return res


class NdrConformantArray(object):
    MEMBER_TYPE = None
    @classmethod
    def pack(cls, data):
        ndrsize = NdrLong.pack(len(data))
        return dword_pad(ndrsize + "".join([cls.MEMBER_TYPE.pack(memberdata) for memberdata in data]))

    @classmethod
    def pack_conformant(cls, data):
        ndrsize = NdrLong.pack(len(data))
        ndrdata = dword_pad("".join([cls.MEMBER_TYPE.pack(memberdata) for memberdata in data]))
        return ndrsize, ndrdata

    @classmethod
    def unpack_conformant(cls, stream, size):
        res = [cls.MEMBER_TYPE.unpack(stream) for i in range(size)]
        stream.align(4)
        return res


class NdrConformantVaryingArrays(object):
    MEMBER_TYPE = None
    @classmethod
    def pack(cls, data):
        ndrsize = NdrLong.pack(len(data))
        offset =  NdrLong.pack(0)
        return dword_pad(ndrsize + offset + ndrsize + "".join([cls.MEMBER_TYPE.pack(memberdata) for memberdata in data]))

    @classmethod
    def unpack(cls, stream):
        maxcount = NdrLong.unpack(stream)
        offset = NdrLong.unpack(stream)
        count = NdrLong.unpack(stream)
        assert(offset == 0)
        # assert(maxcount == count)

        result = []
        post_subcls = []
        for i in range(count):
            member = cls.MEMBER_TYPE
            if hasattr(member, "unpack_in_struct"):
                ptr, subcls = member.unpack_in_struct(stream)
                if not ptr:
                    result.append(None)
                else:
                    result.append(ptr)
                    post_subcls.append((i, subcls))
            else:
                data = member.unpack(stream)
                result.append(data)
        # Unpack pointers
        for i, entry in post_subcls:
            data = entry.unpack(stream)
            result[i] = data

        return cls._post_unpack(result)

    @classmethod
    def _post_unpack(cls, result):
        return result


class NdrWcharConformantVaryingArrays(NdrConformantVaryingArrays):
    MEMBER_TYPE = NdrShort

    @classmethod
    def _post_unpack(self, result):
        return u"".join(unichr(c) for c in result)


class NdrHyperConformantVaryingArrays(NdrConformantVaryingArrays):
    MEMBER_TYPE = NdrHyper

class NdrHyperConformantArray(NdrConformantArray):
    MEMBER_TYPE = NdrHyper

class NdrLongConformantArray(NdrConformantArray):
    MEMBER_TYPE = NdrLong

class NdrShortConformantArray(NdrConformantArray):
    MEMBER_TYPE = NdrShort

class NdrByteConformantArray(NdrConformantArray):
    MEMBER_TYPE = NdrByte

    @classmethod
    def _post_unpack(self, result):
        return bytearray(result)

class NdrGuidConformantArray(NdrConformantArray):
    MEMBER_TYPE = NdrGuid


class NdrStream(object):
    """A stream of bytes used for NDR unpacking"""
    def __init__(self, data):
        self.fulldata = data
        self.data = data

    def partial_unpack(self, format):
        size = struct.calcsize(format)
        toparse = self.data[:size]
        self.data = self.data[size:]
        return struct.unpack(format, toparse)

    def read_aligned_dword(self, size):
        aligned_size = size
        if size % 4:
            aligned_size = size + (4 - (size % 4))
        retdata = self.data[:size]
        self.data = self.data[aligned_size:]
        return retdata

    def read(self, size):
        data = self.data[:size]
        self.data = self.data[size:]
        if len(data) < size:
            raise ValueError("Could not read {0} from stream".format(size))
        return data

    def align(self, size):
        """Discard some bytes to align the remaining stream on ``size``"""
        already_read = len(self.fulldata) - len(self.data)
        if already_read % size:
            # Realign
            size_to_align = (size - (already_read % size))
            self.data = self.data[size_to_align:]
            return size_to_align
        return 0


def make_parameters(types, name=None):
    class NdrCustomParameters(NdrParameters):
        MEMBERS = types
    return NdrCustomParameters

def make_structure(types, name=None):
    class NdrCustomStructure(NdrStructure):
        MEMBERS = types
    return NdrCustomStructure
