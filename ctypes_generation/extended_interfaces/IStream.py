OLD_IStream = IStream
class IStream(OLD_IStream):

    def read(self, size):
        buffer = (CHAR * size)()
        size_read = ULONG()
        self.Read(buffer, size, size_read)
        return buffer[:size_read.value]


    def write(self, data):
        assert isinstance(data, bytes), "IStream.write() only accept bytes but {0} was passed".format(type(data))
        written = ULONG()
        self.Write(data, len(data), written)
        return written.value

    def seek(self, position, origin=STREAM_SEEK_SET):
        newpos = ULARGE_INTEGER()
        self.Seek(position, origin, newpos)
        return newpos.value



