class _tagADDRESS64(_tagADDRESS64):
    def __repr__(self):
        if not self.Segment:
            return "<{0} {offset:#x}>".format(type(self).__name__, offset=self.Offset)
        return "<{0} {seg:#x}:{offset:#x}>".format(type(self).__name__, seg=self.Segment, offset=self.Offset)