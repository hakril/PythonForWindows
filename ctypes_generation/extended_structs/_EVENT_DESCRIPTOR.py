class _EVENT_DESCRIPTOR(_EVENT_DESCRIPTOR):
    def __repr__(self):
        return "<{0} Id={self.Id} Opcode={self.Opcode} Version={self.Version} Level={self.Level}>".format(type(self).__name__, self=self)