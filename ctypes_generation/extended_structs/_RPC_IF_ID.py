INITIAL_RPC_IF_ID = RPC_IF_ID

class _RPC_IF_ID(INITIAL_RPC_IF_ID):
    def __repr__(self):
        return '<RPC_IF_ID "{0}" ({1}, {2})>'.format(self.Uuid.to_string(), self.VersMajor, self.VersMinor)