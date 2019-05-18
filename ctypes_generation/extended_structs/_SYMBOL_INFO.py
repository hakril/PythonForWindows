old_SYMBOL_INFO = _SYMBOL_INFO
class _SYMBOL_INFO(old_SYMBOL_INFO):
    @property
    def tag(self):
        return SymTagEnum.mapper[self.Tag]