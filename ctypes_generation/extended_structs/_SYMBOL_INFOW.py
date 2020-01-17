old_SYMBOL_INFOW = _SYMBOL_INFOW
class _SYMBOL_INFOW(old_SYMBOL_INFOW):
    @property
    def tag(self):
        return SymTagEnum.mapper[self.Tag]