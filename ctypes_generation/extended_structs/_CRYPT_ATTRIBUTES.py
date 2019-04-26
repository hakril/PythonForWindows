OLD_CRYPT_ATTRIBUTES = _CRYPT_ATTRIBUTES
class _CRYPT_ATTRIBUTES(_CRYPT_ATTRIBUTES):
    @property
    def count(self): # __len__ ?
        return self.cAttr

    @property
    def attributes(self):
        return self.rgAttr[:self.cAttr]

    def __getitem__(self, oid):
        return [x for x in self.attributes if x.pszObjId == oid]

    def __repr__(self):
        return """<{0} Attributes={1}>""".format(type(self).__name__, self.cAttr)