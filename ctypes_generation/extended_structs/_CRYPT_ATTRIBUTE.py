OLD_CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE

class _CRYPT_ATTRIBUTE(_CRYPT_ATTRIBUTE):
    @property
    def count(self): # __len__ ?
        return self.cValue

    @property
    def values(self):
        return self.rgValue[:self.cValue]

    @property
    def objid(self):
        # SZOID_MAPPER defined in the generated structures template.py
        return SZOID_MAPPER[self.pszObjId]

    def __repr__(self):
        # return """<{0} pszObjId={1!r} Values={2}>""".format(type(self).__name__, self.objid, self.cValue)
        if not self.pszObjId in SZOID_MAPPER:
            return """<{0} pszObjId="{1}" Values={2}>""".format(type(self).__name__, self.pszObjId, self.cValue)
        flag = SZOID_MAPPER[self.pszObjId]
        return """<{0} pszObjId="{1}" ({2}) Values={3}>""".format(type(self).__name__, flag, flag.name, self.cValue)