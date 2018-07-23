from ctypes import *

import windows.ldap.winproxy as winproxy
import windows.generated_def as gdef


class LDAPEntry(object):
    '''Created from an ldap message and ldap connection'''
    def __init__(self, distinguishedName, **kwargs):
        self._attributes_names = set()
        for name, value in kwargs.items():
            setattr(self, name, value)
        self.distinguishedName = distinguishedName
        
    
    def __repr__(self):
        result = '<{0} dn="{1}" at {2:#08x}>'.format(type(self).__name__, getattr(self, "distinguishedName", "None").encode('utf-8'), id(self))        
        return result
    
    
    ## DICT data model ##
    def __setattr__(self, name, value):
        if name.startswith("_"):
            super(LDAPEntry, self).__setattr__(name, value)
            return
        
        self._attributes_names.add(name)
        self.__dict__[name] = value
    
    
    def __len__(self):
        return len(self._attributes_names)
    

    def __getitem__(self, name):
        return getattr(self, name)
    

    def __setitem__(self, name, value):
        setattr(self, name, value)
    

    def __delitem__(self, key):
        self._attributes_names.remove(key)
        del self.__dict__[key]
    

    def keys(self):
        return self._attributes_names
    

    def values(self):
        return [getattr(self, key) for key in self._attributes_names]
    

    def has_key(self, key):
        return key in self._attributes_names
    

    def items(self):
        return [(key, getattr(self,key)) for key in self._attributes_names]    
    ## END DICT data model ##
