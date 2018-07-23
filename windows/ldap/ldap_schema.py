import os
import json
from ctypes import cast, POINTER

import windows.generated_def as gdef
from windows.winobject.sid import EPSID
from windows.security import EPSECURITY_DESCRIPTOR


schema_attribute_handlers = {}


def schema_attribute_handler(*attribute_syntaxes):
    global schema_attribute_handlers
    
    for attribute_syntax in attribute_syntaxes:
        if attribute_syntax in schema_attribute_handlers:
            raise ValueError('Syntax {0!r} was already declared by {1!r}'.format(
                                    attribute_syntax, 
                                    schema_attribute_handlers[attribute_syntax]))
    
    def wrapper(f):
        for attribute_syntax in attribute_syntaxes:
            schema_attribute_handlers[attribute_syntax] = f
        return f
    
    return wrapper


@schema_attribute_handler('Unicode', 'DN String', 'Case Sensitive String', 'Case Ignored String', 'Print Case String', 'Object ID')
def decode_unicode_string(s):
    return s.decode('utf-8')


@schema_attribute_handler('Boolean')
def decode_boolean(s):
    return True if s.decode('utf-8').lower() == u"true" else False


@schema_attribute_handler('Integer', 'Numeric String', 'Large Integer')
def decode_int(s):
    return int(s)


@schema_attribute_handler('Octet String', 'OR Name DNWithOctetString')
def decode_bytes(s):
    return bytes(s)
    

@schema_attribute_handler('Time')
def decode_time(s):
    return s.decode('utf-8') # TODO cast to datetime, not today though because of the json serialization...
    

@schema_attribute_handler('SID')
def decode_sid(s):
    return cast((gdef.BYTE*len(s)).from_buffer_copy(s), EPSID)


@schema_attribute_handler('NT Security Descriptor')
def decode_security_descriptor(s):
    return cast((gdef.BYTE*len(s)).from_buffer_copy(s), EPSECURITY_DESCRIPTOR)


def decode_iid(s):
    return cast((gdef.BYTE*len(s)).from_buffer_copy(s), POINTER(gdef.winstructs.GUID))


@schema_attribute_handler('IID', 'STRIID')
def decode_str_iid(s):
    return decode_iid(s).contents.to_string()


class LDAPSchema(object):
    # Root DSE attributes
    root_dse_attributes = set([
        'ldapServiceName', 'namingContexts', 'isSynchronized', 'dsServiceName', 
        'supportedSASLMechanisms', 'isGlobalCatalogReady', 'supportedLDAPVersion', 
        'domainControllerFunctionality', 'serverName', 'highestCommittedUSN', 
        'defaultNamingContext', 'schemaNamingContext', 'supportedCapabilities', 
        'rootDomainNamingContext', 'dnsHostName', 'domainFunctionality', 
        'subschemaSubentry', 'supportedLDAPPolicies', 'currentTime', 'supportedControl', 
        'configurationNamingContext', 'forestFunctionality'])

    # Static mapping for types that will be useful when reading the schema and root_dse
    base_type_mapping = {
        'cn':                   'Unicode',
        'distinguishedName':    'Unicode',
        'attributeSyntax':      'Unicode',
        'isSingleValued':       'Boolean',
        'attributeID':          'Unicode',
        'lDAPDisplayName':      'Unicode',
        'objectGUID':           'STRIID',
        'schemaIDGUID':         'STRIID'
    }
    
    # Dynamic mapping to know from a AttributeSyntax attribute the type
    attribute_syntax_mapping = {
        '2.5.5.1': 'DN String',
        '2.5.5.2': 'Object ID',
        '2.5.5.3': 'Case Sensitive String',
        '2.5.5.4': 'Case Ignored String',
        '2.5.5.5': 'Print Case String',
        '2.5.5.6': 'Numeric String',
        '2.5.5.7': 'OR Name DNWithOctetString',
        '2.5.5.8': 'Boolean',
        '2.5.5.9': 'Integer',
        '2.5.5.10': 'Octet String',
        '2.5.5.11': 'Time',
        '2.5.5.12': 'Unicode',
        '2.5.5.13': 'Address',
        '2.5.5.14': 'Distname-Address',
        '2.5.5.15': 'NT Security Descriptor',
        '2.5.5.16': 'Large Integer',
        '2.5.5.17': 'SID'
    }
    
    syntax_to_function_mapping = schema_attribute_handlers
    
    
    def __init__(self, domain_controller, cache_folder = '.cache', cache = None):
        self.domain_controller = domain_controller
        self.cache_folder = cache_folder
        self.initialized = False
        super(LDAPSchema, self).__init__()
        if cache is not None:
            self.cache = cache
            self.initialized = all(len(v) > 0 for v in self.cache.values())
        else:
            self.cache = {
                'root_dse': {},
                'schema': {},
                'extended_rights': {},
                'classes': {}
            }
    
    
    @classmethod
    def from_ldap_connection(cls, conn, force_reload = False):
        return cls.from_cache(conn.domain_controller, conn.cache_folder)
        
    
    @classmethod
    def from_cache(cls, domain_controller, cache_folder = '.cache'):
        '''Load cache from disk'''
        cache_file = os.path.join(cache_folder, domain_controller)
        cache = None
        
        if os.path.isfile(cache_file):
            with open(cache_file) as f:
                try:
                    cache = json.loads(f.read())
                except ValueError as e:
                    pass

        return cls(domain_controller, cache_folder, cache)
    
                    
    def dump_cache(self):
        '''Write cache to disk'''
        with open(os.path.join(self.cache_folder, self.domain_controller), "wb") as f:
            f.write(json.dumps(self.cache, indent=4, encoding="latin-1"))

        
    def load(self, conn):
        self.load_root_dse(conn)
        self.load_schema_attributes(conn)
        self.load_extended_rights(conn)
        self.load_schema_classes(conn)
        self.initialized = True
    
    
    def load_root_dse(self, conn):
        '''Builds or rebuilds the LDAP root_dse and caches it'''
        if 'root_dse' not in self.cache or not len(self.cache['root_dse']):
            self.cache["root_dse"] = dict(next(conn.search_s(None, gdef.LDAP_SCOPE_BASE, None)))
        

    def load_schema_attributes(self, conn):
        '''Builds or rebuilds the LDAP schema and caches it'''
        if 'schema' not in self.cache or not len(self.cache['schema']):
            self.cache['schema'] = {}
            attributes = [
                'cn', 
                'attributeSyntax', 
                'isSingleValued', 
                'attributeID', 
                'lDAPDisplayName',
                'objectGUID',
                'schemaIDGUID'
            ]
            search = conn.search_s_paged(
                base_dn=self.cache['root_dse']['schemaNamingContext'], 
                filter="(objectClass=attributeSchema)", 
                scope=gdef.LDAP_SCOPE_ONELEVEL, 
                returned_attributes=attributes
            )

            for item in search:
                if 'attributeSyntax' in item.keys():
                    self.cache['schema'][item.lDAPDisplayName.lower()] = dict(item)
    
    
    def load_extended_rights(self, conn):
        '''Builds or rebuilds the LDAP extended rights and caches it'''        
        if 'extended_rights' not in self.cache or not len(self.cache['extended_rights']):
            self.cache['extended_rights'] = {}
            attributes = [
                'cn',
                'displayName',
                'objectGUID',
                'rightsGuid'
            ]
            search = conn.search_s_paged(
                base_dn="CN=Extended-Rights,"+self.cache['root_dse']['configurationNamingContext'], 
                filter="(objectClass=*)", 
                scope=gdef.LDAP_SCOPE_SUBTREE, 
                returned_attributes=attributes
            )
            
            for item in search:
                if item.cn == 'Extended-Rights': continue
                self.cache['extended_rights'][item.rightsGuid.lower()] = dict(item)
                

    def load_schema_classes(self, conn):
        '''Builds or rebuilds the LDAP schema and caches it'''
        if 'classes' not in self.cache or not len(self.cache['classes']):
            self.cache['classes'] = {}
            attributes = [
                'cn', 
                'lDAPDisplayName',
                'objectGUID',
                'schemaIDGUID',
                'subClassOf',
                'mayContain',
                'mustContain',
                'possSuperiors',
                'systemMayContain',
                'systemMustContain',
                'systemPossSuperiors'
            ]
            search = conn.search_s_paged(
                base_dn=self.cache['root_dse']['schemaNamingContext'], 
                filter="(objectClass=classSchema)", 
                scope=gdef.LDAP_SCOPE_ONELEVEL, 
                returned_attributes=attributes
            )

            for item in search:
                self.cache['classes'][item.lDAPDisplayName.lower()] = dict(item)
        
        
    def resolve_value_real_type(self, attr_name, attr_values):
        '''This function is used by LDAPEntry objects to get the real object type for each ldap values.'''
        result = list()
        
        for value in attr_values:
            # Handle root_dse attributes (while loading root_dse we don't have a schema yet)
            if attr_name in self.root_dse_attributes:
                result.append(bytearray(value).decode('utf-8'))
            # Handle base type attributes (while loading schema we don't have a schema yet)
            elif attr_name in self.base_type_mapping:
                result.append(schema_attribute_handlers[self.base_type_mapping[attr_name]](bytearray(value)))
            # Then we handle 
            elif attr_name.lower() in self.cache['schema']:
                syntax = self.attribute_syntax_mapping[self.cache['schema'][attr_name.lower()]['attributeSyntax']]
                if syntax in schema_attribute_handlers:
                    val = schema_attribute_handlers[syntax](bytearray(value))
                    result.append(val)
                else:
                    raise NotImplementedError('The attribute syntax {0!r} does not provide function mapping'.format(attr_name))
            
            else:
                print 'Attributes should be in the schema to be resolved: {0!r} : {1!r}'.format(attr_name, value)
                result.append(value)
        
        # Handle root_dse single valued types : 
        if attr_name in self.root_dse_attributes and len(result) == 1:
            return result[0]
        
        # Handle schema single valued types : 
        if attr_name in self.base_type_mapping and len(result) == 1:
            return result[0]
        
        if attr_name.lower() in self.cache['schema'] and self.cache['schema'][attr_name.lower()]['isSingleValued']:
            return result[0]
        return result

    
    def enhance_ldap_message_attributes(self, msg):
        result = {}
        for attr_name, attr_values in msg.items():
            result[attr_name] = self.resolve_value_real_type(attr_name, attr_values)
        return result

    
    def resolve_guid(self, guid):
        if guid is None:
            return None
    
        if not isinstance(guid, gdef.GUID):
            raise ValueError("Not an GUID...")
            
        # The GUID might be an extended right : 
        if guid.to_string().lower() in self.cache['extended_rights']:
            return self.cache['extended_rights'][guid.to_string().lower()]
        
        # The GUID might be an object class :
        for item in self.cache['classes'].values():
            if gdef.GUID.from_string(item['schemaIDGUID']) == guid:
                return item
        
        # The GUID might be an attribute : 
        for item in self.cache['schema'].values():
            if gdef.GUID.from_string(item['schemaIDGUID']) == guid:
                return item
        
        return guid
                