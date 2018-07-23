from ctypes import *

import windows
import windows.ldap.winproxy as winproxy
import windows.generated_def as gdef
from windows.ldap.ldap_entry import LDAPEntry
from windows.ldap.ldap_schema import LDAPSchema


class EPBERVAL(gdef.PBERVAL):
    _type_ = gdef.BERVAL

    def __len__(self):
        return self.contents.bv_len
    
    
    @property
    def value(self):
        buf = (gdef.BYTE * len(self))
        data = bytearray(buf.from_address(self.contents.bv_val))
        return data
    
    

class EPLDAPMessage(gdef.PLDAPMessage):
    _type_ = gdef.LDAPMessage
    
    def __init__(self):
        super(EPLDAPMessage, self).__init__()
        self._distinguishedName = None
        self._attributes_names = set()
        
    
    ## DICT data model ##
    def __setattr__(self, name, value):
        if name.startswith("_"):
            super(EPLDAPMessage, self).__setattr__(name, value)
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

        
    def __str__(self):
        return self.distinguishedName
    
    
    def __repr__(self):
        return '<EPLDAPMessage "{0!r}" at {1:#8x}>'.format(str(self), id(self))
    
    
    @property
    def connection(self):
        return self.contents.Connection
    
    
    @property
    def distinguishedName(self):
        if self._distinguishedName is None:
            self._distinguishedName = winproxy.ldap_get_dn(self.connection, self)
        return self._distinguishedName
    
    
    def initialize_attributes(self):
        attributes = dict()

        current_attribute_index = 0
        ber = gdef.PBerElement()
        
        while True:
            if current_attribute_index == 0:
                p_current_attribute_name = winproxy.ldap_first_attribute(self.connection, self, ber)
            else:
                p_current_attribute_name = winproxy.ldap_next_attribute(self.connection, self, ber)
            
            if p_current_attribute_name:
                current_attribute_index += 1
                
                values_len = winproxy.ldap_get_values_len(self.connection, self, p_current_attribute_name)
                p_values_array = cast(c_void_p(values_len), POINTER(gdef.PBERVAL))
                
                values_array = []
                value_index = 0
                while True:
                    berval = cast(p_values_array[value_index], EPBERVAL)
                
                    if not berval:
                        break
                    
                    values_array.append(berval.value)
                    value_index+=1
                
                if p_current_attribute_name != "distinguishedName":
                    setattr(self, p_current_attribute_name, values_array)
                
                winproxy.ldap_value_free_len(p_values_array)
            else:
                break
        
        winproxy.ber_free(ber, 0)
        return self
        

class EPLDAP(gdef.PLDAP):

    known_scopes = [gdef.LDAP_SCOPE_BASE, gdef.LDAP_SCOPE_ONELEVEL, gdef.LDAP_SCOPE_SUBTREE]

    @staticmethod
    def get_connection(domain_controller, port=gdef.LDAP_PORT, **kwargs):
        '''Static method to use to get a new connexion object.
        This was designed this way because the ldap_init does not fill a parameter but returns the handle'''
        obj = cast(winproxy.ldap_init(domain_controller, port), EPLDAP)
        obj.set_options(domain_controller=domain_controller, port=gdef.LDAP_PORT, **kwargs)
        obj.connect()
        return obj
    
    def __enter__(self):
        '''Simple context manager to unbind on leave'''
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        '''Simple context manager to unbind on leave'''
        self.unbind()
    
    ## CONNECTION METHODS ##
    
    def set_options(self, **kwargs):
        '''Initialization of the connection so that we can set the desired options on a newly created EPLDAP'''

        # Global configuration
        self.domain_controller = kwargs.get('domain_controller') 
        self.port = kwargs.get('port') 
        self.secure = kwargs.get('secure', False)
        self.version = c_int(kwargs.get('version', gdef.LDAP_VERSION3))
        self.opt_on   = c_int(1)
        self.no_limit = c_int(gdef.LDAP_NO_LIMIT)
        self.timeout = gdef.l_timeval()
        self.timeout.tv_sec = kwargs.get('timeout_sec', 100)
        self.timeout.tv_usec =kwargs.get('timeout_usec', 0)
        self.connected = False
        self.bound = False
        self.anonymous = False

        # Search configuration
        self.attributes = kwargs.get('default_attributes', list())
        self.__controls = {}
        self.__controls[gdef.LDAP_CONTROL_SERVER] = {}
        self.__controls[gdef.LDAP_CONTROL_CLIENT] = {}
        self.number_of_entries = 0
        self.current_page_number = None
        self.current_page_number_of_entries = 0
        self.current_page_current_entry_index = None
        self.current_page = None
        self.p_current_entry = None
        self.p_ldap_search = None
        self.number_of_entries_per_page = 10
        self.security_descriptor_desired_access = kwargs.get(
            'security_descriptor_desired_access', 
            gdef.OWNER_SECURITY_INFORMATION | gdef.GROUP_SECURITY_INFORMATION | gdef.DACL_SECURITY_INFORMATION
        )
        
        if self.security_descriptor_desired_access is not None:
            pBerElmt = winproxy.ber_alloc_t(gdef.LBER_USE_DER)
            pBerval = gdef.PBERVAL()
            winproxy.ber_printf(
                pBerElmt, 
                "{i}", 
                self.security_descriptor_desired_access
            )
            winproxy.ber_flatten(pBerElmt, pBerval)
            self.set_ldap_control(gdef.LDAP_SERVER_SD_FLAGS_OID, gdef.LDAP_CONTROL_SERVER, berval = pBerval.contents, critical = True)
        
        # Schema configuration
        self.cache_folder = kwargs.get('cache_folder', '.cache')
        self.disable_cache = kwargs.get('disable_cache', False)
        self.reload_cache = kwargs.get('reload_cache', False)
        self.schema = LDAPSchema.from_ldap_connection(self, self.reload_cache)
        
        winproxy.ldap_set_option(self, gdef.LDAP_OPT_PROTOCOL_VERSION, self.version)
        winproxy.ldap_set_option(self, gdef.LDAP_OPT_SIZELIMIT, self.no_limit)
        winproxy.ldap_set_option(self, gdef.LDAP_OPT_TIMELIMIT, self.no_limit)
        winproxy.ldap_set_option(self, gdef.LDAP_OPT_AUTO_RECONNECT, self.opt_on)
    
    
    def connect(self):
        '''This initializes the TCP connection with the server'''
        if self.connected:
            raise ValueError('Call to connect() method twice')
        
        winproxy.ldap_connect(self, None)
        self.connected = True
        
        
    def bind(self, username=None, password=None, domain_name=None):
        '''Bind method that allows 3 types of authentication : 
        - Anonymous (all parameters to None)
        - Simple (login / password sent in cleartext)
        - Negociate (that will allow sending SASL credentials for example)'''
        self.bound = False
        
        if not self.connected:
            raise ValueError("You should first call the connect() method before binding")
        
        if all(x is None for x in [username, password, domain_name]): # Anonymous bind
            winproxy.ldap_bind_s(self, None, None, gdef.LDAP_AUTH_SIMPLE)
            self.anonymous = True
        elif username is not None and password is not None and domain_name is None:
            winproxy.ldap_bind_s(self, username, password, gdef.LDAP_AUTH_SIMPLE)
        elif all(x is not None for x in [username, password, domain_name]):
            secIdent = gdef.SEC_WINNT_AUTH_IDENTITY()
            secIdent.User = username
            secIdent.UserLength = len(username)
            secIdent.Password = password
            secIdent.PasswordLength = len(password)
            secIdent.Domain = domain_name
            secIdent.DomainLength = len(domain_name)
            secIdent.Flags = gdef.SEC_WINNT_AUTH_IDENTITY_ANSI
            winproxy.ldap_bind_s(self, None, byref(secIdent), gdef.LDAP_AUTH_NEGOTIATE)
        else:
            raise ValueError("Bad arguments given to bind() method")
        
        try:
            self.load_schema()
        except winproxy.LdapError as e:
            if not self.anonymous:  # It is normal to see errors with schema loading in anonymous bindings
                raise e             # depending on the Active Directory configuration
        self.bound = True
        
        
    def load_schema(self):
        if self.reload_cache or not self.schema.initialized:
            self.schema.load(self)
    
    
    def unbind(self):
        '''End the communication with the server, must be called as long as the connect() method was called'''
        if not self.connected:
            raise ValueError("Call to unbind() on disconnected ldap connection")
        winproxy.ldap_unbind(self)
        if not self.disable_cache:
            self.schema.dump_cache()
        self.connected = False
    
    
    ## SEARCH METHODS AND PROPERTIES ##
    
    def check_filter(self, filter):
        if filter is not None:
            try:
                winproxy.ldap_check_filterA(self, filter)
            except winproxy.LdapError as e:
                if e.error_code == gdef.LDAP_FILTER_ERROR:
                    raise ValueError("{0!r} is not a valid ldap filter".format(filter))
                raise e
            else:
                return True
        return True
    
    def check_scope(self, scope):
        if scope not in self.known_scopes:
            raise ValueError("{0!r} is not a valid ldap scope".format(scope))
        return True
    
    def set_ldap_control(self, control_oid, control_type, berval = None, critical=False):
        '''Add LDAP controls to the right list of already present controls'''
        control = gdef.LDAPControl()
        control.ldctl_iscritical = critical
        control.ldctl_oid = control_oid
        if berval is None:
            control.ldctl_value.bv_len = 0
            control.ldctl_value.bv_val = None
        else:
            control.ldctl_value.bv_len = berval.bv_len
            control.ldctl_value.bv_val = berval.bv_val
        self.__controls[control_type][control_oid] = control

    def _get_ldap_controls(self, control_type):
        '''Used internally to convert the c to a ctypes null terminated array of pointers to c_char_p'''
        controls = self.__controls[control_type]
        
        LP_LP_LDAPControl = gdef.PLDAPControl*(len(controls)+1)
        LP_LP_LDAPControl_array = LP_LP_LDAPControl()
        for i, control in enumerate(controls):
            LP_LP_LDAPControl_array[i] = cast(byref(controls[control]), gdef.PLDAPControl)
        
        LP_LP_LDAPControl_array[len(controls)] = None
        
        return LP_LP_LDAPControl_array
    
    def _get_returned_attributes(self, attrs=None):
        '''Used internally to convert the attributes to a ctypes null terminated array of pointers to c_char_p'''
        if attrs is None:
            attrs = self.attributes
        
        if not attrs:
            return None
        else:
            attrs = set(attrs) # Only one mention of the attribute is necessary
            pointer = c_char_p*(len(attrs)+1)
            array = pointer()
            for i, attr in enumerate(attrs):
                array[i] = cast((c_char*(len(attr)+1)).from_buffer_copy(attr+"\x00"), c_char_p)
            return array
    
    def search_s(self, base_dn=None, scope=gdef.LDAP_SCOPE_BASE, filter="(objectclass=*)", returned_attributes=None):
        original_message = EPLDAPMessage()
        timeout = gdef.l_timeval()
        timeout.tv_sec = 100
        timeout.tv_usec = 0
        
        self.check_filter(filter)
        self.check_scope(scope)
        
        winproxy.ldap_search_ext_s(
            self, 
            base_dn, 
            scope, 
            filter, 
            self._get_returned_attributes(returned_attributes),
            False,
            self._get_ldap_controls(gdef.LDAP_CONTROL_SERVER),
            self._get_ldap_controls(gdef.LDAP_CONTROL_CLIENT),
            timeout,
            gdef.LDAP_NO_LIMIT,
            original_message
        )
        
        message = original_message
        while message:
            yield self.get_entry(message)
            message = cast(winproxy.ldap_next_entry(self, message), EPLDAPMessage)
        
        winproxy.ldap_msgfree(original_message)
        
    def search_s_paged(self, base_dn=None, filter=None, scope=gdef.LDAP_SCOPE_ONELEVEL, returned_attributes=None, total_size_limit=gdef.LDAP_NO_LIMIT):
        self.check_filter(filter)
        self.check_scope(scope)
        server_controls = self._get_ldap_controls(gdef.LDAP_CONTROL_SERVER)
        client_controls = self._get_ldap_controls(gdef.LDAP_CONTROL_CLIENT)
        
        self.p_ldap_search = winproxy.ldap_search_init_page(
            self,
            base_dn,
            scope,
            filter,
            self._get_returned_attributes(returned_attributes),
            0,
            server_controls,
            client_controls,
            gdef.LDAP_NO_LIMIT,
            total_size_limit,
            None
        )
        
        entry = self.get_next_entry()
        while entry:
            yield entry
            entry = self.get_next_entry()
        
        self.abandon_current_search()
        
    def abandon_current_search(self):
        if self.current_page is not None:
            winproxy.ldap_msgfree(self.current_page)
        if self.p_ldap_search is not None:
            winproxy.ldap_search_abandon_page(self, self.p_ldap_search)
        self.current_page = None
        self.p_ldap_search = None

    def get_next_entry(self):
        pCurrentEntry = None
        
        timeout = gdef.l_timeval()
        timeout.tv_sec = 100
        timeout.tv_usec = 0
        
        total_count = c_uint(0)
        
        res = gdef.LDAP_SUCCESS
        no_more_result = False
        
        if self.current_page is None or self.current_page_number_of_entries == self.current_page_current_entry_index :
            if self.current_page is None:
                self.current_page = gdef.PLDAPMessage()
            if self.current_page_number_of_entries == self.current_page_current_entry_index:
                winproxy.ldap_msgfree(self.current_page)
                self.current_page = gdef.PLDAPMessage()
            res = winproxy.ldap_get_next_page_s(
                self,
                self.p_ldap_search, 
                timeout,
                self.number_of_entries_per_page,
                total_count,
                self.current_page
            )
            
            if res == gdef.LDAP_NO_RESULTS_RETURNED:
                no_more_result = True
            
            self.current_page_number_of_entries = winproxy.ldap_count_entries(self, self.current_page)
            self.current_page_current_entry_index = 0
        
        if no_more_result or self.current_page_number_of_entries == 0:
            return None
        
        if self.current_page_current_entry_index == 0:
            self.p_current_entry = winproxy.ldap_first_entry(self, self.current_page)
        else:
            self.p_current_entry = winproxy.ldap_next_entry(self, self.p_current_entry)
        
        self.p_current_entry = cast(self.p_current_entry, EPLDAPMessage)
        self.current_page_current_entry_index += 1 
        
        return self.get_entry(self.p_current_entry)
    
    
    def get_entry(self, entry):
        '''Used to get an LDAPEntry instance with enhanced attributes from the schema.'''
        return LDAPEntry(entry.distinguishedName, **self.schema.enhance_ldap_message_attributes(entry.initialize_attributes()))

    
    def find_one(self, returned_attributes=None, **filters):
        filter = ''.join("({0}={1})".format(name, value) for name, value in filters.items())
        
        search = self.search_s_paged(
            base_dn=self.schema.cache['root_dse']['rootDomainNamingContext'], 
            filter=filter, 
            scope=gdef.LDAP_SCOPE_SUBTREE, 
            total_size_limit=1, 
            returned_attributes=returned_attributes
        )
        
        try:
            result = next(search)
        except StopIteration:
            result = None
        self.abandon_current_search()
        
        return result
        
    
    
    