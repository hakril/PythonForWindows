import pytest

import windows.generated_def as gdef
from windows.ldap.ldap_connection import *
from windows.winobject.sid import EPSID
from windows.security import EPSECURITY_DESCRIPTOR
from pfwtest import *


LDAP_SERVER = 'corp.lab.local'
LDAP_PORT = gdef.LDAP_PORT
LDAP_USERNAME = 'user1'
LDAP_USERNAME_DN = 'CN=user1,OU=Employee,DC=corp,DC=lab,DC=local'
LDAP_PASSWORD = 'r@nd0mP@ssword'
LDAP_DOMAIN = 'CORP'


def test_connect_to_ldap():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT) as conn:
        assert conn.connected


def test_bind_anonymously():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT) as conn:
        conn.bind(None, None, None)
        assert conn.bound
        assert conn.anonymous

        
def test_bind_basic():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT) as conn:
        conn.bind(LDAP_USERNAME_DN, LDAP_PASSWORD)
        assert conn.bound


def test_bind_negociate():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT) as conn:
        conn.bind(LDAP_USERNAME, LDAP_PASSWORD, LDAP_DOMAIN)
        assert conn.bound


def test_get_ldap_metadata():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT) as conn:
        conn.bind(LDAP_USERNAME, LDAP_PASSWORD, LDAP_DOMAIN)

        # Root DSE tests
        assert len(conn.schema.cache['root_dse'])
        assert conn.schema.cache['root_dse']['rootDomainNamingContext'] == 'DC=corp,DC=lab,DC=local'
        assert conn.schema.cache['root_dse']['schemaNamingContext'] == 'CN=Schema,CN=Configuration,DC=corp,DC=lab,DC=local' 
        assert '3' in conn.schema.cache['root_dse']['supportedLDAPVersion']
        
        # Schema tests
        assert 'distinguishedName'.lower() in conn.schema.cache['schema'].keys()
        
        
def test_ldap_search_non_paged():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT, disable_cache=True) as conn:
        conn.bind(LDAP_USERNAME, LDAP_PASSWORD, LDAP_DOMAIN)
        
        filter = '(objectClass=user)'
        scope = gdef.LDAP_SCOPE_SUBTREE
        results = list(conn.search_s(base_dn="OU=Employee," + conn.schema.cache['root_dse']['rootDomainNamingContext'], filter=filter, scope=scope))
        
        assert len(results) == 3
        assert results[0].distinguishedName == LDAP_USERNAME_DN
        assert isinstance(results[0].objectSid, EPSID)
        assert isinstance(results[0].nTSecurityDescriptor, EPSECURITY_DESCRIPTOR)


def test_ldap_search_paged():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT, disable_cache=True) as conn:
        conn.bind(LDAP_USERNAME, LDAP_PASSWORD, LDAP_DOMAIN)
        
        filter = '(objectClass=user)'
        scope = gdef.LDAP_SCOPE_SUBTREE
        results = list(conn.search_s_paged(base_dn="OU=Employee," + conn.schema.cache['root_dse']['rootDomainNamingContext'], filter=filter, scope=scope))
        
        assert len(results) == 3
        assert results[0].distinguishedName == LDAP_USERNAME_DN
        assert isinstance(results[0].objectSid, EPSID)
        assert isinstance(results[0].nTSecurityDescriptor, EPSECURITY_DESCRIPTOR)


def test_ldap_find_object():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT, disable_cache=True) as conn:
        conn.bind(LDAP_USERNAME, LDAP_PASSWORD, LDAP_DOMAIN)

        user2 = conn.find_one(sAMAccountName='user2')
        assert user2 is not None
        assert user2.cn == 'user2'
        
        user3 = conn.find_one(objectSid='S-1-5-21-999723994-3185227747-1897881191-1109')
        assert user3 is not None
        assert user3.cn == 'user3' 

        non_existent_user = conn.find_one(sAMAccountName='IdontExist')
        assert non_existent_user is None

        
def test_ldap_restrict_attributes():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT, disable_cache=True) as conn:
        conn.bind(LDAP_USERNAME, LDAP_PASSWORD, LDAP_DOMAIN)

        attributes = ['cn', 'objectGUID', 'givenName']
        user2 = conn.find_one(sAMAccountName='user2', returned_attributes=attributes)
        assert user2 is not None
        assert all(getattr(user2, attr, None) is not None for attr in attributes)
        assert sorted(user2.keys()) == sorted(attributes + ['distinguishedName'])

        
def test_ldap_get_security_descriptor():
    with EPLDAP.get_connection(LDAP_SERVER, port=LDAP_PORT, disable_cache=True) as conn:
        conn.bind(LDAP_USERNAME, LDAP_PASSWORD, LDAP_DOMAIN)
        
        attributes = ['nTSecurityDescriptor']
        user3 = conn.find_one(sAMAccountName='user3', returned_attributes=attributes)
        assert user3 is not None
        assert user3.nTSecurityDescriptor.valid
        assert isinstance(user3.nTSecurityDescriptor, EPSECURITY_DESCRIPTOR)
        assert gdef.SE_DACL_PRESENT in user3.nTSecurityDescriptor.control.flags
        assert isinstance(user3.nTSecurityDescriptor.owner, EPSID)
        assert isinstance(user3.nTSecurityDescriptor.primary_group, EPSID)
        assert len(user3.nTSecurityDescriptor.dacl)

        owner = conn.find_one(objectSid=str(user3.nTSecurityDescriptor.owner), returned_attributes=['cn'])
        primary_group = conn.find_one(objectSid=str(user3.nTSecurityDescriptor.primary_group), returned_attributes=['cn'])

        assert owner.cn == u'Domain Admins'
        assert primary_group.cn == u'Domain Admins'
        
        attributes = ['objectSid']
        user1 = conn.find_one(sAMAccountName='user1', returned_attributes=attributes)
        
        reset_pwd_ace = None
        for ace in user3.nTSecurityDescriptor.dacl:
            if ace.sid == user1.objectSid:
                reset_pwd_ace = ace
                break

        assert reset_pwd_ace is not None
        assert reset_pwd_ace.type == gdef.ACCESS_ALLOWED_OBJECT_ACE_TYPE
        object_type = conn.schema.resolve_guid(reset_pwd_ace.object_type)
        assert object_type['cn'] == u'User-Force-Change-Password'
        inherited_object_type = conn.schema.resolve_guid(reset_pwd_ace.inherited_object_type)
        assert inherited_object_type['lDAPDisplayName'] == u'inetOrgPerson'
        
        
