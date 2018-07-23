import ctypes
from windows.winproxy import ApiProxy, zero_is_fail_error_check
from windows.generated_def.winstructs import LDAP_RETCODE


class LdapError(WindowsError):
    def __new__(cls, func_name, error_code):    
        win_error = error_code
        api_error = super(LdapError, cls).__new__(cls)
        api_error.winerror = error_code
        api_error.strerror = "LDAP"
        api_error.api_name = func_name
        api_error.error_code = error_code
        return api_error
        
    def __init__(self, func_name, error_code):
        super(LdapError, self).__init__(error_code)

    def __repr__(self):
        return "{0}: {1}".format(self.api_name, self.error_code)

    def __str__(self):
        return "Error while calling function \"{0}\", {1}".format(self.api_name, self.error_code)


def ldap_error(func_name, result, func, args):
    if result and LDAP_RETCODE.mapper.get(result, result):
        raise LdapError(func_name, LDAP_RETCODE.mapper.get(result, result))
    return args
    

def ldap_success_or_no_result_returned(func_name, result, func, args):
    if result not in [0, 0x5e] and LDAP_RETCODE.mapper.get(result, result):
        raise LdapError(func_name, LDAP_RETCODE.mapper.get(result, result))
    return args


def should_not_return_none_check(func_name, result, func, args):
    if result is None:
        last_error = LdapGetLastError()
        raise LdapError(func_name, LDAP_RETCODE.mapper.get(last_error, last_error))
    return args
    

def should_not_return_minus_one_check(func_name, result, func, args):
    if result == -1:
        last_error = LdapGetLastError()
        raise LdapError(func_name, LDAP_RETCODE.mapper.get(last_error, last_error))
    return args


def no_error_check(func_name, result, func, args):
    return args


class Wldap32Proxy(ApiProxy):
    APIDLL = "wldap32"
    default_error_check = staticmethod(ldap_error)


# Common functions
@Wldap32Proxy("LdapGetLastError", no_error_check)
def LdapGetLastError():
   return LdapGetLastError.ctypes_function()


# Starting and Stopping an LDAP Session
@Wldap32Proxy("ldap_open", should_not_return_none_check)
def ldap_open(HostName, PortNumber):
    return ldap_open.ctypes_function(HostName, PortNumber)
 
   
@Wldap32Proxy("ldap_init", no_error_check)
def ldap_init(HostName, PortNumber):
   return ldap_init.ctypes_function(HostName, PortNumber)


@Wldap32Proxy("ldap_initW", no_error_check)
def ldap_initW(HostName, PortNumber):
   return ldap_initW.ctypes_function(HostName, PortNumber)


@Wldap32Proxy("ldap_bind")
def ldap_bind(ld, dn, cred, method):
   return ldap_bind.ctypes_function(ld, dn, cred, method)


@Wldap32Proxy("ldap_bind_s")
def ldap_bind_s(ld, dn, cred, method):
   return ldap_bind_s.ctypes_function(ld, dn, cred, method)


@Wldap32Proxy("ldap_unbind")
def ldap_unbind(ld):
   return ldap_unbind.ctypes_function(ld)


@Wldap32Proxy("ldap_unbind_s")
def ldap_unbind_s(ld):
   return ldap_unbind_s.ctypes_function(ld)


@Wldap32Proxy("ldap_connect")
def ldap_connect(ld, timeout):
   return ldap_connect.ctypes_function(ld, timeout)


@Wldap32Proxy("ldap_simple_bind")
def ldap_simple_bind(ld, dn, passwd):
   return ldap_simple_bind.ctypes_function(ld, dn, passwd)


@Wldap32Proxy("ldap_simple_bind_s")
def ldap_simple_bind_s(ld, dn, passwd):
   return ldap_simple_bind_s.ctypes_function(ld, dn, passwd)


@Wldap32Proxy("ldap_sslinit")
def ldap_sslinit(HostName, PortNumber, secure):
   return ldap_sslinit.ctypes_function(HostName, PortNumber, secure)


@Wldap32Proxy("ldap_get_option")
def ldap_get_option(ld, option, outvalue):
   return ldap_get_option.ctypes_function(ld, option, outvalue)


@Wldap32Proxy("ldap_set_option")
def ldap_set_option(ld, option, invalue):
   return ldap_set_option.ctypes_function(ld, option, invalue)


@Wldap32Proxy("ldap_abandon")
def ldap_abandon(ld, msgid):
   return ldap_abandon.ctypes_function(ld, msgid)


@Wldap32Proxy("ldap_check_filterA")
def ldap_check_filterA(ld, SearchFilter):
   return ldap_check_filterA.ctypes_function(ld, SearchFilter)


@Wldap32Proxy("ldap_escape_filter_element")
def ldap_escape_filter_element(sourceFilterElement, sourceLength, destFilterElement, destLength):
   return ldap_escape_filter_element.ctypes_function(sourceFilterElement, sourceLength, destFilterElement, destLength)


@Wldap32Proxy("ldap_count_entries", should_not_return_minus_one_check)
def ldap_count_entries(ld, res):
   return ldap_count_entries.ctypes_function(ld, res)


@Wldap32Proxy("ldap_count_references")
def ldap_count_references(ld, res):
   return ldap_count_references.ctypes_function(ld, res)


@Wldap32Proxy("ldap_count_values", should_not_return_none_check)
def ldap_count_values(vals):
   return ldap_count_values.ctypes_function(vals)   


@Wldap32Proxy("ldap_first_attribute", no_error_check)
def ldap_first_attribute(ld, entry, ptr):
   return ldap_first_attribute.ctypes_function(ld, entry, ptr)


@Wldap32Proxy("ldap_next_attribute", no_error_check)
def ldap_next_attribute(ld, entry, ptr):
   return ldap_next_attribute.ctypes_function(ld, entry, ptr)


@Wldap32Proxy("ldap_first_entry", no_error_check)
def ldap_first_entry(ld, res):
   return ldap_first_entry.ctypes_function(ld, res)


@Wldap32Proxy("ldap_next_entry", no_error_check)
def ldap_next_entry(ld, entry):
   return ldap_next_entry.ctypes_function(ld, entry)


@Wldap32Proxy("ldap_first_reference")
def ldap_first_reference(ld, res):
   return ldap_first_reference.ctypes_function(ld, res)


@Wldap32Proxy("ldap_next_reference")
def ldap_next_reference(ld, entry):
   return ldap_next_reference.ctypes_function(ld, entry)


@Wldap32Proxy("ldap_get_next_page")
def ldap_get_next_page(ExternalHandle, SearchHandle, PageSize, MessageNumber):
   return ldap_get_next_page.ctypes_function(ExternalHandle, SearchHandle, PageSize, MessageNumber)


@Wldap32Proxy("ldap_get_next_page_s", ldap_success_or_no_result_returned)
def ldap_get_next_page_s(ExternalHandle, SearchHandle, timeout, PageSize, TotalCount, Results):
   return ldap_get_next_page_s.ctypes_function(ExternalHandle, SearchHandle, timeout, PageSize, TotalCount, Results)


@Wldap32Proxy("ldap_get_paged_count")   
def ldap_get_paged_count(ExternalHandle, SearchBlock, TotalCount, Results):
   return ldap_get_paged_count.ctypes_function(ExternalHandle, SearchBlock, TotalCount, Results)


@Wldap32Proxy("ldap_get_values", no_error_check)
def ldap_get_values(ld, entry, attr):
   return ldap_get_values.ctypes_function(ld, entry, attr)


@Wldap32Proxy("ldap_get_values_len", no_error_check)
def ldap_get_values_len(ExternalHandle, Message, attr):
   return ldap_get_values_len.ctypes_function(ExternalHandle, Message, attr)


@Wldap32Proxy("ldap_parse_extended_result")
def ldap_parse_extended_result(Connection, ResultMessage, ResultOID, ResultData, Freeit):
   return ldap_parse_extended_result.ctypes_function(Connection, ResultMessage, ResultOID, ResultData, Freeit)


@Wldap32Proxy("ldap_create_page_control")
def ldap_create_page_control(ExternalHandle, PageSize, Cookie, IsCritical, Control):
   return ldap_create_page_control.ctypes_function(ExternalHandle, PageSize, Cookie, IsCritical, Control)

 
@Wldap32Proxy("ldap_parse_page_control")
def ldap_parse_page_control(ExternalHandle, ServerControls, TotalCount, Cookie):
   return ldap_parse_page_control.ctypes_function(ExternalHandle, ServerControls, TotalCount, Cookie)


@Wldap32Proxy("ldap_parse_reference")
def ldap_parse_reference(Connection, ResultMessage, Referrals):
   return ldap_parse_reference.ctypes_function(Connection, ResultMessage, Referrals)


@Wldap32Proxy("ldap_parse_result")
def ldap_parse_result(Connection, ResultMessage, ReturnCode, MatchedDNs, ErrorMessage, Referrals, ServerControls, Freeit):
   return ldap_parse_result.ctypes_function(Connection, ResultMessage, ReturnCode, MatchedDNs, ErrorMessage, Referrals, ServerControls, Freeit)


@Wldap32Proxy("ldap_parse_sort_control")
def ldap_parse_sort_control(ExternalHandle, Control, Result, Attribute):
   return ldap_parse_sort_control.ctypes_function(ExternalHandle, Control, Result, Attribute)


@Wldap32Proxy("ldap_result")
def ldap_result(ld, msgid, all, timeout, res):
   return ldap_result.ctypes_function(ld, msgid, all, timeout, res)


@Wldap32Proxy("ldap_search_s")
def ldap_search_s(ld, base, scope, filter, attrs, attrsonly, res):
   return ldap_search_s.ctypes_function(ld, base, scope, filter, attrs, attrsonly, res)


@Wldap32Proxy("ldap_search_st")
def ldap_search_st(ld, base, scope, filter, attrs, attrsonly, timeout, res):
   return ldap_search_st.ctypes_function(ld, base, scope, filter, attrs, attrsonly, timeout, res)


@Wldap32Proxy("ldap_search_ext")
def ldap_search_ext(ld, base, scope, filter, attrs, attrsonly, ServerControls, ClientControls, TimeLimit, SizeLimit, MessageNumber):
   return ldap_search_ext.ctypes_function(ld, base, scope, filter, attrs, attrsonly, ServerControls, ClientControls, TimeLimit, SizeLimit, MessageNumber)


@Wldap32Proxy("ldap_search_ext_s", no_error_check)
def ldap_search_ext_s(ld, base, scope, filter, attrs, attrsonly, ServerControls, ClientControls, timeout, SizeLimit, res):
   return ldap_search_ext_s.ctypes_function(ld, base, scope, filter, attrs, attrsonly, ServerControls, ClientControls, timeout, SizeLimit, res)


@Wldap32Proxy("ldap_search_init_page", should_not_return_none_check)
def ldap_search_init_page(ExternalHandle, DistinguishedName, ScopeOfSearch, SearchFilter, AttributeList, AttributesOnly, ServerControls, ClientControls, PageTimeLimit, TotalSizeLimit, SortKeys):
   return ldap_search_init_page.ctypes_function(ExternalHandle, DistinguishedName, ScopeOfSearch, SearchFilter, AttributeList, AttributesOnly, ServerControls, ClientControls, PageTimeLimit, TotalSizeLimit, SortKeys)


@Wldap32Proxy("ldap_search_init_pageA", should_not_return_none_check)
def ldap_search_init_pageA(ExternalHandle, DistinguishedName, ScopeOfSearch, SearchFilter, AttributeList, AttributesOnly, ServerControls, ClientControls, PageTimeLimit, TotalSizeLimit, SortKeys):
   return ldap_search_init_pageA.ctypes_function(ExternalHandle, DistinguishedName, ScopeOfSearch, SearchFilter, AttributeList, AttributesOnly, ServerControls, ClientControls, PageTimeLimit, TotalSizeLimit, SortKeys)


@Wldap32Proxy("ldap_search_abandon_page")
def ldap_search_abandon_page(ExternalHandle, SearchBlock):
   return ldap_search_abandon_page.ctypes_function(ExternalHandle, SearchBlock)


@Wldap32Proxy("ldap_msgfree")
def ldap_msgfree(res):
   return ldap_msgfree.ctypes_function(res)


@Wldap32Proxy("ldap_value_free")
def ldap_value_free(vals):
    return ldap_value_free.ctypes_function(vals)


@Wldap32Proxy("ldap_value_free_len")
def ldap_value_free_len(vals):
   return ldap_value_free_len.ctypes_function(vals)


@Wldap32Proxy("ldap_memfree", no_error_check)
def ldap_memfree(Block):
   return ldap_memfree.ctypes_function(Block)


@Wldap32Proxy("ldap_get_dn", should_not_return_none_check)
def ldap_get_dn(ld, entry):
   return ldap_get_dn.ctypes_function(ld, entry)
   
   
######### BERVAL FUNCTIONS #############

@Wldap32Proxy("ber_init", should_not_return_none_check)
def ber_init(pBerVal):
   return ber_init.ctypes_function(pBerVal)


@Wldap32Proxy("ber_free", no_error_check)
def ber_free(pBerElement, fbuf):
   return ber_free.ctypes_function(pBerElement, fbuf)


@Wldap32Proxy("ber_bvfree", no_error_check)
def ber_bvfree(pBerVal):
   return ber_bvfree.ctypes_function(pBerVal)


@Wldap32Proxy("ber_bvecfree", no_error_check)
def ber_bvecfree(pBerVal):
   return ber_bvecfree.ctypes_function(pBerVal)


@Wldap32Proxy("ber_bvdup", should_not_return_none_check)
def ber_bvdup(pBerVal):
   return ber_bvdup.ctypes_function(pBerVal)


@Wldap32Proxy("ber_alloc_t", should_not_return_none_check)
def ber_alloc_t(options):
   return ber_alloc_t.ctypes_function(options)


@Wldap32Proxy("ber_skip_tag", no_error_check)
def ber_skip_tag(pBerElement, pLen):
   return ber_skip_tag.ctypes_function(pBerElement, pLen)


@Wldap32Proxy("ber_peek_tag", no_error_check)
def ber_peek_tag(pBerElement, pLen):
   return ber_peek_tag.ctypes_function(pBerElement, pLen)


@Wldap32Proxy("ber_first_element", no_error_check)
def ber_first_element(pBerElement, pLen, ppOpaque):
   return ber_first_element.ctypes_function(pBerElement, pLen, ppOpaque)


@Wldap32Proxy("ber_next_element", no_error_check)
def ber_next_element(pBerElement, pLen, opaque):
   return ber_next_element.ctypes_function(pBerElement, pLen, opaque)


@Wldap32Proxy("ber_flatten", should_not_return_minus_one_check)
def ber_flatten(pBerElement, pBerVal):
   return ber_flatten.ctypes_function(pBerElement, pBerVal)


@Wldap32Proxy("ber_printf", should_not_return_minus_one_check)
def ber_printf(pBerElement, fmt, argument):
   return ber_printf.ctypes_function(pBerElement, fmt, argument)

