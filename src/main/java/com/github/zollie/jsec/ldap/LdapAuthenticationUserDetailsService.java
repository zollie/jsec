package com.github.zollie.jsec.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Used by Preauth tokens to load from AD
 *
 * @author zollie
 */
public class LdapAuthenticationUserDetailsService
        implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
    private static final Log log = LogFactory.getLog(LdapAuthenticationUserDetailsService.class);
    @Autowired
    private LdapUserDetailsService ldapUserDetailService;

    /**
     * Get a UserDetails object based on the user name contained in the given
     * token, and the GrantedAuthorities as returned by the
     * GrantedAuthoritiesContainer implementation as returned by
     * the token.getDetails() method.
     */
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws AuthenticationException {
        log.debug("Creating UserDetails for Authentication " + token);
        log.debug(token.getName());
        log.debug(token.getCredentials());
        log.debug(token.getDetails());
        log.debug(token.getPrincipal());
        return ldapUserDetailService.loadUserByUsername(token.getName());
    }
}
