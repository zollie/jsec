package com.github.zollie.jsec.krb5;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/** 
 * Just returns username which is all we get from Kerberos 
 * without PAC decoding. Use this if you only want Authentication
 * and not Authorization. Loads one role called ROLE_USER.
 */
public class KerberosUserDetailsService 
implements UserDetailsService {

	/** {@inheritDoc}
	 * @see UserDetailsService#loadUserByUsername(java.lang.String)
	 */
	@Override
	public UserDetails loadUserByUsername(String username) {
		return new 
		User(username, "notUsed", AuthorityUtils.createAuthorityList("ROLE_USER"));
	}
}
