package com.github.zollie.jsec.krb5;

import javax.security.auth.Subject;

/**
 * A Kerberos Principal
 * 
 * @author zollie
 */
public interface KerberosClientPrincipal {
	/**
	 * Set the service principal name
	 * 
	 * @param name
	 */
	void setName(String name);
	
	/**
	 * Get the service principal name
	 * 
	 * @return the name
	 */
	String getName();

	/**
	 * Get the JAAS subject.
	 * This may only be valid after {@link #login()}
	 * 
	 * @return the JAAS Subject
	 */
	Subject getSubject();
	
	/**
	 * Login and initialize.
	 */
	void login();
	
	/**
	 * Get new Kerberos ticket for Service Principal
	 * 
	 * @param spn service name
	 * @return krb5 ticket
	 */
	byte[] newKerberosServiceTicket(final String spn);	
}
