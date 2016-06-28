package com.github.zollie.jsec.krb5;

import org.apache.http.impl.auth.SpnegoTokenGenerator;

/**
 * Factory for new Kerberos Tickets and SPNEGO tokens
 * 
 * @author zollie
 */
public interface KerberosTicketFactory {

	/**
	 * Get a service ticket using a default Spn. 
	 * 
	 * @return a new service ticket in byte form
	 * @see #setDefaultRemoteSpn(String)
	 */
	byte[] newKerberosServiceTicket();
	
	/**
	 * Get a service ticket for a specific spn
	 * 
	 * @param spn the service principal name of the remote service
	 * @return a new service ticket in byte form
	 */
	byte[] newKerberosServiceTicket(String spn);
	
	/**
	 * Get a service ticket wrapped in Spnego token for default spn
	 *
	 * @return a new spnego token
	 */
	String newSpnegoToken();
	
	/**
	 * Get a service ticket wrapped in Spnego token for a sepcfic spn
	 * 
	 * @param spn the service principal name of the remote service
	 * @return a new spnego token
	 */
	String newSpnegoToken(String spn);	
	
	/**
	 * Get a Spnego token from a kerberos ticket
	 * 
	 * @param ticket the krb5 ticket
	 * @return a spnego token
	 */
	byte[] getSpnegoTokenFromKerberosTicket(byte[] ticket);
	
	/**
	 * Get a Base64 encoded Spnego token from a kerberos ticket
	 * 
	 * @param ticket the krb5 ticket
	 * @return a Base64 spnego token
	 */
	String getBase64SpnegoTokenFromKerberosTicket(byte[] ticket);
	
	/**
	 * {@inheritDoc}
	 */
	void setDefaultRemoteSpn(String spn);

	/**
	 * {@inheritDoc}
	 */
	String getDefaultRemoteSpn();
	
	/**
	 * Sets a SpnegoTokenGenerator
	 * 
	 * @return the spnegoTokenGenerator
	 */
	SpnegoTokenGenerator getSpnegoTokenGenerator();
	
	/**
	 * Get the set SpnegoTokenGenerator
	 * 
	 * @param spnegoTokenGenerator the spnegoTokenGenerator to set
	 */
	void setSpnegoTokenGenerator(SpnegoTokenGenerator spnegoTokenGenerator);
}
