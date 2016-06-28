package com.github.zollie.jsec.krb5;

/**
 * Defines a Kerberos Service Principal
 * 
 * @author zollie
 */
public interface KerberosServicePrincipal 
extends KerberosClientPrincipal {

	/**
	 * Validates a Kerberos ticket
	 * 
	 * @param ticket
	 * @return the username extracted from the ticket
	 */
	String validateTicket(final byte[] ticket);	
}