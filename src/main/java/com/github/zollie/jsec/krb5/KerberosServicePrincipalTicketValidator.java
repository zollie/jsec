package com.github.zollie.jsec.krb5;

import org.springframework.security.extensions.kerberos.KerberosTicketValidator;

/**
 * {@link KerberosTicketValidator} that delegates to 
 * {@link KerberosServicePrincipal#validateTicket(byte[])}
 * 
 * @author zollie
 */
public class KerberosServicePrincipalTicketValidator 
implements KerberosTicketValidator {
	// ksp
	private KerberosServicePrincipal kerberosServicePrincipal;
	
	/**
	 * {@inheritDoc}
	 */
	public String validateTicket(byte[] ticket) {
	return kerberosServicePrincipal.validateTicket(ticket);
	}

	/**
	 * @return the serviceSubject
	 */
	public KerberosServicePrincipal getKerberosServicePrincipal() {
	return kerberosServicePrincipal;
	}

	/**
	 * @param kerberosServicePrincipal the serviceSubject to set
	 */
	public void setKerberosServicePrincipal(KerberosServicePrincipal kerberosServicePrincipal) {
	this.kerberosServicePrincipal = kerberosServicePrincipal;
	}	
}
