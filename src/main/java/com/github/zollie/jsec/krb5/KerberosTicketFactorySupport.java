package com.github.zollie.jsec.krb5;

import java.util.Map;

/**
 * Support class for {@link KerberosTicketFactory}
 * 
 * @author zollie
 */
abstract
public class KerberosTicketFactorySupport 
extends AbstractKerberosTicketFactory {
	// princ map
	private final Map<String, KerberosClientPrincipal> principalMap;
	// service princ
	private final KerberosClientPrincipal kerberosPrincipal;
	
	/**
	 * Ctor with required types
	 * @param principalMap
	 */
	public KerberosTicketFactorySupport
	(Map<String, KerberosClientPrincipal> principalMap, KerberosClientPrincipal kerberosServicePrincipal) {
	this.principalMap = principalMap;
	this.kerberosPrincipal = kerberosServicePrincipal;	
	}
		
	/**
	 * Get princ map 
	 * 
	 * @return the principalMap
	 */
	public Map<String, KerberosClientPrincipal> getPrincipalMap() {
	return principalMap;
	}

	/**
	 * Get default KTF
	 * 
	 * @return the defaultFactory
	 */
	public KerberosClientPrincipal getKerberosServicePrincipal() {
	return kerberosPrincipal;
	}	
}
