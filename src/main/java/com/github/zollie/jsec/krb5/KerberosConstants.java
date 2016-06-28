package com.github.zollie.jsec.krb5;

import org.ietf.jgss.Oid;

/**
 * Kerberos Constants
 * 
 * @author zollie
 */
public class KerberosConstants {
	public static final Oid SPENGO_MECH_OID;
	public static final Oid KRB5_MECH_OID;
	public static final Oid KRB5_PRINC_NAME_OID;
	public static final byte[] EMPTY_TICKET = new byte[0];
	
	static {
		try {
			SPENGO_MECH_OID = new Oid("1.3.6.1.5.5.2");
			KRB5_MECH_OID = new Oid("1.2.840.113554.1.2.2");
			KRB5_PRINC_NAME_OID = new Oid("1.2.840.113554.1.2.2.1");
		} catch(Exception e) {
			throw new SecurityException(e);
		}
	}
}
