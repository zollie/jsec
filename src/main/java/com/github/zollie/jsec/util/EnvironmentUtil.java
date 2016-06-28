package com.github.zollie.jsec.util;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Util to help with determining runtime environment 
 * and appropriate default properties
 * 
 * @author zollie
 */ 
public class EnvironmentUtil {
	private static String realm;
	private static String fqdn;
	private static String hostname;	
	private static String spn;
	private static String keytabName;
	
	public static final String DEFAULT_REALM = "GITHUB.COM";
	
	static {
	try {
		fqdn = InetAddress.getLocalHost().getCanonicalHostName().toLowerCase();
	} catch(UnknownHostException e) {
	throw new ExceptionInInitializerError(e);
	}
	
	realm = fqdn.substring(fqdn.indexOf('.')+1).toUpperCase();		
	if(realm.indexOf('.') < 0) { 
		realm = DEFAULT_REALM;
		fqdn = fqdn +"."+DEFAULT_REALM.toLowerCase();
	}
	hostname  = fqdn.substring(0, fqdn.indexOf('.'));
	spn = "HTTP/"+fqdn+"@"+realm;
	keytabName ="http-"+hostname+".keytab";
	}
	
	/**
	 * Singleton
	 */
	private EnvironmentUtil() {}
	
	/**
	 * Get the REALM
	 * @return
	 */
	public static String getRealm() {
	return realm;
	}	
	
	/**
	 * Get fully qualified domain name
	 * @return
	 */
	public static String getFqdn() {
	return fqdn;
	}	
	
	/**
	 * Get simple host name
	 * @return
	 */
	public static String getSimpleHostName() {
	return hostname;
	}
	
	/**
	 * Get Service Principal Name
	 * @return
	 */
	public static String getSpn() {
	return spn;
	}
	
	/**
	 * Get HTTP Service Principal Name for a given URL
	 * @return
	 */
	public static String getSpn(URL url) {
	return getSpn(url, null);
	}	
	
	/**
	 * Get HTTP Service Principal Name for a given URL
	 * @return
	 */
	public static String getSpn(URL url, String realm) {
	if(url == null) throw new IllegalArgumentException("url cannot be null");
	String lHost  = url.getHost();
	String lFqdn = lHost;
	String lRealm = realm;
	try { // this requires correct DNS entries
		lFqdn = InetAddress.getByName(lHost).getCanonicalHostName();
	} catch(UnknownHostException e) {}
		
	if(lRealm == null || lRealm.indexOf('.') < 0) {
		lRealm = lFqdn.substring(lFqdn.indexOf('.')+1).toUpperCase();
	}
	
	if(lRealm.indexOf('.') < 0) { 
		lRealm = DEFAULT_REALM;
		lFqdn = lFqdn +"."+DEFAULT_REALM.toLowerCase();
	}
	
	return "HTTP/"+lFqdn+"@"+lRealm;
	}	
	
	/**
	 * Get the calculated keytab name
	 * @return
	 */
	public static String getKeytabName() {
	return keytabName;
	}	
}

 
