package com.github.zollie.jsec.krb5;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.springframework.core.io.Resource;

/**
 * Base support for Kerberos JAAS Login Configurations
 *
 * @author zollie
 */
public abstract class AbstractJaasKerberosLoginConfiguration
extends Configuration {
	// Kerberos Principal Name
	private String principalName;
	// URL to keyTab file
	private Resource keyTab;
	// non-standard path to krb5.conf
	private Resource krb5ConfPath;

	/**
	 * @return the keyTabUrl
	 */
	public String getPrincipalName() {
	return principalName;
	}

	/**
	 * @param principalName the servicePrincipal to set
	 */
	public void setPrincipalName(String principalName) {
	this.principalName = principalName;
	}

	/**
	 * @return the keyTabUrl
	 */
	public Resource getKeyTab() {
	return keyTab;
	}

	/**
	 * @param keyTab the keyTabUrl to set
	 */
	public void setKeyTab(Resource keyTab) {
	this.keyTab = keyTab;
	}

	/**
	 * @return the keyTabUrl
	 */
	public Resource getKrb5ConfPath() {
	return krb5ConfPath;
	}

	/**
	 * @param krb5ConfPath the keyTabUrl to set
	 */
	public void setKrb5ConfPath(Resource krb5ConfPath) {
	this.krb5ConfPath = krb5ConfPath;
	try {
	System.setProperty("java.security.krb5.conf", krb5ConfPath.getURL().getPath());
	} catch(Exception e) {
	throw new SecurityException(e);
	}
	}

	/**
	 *	Build app config entries
	 */
	@Override
	public abstract AppConfigurationEntry[] getAppConfigurationEntry(String name);
}
