package com.github.zollie.jsec.krb5;

import java.util.HashMap;

import javax.security.auth.login.AppConfigurationEntry;

import com.github.zollie.jsec.SecurityException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.io.Resource;

/**
 * Client JAAS login config for IBM JDK.
 * 
 * @author zollie
 */
public class IbmJaasKerberosClientLoginConfiguration 
extends AbstractJaasKerberosLoginConfiguration {
	// logger
	private static final Log log 
	= LogFactory.getLog(IbmJaasKerberosClientLoginConfiguration.class);
	
	/**
     *	Build app config entries 
     *
     *	@see <a href="https://www.ibm.com/support/knowledgecenter/SSYKE2_7.0.0/com.ibm.java.security.api.doc/jgss/com/ibm/security/auth/module/Krb5LoginModule.html">com.ibm.security.auth.module.Krb5LoginModule</a>
     */
    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
    	try {
	    	// IBM has different options then Sun
	        HashMap<String, Object> options = new HashMap<String, Object>();
	        Resource keytab = getKeyTab();
	        if(keytab != null && keytab.exists())
	        	options.put("useCcache", keytab.getURL().toString());
	        else 
	        	options.put("useDefaultCcache", "true");
	        options.put("principal", getPrincipalName());            
	        options.put("credsType", "initiator");	        
	        options.put("forwardable", "true");
	        options.put("refreshKrb5Config", "true");	        	        
	        if (log.isDebugEnabled()) {
	        	options.put("debug", "true");
	        	System.setProperty("com.ibm.security.jgss.debug", "all");
	        	System.setProperty("com.ibm.security.krb5.Krb5Debug", "all");
	        	System.setProperty("com.ibm.security.krb5.debug", "true");
	        	System.setProperty("ibm.security.krb5.debug", "true");
	        }
	        
	        AppConfigurationEntry configEntry = new AppConfigurationEntry
	        ("com.ibm.security.auth.module.Krb5LoginModule", 
	        		AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
	        
	        return new AppConfigurationEntry[] { configEntry };
    	} catch(Exception e) {
    		throw new SecurityException(e);
    	}               
    }
}
