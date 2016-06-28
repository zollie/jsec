package com.github.zollie.jsec.krb5;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Abstract base {@link KerberosClientPrincipal}
 *
 * @author zollie
 */
abstract
public class AbstractKerberosPrincipal
implements KerberosClientPrincipal {
	// logger
	private static final Log log
	= LogFactory.getLog(AbstractKerberosPrincipal.class);
	// spn
	private String name;
	// jaas subject
	private Subject subject;
	// jaas login conf
	private AbstractJaasKerberosLoginConfiguration loginConfig;

	/**
	 * Ctor taking required Configuration
	 * @param loginConfig JaaS log config
	 */
	public AbstractKerberosPrincipal
	(AbstractJaasKerberosLoginConfiguration loginConfig) {
	this.loginConfig = loginConfig;
	setName(loginConfig.getPrincipalName());
	login();
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see KerberosServicePrincipal#setName(String)
	 */
	@Override
	public void setName(String name) {
	this.name = name;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see KerberosServicePrincipal#getName()
	 */
	@Override
	public String getName() {
	return name;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see KerberosServicePrincipal#getSubject()
	 */
	@Override
	public Subject getSubject() {
	return subject;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see KerberosServicePrincipal#login()
	 */
	@Override
	public void login() {
	log.debug("login for principal "+getName());

	Set<KerberosPrincipal> princs = new HashSet<KerberosPrincipal>(1);
	princs.add(new KerberosPrincipal(getName()));

	Subject tmpSubject = new Subject
	(false, princs, Collections.EMPTY_SET, Collections.EMPTY_SET);

	LoginContext loginContext;
	try {
		loginContext = new LoginContext
		(getName(), tmpSubject, new NoOpCallbackHandler(), loginConfig);
		loginContext.login();
		subject = loginContext.getSubject();
	} catch(Exception e) {
		log.warn("Login Failure", e);
	}
	}

	/**
	 * Dump debug info of Kerberos Tickets
	 */
	public void dumpTickets() {
    if(log.isDebugEnabled() && getSubject() != null)
	    for(KerberosTicket t : getSubject().getPrivateCredentials(KerberosTicket.class))
	    	log.debug(t);
	}
}
