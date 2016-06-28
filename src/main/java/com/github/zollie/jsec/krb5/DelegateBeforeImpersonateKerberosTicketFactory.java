package com.github.zollie.jsec.krb5;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;

import com.github.zollie.jsec.util.SecUtil;

/**
 * A {@link KerberosTicketFactory} that will delegate if a forwardable ticket is present.
 * If not, searches a registry for the principal name and impersonates if found.
 *
 * @author zollie
 */
public class DelegateBeforeImpersonateKerberosTicketFactory
extends KerberosTicketFactorySupport {
	// logger
	private static final Log log
	= LogFactory.getLog(DelegateBeforeImpersonateKerberosTicketFactory.class);

	/**
	 * @param principalMap
	 */
	public DelegateBeforeImpersonateKerberosTicketFactory
	(Map<String, KerberosClientPrincipal> principalMap, KerberosServicePrincipal defaultFactory) {
	super(principalMap, defaultFactory);
	}

	/** {@inheritDoc}
	 * @see KerberosTicketFactory#newKerberosServiceTicket(java.lang.String)
	 */
	@Override
	public byte[] newKerberosServiceTicket(String spn) {
	log.debug("Getting new ticket for spn "+spn);
	GSSContext gssContext = GssContextHolder.getGssContext();
	if(gssContext != null && gssContext.getCredDelegState())
		return getKerberosServicePrincipal().newKerberosServiceTicket(spn);

	String princ = SecUtil.getCurrentUser();
	KerberosClientPrincipal kcp = getPrincipalMap().get(princ);
	if(kcp != null) return kcp.newKerberosServiceTicket(spn);

	log.warn("Returning empty krb5 ticket");
	return KerberosConstants.EMPTY_TICKET;
	}
}
