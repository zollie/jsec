package com.github.zollie.jsec.krb5;

import java.util.Map;

import com.github.zollie.jsec.util.SecUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;

/**
 * A {@link KerberosTicketFactory} that searches a registry for principal name
 * and impersonates if found. If not found, delegation is attempted. 
 * 
 * @author zollie
 */
public class ImpersonateBeforeDelegateKerberosTicketFactory 
extends KerberosTicketFactorySupport {
	// logger
	private static final Log log 
	= LogFactory.getLog(ImpersonateBeforeDelegateKerberosTicketFactory.class);
		
	/**
	 * 
	 * @param principalMap
	 */
	public ImpersonateBeforeDelegateKerberosTicketFactory
	(Map<String, KerberosClientPrincipal> principalMap, KerberosServicePrincipal defaultFactory) {
	super(principalMap, defaultFactory);
	}

	/** {@inheritDoc}
	 * @see KerberosTicketFactory#newKerberosServiceTicket(java.lang.String)
	 */
	@Override
	public byte[] newKerberosServiceTicket(String spn) {
	log.debug("Getting new ticket for spn "+spn);
	String princ = SecUtil.getCurrentUser();
	KerberosClientPrincipal kcp = getPrincipalMap().get(princ);
	if(kcp != null) return kcp.newKerberosServiceTicket(spn);
	
	GSSContext gssContext = GssContextHolder.getGssContext();
	if(gssContext != null && gssContext.getCredDelegState())
		return getKerberosServicePrincipal().newKerberosServiceTicket(spn);
	
	log.warn("Returning empty krb5 ticket");
	return KerberosConstants.EMPTY_TICKET;
	}	
}
