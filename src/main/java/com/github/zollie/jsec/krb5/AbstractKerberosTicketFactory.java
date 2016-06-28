package com.github.zollie.jsec.krb5;

import com.github.zollie.jsec.SecurityException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.contrib.auth.BouncySpnegoTokenGenerator;
import org.apache.http.impl.auth.SpnegoTokenGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;

import com.github.zollie.jsec.util.EnvironmentUtil;

/**
 * Base support for {@link KerberosTicketFactory}
 * 
 * @author zollie
 */
abstract
public class AbstractKerberosTicketFactory 
implements KerberosTicketFactory {
	// logger
	private static final Log log 
	= LogFactory.getLog(AbstractKerberosTicketFactory.class);	
	private String defaultRemoteSpn;
	private SpnegoTokenGenerator spnegoTokenGenerator = new BouncySpnegoTokenGenerator();
	
	/**
	 * Default Ctor
	 */
	public AbstractKerberosTicketFactory() {
	setDefaultRemoteSpn(EnvironmentUtil.getSpn());
	}

	/** {@inheritDoc}
	 * @see KerberosTicketFactory#newKerberosServiceTicket()
	 */
	@Override
	public byte[] newKerberosServiceTicket() {
	return newKerberosServiceTicket(getDefaultRemoteSpn());
	}
	
	/** {@inheritDoc}
	 * @see KerberosTicketFactory#newSpnegoToken()
	 */
	@Override
	public String newSpnegoToken() {
	return newSpnegoToken(getDefaultRemoteSpn());
	}

	/** {@inheritDoc}
	 * @see KerberosTicketFactory#newSpnegoToken(String)
	 */
	@Override
	public String newSpnegoToken(String spn) {
	return getBase64SpnegoTokenFromKerberosTicket(newKerberosServiceTicket(spn));
	}
	
	/** {@inheritDoc}
	 * @see KerberosTicketFactory#getSpnegoTokenFromKerberosTicket(byte[])
	 */
	@Override
	public byte[] getSpnegoTokenFromKerberosTicket(byte[] ticket) {
	try {
	if(ticket.equals(KerberosConstants.EMPTY_TICKET)) return KerberosConstants.EMPTY_TICKET;
	byte[] token = getSpnegoTokenGenerator().generateSpnegoDERObject(ticket);
	log.debug("new Spnego token is length of "+token.length);
	return token;
	} catch(Exception e) { throw new SecurityException(e); }
	}

	/** {@inheritDoc}
	 * @see KerberosTicketFactory#getBase64SpnegoTokenFromKerberosTicket(byte[])
	 */
	@Override
	public String getBase64SpnegoTokenFromKerberosTicket(byte[] ticket) {
	byte[] token = getSpnegoTokenFromKerberosTicket(ticket);
	return new String(Base64.encode(token));
	}				

	/** {@inheritDoc}
	 * @see KerberosTicketFactory#setDefaultRemoteSpn(String)
	 */
	@Override
	public void setDefaultRemoteSpn(String spn) {
	this.defaultRemoteSpn = spn;
	}

	/** {@inheritDoc}
	 * @see KerberosTicketFactory#getDefaultRemoteSpn()
	 */
	@Override
	public String getDefaultRemoteSpn() {
	return defaultRemoteSpn;
	}

	/** {@inheritDoc}
	 * @see KerberosTicketFactory#getSpnegoTokenGenerator()
	 */
	@Override
	public SpnegoTokenGenerator getSpnegoTokenGenerator() {
	return spnegoTokenGenerator;
	}

	/** {@inheritDoc}
	 * @see KerberosTicketFactory#setSpnegoTokenGenerator(SpnegoTokenGenerator)
	 */
	@Override
	@Autowired(required=false)
	public void setSpnegoTokenGenerator(SpnegoTokenGenerator spnegoTokenGenerator) {
	this.spnegoTokenGenerator = spnegoTokenGenerator;
	}
}
 