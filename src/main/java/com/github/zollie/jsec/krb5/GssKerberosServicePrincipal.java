package com.github.zollie.jsec.krb5;

import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import com.github.zollie.jsec.SecurityException;
import com.github.zollie.jsec.util.SecUtil;


/**
 * Represents a Kerberos Service Principal that uses the GSS API.
 *
 * This is the core class for the delegatable Kerberos authentication framework.
 *
 * @author zollie
 */
public class GssKerberosServicePrincipal
extends AbstractKerberosPrincipal
implements KerberosServicePrincipal {
	// logger
	private static final Log log
	= LogFactory.getLog(GssKerberosServicePrincipal.class);

	/**
	 * Ctor taking required Configuration
	 * @param loginConfig JAAS log config
	 */
	public GssKerberosServicePrincipal
	(AbstractJaasKerberosLoginConfiguration loginConfig) {
	super(loginConfig);
	}


	/**
	 * {@inheritDoc}
	 *
	 * @see KerberosServicePrincipal#validateTicket(byte[])
	 */
	@Override
	public String validateTicket(final byte[] ticket) {
	log.debug("Validating ticket of length "+ticket.length);
	try {
		return Subject.doAs
		(getSubject(), new PrivilegedExceptionAction<String>() {
		/**
		 * {@inheritDoc}
		 *
		 * @see java.security.PrivilegedExceptionAction#run()
		 */
		public String run() throws Exception {
			GSSManager gssManager = GSSManager.getInstance();
			log.debug("Setting up GSSName");
			GSSName gssName = gssManager.createName(getName(), KerberosConstants.KRB5_PRINC_NAME_OID);
			log.debug("Setting up server credentials");
			GSSCredential gssCredential = gssManager.createCredential
					(gssName, GSSCredential.INDEFINITE_LIFETIME, KerberosConstants.SPENGO_MECH_OID, GSSCredential.ACCEPT_ONLY);
			log.debug("Creating new GSSContext");
			GSSContext clientContext = gssManager.createContext(gssCredential);
			if(clientContext == null) {
				log.warn("\nClient GSSContext is null! Returning anonymousUser");
				return SecUtil.getAnonymousUsername();
			}

			log.debug("Processing client ticket");
			clientContext.acceptSecContext(ticket, 0, ticket.length);

			if(!clientContext.isEstablished()) {
				throw new SecurityException("Kerberos authentication failed.");
			}

			log.debug("Kerberos authentication succeeded.");
			log.debug("Client Principal is "+clientContext.getSrcName());
			log.debug("Server Principal is "+clientContext.getTargName());
			log.debug("Client CredDelegState is "+clientContext.getCredDelegState());

			GssContextHolder.setGssContext(clientContext);

			// return the user here so that Spring Security
			// can build out its security context
			String user = clientContext.getSrcName().toString();
			return removeDuplicateRealm(user);
		}
		});
	} catch(Exception e) { throw new SecurityException(e); }
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see KerberosServicePrincipal#newKerberosServiceTicket(String)
	 */
	@Override
	public byte[] newKerberosServiceTicket(String spn) {
	GSSContext clientContext = GssContextHolder.getGssContext();
	return doNewKerberosServiceTicket(clientContext, spn);
	}


	/**
	 * Internal method that gets a new service ticket from
	 * the KDC using a client TGT
	 *
	 * @param clientContext Clients GSS Context
	 * @param spn Service Principal Name of the remote service
	 * @return new ticket
	 */
	private byte[] doNewKerberosServiceTicket(GSSContext clientContext, String spn) {
	if(spn == null)
		throw new IllegalArgumentException("remote spn cannot be null");

	log.debug("Attempting to get new service ticket for remote spn of "+spn);
	if(clientContext == null) { // security is most likely off
		log.warn
		("\n\n** ClientSecurityContext is null. An empty Kerberos ticket will be used. **\n\n");
		return KerberosConstants.EMPTY_TICKET;
	}

	// The krb5 ticket has to be marked forwardable
	if (!clientContext.getCredDelegState()) {
		log.warn("Credentials are not forwardable");
		log.warn("Returning empty ticket");
		return KerberosConstants.EMPTY_TICKET;
	}

	GSSContext tmpContext = null;
	GSSManager gssManager = GSSManager.getInstance();
	try {
		log.debug("Getting delegated credentials");
		log.debug("GSSContext Mech is "+clientContext.getMech());
		GSSCredential clientCred = clientContext.getDelegCred();

		if(log.isDebugEnabled()) {
			StringBuilder sb = new StringBuilder("Client mechs are:");
			for(Oid oid : clientCred.getMechs()) sb.append("\n\t"+oid);
			log.debug(sb.toString());
		}

		log.debug("Creating GSSName for spn "+spn);
		GSSName gssSpn = gssManager.createName(spn, KerberosConstants.KRB5_PRINC_NAME_OID);

		// create new context for user
		log.debug("Creating GSSContext for new ticket");
		tmpContext = gssManager.createContext
		(gssSpn.canonicalize(KerberosConstants.KRB5_MECH_OID), KerberosConstants.KRB5_MECH_OID,
				clientCred, GSSContext.INDEFINITE_LIFETIME);

		// enable gss credential delegation
		tmpContext.requestCredDeleg(true);

		log.debug("Getting new ticket");
		byte[] newTicket = tmpContext.initSecContext(KerberosConstants.EMPTY_TICKET, 0, 0);
		log.debug("new krb5 ticket is length of "+newTicket.length);
		return newTicket;
	} catch(GSSException e) { throw new SecurityException(e); }
	finally { try { tmpContext.dispose(); } catch(Exception e) {} }
	}

	/**
	 * In some cases (for example over VPN) the realm suffix
	 * (i.e @GITHUB.COM) is appended twice
	 *
	 * @param username - username to normalize
	 * @return fixed username
	 */
	private static String removeDuplicateRealm(String username) {
	String[] sa = username.split("@");
	return sa.length < 2 ? sa[0] : sa[0]+"@"+sa[1];
	}
}

