package com.github.zollie.jsec.krb5;

import com.github.zollie.jsec.SecurityException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;
import java.security.PrivilegedExceptionAction;


/**
 * Implementation of {@link KerberosClientPrincipal}
 * that uses the GSS API.
 *
 * @author zollie
 */
public class GssKerberosClientPrincipal
        extends AbstractKerberosPrincipal implements KerberosClientPrincipal {
    // logger
    private static final Log log
            = LogFactory.getLog(GssKerberosClientPrincipal.class);
    private boolean forwardable;


    /**
     * Ctor taking required Configuration
     *
     * @param loginConfig JAAS log config
     */
    public GssKerberosClientPrincipal
    (AbstractJaasKerberosLoginConfiguration loginConfig) {
        super(loginConfig);
    }

    /**
     * Ctor taking required Configuration
     *
     * @param loginConfig JAAS log config
     */
    public GssKerberosClientPrincipal
    (AbstractJaasKerberosLoginConfiguration loginConfig, boolean forwardable) {
        this(loginConfig);
        this.setForwardable(forwardable);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] newKerberosServiceTicket(final String spn) {
        for (KerberosTicket t : getSubject().getPrivateCredentials(KerberosTicket.class))
            if (!t.isCurrent())
                login();
        try {
            return Subject.doAs(getSubject(), new PrivilegedExceptionAction<byte[]>() {
                @Override
                public byte[] run() throws Exception {
                    GSSContext gssContext = null;
                    GSSManager gssManager = GSSManager.getInstance();
                    GSSName clientName = gssManager.createName(getName(), GSSName.NT_USER_NAME);
                    try {
                        dumpTickets();

                        GSSName serviceName = gssManager.createName(spn, null);
                        log.debug("Setting up client credentials");
                        GSSCredential gssCredential = gssManager.createCredential
                                (clientName, GSSCredential.DEFAULT_LIFETIME, KerberosConstants.KRB5_MECH_OID, GSSCredential.INITIATE_ONLY);
                        gssCredential.getRemainingInitLifetime(KerberosConstants.KRB5_MECH_OID);
                        log.debug("Getting Kerberos ticket");
                        gssContext = gssManager.createContext(serviceName, KerberosConstants.KRB5_MECH_OID, gssCredential, GSSContext.DEFAULT_LIFETIME);
                        // request ticket flags
                        gssContext.requestConf(true);
                        gssContext.requestInteg(true);
                        gssContext.requestReplayDet(true);
                        gssContext.requestSequenceDet(true);
                        gssContext.requestCredDeleg(isForwardable());
                        byte[] ticket = gssContext.initSecContext(KerberosConstants.EMPTY_TICKET, 0, 0);
                        return ticket;
                    } finally {
                        try {
                            gssContext.dispose();
                        } catch (Exception e) {
                            // rarely there is ConcurrentModificationException disposing
                            log.warn("gssContext.dispose() threw error: " + e.getMessage());
                        }
                    }
                }


            });
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }


    /**
     * @return the forwardable
     */
    public boolean isForwardable() {
        return forwardable;
    }

    /**
     * @param forwardable the forwardable to set
     */
    public void setForwardable(boolean forwardable) {
        this.forwardable = forwardable;
    }
}

