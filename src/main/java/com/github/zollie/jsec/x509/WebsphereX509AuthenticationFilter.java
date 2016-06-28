package com.github.zollie.jsec.x509;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import com.github.zollie.jsec.util.EnvironmentUtil;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

/**
 * Handles authenticating X.509 cert in a Websphere cluster
 * where the App Servers are behind an IBM HTTP Server.
 * <p>
 * This is copied from Springs X509AuthenticationFilter and modified for WAS.
 * </p>
 *
 * @author zollie
 */
public class WebsphereX509AuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {
    private static final Log log = LogFactory.getLog(WebsphereX509AuthenticationFilter.class);
    private X509PrincipalExtractor principalExtractor = new SubjectDnX509PrincipalExtractor();

    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        X509Certificate cert = extractClientCertificate(request);

        if (cert == null) {
            return null;
        }

        String princ = principalExtractor.extractPrincipal(cert).toString();
        if (princ.indexOf('@') == -1) {
            princ = princ + "@" + EnvironmentUtil.getRealm();
        }

        return princ;
    }

    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return extractClientCertificate(request);
    }

    private X509Certificate extractClientCertificate(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Headers are ...");
            @SuppressWarnings("unchecked")
            Enumeration<String> hnames = request.getHeaderNames();
            while (hnames.hasMoreElements()) {
                String hn = hnames.nextElement();
                log.debug(hn + ": " + request.getHeader(hn));
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Attributes are ...");
            @SuppressWarnings("unchecked")
            Enumeration<String> anames = request.getAttributeNames();
            while (anames.hasMoreElements()) {
                String an = anames.nextElement();
                log.debug(an + ": " + request.getAttribute(an));
            }
        }

        String clientCert = request.getHeader("$WSCC");
        log.debug("Client Cert is " + clientCert);

        if (StringUtils.isEmpty(clientCert)) {
            log.debug("No client certificate found in request.");
            return null;
        }

        if (!clientCert.startsWith("-----BEGIN CERTIFICATE-----")) {
            // req'd by CertificateFactory
            clientCert = "-----BEGIN CERTIFICATE-----\n"
                    + clientCert
                    + "\n-----END CERTIFICATE-----";
        }

        X509Certificate x509 = null;

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            x509 = (X509Certificate) cf.generateCertificate(IOUtils.toInputStream(clientCert));
        } catch (Exception e) {
            log.error(e);
        }

        log.debug("X.509 client authentication certificate:" + x509);

        return x509;
    }

    public void setPrincipalExtractor(X509PrincipalExtractor principalExtractor) {
        this.principalExtractor = principalExtractor;
    }
}
