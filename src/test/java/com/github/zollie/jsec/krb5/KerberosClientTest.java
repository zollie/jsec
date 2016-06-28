package com.github.zollie.jsec.krb5;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;


/**
 * Example client test
 *
 * @author zollie
 */
public class KerberosClientTest {
    private static final Logger log = Logger.getLogger(KerberosClientTest.class);
	// your non-kerberos username
	// could be your real princ, does not have to be
	private final static String username = "zollie";

	/**
	 * Set's up Authentication for Spring Security
	 */
	@BeforeClass
	public static void setUp() {
		// Create a dummy Authentication object with a username
		final Authentication auth = new Authentication() {
		    private static final long serialVersionUID = 1L;

			@Override
			public String getName() { return username; }

			@Override
		    public Collection<? extends GrantedAuthority> getAuthorities() {
		    // TODO Auto-generated method stub
		    return null;
		    }

			@Override
		    public Object getCredentials() {
		    // TODO Auto-generated method stub
		    return null;
		    }

			@Override
		    public Object getDetails() {
		    // TODO Auto-generated method stub
		    return null;
		    }

			@Override
		    public Object getPrincipal() {
		    // TODO Auto-generated method stub
		    return null;
		    }

			@Override
		    public boolean isAuthenticated() {
		    // TODO Auto-generated method stub
		    return false;
		    }

			@Override
		    public void setAuthenticated(boolean isAuthenticated)
		            throws IllegalArgumentException {
		    // TODO Auto-generated method stub

		    }
		};

		// This is the Spring SecurityContext, holder
		// of the Authentication instance
		SecurityContext secContext = new SecurityContext() {
		    private static final long serialVersionUID = 1L;

			@Override
			public Authentication getAuthentication() { return auth; }

			@Override
		    public void setAuthentication(Authentication authentication) {
		    // TODO Auto-generated method stub

		    }
		};

		// This sets up your SecurityContext on a ThreadLocal
		SecurityContextHolder.setContext(secContext);

		/** Now it looks like we logged in via Spring Security */
	}

	/**
	 * Test using client credential cache.
	 * That is using a normal AD user
	 */
//	@Test
	public void testUser() {
	final String principalName = "zollie@GITHUB.COM";
	final String spn = "HTTP/someserver.com";
	final String keytabName = "zollie.keytab"; // this needs to be fresh (use kinit)

	// Lets create the Jaas Login Config
	AbstractJaasKerberosLoginConfiguration loginConfig
	= new IbmJaasKerberosClientLoginConfiguration();

	// It will need your principal name
	loginConfig.setPrincipalName(principalName);
	// And location to your credential cache
	loginConfig.setKeyTab(new ClassPathResource(keytabName));

	// Create a KerberosClientPrincipal with this LoginConfig
	GssKerberosClientPrincipal princ = new GssKerberosClientPrincipal(loginConfig);

	// You should see a TGT in here
	princ.dumpTickets();

	// Create a principal map
	Map<String, KerberosClientPrincipal> princMap
	= new HashMap<String, KerberosClientPrincipal>();

	// Map username to principalName
	princMap.put(username, princ);

	// Create a Ticket Factory using this princ Map
	KerberosTicketFactory ktf
	= new DelegateBeforeImpersonateKerberosTicketFactory(princMap, null);

	// And finally get your spnego token
	String spnegoToken = ktf.newSpnegoToken(spn);
	System.out.println("Your spnego token is:\n"+spnegoToken);

	// You can then add this token to an HTTP header
	// httpMessage.addHeader("Authorization", "Negotiate "+spnegoToken);

	// Make sure it's not an NTLM token
	Assert.assertTrue(spnegoToken.startsWith("YII"));
	}

	/**
	 * Test mapping to an SPN using a keytab.
	 */
//	@Test
	public void testSpn() throws Exception {
	final String principalName =  "HTTP/someserver.com";
	final String spn = "HTTP/someserver.com";
	final String keytabName = "http-someserver.keytab";

	// Lets create the Jaas Login Config
	AbstractJaasKerberosLoginConfiguration loginConfig
	= new IbmJaasKerberosServiceLoginConfiguration(); //<-- Notice the Service Config!

	// It will need your principal name
	loginConfig.setPrincipalName(principalName);
	// And location to your credential cache
	loginConfig.setKeyTab(new ClassPathResource(keytabName));

	// Create a KerberosClientPrincipal with this LoginConfig
	GssKerberosClientPrincipal princ = new GssKerberosClientPrincipal(loginConfig);

	// You shold see a TGT in here
	princ.dumpTickets();

	// Create a principal map
	Map<String, KerberosClientPrincipal> princMap
	= new HashMap<String, KerberosClientPrincipal>();

	// Map username to principalName
	princMap.put(username, princ);

	// Create an Impersonating Ticket Factory using this princ Map
	/* This is discouraged. Please delegate if you can */
//	KerberosTicketFactory ktf
//	= new ImpersonateBeforeDelegateKerberosTicketFactory(princMap, null);
//
//	// And finally get your spnego token
//	String spnegoToken = ktf.newSpnegoToken(spn);
//	System.out.println("Your spnego token is:\n"+spnegoToken);
//
//	// You can then add this token to an HTTP header
//	// httpMessage.addHeader("Authorization", "Negotiate "+spnegoToken);
//
//  // Make sure it's not an NTLM token
//	Assert.assertTrue(spnegoToken.startsWith("YII"));
//
//    String url = "http://someserver.com";
//    
//    DefaultHttpClient client = new DefaultHttpClient();
//
//    try {
//    	HttpGet request = new HttpGet(url);
//		request.addHeader("Authorization", "Negotiate " + spnegoToken);
//    	HttpResponse response = client.execute(request);
//    	Assert.assertEquals(200, response.getStatusLine().getStatusCode());
//    	Assert.assertNotNull(response.getStatusLine().getStatusCode());
//    } finally {
//    	client.getConnectionManager().shutdown();
//    }
	}	
}
