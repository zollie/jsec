package com.github.zollie.jsec.x509;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyStore;


import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;

import org.junit.Test;

/**
 * Simple Testing of x509 client side cert
 *
 * @author zollie
 */
public class X509ClientTest {
	final String KEY_STORE_PATH = "/Users/home/zollie/keystore.jks";
	final String KEY_STORE_PASSWORD = "changeit";
	final String PRIV_KEY_PASSWORD = "password";
	final String TRUST_STORE_PATH = "/Users/home/zollie/cacerts";
	final String TRUST_STORE_PASSWORD = "changeit";


	@Test
	public void testClientCall() throws Exception {
		// load keystore
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		InputStream keystoreInput = new FileInputStream(KEY_STORE_PATH);
		keystore.load(keystoreInput, KEY_STORE_PASSWORD.toCharArray());
		System.out.println("Keystore has " + keystore.size() + " keys");

		// load truststore
		KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
		InputStream truststoreInput = new FileInputStream(TRUST_STORE_PATH);
		truststore.load(truststoreInput, TRUST_STORE_PASSWORD.toCharArray());
		System.out.println("Truststore has " + truststore.size() + " keys");

		SchemeRegistry schemeRegistry = new SchemeRegistry();
		SSLSocketFactory schemeSocketFactory = new SSLSocketFactory(keystore, PRIV_KEY_PASSWORD, truststore);
		schemeRegistry.register(new Scheme("https", 443, schemeSocketFactory));

		final HttpParams httpParams = new BasicHttpParams();
		DefaultHttpClient httpClient = new DefaultHttpClient(new SingleClientConnManager(schemeRegistry), httpParams);

		HttpPost post = new HttpPost();
		post.setURI(new URI("https://someserver/context"));

		BasicHttpEntity entity = new BasicHttpEntity();
		entity.setContentType("text/xml");
		entity.setContent(new FileInputStream("/Users/home/zollie/test_request.xml"));

		HttpResponse response = httpClient.execute(post);

		System.out.println("Response status code: " + response.getStatusLine().getStatusCode());
		System.out.println("Response body: ");
		System.out.println(EntityUtils.toString(response.getEntity()));
	}
}
