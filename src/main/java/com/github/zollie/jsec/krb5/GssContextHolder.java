package com.github.zollie.jsec.krb5;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;

/**
 * Holder of a threads client GSSContext
 *
 * @author zollie
 */
public class 	GssContextHolder {
	private static final Log log = LogFactory.getLog(GssContextHolder.class);
	private static final ThreadLocal<GSSContext> gssContext = new ThreadLocal<GSSContext>();

	/**
	 * Set ThreadLocal GSSContext
	 * @param gssc
	 */
	public static void setGssContext(GSSContext gssc) {
	log.debug("Setting gssContext to "+gssc);
	gssContext.set(gssc);
	}

	/**
	 * Get the ThreadLocal GSSContext.
	 * @return may return null
	 */
	public static GSSContext getGssContext() {
	return gssContext.get();
	}

	/**
	 * Clear this Thread's GSSContext
	 */
	public static void clear() {
	gssContext.remove();
	}
}
