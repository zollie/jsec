package com.github.zollie.jsec.krb5;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

/**
 * A NoOp {@link CallbackHandler}
 * 
 * @author zollie
 */
public class NoOpCallbackHandler 
implements CallbackHandler {

	/**
	 * {@inheritDoc}
	 *  
	 * @see CallbackHandler#handle(Callback[])
	 */
	@Override
	public void handle(Callback[] callbacks) {
	}
}
