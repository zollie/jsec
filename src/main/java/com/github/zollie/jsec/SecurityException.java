package com.github.zollie.jsec;

/**
 * General Security Exception
 * 
 * @author zollie
 */
public class SecurityException 
extends Error {
	/**
	 * Serialization Uid
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * {@inheritDoc}
	 */
	public SecurityException() {
	super();
	}

	/**
	 * {@inheritDoc}
	 */	
	public SecurityException(String message, Throwable cause) {
	super(message, cause);
	}

	/**
	 * {@inheritDoc}
	 */	
	public SecurityException(String message) {
	super(message);
	}

	/**
	 * {@inheritDoc}
	 */	
	public SecurityException(Throwable cause) {
	super(cause);
	}
}
