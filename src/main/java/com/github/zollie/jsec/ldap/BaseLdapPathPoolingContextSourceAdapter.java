package com.github.zollie.jsec.ldap;

import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.pool.factory.PoolingContextSource;

/**
 * Wraps a {@link BaseLdapPathContextSource} so that it may be pooled
 * 
 * @author zollie
 */
public class BaseLdapPathPoolingContextSourceAdapter 
extends PoolingContextSource implements BaseLdapPathContextSource {
	private BaseLdapPathContextSource target;
	
	/**
	 * Ctor taking the BaseLdapPathContextSource to adapt
	 * @param target
	 */
	public BaseLdapPathPoolingContextSourceAdapter(BaseLdapPathContextSource target) {
	super();
	this.target = target;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public DistinguishedName getBaseLdapPath() {
	return target.getBaseLdapPath();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getBaseLdapPathAsString() {
	return target.getBaseLdapPathAsString();
	}
}
