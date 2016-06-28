package com.github.zollie.jsec.ldap;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.github.zollie.jsec.SecurityException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

/**
 * Extends Springs {@link FilterBasedLdapUserSearch}
 * to support caching results.
 *
 * @author zollie
 */
public class CachingFilterBasedLdapUserSearch
        extends FilterBasedLdapUserSearch {
    private static final Log log
            = LogFactory.getLog(CachingFilterBasedLdapUserSearch.class);
    private Cache<String, DirContextOperations> cache = CacheBuilder.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(12, TimeUnit.HOURS)
            .build();


    /**
     * Calls super ctor
     *
     * @param searchBase
     * @param searchFilter
     * @param contextSource
     */
    public CachingFilterBasedLdapUserSearch(String searchBase,
                                            String searchFilter, BaseLdapPathContextSource contextSource) {
        super(searchBase, searchFilter, contextSource);
    }

    /**
     * {@inheritDoc}
     *
     * @see FilterBasedLdapUserSearch#searchForUser(String)
     */
    @Override
    public DirContextOperations searchForUser(final String username) {
        try {
            return cache.get(username, new Callable<DirContextOperations>() {
                @Override
                public DirContextOperations call() throws Exception {
                    return CachingFilterBasedLdapUserSearch.super.searchForUser(username);
                }
            });
        } catch (ExecutionException e) {
            throw new SecurityException(e);
        }
    }

    /**
     * Clear cache
     */
    public void invalidateAll() {
        log.debug("Invalidating all in cache ...");
        cache.invalidateAll();
    }
}
