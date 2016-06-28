package com.github.zollie.jsec.util;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Security Utilities.
 *
 * <p>
 * Assumes you have been authenticated using Spring Security
 * as it uses {@link SecurityContextHolder}
 * </p>
 *
 * @author zollie
 */
public class SecUtil {
    public static final String ANONYMOUS_USERNAME = "anonymousUser";

    /**
     * Simple Singleton
     */
    private SecUtil() {
    }

    public static final String getAnonymousUsername() {
        return ANONYMOUS_USERNAME;
    }

    /**
     * Get the simple name from a user prin name, i.e
     * zollie where the fullname would be zollie@GITHUB.COM
     *
     * @param username
     * @return
     */
    public static String getSimpleName(String username) {
        String[] sa = username.split("@", 2);
        return sa[0];
    }

    /**
     * Get the currently logged in User
     *
     * @return may return anonymousUser
     */
    public static final String getCurrentUser() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

    /**
     * Get the currently logged in User
     *
     * @return may return anonymousUser
     */
    public static final String getCurrentUserSimpleName() {
        return getSimpleName(getCurrentUser());
    }

    /**
     * Get the currently logged in User
     *
     * @return may return anonymousUser
     */
    @SuppressWarnings("unchecked")
    public static final Set<String> getCurrentUserRoles() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return Collections.EMPTY_SET;

        Set<String> roles = new HashSet<String>();
        for (GrantedAuthority ga : auth.getAuthorities())
            roles.add(ga.getAuthority());
        return roles;
    }

    /**
     * Check if current user is in role
     *
     * @param role
     * @return
     */
    public static boolean isCurrentUserInRole(String role) {
        return getCurrentUserRoles().contains(role);
    }

    /**
     * Check if current user is in a list of roles
     *
     * @param roles
     * @return
     */
    public static boolean isCurrentUserInRoles(Set<String> roles) {
        for (String r : roles) if (isCurrentUserInRole(r)) return true;
        return false;
    }

    /**
     * Get the currently logged in User
     *
     * @return may return anonymousUser
     */
    public static final String getRealFromUserName(String name) {
        if (name == null) throw new IllegalArgumentException("username cannot be null");
        int x = name.indexOf("@");
        if (x < 0) return "";
        return name.substring(x + 1);
    }

}
