package com.github.zollie.jsec.web;

import javax.servlet.http.HttpServletRequest;

/**
 * ThreadLocal holder for HttpServletRequest
 *
 * @author zollie
 */
public class HttpServletRequestHolder {
    // holds request
    private static final ThreadLocal<HttpServletRequest> threadLocal = new ThreadLocal<HttpServletRequest>();

    /**
     * Set HttpServletRequest on ThreadLocal
     *
     * @param request the request
     */
    public static void setHttpServletRequest(HttpServletRequest request) {
        threadLocal.set(request);
    }

    /**
     * Get HttpServletRequest from ThreadLocal
     *
     * @return
     */
    public static HttpServletRequest getHttpServletRequest() {
        return threadLocal.get();
    }

    /**
     * Clear ThreadLocal
     */
    public static void clear() {
        threadLocal.remove();
    }
}
