package com.github.zollie.jsec.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Sends a 403 error
 *
 * @author zollie
 */
public class ErrorSendingAccessDeniedHandler implements AccessDeniedHandler {
    private static final Log log = LogFactory.getLog(ErrorSendingAccessDeniedHandler.class);

    /** {@inheritDoc}
     *  @see AccessDeniedHandler#handle(HttpServletRequest, HttpServletResponse, AccessDeniedException)
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        log.debug("Sending 401 error");
        response.sendError(401);
    }
}
