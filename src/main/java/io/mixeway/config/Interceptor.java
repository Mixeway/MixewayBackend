package io.mixeway.config;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerInterceptor;

public class Interceptor implements HandlerInterceptor {
    private static final Logger log = LoggerFactory.getLogger(Interceptor.class);


    /**
     * Executed before actual handler is executed
     **/
    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler) throws Exception {
        log.debug("[preHandle]" + "[" + request.getMethod() + "]" + request.getRequestURI());
        Enumeration<String> headerNames = request.getHeaderNames();
        while(headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            log.debug(headerName + " : " + request.getHeader(headerName));
        }
        response.setHeader("test","test");
        return true;
    }

}