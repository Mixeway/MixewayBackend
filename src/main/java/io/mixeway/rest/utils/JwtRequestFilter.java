package io.mixeway.rest.utils;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.web.util.WebUtils;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(JwtRequestFilter.class);

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;
    @Autowired
    private JwtUtils jwtTokenUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String requestTokenHeader = "";
        String s_dn = request.getHeader("ssl_client_s_dn");
        String apiKey = request.getHeader("apiKey");
        try{
            requestTokenHeader = WebUtils.getCookie(request, "token").getValue();
        } catch (NullPointerException ignored){}
        String username = null;
        String jwtToken = null;
        if (requestTokenHeader != null && requestTokenHeader.contains(".")) {
            jwtToken = requestTokenHeader;
            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                log.error("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                log.error("JWT Token has expired");
            }
        }  else if (s_dn != null && !s_dn.equals("")){
            username = s_dn.replaceFirst(".*CN=(.*?),.*", "$1");
        }else if (apiKey != null && !apiKey.equals("")){
            username = apiKey.replaceFirst(".*CN=(.*?),.*", "$1");
        } else {
            logger.debug("JWT Token does not look like token "+ request.getRequestURI());
        }
        if (username != null ) {
            UserDetails userDetails = null;
            boolean apiKeyAuth = false;
            try {
                UUID uuid = UUID.fromString(username);
                userDetails = this.jwtUserDetailsService.loadUserByApiKeyAndRequestUri(username, request.getRequestURI());
                apiKeyAuth = true;
            } catch (Exception ignored){ }
            if (userDetails == null) {
                try {
                    userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
                } catch (UsernameNotFoundException n){
                    log.error(n.getLocalizedMessage());
                }
            }
            try {
                if (apiKeyAuth) {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                            .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                } else if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                            .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            } catch (IllegalArgumentException e){
                log.error("Error in JWT verification");
            }

        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        chain.doFilter(request, response);

    }
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String[] AUTH_WHITELIST = {
                "/v2/auth/",
                "/api/packetdiscovery"
        };
        String path = request.getServletPath();
        return (StringUtils.startsWithAny(path, AUTH_WHITELIST));
    }


}