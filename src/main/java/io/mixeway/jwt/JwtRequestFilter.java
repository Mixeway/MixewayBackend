package io.mixeway.jwt;

import io.mixeway.config.Constants;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(JwtRequestFilter.class);
    private final JwtUserDetailsService jwtUserDetailsService;
    private final JwtUtils jwtTokenUtil;

    public JwtRequestFilter(final JwtUserDetailsService jwtUserDetailsService, final JwtUtils jwtTokenUtil){
        this.jwtTokenUtil = jwtTokenUtil;
        this.jwtUserDetailsService = jwtUserDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        LoginUtil login = new LoginUtil(request, jwtTokenUtil);
        UserDetails userDetails = null;
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = null;
        if (StringUtils.isNotBlank(login.getUsername())) {
            switch (login.getAuthType()){
                case Constants.AUTH_TYPE_APIKEY:
                    try {
                        userDetails = this.jwtUserDetailsService.loadUserByApiKeyAndRequestUri(login.getUsername(), request.getRequestURI());
                    } catch (UsernameNotFoundException e) {
                        log.error("User {} has no permision for {}", login.getUsername(), request.getRequestURI());
                    }
                    if (userDetails == null) {
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        return;
                    }
                    usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                            .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    break;
                case Constants.AUTH_TYPE_JWT_TOKEN:
                case Constants.AUTH_TYPE_X509:
                    userDetails = this.jwtUserDetailsService.loadUserByUsername(login.getUsername());
                    usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                            .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    break;

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