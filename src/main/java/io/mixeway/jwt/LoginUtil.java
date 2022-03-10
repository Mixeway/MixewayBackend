package io.mixeway.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.mixeway.config.Constants;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;
import java.util.UUID;


public class LoginUtil {
    private static final Logger log = LoggerFactory.getLogger(LoginUtil.class);
    String username;
    String authType;

    public LoginUtil(HttpServletRequest request, JwtUtils jwtTokenUtil){
        try {
            String s_dn = request.getHeader("ssl_client_s_dn");
            String apiKey = request.getHeader("apiKey");
            String requestTokenHeader = null;
            try {
                requestTokenHeader = Objects.requireNonNull(WebUtils.getCookie(request, "token")).getValue();
            } catch (NullPointerException ignored) {}
            if (requestTokenHeader != null && requestTokenHeader.contains(".")){
                this.username = jwtTokenUtil.getUsernameFromToken(requestTokenHeader);
                this.authType = Constants.AUTH_TYPE_JWT_TOKEN;
            } else if (StringUtils.isNotBlank(apiKey)){
                UUID uuid = UUID.fromString(apiKey);
                this.username = apiKey;
                this.authType = Constants.AUTH_TYPE_APIKEY;
            } else if (StringUtils.isNotBlank(s_dn)){
                this.username = s_dn.replaceFirst(".*CN=(.*?),.*", "$1");
                this.authType = Constants.AUTH_TYPE_X509;
            } else {
                log.error("Request with no credentials");
            }

        }  catch (IllegalArgumentException e) {
            log.error("Unable to get JWT Token");
        } catch (ExpiredJwtException e) {
            log.error("JWT Token has expired");
        } catch (Exception e){
            log.error("Exception occured: {}", e.getLocalizedMessage());
        }
    }

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
