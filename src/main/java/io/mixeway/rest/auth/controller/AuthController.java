package io.mixeway.rest.auth.controller;

import io.mixeway.rest.model.PasswordAuthModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import io.mixeway.rest.model.Password;
import io.mixeway.rest.auth.model.StatusEntity;
import io.mixeway.rest.auth.service.AuthService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.security.Principal;

@RestController
public class AuthController {

     private final AuthService authService;

    @Autowired
    AuthController (AuthService authService){
        this.authService = authService;
    }

    @PreAuthorize("permitAll()")
    @GetMapping(value = "/v2/auth/x509")
    public void authUsingX509(HttpServletResponse httpServletResponse, HttpServletRequest request, Principal principal) throws IOException   {
        try {
            String s_dn = request.getHeader("ssl_client_s_dn").replaceFirst(".*CN=(.*?),.*", "$1");
            if (principal == null && s_dn == null) {
                httpServletResponse.setHeader("Location", "/auth/login?error=cert");
                httpServletResponse.setStatus(302);
                httpServletResponse.flushBuffer();
            } else {
                authService.generateJWTTokenForUser(s_dn, httpServletResponse);
            }
        } catch (NullPointerException npe) {
            httpServletResponse.setHeader("Location", "/auth/login?error=cert");
            httpServletResponse.setStatus(302);
            httpServletResponse.flushBuffer();
        }
    }
    @PreAuthorize("permitAll()")
    @PostMapping(value = "/v2/auth/pass")
    public void authUssingPassword(HttpServletResponse httpServletResponse,@RequestBody PasswordAuthModel passwordAuthModel) throws IOException {
        try{
            authService.processPasswordAuth(httpServletResponse,passwordAuthModel);
        } catch (Exception e){
            httpServletResponse.setHeader("Location", "/auth/login?error=pass");
            httpServletResponse.setStatus(302);
            httpServletResponse.flushBuffer();
        }
    }
    @PreAuthorize("permitAll()")
    @PostMapping(value = "/v2/auth/init")
    public ResponseEntity initialize(@Valid @RequestBody Password password) {
            return authService.initialize(password);
    }
    @PreAuthorize("permitAll()")
    @GetMapping(value = "/v2/auth/status")
    public ResponseEntity<StatusEntity> initialize() {
        return authService.getStatus();
    }
    @PreAuthorize("permitAll()")
    @GetMapping(value = "/v2/auth/status/test")
    public ResponseEntity<StatusEntity> initialize2() {
        return authService.getStatus2();
    }
}
