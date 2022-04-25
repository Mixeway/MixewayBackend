package io.mixeway.api.auth.controller;

import io.mixeway.api.auth.model.Password;
import io.mixeway.api.auth.model.PasswordAuthModel;
import io.mixeway.api.auth.model.StatusEntity;
import io.mixeway.api.auth.service.AuthService;
import io.mixeway.domain.exceptions.NotValidRoleException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.security.Principal;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


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
    @GetMapping(value = "/v2/auth/fb")
    public void authUsingFacebook(HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) throws IOException {
        authService.processFbLogin(httpServletRequest, httpServletResponse);
    }
    @PreAuthorize("permitAll()")
    @GetMapping(value = "/v2/auth/github")
    public void authUsingGitHub(HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) throws IOException {
        authService.processGitHubLogin(httpServletResponse,httpServletRequest);
    }

    @PreAuthorize("permitAll()")
    @RequestMapping(value = "/v2/auth/fb/forward")
    public void authUsingFacebookForward(@RequestParam("code") String authorizationCode, HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) throws IOException, NotValidRoleException {
        authService.authenticateFBUser(authorizationCode, httpServletResponse, httpServletRequest);
    }
    @PreAuthorize("permitAll()")
    @RequestMapping(value = "/v2/auth/github/forward")
    public void authUsingGitHubForward(@RequestParam("code") String authorizationCode, HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) throws IOException, NotValidRoleException {
       authService.authenticateGitHubUser(authorizationCode,httpServletRequest,httpServletResponse);
    }

    @GetMapping(value = "/v2/auth/keycloak")
    public void authUsingKeycloakGet(FirewalledRequest request, HttpServletResponse httpServletResponse) throws IOException, NotValidRoleException {
        authService.authUsingKeycloak(request, httpServletResponse);
    }

    @PostMapping(value = "/v2/auth/init")
    public ResponseEntity initialize(@Valid @RequestBody Password password) throws NotValidRoleException {
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
