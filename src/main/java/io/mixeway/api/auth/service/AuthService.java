 package io.mixeway.api.auth.service;

import io.mixeway.api.auth.model.Password;
import io.mixeway.api.auth.model.PasswordAuthModel;
import io.mixeway.api.auth.model.StatusEntity;
import io.mixeway.api.protocol.user.UserModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.Status;
import io.mixeway.db.entity.User;
import io.mixeway.domain.exceptions.NotValidRoleException;
import io.mixeway.domain.service.settings.GetSettingsService;
import io.mixeway.domain.service.settings.UpdateSettingsService;
import io.mixeway.domain.service.user.EditUserService;
import io.mixeway.domain.service.user.FindUserService;
import io.mixeway.domain.service.user.GetOrCreateUserService;
import io.mixeway.jwt.JwtUserDetailsService;
import io.mixeway.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.social.connect.Connection;
import org.springframework.social.facebook.api.Facebook;
import org.springframework.social.facebook.connect.FacebookConnectionFactory;
import org.springframework.social.github.api.GitHub;
import org.springframework.social.github.api.GitHubUserProfile;
import org.springframework.social.github.connect.GitHubConnectionFactory;
import org.springframework.social.oauth2.AccessGrant;
import org.springframework.social.oauth2.OAuth2Operations;
import org.springframework.social.oauth2.OAuth2Parameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Log4j2
public class AuthService {

    @Value("${facebook.client.id}")
    String facebookClientId;
    @Value("${facebook.secret}")
    String facebookSecret;
    @Value("${github.client.id}")
    String gitHubClientId;
    @Value("${github.secret}")
    String gitHubSecret;
    @Value("${keycloak.realm}")
    private String keycloakRealm;
    @Value("${frontend.url}")
    private String frontendUrl;
    private boolean isFacebookEnabled = false;
    private boolean isKeycloakEnabled = false;
    private boolean isGitHubEnabled = false;
    private GitHubConnectionFactory gitHubFactory;
    private FacebookConnectionFactory facebookFactory;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtUserDetailsService userDetailsService;
    private final JwtUtils jwtUtils;
    private final FindUserService findUserService;
    private final EditUserService editUserService;
    private final UpdateSettingsService updateSettingsService;
    private final GetSettingsService getSettingsService;
    private final GetOrCreateUserService getOrCreateUserService;



    @PostConstruct
    public void init(){
        if (StringUtils.isNotBlank(gitHubClientId) && StringUtils.isNotBlank(gitHubSecret)){
            gitHubFactory = new GitHubConnectionFactory(gitHubClientId, gitHubSecret);
            isGitHubEnabled = true;
        }
        if (StringUtils.isNotBlank(facebookClientId) && StringUtils.isNotBlank(facebookSecret)){
            facebookFactory = new FacebookConnectionFactory(facebookClientId, facebookClientId);
            isFacebookEnabled = true;
        }
        if (!keycloakRealm.equals("dummy")){
            isKeycloakEnabled = true;
        }
    }
    

    public void generateJWTTokenForUser(String commonName, HttpServletResponse httpServletResponse) throws IOException {

        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(commonName);
        final String token = jwtUtils.generateToken(userDetails);
        Optional<User> user = findUserService.findByCommonName(commonName);
        if (user.isPresent()) {
            Cookie role = new Cookie("role", user.get().getPermisions());
            role.setPath("/");
            role.setMaxAge(3600);
            Cookie jwt = new Cookie("token", token);
            jwt.setPath("/");
            jwt.setMaxAge(3600);
            jwt.setSecure(true);
            jwt.setHttpOnly(true);
            log.info("User is successfuly logged {}", commonName);
            editUserService.increaseLogins(user.get());
            httpServletResponse.addCookie(jwt);
            httpServletResponse.addCookie(role);
            httpServletResponse.setHeader("Location", "/pages/dashboard");
            httpServletResponse.setStatus(302);
            httpServletResponse.flushBuffer();
        }
    }


    public void processPasswordAuth(HttpServletResponse httpServletResponse, PasswordAuthModel passwordAuthModel) throws IOException {
        try {
            Optional<User> user = findUserService.findEnabledByUsername(passwordAuthModel.getUsername());
            if (user.isPresent() && user.get().getEnabled()) {
                if (bCryptPasswordEncoder.matches(passwordAuthModel.getPassword(), user.get().getPassword())) {
                    final UserDetails userDetails = userDetailsService
                            .loadUserByUsername(user.get().getUsername());
                    final String token = jwtUtils.generateToken(userDetails);
                    Cookie role = new Cookie("role", user.get().getPermisions());
                    role.setPath("/");
                    role.setMaxAge(3600);
                    Cookie jwt = new Cookie("token", token);
                    jwt.setPath("/");
                    jwt.setMaxAge(3600);
                    jwt.setSecure(true);
                    jwt.setHttpOnly(true);
                    log.info("User is successfuly logged {}", user.get().getUsername());
                    editUserService.increaseLogins(user.get());
                    httpServletResponse.addCookie(jwt);
                    httpServletResponse.addCookie(role);
                    httpServletResponse.flushBuffer();
                } else {
                    editUserService.increaseFailedLogins(user.get());
                    httpServletResponse.setHeader("Location", "/auth/login?error=pass");
                    httpServletResponse.setStatus(302);
                    httpServletResponse.flushBuffer();
                }

            } else {
                httpServletResponse.setHeader("Location", "/auth/login?error=pass");
                httpServletResponse.setStatus(302);
                httpServletResponse.flushBuffer();
            }
        } catch (Exception e){
            httpServletResponse.setHeader("Location", "/auth/login?error=pass");
            httpServletResponse.setStatus(302);
            httpServletResponse.flushBuffer();
        }
    }

    public ResponseEntity<Status> initialize(Password password) throws NotValidRoleException {
        Optional<User> user = findUserService.findByUsername(Constants.ADMIN_USERNAME);
        Settings settings = getSettingsService.getSettings();
        if (user.isPresent() && settings.getInitialized()){
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        } else if ( user.isPresent()){
            editUserService.changePassword(user.get(), password);
            updateSettingsService.initialize(settings);

            return new ResponseEntity<>(HttpStatus.OK);
        } else{
            UserModel userModel = UserModel.builder()
                    .userCN(Constants.ADMIN_USERNAME)
                    .userUsername(Constants.ADMIN_USERNAME)
                    .userPassword(password.getPassword())
                    .userRole(Constants.ROLE_ADMIN).build();
            getOrCreateUserService.getOrCreateUser(userModel);
            user = findUserService.findByUsername(Constants.ADMIN_USERNAME);
            if (user.isPresent() && user.get().getPassword()!=null)
                updateSettingsService.initialize(settings);
            return new ResponseEntity<>(HttpStatus.OK);
        }
    }

    public ResponseEntity<StatusEntity> getStatus() {
        Settings settings = getSettingsService.getSettings();
        return new ResponseEntity<>(
                StatusEntity.builder()
                        .facebook(isFacebookEnabled)
                        .gitHub(isGitHubEnabled)
                        .keycloak(isKeycloakEnabled)
                        .initialized(settings.getInitialized())
                        .password(settings.getPasswordAuth())
                        .cert(settings.getCertificateAuth())
                        .build()
                , HttpStatus.OK);

    }

    public ResponseEntity<StatusEntity> getStatus2() {
        //this.openVasSocketClient.processRequest(null,null,null);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    public void proceedWithSocialLogin(String email, HttpServletResponse httpServletResponse) throws IOException, NotValidRoleException {
        User user = getUserByUsername(email);
        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(user.getUsername());
        final String token = jwtUtils.generateToken(userDetails);
        Cookie role = new Cookie("role", user.getPermisions());
        role.setPath("/");
        role.setMaxAge(3600);
        Cookie jwt = new Cookie("token", token);
        jwt.setPath("/");
        jwt.setMaxAge(3600);
        jwt.setSecure(true);
        jwt.setHttpOnly(true);
        log.info("User is successfuly logged {}", user.getUsername());
        editUserService.increaseLogins(user);
        httpServletResponse.addCookie(jwt);
        httpServletResponse.addCookie(role);
        httpServletResponse.setHeader("Location", frontendUrl + "/pages/dashboard");
        httpServletResponse.setStatus(302);
        httpServletResponse.flushBuffer();
    }

    private User getUserByUsername(String email) throws NotValidRoleException {
        Optional<User> user = findUserService.findByUsername(email);
        if (user.isPresent()){
            return user.get();
        } else {
            UserModel userModel = UserModel.builder()
                    .userCN(email)
                    .userUsername(email)
                    .userRole(Constants.ADMIN_USERNAME)
                    .userRole(Constants.ROLE_USER).build();
            User userToCreate = getOrCreateUserService.getOrCreateUser(userModel);
            log.info("Created user - {}", email);
            return userToCreate;
        }
    }

    public void processFbLogin(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        OAuth2Operations operations = facebookFactory.getOAuthOperations();
        OAuth2Parameters params = new OAuth2Parameters();

        params.setRedirectUri(httpServletRequest.getRequestURL() + "/forward");
        params.setScope("profile email");

        String url = operations.buildAuthenticateUrl(params);
        httpServletResponse.setHeader("Location", url);
        httpServletResponse.setStatus(302);
        httpServletResponse.flushBuffer();
    }

    public void processGitHubLogin(HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) throws IOException {
        OAuth2Operations operations = gitHubFactory.getOAuthOperations();
        OAuth2Parameters params = new OAuth2Parameters();

        params.setRedirectUri(httpServletRequest.getRequestURL() + "/forward");
        gitHubFactory.setScope("user:email");
        params.setScope("user:email");

        String url = operations.buildAuthenticateUrl(params);
        httpServletResponse.setHeader("Location", url);
        httpServletResponse.setStatus(302);
        httpServletResponse.flushBuffer();
    }

    public void authenticateFBUser(String authorizationCode, HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) throws IOException, NotValidRoleException {
        OAuth2Operations operations = facebookFactory.getOAuthOperations();


        AccessGrant accessToken = operations.exchangeForAccess(authorizationCode, httpServletRequest.getRequestURL()+"" ,
                null);

        Connection<Facebook> connection = facebookFactory.createConnection(accessToken);
        Facebook facebook = connection.getApi();
        String[] fields = {"email"};
        org.springframework.social.facebook.api.User userProfile = facebook.fetchObject("me", org.springframework.social.facebook.api.User.class, fields);
        proceedWithSocialLogin(userProfile.getEmail(), httpServletResponse);
    }


    public void authenticateGitHubUser(String authorizationCode, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, NotValidRoleException {
        OAuth2Operations operations = gitHubFactory.getOAuthOperations();
        AccessGrant accessToken = operations.exchangeForAccess(authorizationCode, httpServletRequest.getRequestURL()+"" ,
                null);

        Connection<GitHub> connection = gitHubFactory.createConnection(accessToken);
        GitHub github = connection.getApi();
        GitHubUserProfile profile = github.userOperations().getUserProfile();

        proceedWithSocialLogin(profile.getUsername(), httpServletResponse);
    }

    public void authUsingKeycloak(FirewalledRequest request, HttpServletResponse httpServletResponse) throws IOException, NotValidRoleException {
        KeycloakPrincipal principal=(KeycloakPrincipal) request.getUserPrincipal();
        KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
        AccessToken accessToken = session.getToken();
        proceedWithSocialLogin( accessToken.getEmail(), httpServletResponse);
    }
}
