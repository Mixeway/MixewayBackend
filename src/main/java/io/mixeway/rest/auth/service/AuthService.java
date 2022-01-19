package io.mixeway.rest.auth.service;

import io.mixeway.config.Constants;
import io.mixeway.rest.auth.model.StatusEntity;
import io.mixeway.rest.model.PasswordAuthModel;
import io.mixeway.rest.utils.JwtUserDetailsService;
import io.mixeway.rest.utils.JwtUtils;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.rest.model.Password;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.List;
import java.util.Optional;

@Service
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
    private final UserRepository userRepository;
    private final SettingsRepository settingsRepository;
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    AuthService(BCryptPasswordEncoder bCryptPasswordEncoder, JwtUserDetailsService jwtUserDetailsService,
                JwtUtils jwtUtils, UserRepository userRepository, SettingsRepository settingsRepository
                ) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.jwtUtils = jwtUtils;
        this.userDetailsService = jwtUserDetailsService;
        this.userRepository = userRepository;
        this.settingsRepository = settingsRepository;
    }
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
        Optional<User> user = userRepository.findByCommonName(commonName);
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
            user.get().setLogins(user.get().getLogins() + 1);
            userRepository.save(user.get());
            httpServletResponse.addCookie(jwt);
            httpServletResponse.addCookie(role);
            httpServletResponse.setHeader("Location", "/pages/dashboard");
            httpServletResponse.setStatus(302);
            httpServletResponse.flushBuffer();
        }
    }


    public void processPasswordAuth(HttpServletResponse httpServletResponse, PasswordAuthModel passwordAuthModel) throws IOException {
        try {
            Optional<User> user = userRepository.findByUsernameAndEnabled(passwordAuthModel.getUsername(), true);
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
                    user.get().setLogins(user.get().getLogins()+1);
                    userRepository.save(user.get());
                    httpServletResponse.addCookie(jwt);
                    httpServletResponse.addCookie(role);
                    httpServletResponse.flushBuffer();
                } else {
                    user.get().setFailedLogins(user.get().getFailedLogins()+1);
                    if (user.get().getFailedLogins() > 5)
                        user.get().setEnabled(false);
                    userRepository.save(user.get());
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

    public ResponseEntity initialize(Password password) {
        Optional<User> user = userRepository.findByUsername("admin");
        List<Settings> settings = settingsRepository.findAll();
        if (user.isPresent() && settings.get(0).getInitialized()){
            return new ResponseEntity(HttpStatus.EXPECTATION_FAILED);
        } else if ( user.isPresent()){
           User admin = user.get();
            admin.setPassword(bCryptPasswordEncoder.encode(password.getPassword()));
            userRepository.save(admin);
            Settings s = settings.get(0);
            s.setInitialized(true);
            settingsRepository.save(s);
            return new ResponseEntity(HttpStatus.OK);
        } else{
            User admin = new User();
            admin.setUsername("admin");
            admin.setCommonName("admin");
            admin.setPermisions("ROLE_ADMIN");
            admin.setEnabled(true);
            admin.setLogins(0);
            admin.setFailedLogins(0);
            admin.setPassword(bCryptPasswordEncoder.encode(password.getPassword()));
            userRepository.save(admin);
            Settings s = settings.get(0);
            s.setInitialized(true);
            settingsRepository.save(s);
            return new ResponseEntity(HttpStatus.OK);
        }
    }

    public ResponseEntity<StatusEntity> getStatus() {
        Settings settings = settingsRepository.findAll().stream().findFirst().orElse(null);
        assert settings != null;
        return new ResponseEntity<>(new StatusEntity(settings.getInitialized(), settings.getCertificateAuth(),settings.getPasswordAuth(), isFacebookEnabled, isGitHubEnabled, isKeycloakEnabled), HttpStatus.OK);

    }

    public ResponseEntity<StatusEntity> getStatus2() {
        //this.openVasSocketClient.processRequest(null,null,null);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    public void proceedWithSocialLogin(String email, HttpServletResponse httpServletResponse) throws IOException {
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
        user.setLogins(user.getLogins()+1);
        userRepository.save(user);
        httpServletResponse.addCookie(jwt);
        httpServletResponse.addCookie(role);
        httpServletResponse.setHeader("Location", frontendUrl + "/pages/dashboard");
        httpServletResponse.setStatus(302);
        httpServletResponse.flushBuffer();
    }

    private User getUserByUsername(String email) {
        Optional<User> user = userRepository.findByUsername(email);
        if (user.isPresent()){
            return user.get();
        } else {
            User userToCreate = new User();
            userToCreate.setUsername(email);
            userToCreate.setCommonName(email);
            userToCreate.setEnabled(true);
            userToCreate.setPermisions(Constants.ROLE_USER);
            log.info("Created user - {}", email);
            return userRepository.save(userToCreate);
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

    public void authenticateFBUser(String authorizationCode, HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) throws IOException {
        OAuth2Operations operations = facebookFactory.getOAuthOperations();


        AccessGrant accessToken = operations.exchangeForAccess(authorizationCode, httpServletRequest.getRequestURL()+"" ,
                null);

        Connection<Facebook> connection = facebookFactory.createConnection(accessToken);
        Facebook facebook = connection.getApi();
        String[] fields = {"email"};
        org.springframework.social.facebook.api.User userProfile = facebook.fetchObject("me", org.springframework.social.facebook.api.User.class, fields);
        proceedWithSocialLogin(userProfile.getEmail(), httpServletResponse);
    }


    public void authenticateGitHubUser(String authorizationCode, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        OAuth2Operations operations = gitHubFactory.getOAuthOperations();
        AccessGrant accessToken = operations.exchangeForAccess(authorizationCode, httpServletRequest.getRequestURL()+"" ,
                null);

        Connection<GitHub> connection = gitHubFactory.createConnection(accessToken);
        GitHub github = connection.getApi();
        GitHubUserProfile profile = github.userOperations().getUserProfile();

        proceedWithSocialLogin(profile.getUsername(), httpServletResponse);
    }

    public void authUsingKeycloak(FirewalledRequest request, HttpServletResponse httpServletResponse) throws IOException {
        KeycloakPrincipal principal=(KeycloakPrincipal) request.getUserPrincipal();
        KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
        AccessToken accessToken = session.getToken();
        proceedWithSocialLogin( accessToken.getEmail(), httpServletResponse);
    }
}
