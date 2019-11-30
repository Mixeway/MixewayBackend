package io.mixeway.rest.auth.service;

import io.mixeway.plugins.infrastructurescan.openvas.apiclient.OpenVasSocketHelper;
import io.mixeway.rest.auth.model.StatusEntity;
import io.mixeway.rest.model.PasswordAuthModel;
import io.mixeway.rest.utils.JwtUserDetailsService;
import io.mixeway.rest.utils.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.rest.model.Password;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

@Service
public class AuthService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtUserDetailsService userDetailsService;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final SettingsRepository settingsRepository;
    private OpenVasSocketHelper openVasSocketClient = new OpenVasSocketHelper(new URI("wss://localhost:9390"));

    @Autowired
    AuthService(BCryptPasswordEncoder bCryptPasswordEncoder, JwtUserDetailsService jwtUserDetailsService,
                JwtUtils jwtUtils, UserRepository userRepository, SettingsRepository settingsRepository
                ) throws URISyntaxException {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.jwtUtils = jwtUtils;
        this.userDetailsService = jwtUserDetailsService;
        this.userRepository = userRepository;
        this.settingsRepository = settingsRepository;
    }
    
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);


    public void generateJWTTokenForUser(String commonName, HttpServletResponse httpServletResponse) throws IOException {

        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(commonName);
        final String token = jwtUtils.generateToken(userDetails);
        Cookie role = new Cookie("role", userRepository.findByCommonName(commonName).get().getPermisions());
        role.setPath("/");
        role.setMaxAge(3600);
        Cookie jwt = new Cookie("token",token);
        jwt.setPath("/");
        jwt.setMaxAge(3600);
        jwt.setSecure(true);
        jwt.setHttpOnly(true);
        log.info("User is successfuly logged {}",commonName);
        Optional<User> user = userRepository.findByCommonName(commonName);
        if (user.isPresent()){
            user.get().setLogins(user.get().getLogins()+1);
            userRepository.save(user.get());
        }
        httpServletResponse.addCookie(jwt);
        httpServletResponse.addCookie(role);
        httpServletResponse.setHeader("Location", "/pages/dashboard");
        httpServletResponse.setStatus(302);
        httpServletResponse.flushBuffer();
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
        } else {
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
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        return new ResponseEntity<>(new StatusEntity(settings.getInitialized(), settings.getCertificateAuth(),settings.getPasswordAuth()), HttpStatus.OK);

    }

    public ResponseEntity<StatusEntity> getStatus2() {
        //this.openVasSocketClient.processRequest(null,null,null);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
