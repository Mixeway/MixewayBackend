package io.mixeway.jwt;

import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class JwtUserDetailsServiceTest {
    private final JwtUserDetailsService jwtUserDetailsService;
    private final UserRepository userRepository;
    private final SettingsRepository settingsRepository;

    @BeforeEach
    public void prepare(){
        Settings settings = settingsRepository.findAll().get(0);
        settings.setMasterApiKey("master_key");
        settingsRepository.save(settings);
        Optional<User> testUser = userRepository.findByUsername("jwt_admin");
        if (!testUser.isPresent()) {
            User user = new User();
            user.setUsername("jwt_admin");
            user.setPermisions("ROLE_ADMIN");
            userRepository.save(user);
            User user2 = new User();
            user2.setUsername("jwt_user");
            user2.setPermisions("ROLE_USER");
            user2.setApiKey("user_key");
            userRepository.save(user2);
        }
    }

    @Test
    void loadUserByUsername() {
        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername("jwt_admin");
        assertEquals("jwt_admin", userDetails.getUsername());
        assertTrue(userDetails.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN")));
        UserDetails userDetails2 = jwtUserDetailsService.loadUserByUsername("jwt_user");
        assertEquals("jwt_user", userDetails2.getUsername());
        assertTrue(userDetails2.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER")));
        assertFalse(userDetails2.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void loadUserByApiKeyAndRequestUri() {
        UserDetails masterUser = jwtUserDetailsService.loadUserByApiKeyAndRequestUri("master_key", null);
        assertEquals("admin", masterUser.getUsername());
        assertTrue(masterUser.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN")));

        UserDetails user = jwtUserDetailsService.loadUserByApiKeyAndRequestUri("user_key", null);
        assertEquals("jwt_user", user.getUsername());
        assertTrue(user.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER")));
        assertFalse(user.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN")));
        assertThrows(UsernameNotFoundException.class, () -> {
            jwtUserDetailsService.loadUserByApiKeyAndRequestUri("not_existing_key", null);
        });
    }
}