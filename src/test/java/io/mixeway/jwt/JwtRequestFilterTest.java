package io.mixeway.jwt;

import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JwtRequestFilterTest {


    private final SettingsRepository settingsRepository;
    private final UserRepository userRepository;
    private final JwtRequestFilter jwtRequestFilter;

    @BeforeAll
    public void prepare(){
        Settings settings = settingsRepository.findAll().get(0);
        settings.setMasterApiKey("master_key");
        settingsRepository.save(settings);
        if (userRepository.findAll().size() == 0 ) {
            User user2 = new User();
            user2.setUsername("jwt_user2");
            user2.setPermisions("ROLE_USER");
            user2.setApiKey("user_key");
            userRepository.save(user2);
        }
    }

    @Test
    void doFilterInternal() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        MockFilterChain mockFilterChain = new MockFilterChain();
        request.setRequestURI("/api/v2/testing");
        request.addHeader("apikey","user_key");
        jwtRequestFilter.doFilterInternal(request, httpServletResponse, mockFilterChain);
    }
}