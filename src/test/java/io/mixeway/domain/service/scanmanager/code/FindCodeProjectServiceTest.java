package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.FindProjectService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class FindCodeProjectServiceTest {
    private final CreateProjectService createProjectService;
    private final UserRepository userRepository;
    private final SettingsRepository settingsRepository;
    private final FindProjectService findProjectService;
    private final FindCodeProjectService findCodeProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;

    @Mock
    Principal principal;

    @BeforeEach
    private void prepareDB() {
        Optional<User> user = userRepository.findByUsername("test_find_cp");
        Settings settings = settingsRepository.findAll().get(0);
        settings.setMasterApiKey("test");
        settingsRepository.save(settings);
        Mockito.when(principal.getName()).thenReturn("test_find_cp");
        if (!user.isPresent()){
            User userToCreate = new User();
            userToCreate.setUsername("test_find_cp");
            userToCreate.setPermisions("ROLE_ADMIN");
            userRepository.save(userToCreate);
            createProjectService.createAndReturnProject("test_find_cp","test_find_cp",principal);

        }
    }

    @Test
    void findRunningCodeProjects() {
        assertTrue(false);
    }

    @Test
    void findById() {
        assertTrue(false);
    }
}