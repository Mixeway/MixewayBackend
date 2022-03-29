package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeProjectRepository;
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

import java.net.MalformedURLException;
import java.security.Principal;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class CreateOrGetCodeProjectServiceTest {
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final CreateProjectService createProjectService;
    private final UserRepository userRepository;
    private final SettingsRepository settingsRepository;
    private final FindProjectService findProjectService;
    private final CodeProjectRepository codeProjectRepository;

    @Mock
    Principal principal;

    @BeforeEach
    private void prepareDB() {
        Optional<User> user = userRepository.findByUsername("test_create_cp");
        Settings settings = settingsRepository.findAll().get(0);
        settings.setMasterApiKey("test");
        settingsRepository.save(settings);
        Mockito.when(principal.getName()).thenReturn("test_create_cp");
        if (!user.isPresent()){
            User userToCreate = new User();
            userToCreate.setUsername("test_create_cp");
            userToCreate.setPermisions("ROLE_ADMIN");
            userRepository.save(userToCreate);
            createProjectService.createAndReturnProject("test_create_cp","test_create_cp",principal);

        }
    }

    @Test
    void createOrGetCodeProject() throws MalformedURLException {
        Optional<Project> project = findProjectService.findProjectByCiid("test_create_cp");
        assertTrue(project.isPresent());
        CodeProject codeProject = createOrGetCodeProjectService.createOrGetCodeProject("https://test/test_cp","master",principal, project.get());
        assertNotNull(codeProject);
        Optional<CodeProject> codeProjectFromRepo = codeProjectRepository.findByProjectAndName(project.get(), "test_cp");
        assertTrue(codeProjectFromRepo.isPresent());
        assertEquals(codeProjectFromRepo.get().getId(), codeProject.getId());
    }



    @Test
    void testCreateCodeProject() {
        assertTrue(false);
    }

    @Test
    void testCreateOrGetCodeProject() {
        assertTrue(false);
    }

    @Test
    void testCreateOrGetCodeProject1() {
        assertTrue(false);
    }
}