package io.mixeway.domain.service.project;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CreateProjectServiceTest {
    private final CreateProjectService createProjectService;
    private final ProjectRepository projectRepository;
    private final SettingsRepository settingsRepository;
    private final UserRepository userRepository;
    @Mock
    Principal principal;

    @BeforeAll
    public void prepare(){
        Settings settings = settingsRepository.findAll().get(0);
        settings.setMasterApiKey("test");
        settingsRepository.save(settings);
        if (userRepository.findAll().size() == 0 ) {
            User user = new User();
            user.setUsername("admin");
            user.setPermisions("ROLE_ADMIN");
            userRepository.save(user);
        }
        Mockito.when(principal.getName()).thenReturn("admin");
    }

    @Test
    void createProject() {
        Mockito.when(principal.getName()).thenReturn("admin");
        Project project = createProjectService.createProject("createProject_testProject","empty", principal);
        assertEquals(projectRepository.findByName("createProject_testProject").get().stream().findFirst().get(), project);
    }

    @Test
    void putProject() {
        Mockito.when(principal.getName()).thenReturn("admin");
        assertTrue(createProjectService.putProject("testProject2", "desc", "empty", 1, principal));
        assertEquals(1, projectRepository.findByName("testProject2").get().stream().count());

    }

    @Test
    void createAndReturnProject() {
        Mockito.when(principal.getName()).thenReturn("admin");
        assertNotNull(createProjectService.createAndReturnProject("createProject_testProject2","empty", principal));
    }

}