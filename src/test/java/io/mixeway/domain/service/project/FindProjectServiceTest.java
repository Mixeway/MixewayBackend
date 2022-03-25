package io.mixeway.domain.service.project;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
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
class FindProjectServiceTest {

    private final FindProjectService findProjectService;
    private final CreateProjectService createProjectService;
    private final ProjectRepository projectRepository;
    private final SettingsRepository settingsRepository;
    private final UserRepository userRepository;

    @Mock
    Principal principal;

    @BeforeEach
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
    void findProjectIdByCiid() {
        Project project = createProjectService.createProject("testProject", "findProjectIdByCiid_empty", principal);
        assertEquals(Optional.of(project), findProjectService.findProjectByCiid("findProjectIdByCiid_empty"));
        assertEquals(Optional.empty(), findProjectService.findProjectByCiid("anotherEmpty"));
    }

    @Test
    void findProjectIdByName() {
        Project project = createProjectService.createProject("findProjectIdByName_testProject2", "empty", principal);
        assertEquals(Optional.of(project), findProjectService.findProjectByName("findProjectIdByName_testProject2"));
        assertEquals(Optional.empty(), findProjectService.findProjectByName("not found name"));
    }

    @Test
    void findProjectsWithAutoCodeScan() {
        assertTrue(false);
    }

    @Test
    void findProjectsWithAutoWebAppScan() {
        assertTrue(false);
    }

    @Test
    void findProjectsWithAutoInfraScan() {
        assertTrue(false);
    }

    @Test
    void findAll() {
        assertTrue(false);
    }
}