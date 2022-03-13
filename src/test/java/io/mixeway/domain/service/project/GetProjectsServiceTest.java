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

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class GetProjectsServiceTest {
    private final ProjectRepository projectRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final SettingsRepository settingsRepository;
    private final UserRepository userRepository;
    private final GetProjectsService getProjectsService;

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
        projectRepository.deleteAll();
    }

    @Test
    void getProjects() {
        for (int i=0; i <5; i++){
            getOrCreateProjectService.getProjectId("ciid","project"+i,principal);
        }
        assertTrue(projectRepository.findAll().size() >= 5);
    }

    @Test
    void getProject() {
        long id = getOrCreateProjectService.getProjectId("test_get_project","test_get_project",principal);
        Project project = getProjectsService.getProject(id);
        Project projectNotExisting = getProjectsService.getProject(9000L);
        assertNotNull(project);
        assertNull(projectNotExisting);
    }
}