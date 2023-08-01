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
import org.springframework.test.annotation.DirtiesContext;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GetProjectsServiceTest {
    private final ProjectRepository projectRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final SettingsRepository settingsRepository;
    private final UserRepository userRepository;
    private final FindProjectService findProjectService;

    @Mock
    Principal principal;

//    @BeforeAll
//    public void prepare(){
//        Settings settings = settingsRepository.findAll().get(0);
//        settings.setMasterApiKey("test");
//        settingsRepository.save(settings);
//        User user = new User();
//        user.setUsername("get_projects");
//        user.setPermisions("ROLE_ADMIN");
//        userRepository.save(user);
//        Mockito.when(principal.getName()).thenReturn("get_projects");
//        projectRepository.deleteAll();
//    }
//
//    @Test
//    void getProjects() {
//        Mockito.when(principal.getName()).thenReturn("get_projects");
//        for (int i=0; i <5; i++){
//            getOrCreateProjectService.getProjectId("ciid"+i,"project"+i,principal);
//        }
//        List<Project>  projects = projectRepository.findAll();
//        assertTrue(projectRepository.findAll().size() >= 5);
//    }
//
//    @Test
//    void getProject() {
//        Mockito.when(principal.getName()).thenReturn("get_projects");
//        Project project= getOrCreateProjectService.getProjectId("test_get_project","test_get_project",principal);
//        Optional<Project> projectNotExisting = findProjectService.findProjectById(9000L);
//        assertNotNull(project);
//        assertFalse(projectNotExisting.isPresent());
//    }
}