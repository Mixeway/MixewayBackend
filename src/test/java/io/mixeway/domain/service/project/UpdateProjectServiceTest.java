package io.mixeway.domain.service.project;

import io.mixeway.api.dashboard.model.Projects;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.parameters.P;

import java.security.Principal;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UpdateProjectServiceTest {
    private final UpdateProjectService updateProjectService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;

    @Mock
    Principal principal;
    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("update_project");
        User user = new User();
        user.setUsername("update_project");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
    }
    @Test
    void update() {
        Mockito.when(principal.getName()).thenReturn("update_project");
        Project project = getOrCreateProjectService.getProjectId("update_project","update_project",principal);
        Projects projects = new Projects();
        projects.setCiid("updated_ciid");
        projects.setName("updated_name");
        projects.setEnableVulnManage(1);
        projects.setId(project.getId());
        updateProjectService.update(project,projects);
        project = getOrCreateProjectService.getProjectId("updated_ciid","updated_name",principal);
        assertNotNull(project);
        assertTrue(project.isEnableVulnManage());
    }
}