package io.mixeway.domain.service.vulnmanager;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.CreateProjectService;
import lombok.AllArgsConstructor;
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

import javax.transaction.Transactional;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class VulnTemplateTest {

    private final VulnTemplate vulnTemplate;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final CreateProjectService createProjectService;
    private final ProjectRepository projectRepository;
    private final SettingsRepository settingsRepository;
    private final UserRepository userRepository;

    @Mock
    private Principal principal;

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
    }

    @Test
    @Transactional
    void vulnerabilityPersist() {
        Mockito.when(principal.getName()).thenReturn("admin");
        Project project = createProjectService.createProject("project","empty",principal);
        ProjectVulnerability projectVulnerability = new ProjectVulnerability();
        projectVulnerability.setProject(project);
        projectVulnerability.setSeverity("High");
        projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
        projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
        vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        assertEquals(vulnTemplate.projectVulnerabilityRepository.findByProject(project).count(), 1);
    }

    @Test
    @Transactional
    void vulnerabilityPersistList() {
        Mockito.when(principal.getName()).thenReturn("admin");
        Project project = createProjectService.createProject("project2","empty2",principal);
        List<ProjectVulnerability> projectVulns =new ArrayList<>();
        for (int i=0; i<10; i++){
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"+i));
            projectVulns.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(new ArrayList<>(), projectVulns);
        assertEquals(vulnTemplate.projectVulnerabilityRepository.findByProject(project).count(), 10);
    }

}