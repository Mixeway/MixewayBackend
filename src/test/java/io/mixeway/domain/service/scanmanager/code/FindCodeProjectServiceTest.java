package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
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
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FindCodeProjectServiceTest {
    private final CreateProjectService createProjectService;
    private final UserRepository userRepository;
    private final SettingsRepository settingsRepository;
    private final FindProjectService findProjectService;
    private final FindCodeProjectService findCodeProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final UpdateCodeProjectService updateCodeProjectService;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("test_find_cp");
        User userToCreate = new User();
        userToCreate.setUsername("test_find_cp");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void findRunningCodeProjects() {
        Mockito.when(principal.getName()).thenReturn("test_find_cp");
        Project project = getOrCreateProjectService.getProjectId("test_find_cp","test_find_cp",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"test_find_cp","master");
        updateCodeProjectService.startScan(codeProject);
        assertTrue(findCodeProjectService.findRunningCodeProjects().size() > 0);
    }

    @Test
    void findById() {
        Mockito.when(principal.getName()).thenReturn("test_find_cp");
        Project project = getOrCreateProjectService.getProjectId("test_find_cp2","test_find_cp2",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"test_find_cp2","master");
        Optional<CodeProject> foundCodeProject = findCodeProjectService.findById(codeProject.getId());
        assertTrue(foundCodeProject.isPresent());
        Optional<CodeProject> foundCodeProject2 = findCodeProjectService.findById(666L);
        assertFalse(foundCodeProject2.isPresent());
    }
}