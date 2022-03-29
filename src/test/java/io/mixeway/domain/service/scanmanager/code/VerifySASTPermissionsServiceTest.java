package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.MalformedURLException;
import java.security.Principal;
import java.util.List;
import java.util.Optional;


/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class VerifySASTPermissionsServiceTest {

    private final VerifySASTPermissionsService verifySASTPermissionsService;
    private final CreateProjectService createProjectService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final ProjectRepository projectRepository;
    private final UserRepository userRepository;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final SettingsRepository settingsRepository;

    @BeforeEach
    private void prepareDB() throws MalformedURLException {
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getName()).thenReturn("sast_verify_tester");
        Optional<List<Project>> project = projectRepository.findByName("sast_verify_name");
        Settings settings = settingsRepository.findAll().get(0);
        settings.setMasterApiKey("test");
        settingsRepository.save(settings);
        if (project.isPresent() && project.get().size()==0) {
            User user = new User();
            user.setUsername("sast_verify_tester");
            user.setPermisions("ROLE_ADMIN");
            userRepository.save(user);
            Project projectToCreate = createProjectService.createProject("sast_verify_name","sast_verify_name",principal);
            createOrGetCodeProjectService.createOrGetCodeProject("https://test/sast_verify_name", "sast_verify_project", principal,projectToCreate);
        }
    }


}