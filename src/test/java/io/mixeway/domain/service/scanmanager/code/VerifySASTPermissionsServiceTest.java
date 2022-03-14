package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import lombok.RequiredArgsConstructor;
import org.junit.Before;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class VerifySASTPermissionsServiceTest {

    private final VerifySASTPermissionsService verifySASTPermissionsService;
    private final CreateOrGetCodeGroupService createOrGetCodeGroupService;
    private final CreateProjectService createProjectService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final ProjectRepository projectRepository;
    private final UserRepository userRepository;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final CodeGroupRepository codeGroupRepository;
    private final SettingsRepository settingsRepository;

    @BeforeEach
    private void prepareDB(){
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
            CodeGroup codeGroup = createOrGetCodeGroupService
                    .createOrGetCodeGroupService(principal, "sast_verify_permissions", "http://dummy.com/git", projectToCreate, "", "", "");
            createOrGetCodeProjectService.createOrGetCodeProject(codeGroup, "sast_verify_project", "master");
        }
    }

    @Test
    void verifyIfCodeGroupIsPresent() {
        List<User> users = userRepository.findAll();
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getName()).thenReturn("sast_verify_tester");
        Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName( getOrCreateProjectService.getProjectId("sast_verify_name", "sast_verify_name", principal), "sast_verify_permissions");
        assertEquals(true, verifySASTPermissionsService.verifyIfCodeGroupIsPresent(codeGroup, "sast_verify_project", true).getValid());
        assertEquals(false, verifySASTPermissionsService.verifyIfCodeGroupIsPresent(codeGroup, "sast_verify_project", false).getValid());
        assertEquals(false, verifySASTPermissionsService.verifyIfCodeGroupIsPresent(codeGroup, "sast_verify_project2", false).getValid());
    }

    @Test
    void verifyIfCodeGroupIsNotPresent() {
        assertFalse(verifySASTPermissionsService.verifyIfCodeGroupIsNotPresent().getValid());
    }

    @Test
    void returnNotValidRequestWithGroup() {
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getName()).thenReturn("sast_verify_tester");
        Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName( getOrCreateProjectService.getProjectId("sast_verify_name", "sast_verify_name", principal), "sast_verify_permissions");
        assertFalse(verifySASTPermissionsService.returnNotValidRequestWithGroup(codeGroup).getValid());
        assertEquals(codeGroup.get(), verifySASTPermissionsService.returnNotValidRequestWithGroup(codeGroup).getCg());
    }

    @Test
    void returnNotValidRequestWithLog() {
        assertFalse(verifySASTPermissionsService.returnNotValidRequestWithLog("group", " message").getValid());
    }
}