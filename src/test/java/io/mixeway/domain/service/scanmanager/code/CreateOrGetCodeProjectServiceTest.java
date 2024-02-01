package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeProjectBranchRepository;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
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

import java.net.MalformedURLException;
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
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class CreateOrGetCodeProjectServiceTest {
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final CreateProjectService createProjectService;
    private final UserRepository userRepository;
    private final SettingsRepository settingsRepository;
    private final FindProjectService findProjectService;
    private final CodeProjectRepository codeProjectRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CodeProjectBranchRepository codeProjectBranchRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("test_create_cp");
        User userToCreate = new User();
        userToCreate.setUsername("test_create_cp");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void createOrGetCodeProject() throws MalformedURLException {
        Mockito.when(principal.getName()).thenReturn("test_create_cp");
        Project project = getOrCreateProjectService.getProjectId("test_create_cp","test_create_cp",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createOrGetCodeProject("https://test/test_cp","master",principal, project);
        assertNotNull(codeProject);
        Optional<CodeProject> codeProjectFromRepo = codeProjectRepository.findByProjectAndName(project, "test_cp");
        assertTrue(codeProjectFromRepo.isPresent());
        assertEquals(codeProjectFromRepo.get().getId(), codeProject.getId());
    }

    @Test
    void createOrGetCodeProjectWithoutProject() throws MalformedURLException {

        Mockito.when(principal.getName()).thenReturn("test_create_cp");
        CodeProject codeProject1 = createOrGetCodeProjectService.createOrGetCodeProject("https://test/test_cp1","master","test_cp1",principal);
        assertNotNull(codeProject1);
        assertEquals("test_cp1", codeProject1.getProject().getName());
        CodeProject codeProject2 = createOrGetCodeProjectService.createOrGetCodeProject("https://user:password@test/test_cp2","master","test_cp2",principal);
        assertNotNull(codeProject2);
        assertEquals("test_cp2", codeProject2.getProject().getName());
        CodeProject codeProject3 = createOrGetCodeProjectService.createOrGetCodeProject("https://test/test_cp3.git","master","test_cp3",principal);
        assertNotNull(codeProject3);
        assertEquals("test_cp3", codeProject3.getProject().getName());

        CodeProject codeProject4 = createOrGetCodeProjectService.createOrGetCodeProject("https://user:passwrd@test/test_cp4.git","master","test_cp3",principal);
        assertNotNull(codeProject4);
        assertEquals("test_cp4", codeProject4.getProject().getName());
        codeProject4 = createOrGetCodeProjectService.createOrGetCodeProject("https://user:passwrd@test/test_cp4.git","master","test_cp4",principal);
        assertNotNull(codeProject4);
        assertEquals("test_cp4", codeProject4.getProject().getName());
    }



    @Test
    void testCreateCodeProject() {

        Mockito.when(principal.getName()).thenReturn("test_create_cp");
        Project project = getOrCreateProjectService.getProjectId("test_create_cp","test_create_cp",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"test_name_x","master");
        assertNotNull(codeProject);

    }

    @Test
    void testCreateOrGetCodeProject() {
        Mockito.when(principal.getName()).thenReturn("test_create_cp");
        Project project = getOrCreateProjectService.getProjectId("test_create_cp2","test_create_cp2",principal);
        CodeScanRequestModel codeScanRequestModel = new CodeScanRequestModel();
        codeScanRequestModel.setRepoUrl("https://test.url");
        codeScanRequestModel.setBranch("master");
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(codeScanRequestModel, project);
        assertNotNull(codeProject);
        assertEquals("https://test.url",codeProject.getRepoUrl());
        assertEquals("master", codeProject.getBranch());
    }

    @Test
    void testCreateOrGetCodeProject1() {
        Mockito.when(principal.getName()).thenReturn("test_create_cp");
        Project project = getOrCreateProjectService.getProjectId("test_create_cp3","test_create_cp3",principal);

        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject("https://repo.url","new_repo","master",principal, project);
        assertNotNull(codeProject);
        assertEquals("https://repo.url",codeProject.getRepoUrl());
        assertEquals("master", codeProject.getBranch());
    }
}