package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
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
class UpdateCodeProjectServiceTest {
    private final UpdateCodeProjectService updateCodeProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;

    @Mock
    Principal principal;
    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("update_cp");
        User user = new User();
        user.setUsername("update_cp");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
    }

    @Test
    void updateCodeProject() {
        Mockito.when(principal.getName()).thenReturn("update_cp");
        Project project = getOrCreateProjectService.getProjectId("update_cp","update_cp", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"update_cp","master");
        CodeScanRequestModel codeScanRequestModel = new CodeScanRequestModel();
        codeScanRequestModel.setRepoUrl("https://repo.url");
        codeScanRequestModel.setBranch("new_branch");
        updateCodeProjectService.updateCodeProject(codeScanRequestModel, codeProject);
        codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"update_cp","master");
        assertEquals("https://repo.url", codeProject.getRepoUrl());

    }

    @Test
    void updateCodeProjectAndPutToQueue() {
        Mockito.when(principal.getName()).thenReturn("update_cp");
        Project project = getOrCreateProjectService.getProjectId("update_cp_2","update_cp_2", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"update_cp_2","master");
        CodeScanRequestModel codeScanRequestModel = new CodeScanRequestModel();
        codeScanRequestModel.setTech("java");
        codeScanRequestModel.setRepoUrl("https://new_repo.url");
        updateCodeProjectService.updateCodeProjectAndPutToQueue(codeScanRequestModel,codeProject);
        codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"update_cp_2","master");
        assertTrue(codeProject.getInQueue());
        assertEquals("https://new_repo.url", codeProject.getRepoUrl());
        assertEquals("java", codeProject.getTechnique());

    }

    @Test
    void putCodeProjectToQueue() {

        Mockito.when(principal.getName()).thenReturn("update_cp");
        Project project = getOrCreateProjectService.getProjectId("update_cp_3","update_cp_3", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"update_cp_3","master");
        updateCodeProjectService.putCodeProjectToQueue(codeProject);
        assertTrue(codeProject.getInQueue());

    }

    @Test
    void removeFromQueue() {
        Mockito.when(principal.getName()).thenReturn("update_cp");
        Project project = getOrCreateProjectService.getProjectId("update_cp_3","update_cp_3", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"update_cp_3","master");
        updateCodeProjectService.putCodeProjectToQueue(codeProject);
        assertTrue(codeProject.getInQueue());
        updateCodeProjectService.removeFromQueue(codeProject);
        assertFalse(codeProject.getInQueue());
    }
}