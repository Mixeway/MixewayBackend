package io.mixeway.domain.service.cioperations;

import io.mixeway.api.protocol.cioperations.InfoScanPerformed;
import io.mixeway.db.entity.CiOperations;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.scanmanager.model.SASTRequestVerify;
import io.mixeway.utils.SecurityGatewayEntry;
import io.mixeway.utils.SecurityQualityGateway;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
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
class CreateCiOperationsServiceTest {
    private final CreateCiOperationsService createCiOperationsService;
    private final UserRepository userRepository;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CiOperationsRepository ciOperationsRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("create_ci_o");
        User userToCreate = new User();
        userToCreate.setUsername("create_ci_o");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void create() {
        Mockito.when(principal.getName()).thenReturn("create_ci_o");
        Project project = getOrCreateProjectService.getProjectId("create_ci_o","create_ci_o",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"ci_cp","master");
        InfoScanPerformed infoScanPerformed = InfoScanPerformed.builder()
                .branch("dev")
                .codeProjectId(codeProject.getId())
                .commitId("sha")
                .build();
        createCiOperationsService.create(codeProject,infoScanPerformed);
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject, "sha");
        assertTrue(ciOperations.isPresent());
        assertEquals(codeProject.getId(), ciOperations.get().getCodeProject().getId());
    }

    @Test
    void testCreate() {
        Mockito.when(principal.getName()).thenReturn("create_ci_o");
        Project project = getOrCreateProjectService.getProjectId("create_ci_o2","create_ci_o2",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"ci_cp2","master");
        SASTRequestVerify sastRequestVerify = SASTRequestVerify.builder()
                .cp(codeProject)
                .valid(true)
                .build();

        createCiOperationsService.create(sastRequestVerify,project,"new_sha");
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject, "new_sha");
        assertTrue(ciOperations.isPresent());
        assertEquals(codeProject.getId(), ciOperations.get().getCodeProject().getId());
    }

    @Test
    void testCreate1() {
        Mockito.when(principal.getName()).thenReturn("create_ci_o");
        Project project = getOrCreateProjectService.getProjectId("create_ci_o3","create_ci_o3",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"ci_cp3","master");
        SecurityGatewayEntry securityGatewayEntry = SecurityGatewayEntry.builder()
                .passed(true)
                .imageHigh(2)
                .sastCritical(2)
                .osCritical(2)
                .webHigh(2)
                .build();
        createCiOperationsService.create(securityGatewayEntry,codeProject, Optional.empty());
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject, "unknown");
        assertTrue(ciOperations.isPresent());
        assertEquals("Ok",ciOperations.get().getResult());
    }
}