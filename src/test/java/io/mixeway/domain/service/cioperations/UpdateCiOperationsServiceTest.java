package io.mixeway.domain.service.cioperations;

import io.mixeway.api.protocol.cioperations.InfoScanPerformed;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.SecurityGatewayRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.securitygateway.UpdateSecurityGatewayService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UpdateCiOperationsServiceTest {
    private final UpdateCiOperationsService updateCiOperationsService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final CreateCiOperationsService createCiOperationsService;
    private final CiOperationsRepository ciOperationsRepository;
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final FindCiOperationsService findCiOperationsService;
    private final CodeProjectRepository codeProjectRepository;
    private final SecurityGatewayRepository securityGatewayRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        SecurityGateway securityGateway = securityGatewayRepository.findAll().stream().findFirst().orElse(null);
        securityGateway.setGrade(false);
        securityGatewayRepository.save(securityGateway);
        Mockito.when(principal.getName()).thenReturn("update_ci");
        User userToCreate = new User();
        userToCreate.setUsername("update_ci");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Project project = getOrCreateProjectService.getProjectId("update_ci", "update_ci", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"update_ci", "master");
        codeProject.setCommitid("commit");
        codeProjectRepository.save(codeProject);
        InfoScanPerformed infoScanPerformed = InfoScanPerformed.builder()
                .commitId("commit")
                .codeProjectId(codeProject.getId())
                .branch("master")
                .build();
        CiOperations ciOperations = createCiOperationsService.create(codeProject, infoScanPerformed);
        ciOperations.setResult("Ok");
        ciOperationsRepository.save(ciOperations);
        for (int i =0 ; i < 5 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setCodeProject(codeProject);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setGrade(1);
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_OPENSOURCE);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }
        for (int i =0 ; i < 5 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setCodeProject(codeProject);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setGrade(1);
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }
    }

    @Test
    void updateCiOperationsForOpenSource() {
        Mockito.when(principal.getName()).thenReturn("update_ci");
        Project project = getOrCreateProjectService.getProjectId("update_ci", "update_ci", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"update_ci", "master");
        updateCiOperationsService.updateCiOperationsForOpenSource(codeProject);
        Optional<CiOperations> ciOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject,"commit");
        assertTrue(ciOperations.isPresent());
        assertTrue(ciOperations.get().getOpenSourceScan());
        assertTrue(ciOperations.get().getOpenSourceHigh() > 0);
    }

    @Test
    void updateCiOperationsForSAST() {

        Mockito.when(principal.getName()).thenReturn("update_ci");
        Project project = getOrCreateProjectService.getProjectId("update_ci", "update_ci", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"update_ci", "master");
        updateCiOperationsService.updateCiOperationsForSAST(codeProject);
        Optional<CiOperations> ciOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject,"commit");
        assertTrue(ciOperations.isPresent());
        assertTrue(ciOperations.get().getSastScan());
        assertTrue(ciOperations.get().getSastHigh() > 0);
    }
}