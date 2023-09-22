package io.mixeway.scanmanager.service.opensource;

import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.config.Constants;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.projectvulnerability.DeleteProjectVulnerabilityService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.dependencytrack.apiclient.DependencyTrackApiClient;
import io.mixeway.scanmanager.model.Projects;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.utils.ScannerType;
import io.mixeway.utils.Status;
import io.mixeway.utils.VulnerabilityModel;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class OpenSourceScanServiceTest {
    private final OpenSourceScanService openSourceScanService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final ScannerTypeRepository scannerTypeRepository;
    private final ScannerRepository scannerRepository;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final VulnTemplate vulnTemplate;
    private final DeleteProjectVulnerabilityService deleteProjectVulnerabilityService;
    @MockBean
    GlobalScheduler globalScheduler;

    @Mock
    Principal principal;

    @MockBean
    DependencyTrackApiClient dependencyTrackApiClient;

    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("admin_os_scan_service");
        User user = new User();
        user.setUsername("admin_os_scan_service");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
        Project project = getOrCreateProjectService.getProjectId("os_scan_service","os_scan_service",principal);
        Scanner scanner = new Scanner();
        scanner.setStatus(true);
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        scannerRepository.save(scanner);
    }


    @Test
    void getOpenSourceScannerConfiguration() {
        Mockito.when(principal.getName()).thenReturn("admin_os_scan_service");
        Project project = getOrCreateProjectService.getProjectId("os_scan_service_config","os_scan_service_config",principal);
        ResponseEntity<OpenSourceConfig> statusResponseEntity = openSourceScanService.getOpenSourceScannerConfiguration(project.getId(),null,"randomname",principal);
        assertEquals(HttpStatus.PRECONDITION_FAILED, statusResponseEntity.getStatusCode());
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"os_scan_service_config","master");
        statusResponseEntity = openSourceScanService.getOpenSourceScannerConfiguration(project.getId(),null,"os_scan_service_config",principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());

    }

    @Test
    void loadVulnerabilities() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("admin_os_scan_service");
        Project project = getOrCreateProjectService.getProjectId("os_scan_service","os_scan_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"code_project_test_os","master");
        for (int i =0 ; i < 15 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setCodeProject(codeProject);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_OPENSOURCE);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }
        Mockito.doNothing().when(dependencyTrackApiClient).loadVulnerabilities(Mockito.any(CodeProject.class),Mockito.any(CodeProjectBranch.class));
        Mockito.when(dependencyTrackApiClient.canProcessRequest(Mockito.any(CodeProject.class))).thenReturn(true);
        openSourceScanService.loadVulnerabilities(codeProject);
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject);
        assertEquals(15, projectVulnerabilities.size());
    }

    @Test
    void getOpenSourceProjectFromScanner() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        List<Projects> projects = new ArrayList<>();
        for (int i=0; i<10; i++){
            Projects projects1 = new Projects();
            projects1.setName("test"+i);
            projects1.setUuid(UUID.randomUUID().toString());
            projects.add(projects1);
        }
        Mockito.when(dependencyTrackApiClient.canProcessRequest(Mockito.any(CodeProject.class))).thenReturn(true);
        Mockito.when(dependencyTrackApiClient.getProjects()).thenReturn(projects);
        List<Projects> projectsList = openSourceScanService.getOpenSourceProjectFromScanner();
        assertNotNull(projectsList);
        assertEquals(10, projects.size());

    }

    @Test
    void createProjectOnOpenSourceScanner() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Mockito.when(dependencyTrackApiClient.canProcessRequest()).thenReturn(true);
        Mockito.when(dependencyTrackApiClient.createProject(Mockito.any(CodeProject.class))).thenReturn(true);

        boolean status = openSourceScanService.createProjectOnOpenSourceScanner(new CodeProject());
        assertTrue(status);
    }

    @Test
    void loadVulnsFromCICDToCodeProject() {
        Mockito.when(principal.getName()).thenReturn("admin_os_scan_service");
        Project project = getOrCreateProjectService.getProjectId("os_scan_service","os_scan_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"code_project_test_os2","master");
        List<VulnerabilityModel> vulnerabilityModels = new ArrayList<>();
        for(int i=0; i<15; i++){
            vulnerabilityModels.add(VulnerabilityModel.builder()
                    .filename("file"+i)
                    .name("vuln_name"+i)
                    .scannerType(ScannerType.OPENSOURCE)
                    .severity("Critical")
                    .packageName("test-package")
                    .packageVersion(""+i)
                    .description("test")
                    .build());
        }
        openSourceScanService.loadVulnsFromCICDToCodeProject(codeProject, vulnerabilityModels);
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject);
        assertEquals(15, projectVulnerabilities.size());

    }

    @Test
    @Order(1)
    void removeOldVulns() {
        Project project = getOrCreateProjectService.getProjectId("os_scan_service1","os_scan_service1",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"code_project_test_os3","master");
        for (int i =0 ; i < 15 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setCodeProject(codeProject);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_OPENSOURCE);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }
        deleteProjectVulnerabilityService.deleteRemovedVulnerabilitiesInCodeProject(codeProject);
        codeProject = createOrGetCodeProjectService.createCodeProject(project,"code_project_test_os3","master");
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject);
        assertEquals(0, projectVulnerabilities.size());

    }
}