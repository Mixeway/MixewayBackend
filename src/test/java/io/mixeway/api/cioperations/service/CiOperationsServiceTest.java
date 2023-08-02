package io.mixeway.api.cioperations.service;

import io.mixeway.api.cioperations.model.CIVulnManageResponse;
import io.mixeway.api.cioperations.model.CiResultModel;
import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.api.protocol.cioperations.GetInfoRequest;
import io.mixeway.api.protocol.cioperations.InfoScanPerformed;
import io.mixeway.api.protocol.cioperations.PrepareCIOperation;
import io.mixeway.api.protocol.securitygateway.SecurityGatewayResponse;
import io.mixeway.api.protocol.user.UserModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.cioperations.CreateCiOperationsService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.dependencytrack.apiclient.DependencyTrackApiClient;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.ScannerType;
import io.mixeway.utils.Status;
import io.mixeway.utils.VulnerabilityModel;
import liquibase.pro.packaged.L;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CiOperationsServiceTest {
    private final CiOperationsService ciOperationsService;
    private final UserRepository userRepository;
    private final CiOperationsRepository ciOperationsRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final CreateCiOperationsService createCiOperationsService;
    private final CodeProjectRepository codeProjectRepository;
    private final VulnTemplate vulnTemplate;

    @Mock
    Principal principal;

    @MockBean
    DependencyTrackApiClient dependencyTrackApiClient;

    @MockBean
    GlobalScheduler globalScheduler;

    @MockBean
    NetworkScanScheduler networkScheduler;

    @MockBean
    CodeScheduler codeScheduler;

    @MockBean
    WebAppScheduler webAppScheduler;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        User userToCreate = new User();
        userToCreate.setUsername("cioperations_service");
        userToCreate.setCommonName("cioperations_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"cioperations_service", "master");
        codeProject.setCommitid("old_project");
        codeProject.setInQueue(false);
        codeProjectRepository.save(codeProject);
        InfoScanPerformed infoScanPerformed = InfoScanPerformed.builder()
                .commitId("commit")
                .codeProjectId(codeProject.getId())
                .branch("master")
                .build();
        CiOperations ciOperations = createCiOperationsService.create(codeProject, infoScanPerformed);
        ciOperations.setResult("Ok");
        ciOperationsRepository.save(ciOperations);
    }

    @Test
    void getVulnTrendData() {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        ResponseEntity<List<OverAllVulnTrendChartData>> listResponseEntity = ciOperationsService.getVulnTrendData(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertTrue(Objects.requireNonNull(listResponseEntity.getBody()).size() > 0);
    }

    @Test
    void getResultData() {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        ResponseEntity<CiResultModel> ciResultModelResponseEntity = ciOperationsService.getResultData(principal);
        assertEquals(HttpStatus.OK, ciResultModelResponseEntity.getStatusCode());
        assertNotNull(ciResultModelResponseEntity.getBody());
        assertTrue(ciResultModelResponseEntity.getBody().getOk() > 0);

    }

    @Test
    void getTableData() {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");

        ResponseEntity<List<CiOperations>> listResponseEntity = ciOperationsService.getTableData(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size() > 0);
    }

    @Test
    void startPipeline() {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        ResponseEntity<Status> statusResponseEntity = ciOperationsService.startPipeline(project.getId(),"cioperations_service","new_commit",principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"cioperations_service", "master");
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,"new_commit");
        assertTrue(ciOperations.isPresent());

    }


    @Test
    void codeVerify() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        ResponseEntity<Status> statusResponseEntity = ciOperationsService.startPipeline(project.getId(),"cioperations_service","new_commit",principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"cioperations_service", "master");

        ResponseEntity<CIVulnManageResponse>  ciVulnManageResponseResponseEntity = ciOperationsService.codeVerify("cioperations_service","cioperations_service", project.getId(),"newest_commit",principal);
        assertEquals(HttpStatus.OK, ciVulnManageResponseResponseEntity.getStatusCode());
    }

    @Test
    void getTableDataForProject() {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);


        ResponseEntity<List<CiOperations>> listResponseEntity = ciOperationsService.getTableDataForProject(principal,project.getId());
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size()>0);

    }

    @Test
    void getInfoForCI() throws Exception {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Mockito.when(dependencyTrackApiClient.canProcessRequest()).thenReturn(true);
        Mockito.when(dependencyTrackApiClient.createProject(Mockito.any())).thenReturn(true);

        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        GetInfoRequest getInfoRequest = GetInfoRequest.builder()
                .branch("dev")
                .projectId(project.getId())
                .repoName("new_project")
                .repoUrl("https://new-project.com")
                .scope(Constants.CI_SCOPE_OPENSOURCE)
                .build();

        ResponseEntity<PrepareCIOperation> prepareCIOperationResponseEntity = ciOperationsService.getInfoForCI(getInfoRequest,principal);
        assertEquals(HttpStatus.OK, prepareCIOperationResponseEntity.getStatusCode());
        assertNotNull(prepareCIOperationResponseEntity.getBody());
        assertTrue(prepareCIOperationResponseEntity.getBody().getCodeProjectId()>0);


    }

    @Test
    void infoScanPerformed() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"cioperations_service", "master");

        InfoScanPerformed infoScanPerformed = InfoScanPerformed.builder()
                .branch("branch")
                .commitId("new_commit_id")
                .scope("opensource")
                .codeProjectId(codeProject.getId())
                .build();
        ResponseEntity<Status> statusResponseEntity1 = ciOperationsService.infoScanPerformed(infoScanPerformed, principal);
        assertEquals(HttpStatus.OK, statusResponseEntity1.getStatusCode());
    }

    @Test
    @Order(1)
    void loadVulnerabilitiesFromCICDToProject() throws Exception {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"cioperations_service", "master");

        List<VulnerabilityModel> vulnerabilityModels = new ArrayList<>();
        for(int i =0; i<10; i ++){
            VulnerabilityModel vulnerabilityModel = VulnerabilityModel.builder()
                    .description("test")
                    .filename("test")
                    .name("test"+i)
                    .severity("High")
                    .scannerType(ScannerType.SAST)
                    .line("31").build();
            vulnerabilityModels.add(vulnerabilityModel);
        }
        ResponseEntity<Status> statusResponseEntity1 = ciOperationsService.loadVulnerabilitiesFromCICDToProject(vulnerabilityModels,project.getId(),"cioperations_service","branch","commitid",principal);
        assertEquals(HttpStatus.OK, statusResponseEntity1.getStatusCode());
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject);
        assertTrue(projectVulnerabilities.size()>5);
    }

    @Test
    void loadVulnerabilitiesForAnonymousProject() {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        List<VulnerabilityModel> vulnerabilityModels = new ArrayList<>();
        for(int i =0; i<10; i ++){
            VulnerabilityModel vulnerabilityModel = VulnerabilityModel.builder()
                    .description("test")
                    .filename("test")
                    .name("test"+i)
                    .severity("High")
                    .scannerType(ScannerType.SAST)
                    .line("31").build();
            vulnerabilityModels.add(vulnerabilityModel);
        }

        ciOperationsService.loadVulnerabilitiesForAnonymousProject(vulnerabilityModels,"anonymous",principal);
        Optional<CodeProject> codeProject = codeProjectRepository.findByName("anonymous");
        assertTrue(codeProject.isPresent());
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject.get());
        assertTrue(projectVulnerabilities.size() > 0);
    }

    @Test
    void getInfoForCIForProject() throws Exception {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);

        GetInfoRequest getInfoRequest = GetInfoRequest.builder()
                .scope("opensource")
                .repoUrl("https://repo.new.project")
                .branch("master")
                .repoName("repo-new-project")
                .build();

        ResponseEntity<PrepareCIOperation> prepareCIOperationResponseEntity = ciOperationsService.getInfoForCIForProject(getInfoRequest,principal, project.getId());
        assertEquals(HttpStatus.OK, prepareCIOperationResponseEntity.getStatusCode());
        assertNotNull(prepareCIOperationResponseEntity.getBody());
    }

    @Test
    void performSastScanForCodeProject() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"cioperations_service", "master");

        ResponseEntity<Status> statusResponseEntity = ciOperationsService.performSastScanForCodeProject(codeProject.getId(), principal);
        codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"cioperations_service", "master");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        assertTrue(codeProject.getInQueue());
    }

    @Test
    void verifyCodeProject() {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"cioperations_service", "master");

        ResponseEntity<CIVulnManageResponse> ciVulnManageResponseResponseEntity = ciOperationsService.verifyCodeProject(codeProject.getId(),principal);
        assertEquals(HttpStatus.OK, ciVulnManageResponseResponseEntity.getStatusCode());
        assertNotNull(ciVulnManageResponseResponseEntity.getBody());

    }

    @Test
    @Order(2)
    void getVulnerabilitiesForCodeProject() throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("cioperations_service");
        Project project = getOrCreateProjectService.getProjectId("cioperations_service", "cioperations_service", principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"cioperations_service", "master");

        ResponseEntity<SecurityGatewayResponse> securityGatewayResponseResponseEntity = ciOperationsService.getVulnerabilitiesForCodeProject(codeProject.getId(), principal);
        assertEquals(HttpStatus.OK, securityGatewayResponseResponseEntity.getStatusCode());
        assertNotNull(securityGatewayResponseResponseEntity.getBody());
        assertTrue(securityGatewayResponseResponseEntity.getBody().getVulnList().size() > 0);

    }

}