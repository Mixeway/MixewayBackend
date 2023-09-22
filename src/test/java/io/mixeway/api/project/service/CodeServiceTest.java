package io.mixeway.api.project.service;

import io.mixeway.api.project.model.CodeProjectPutModel;
import io.mixeway.api.project.model.CodeProjectSearch;
import io.mixeway.api.project.model.EditCodeProjectModel;
import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.GetOrCreateCodeProjectBranchService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.checkmarx.apiclient.CheckmarxApiClient;
import io.mixeway.scanmanager.integrations.dependencytrack.apiclient.DependencyTrackApiClient;
import io.mixeway.scanmanager.model.Projects;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.RunScanForCodeProject;
import io.mixeway.utils.SASTProject;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.codehaus.jettison.json.JSONException;
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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CodeServiceTest {
    private final UserRepository userRepository;
    private final CodeService codeService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final FindCodeProjectService findCodeProjectService;
    private final CodeProjectRepository codeProjectRepository;
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final GetOrCreateCodeProjectBranchService getOrCreateCodeProjectBranchService;

    @Mock
    Principal principal;

    @MockBean
    CheckmarxApiClient checkmarxApiClient;
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
        Mockito.when(principal.getName()).thenReturn("code_service");
        User userToCreate = new User();
        userToCreate.setUsername("code_service");
        userToCreate.setCommonName("code_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Scanner scanner = new Scanner();
        scanner.setStatus(true);
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX));
        scannerRepository.save(scanner);
        Scanner scanner2 = new Scanner();
        scanner2.setStatus(true);
        scanner2.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK));
        scannerRepository.save(scanner2);

    }

    @Test
    @Order(1)
    void saveCodeProject() {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);

        CodeProjectPutModel codeProjectPutModel = new CodeProjectPutModel();
        codeProjectPutModel.setCodeProjectName("save_code");
        codeProjectPutModel.setProjectTech("java");
        codeProjectPutModel.setProjectGiturl("https://git/save_code");
        codeProjectPutModel.setBranch("master");

        ResponseEntity<Status> statusResponseEntity = codeService.saveCodeProject(project.getId(),codeProjectPutModel, principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        List<CodeProject> codeProjects = codeProjectRepository.findByProject(project);
        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());
    }


    @Test
    @Order(2)
    void searchCodeProject_OK(){
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service", principal);

        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());

        ResponseEntity<CodeProject> codeProjectResponseEntity = codeService.searchCodeProject(CodeProjectSearch.builder().repourl("https://git/save_code").build(), principal);
        assertEquals(HttpStatus.OK, codeProjectResponseEntity.getStatusCode());
    }

    @Test
    @Order(2)
    void searchCodeProject_NOT_FOUND(){
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service", principal);

        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());

        ResponseEntity<CodeProject> codeProjectResponseEntity = codeService.searchCodeProject(CodeProjectSearch.builder().repourl("random").build(), principal);
        assertEquals(HttpStatus.NOT_FOUND, codeProjectResponseEntity.getStatusCode());
    }

    @Test
    @Order(2)
    void searchCodeProject_FORBIDDEN(){
        Mockito.when(principal.getName()).thenReturn("random");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service", principal);

        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());

        ResponseEntity<CodeProject> codeProjectResponseEntity = codeService.searchCodeProject(CodeProjectSearch.builder().repourl("https://git/save_code").build(), principal);
        assertEquals(HttpStatus.FORBIDDEN, codeProjectResponseEntity.getStatusCode());
    }

    @Test
    @Order(3)
    void runSelectedCodeProjects() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException, JSONException, ParseException {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Mockito.doNothing().when(checkmarxApiClient).loadVulnerabilities(null,null,null,null,null, null);
        Mockito.when(checkmarxApiClient.isScanDone(Mockito.any(CodeProject.class))).thenReturn(true);
        Mockito.when(checkmarxApiClient.canProcessRequest(Mockito.any(Scanner.class))).thenReturn(true);

        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);
        List<RunScanForCodeProject> runScanForCodeProjects = new ArrayList<>();
        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        RunScanForCodeProject runScanForCodeProject = new RunScanForCodeProject();
        assertTrue(codeProject.isPresent());
        runScanForCodeProject.setId(codeProject.get().getId());

        ResponseEntity<Status> statusResponseEntity = codeService.runSelectedCodeProjects(project.getId(),runScanForCodeProjects,principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());

    }

    @Test
    @Order(4)
    void enableAutoScanForCodeProjects() {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);

        ResponseEntity<Status> statusResponseEntity = codeService.enableAutoScanForCodeProjects(project.getId(),principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);
        assertTrue(project.isAutoCodeScan());

    }

    @Test
    @Order(6)
    void runSingleCodeProjectScan() throws UnrecoverableKeyException, JSONException, CertificateException, ParseException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Mockito.doNothing().when(checkmarxApiClient).loadVulnerabilities(null,null,null,null,null,null);
        Mockito.when(checkmarxApiClient.isScanDone(Mockito.any(CodeProject.class))).thenReturn(true);
        Mockito.when(checkmarxApiClient.canProcessRequest(Mockito.any(Scanner.class))).thenReturn(true);

        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);

        List<RunScanForCodeProject> runScanForCodeProjects = new ArrayList<>();
        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());

        ResponseEntity<Status> statusResponseEntity = codeService.runSingleCodeProjectScan(codeProject.get().getId(),principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    @Order(14)
    void deleteCodeProject() {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);

        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());

        ResponseEntity<Status> statusResponseEntity =codeService.deleteCodeProject(codeProject.get().getId(),principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertFalse(codeProject.isPresent());

    }

    @Test
    @Order(7)
    void showCodeVulns() {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);

        List<RunScanForCodeProject> runScanForCodeProjects = new ArrayList<>();
        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());

        List<ProjectVulnerability> projectVulnerabilities =new ArrayList<>();
        for (int i=0; i<10; i++){
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setCodeProject(codeProject.get());
            projectVulnerability.setProject(project);
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("networkvuln"));
            projectVulnerability.setSeverity("Critical");
            projectVulnerability.setLocation("test");
            projectVulnerability.setAnalysis("");
            projectVulnerabilities.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(new ArrayList<>(), projectVulnerabilities);

        ResponseEntity<List<ProjectVulnerability>> listResponseEntity = codeService.showCodeVulns(project.getId(),principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size() > 0);

    }

    @Test
    @Order(5)
    void disableAutoScanForCodeProjects() {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);

        ResponseEntity<Status> statusResponseEntity = codeService.disableAutoScanForCodeProjects(project.getId(),principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);
        assertFalse(project.isAutoCodeScan());
    }

    @Test
    @Order(8)
    void editCodeProject() {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);
        EditCodeProjectModel editCodeProjectModel = new EditCodeProjectModel();
        editCodeProjectModel.setBranch("new_branch");
        editCodeProjectModel.setRepoPassword("thisisdummypassword");
        editCodeProjectModel.setRepoUrl("https://git/new_repo_edited");
        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());


        ResponseEntity<Status> statusResponseEntity = codeService.editCodeProject(codeProject.get().getId(), editCodeProjectModel, principal);
        codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        assertEquals("master", codeProject.get().getBranch());
        assertEquals("https://git/new_repo_edited", codeProject.get().getRepoUrl());

    }

    @Test
    @Order(9)
    void createDTrackProject() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Mockito.when(dependencyTrackApiClient.createProject(Mockito.any(CodeProject.class))).thenReturn(true);
        Mockito.when(dependencyTrackApiClient.canProcessRequest()).thenReturn(true);
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);
        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());

        ResponseEntity<Status> statusResponseEntity = codeService.createDTrackProject(codeProject.get().getId(), principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());

    }

    @Test
    @Order(10)
    void getdTracksProjects() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Mockito.when(dependencyTrackApiClient.getProjects()).thenReturn(new ArrayList<>());
        Mockito.when(dependencyTrackApiClient.canProcessRequest()).thenReturn(true);

        ResponseEntity<List<Projects>> listResponseEntity = codeService.getOpenSourceProjects();
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());


    }

    @Test
    @Order(11)
    void getCodeProjects() throws UnrecoverableKeyException, JSONException, CertificateException, NoSuchAlgorithmException, KeyStoreException, ParseException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);
        Mockito.when(checkmarxApiClient.getProjects(Mockito.any())).thenReturn(new ArrayList<>());
        Mockito.when(checkmarxApiClient.canProcessRequest(Mockito.any(Scanner.class))).thenReturn(true);

        ResponseEntity<List<SASTProject>> codeProjects = codeService.getCodeProjects();
        assertEquals(HttpStatus.OK, codeProjects.getStatusCode());
        assertNotNull(codeProjects.getBody());
    }

    @Test
    @Order(12)
    void createRemoteProject() throws UnrecoverableKeyException, JSONException, CertificateException, NoSuchAlgorithmException, KeyStoreException, ParseException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Mockito.when(checkmarxApiClient.createProject(Mockito.any(),Mockito.any())).thenReturn(true);
        Mockito.when(checkmarxApiClient.canProcessRequest(Mockito.any(Scanner.class))).thenReturn(true);

        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);
        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, "save_code");
        assertTrue(codeProject.isPresent());

        ResponseEntity<Status> statusResponseEntity = codeService.createRemoteProject(codeProject.get().getId(),project.getId(), principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
    }

    @Test
    @Order(13)
    void getOpenSourceConfig() {
        Mockito.when(principal.getName()).thenReturn("code_service");
        Project project = getOrCreateProjectService.getProjectId("code_service","code_service",principal);

        ResponseEntity<OpenSourceConfig> openSourceConfigResponseEntity = codeService.getOpenSourceConfig(project.getId(), "","save_code",principal);
        assertEquals(HttpStatus.OK, openSourceConfigResponseEntity.getStatusCode());

    }
}