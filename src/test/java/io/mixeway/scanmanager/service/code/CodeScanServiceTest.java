package io.mixeway.scanmanager.service.code;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.domain.service.projectvulnerability.GetProjectVulnerabilitiesService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.scanner.GetScannerService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.checkmarx.apiclient.CheckmarxApiClient;
import io.mixeway.scanmanager.integrations.dependencytrack.apiclient.DependencyTrackApiClient;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.utils.RunScanForCodeProject;
import io.mixeway.utils.SASTProject;
import io.mixeway.utils.ScannerType;
import io.mixeway.utils.Status;
import io.mixeway.utils.VulnerabilityModel;
import lombok.RequiredArgsConstructor;
import org.codehaus.jettison.json.JSONException;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import javax.annotation.PostConstruct;
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
class CodeScanServiceTest {
    private final CodeScanService codeScanService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final UserRepository userRepository;
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final UpdateProjectService updateProjectService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final CiOperationsRepository ciOperationsRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final ScannerRepository scannerRepository;
    private final GetProjectVulnerabilitiesService getProjectVulnerabilitiesService;

    private Scanner scanner;
    @Mock
    Principal principal;
    @MockBean
    CheckmarxApiClient checkmarxApiClient;

    @MockBean
    private CodeScheduler schedulerService;


    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("admin_code_scan_service");
        System.out.println("In SETUP");
        User user = new User();
        user.setUsername("admin_code_scan_service");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
        Project project = getOrCreateProjectService.getProjectId("code_scan_service","code_scan_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"code_scan_service","master");
        for (int i =0 ; i < 5 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setCodeProject(codeProject);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }
        Scanner scanner = new Scanner();
        scanner.setStatus(true);
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX));
        scannerRepository.save(scanner);
    }

    @Test
    @Order(1)
    void getResultsForProject() {
        Project project = getOrCreateProjectService.getProjectId("code_scan_service","code_scan_service",principal);
        ResponseEntity<List<ProjectVulnerability>> projectVulnerabilityList = codeScanService.getResultsForProject(project.getId(),"code_scan_service",principal);
        assertEquals(projectVulnerabilityList.getStatusCode(), HttpStatus.OK);
        assertNotNull(projectVulnerabilityList.getBody());
        assertTrue(projectVulnerabilityList.getBody().size() > 1);
    }


    @Test
    @Order(2)
    void performScanFromScanManager() {
        Mockito.when(principal.getName()).thenReturn("admin_code_scan_service");
        CodeScanRequestModel codeScanRequestModel = new CodeScanRequestModel();
        codeScanRequestModel.setCodeProjectName("code_scan_service");
        codeScanRequestModel.setBranch("new_branch");
        codeScanRequestModel.setCiid("code_scan_service");
        codeScanRequestModel.setRepoUrl("https://repo.com");
        codeScanRequestModel.setProjectName("code_scan_service");
        codeScanRequestModel.setFortifySSCVersionId(7);

        ResponseEntity<Status> statusResponseEntity = codeScanService.performScanFromScanManager(codeScanRequestModel, principal);
        assertEquals(statusResponseEntity.getStatusCode(), HttpStatus.CREATED);
        Project project = getOrCreateProjectService.getProjectId("code_scan_service","code_scan_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"code_scan_service","master");
        assertTrue(codeProject.getInQueue());
        assertNotNull(codeProject.getRequestId());

    }

    @Test
    @Order(3)
    void schedulerRunAutoScans() {
        Mockito.when(principal.getName()).thenReturn("admin_code_scan_service");
        Project project = getOrCreateProjectService.getProjectId("code_scan_service2","code_scan_service2",principal);
        updateProjectService.enableCodeAutoScan(project);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"code_scan_service2","master");
        codeScanService.schedulerRunAutoScans();
        codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"code_scan_service2","master");
        assertTrue(codeProject.getInQueue());
    }

    @Test
    @Order(4)
    void getResultsForRunningScan() throws UnrecoverableKeyException, JSONException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, ParseException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("admin_code_scan_service");
        Project project = getOrCreateProjectService.getProjectId("code_scan_service","code_scan_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"code_scan_service","master");

        updateCodeProjectService.changeCommitId("test",codeProject);
        updateCodeProjectService.startScan(codeProject);
        Mockito.doNothing().when(checkmarxApiClient).loadVulnerabilities(null,null,null,null,null,null);
        Mockito.when(checkmarxApiClient.isScanDone(Mockito.any(CodeProject.class))).thenReturn(true);
        Mockito.when(checkmarxApiClient.canProcessRequest(Mockito.any(Scanner.class))).thenReturn(true);
        CiOperations ciOperations = new CiOperations();
        ciOperations.setCodeProject(codeProject);
        ciOperations.setCommitId("test");
        ciOperationsRepository.save(ciOperations);

        codeScanService.getResultsForRunningScan();
        Optional<CiOperations> ciOperations2 = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject, "test");
        assertTrue(ciOperations2.isPresent());
        assertNotNull(ciOperations2.get().getResult());

    }

    @Test
    @Order(5)
    void runFromQueue() throws UnrecoverableKeyException, JSONException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, ParseException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("admin_code_scan_service");
        Project project = getOrCreateProjectService.getProjectId("code_scan_service","code_scan_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"code_scan_service","master");
        updateCodeProjectService.putCodeProjectToQueue(codeProject);
        Mockito.when(checkmarxApiClient.canProcessRequest(Mockito.any(CodeProject.class))).thenReturn(true);
        Mockito.when(checkmarxApiClient.runScan(Mockito.any(CodeProject.class))).thenReturn(true);
        codeScanService.runFromQueue();

        codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"code_scan_service","master");
        assertFalse(codeProject.getInQueue());

    }

    @Test
    @Order(8)
    void codescanrunSelectedCodeProjectsScan() throws UnrecoverableKeyException, JSONException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, ParseException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("admin_code_scan_service");
        List<RunScanForCodeProject> runScanForCodeProjects = new ArrayList<>();
        Project project = getOrCreateProjectService.getProjectId("code_scan_service","code_scan_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"code_scan_service","master");
        runScanForCodeProjects.add(new RunScanForCodeProject(codeProject.getId()));
        Mockito.when(checkmarxApiClient.canProcessRequest(Mockito.any(CodeProject.class))).thenReturn(true);
        Mockito.when(checkmarxApiClient.runScan(Mockito.any(CodeProject.class))).thenReturn(true);
        ResponseEntity<Status> statusResponseEntity = codeScanService.codescanrunSelectedCodeProjectsScan(project.getId(), runScanForCodeProjects, principal);

        assertEquals(statusResponseEntity.getStatusCode(), HttpStatus.OK);
    }

    @Test
    @Order(9)
    void getProjectFromSASTScanner() throws UnrecoverableKeyException, JSONException, CertificateException, NoSuchAlgorithmException, KeyStoreException, ParseException, IOException, KeyManagementException {
        List<SASTProject> sastProjects = new ArrayList<>();
        for (int i=0; i<10 ; i++){
            sastProjects.add(new SASTProject(i, "test"+i));
        }
        Mockito.when(checkmarxApiClient.canProcessRequest(Mockito.any(Scanner.class))).thenReturn(true);
        Mockito.when(checkmarxApiClient.getProjects(Mockito.any(Scanner.class))).thenReturn(sastProjects);
        ResponseEntity<List<SASTProject>> listResponseEntity = codeScanService.getProjectFromSASTScanner();

        assertEquals(listResponseEntity.getStatusCode(), HttpStatus.OK);
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size() >5);
    }

    @Test
    @Order(10)
    void createProjectOnSASTScanner() throws UnrecoverableKeyException, JSONException, CertificateException, NoSuchAlgorithmException, KeyStoreException, ParseException, IOException, KeyManagementException {
        Mockito.when(principal.getName()).thenReturn("admin_code_scan_service");
        Project project = getOrCreateProjectService.getProjectId("code_scan_service","code_scan_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"code_scan_service","master");
        Mockito.when(checkmarxApiClient.canProcessRequest(Mockito.any(Scanner.class))).thenReturn(true);
        Mockito.when(checkmarxApiClient.createProject(Mockito.any(Scanner.class), Mockito.any(CodeProject.class))).thenReturn(true);
        ResponseEntity<Status> statusResponseEntity = codeScanService.createProjectOnSASTScanner(codeProject.getId(), project.getId(),principal);
        assertEquals(statusResponseEntity.getStatusCode(), HttpStatus.CREATED);
    }

    @Test
    @Order(11)
    void loadVulnsFromCICDToCodeProject() {
        Mockito.when(principal.getName()).thenReturn("admin_code_scan_service");
        List<VulnerabilityModel> vulnerabilityModels = new ArrayList<>();
        for (int i=0; i<20; i++){
            vulnerabilityModels.add(VulnerabilityModel.builder()
                    .line("10")
                    .scannerType(ScannerType.SAST)
                    .name("test"+i)
                    .severity("Critical")
                    .filename("file")
                    .build());
        }
        Project project = getOrCreateProjectService.getProjectId("code_scan_service","code_scan_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"code_scan_service","master");

        codeScanService.loadVulnsFromCICDToCodeProject(codeProject,vulnerabilityModels,ScannerType.SAST);
        List<ProjectVulnerability> projectVulnerabilities = getProjectVulnerabilitiesService.getProjectVulnerabilitiesForSource(codeProject,"test");
        assertTrue(projectVulnerabilities.size() > 15);
    }
}