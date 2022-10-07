package io.mixeway.api.vulnmanage.service;

import io.mixeway.api.cioperations.service.CiOperationsService;
import io.mixeway.api.vulnmanage.model.CreateScanManageRequest;
import io.mixeway.api.vulnmanage.model.SecurityScans;
import io.mixeway.api.vulnmanage.model.Vulnerabilities;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.infrascan.FindInfraScanService;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.intf.InterfaceOperations;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetCisRequirementService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.scanmanager.integrations.openvas.apiclient.OpenVasApiClient;
import io.mixeway.scanmanager.model.*;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.ScannerType;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.Principal;
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
class ScanManagerServiceTest {
    private final ScanManagerService scanManagerService;
    private final UserRepository userRepository;
    private final FindCodeProjectService findCodeProjectService;
    private final CodeProjectRepository codeProjectRepository;
    private final FindProjectService findProjectService;
    private final FindInterfaceService findInterfaceService;
    private final FindInfraScanService findInfraScanService;
    private final InfraScanRepository infraScanRepository;
    private final AssetRepository assetRepository;
    private final CiOperationsService ciOperationsService;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;

    @Mock
    Principal principal;

    @MockBean
    OpenVasApiClient openVasApiClient;

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
        Mockito.when(principal.getName()).thenReturn("scan_manage_service");
        User userToCreate = new User();
        userToCreate.setUsername("scan_manage_service");
        userToCreate.setCommonName("scan_manage_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        scannerRepository.deleteAll();
        Scanner scanner = new Scanner();
        scanner.setStatus(true);
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS));
        scannerRepository.save(scanner);
    }

    @Test
    @Order(6)
    void createScanManageRequestWebApp() throws Exception {
        Mockito.when(principal.getName()).thenReturn("scan_manage_service");
        List<WebAppScanModel> webAppScanModels = new ArrayList<>();
        for (int i=0; i <5; i++){
            WebAppScanModel webAppScanModel = new WebAppScanModel();
            webAppScanModel.setUrl("https://scan_request"+i);
            webAppScanModel.setRoutingDomain("default");
            webAppScanModels.add(webAppScanModel);
        }
        WebAppScanRequestModel webAppScanRequestModel = new WebAppScanRequestModel();
        webAppScanRequestModel.setProjectName(Optional.of("web_app_scan"));
        webAppScanRequestModel.setCiid(Optional.of("web_app_scan"));
        webAppScanRequestModel.setWebApp(webAppScanModels);
        CreateScanManageRequest createScanManageRequest = new CreateScanManageRequest();
        createScanManageRequest.setWebAppScanRequest(webAppScanRequestModel);
        createScanManageRequest.setTestType("webApp");
        ResponseEntity<Status>  statusResponseEntity = scanManagerService.createScanManageRequest(createScanManageRequest, principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Optional<Project> project = findProjectService.findProjectByName("web_app_scan");
        assertTrue(project.isPresent());
        assertTrue(project.get().getWebapps().size() >= 5);
        project.get().getWebapps().stream().map(WebApp::getInQueue).forEach(Assertions::assertTrue);
    }
    @Test
    @Order(7)
    void createScanManageRequestCode() throws Exception {
        Mockito.when(principal.getName()).thenReturn("scan_manage_service");
        CodeScanRequestModel codeScanRequestModel = new CodeScanRequestModel();

        codeScanRequestModel.setBranch("master");
        codeScanRequestModel.setCodeProjectName("scan_request_");
        codeScanRequestModel.setRepoUrl("https://scan_request");
        codeScanRequestModel.setCodeProjectName("new_scan_request_project");
        codeScanRequestModel.setCiid("new_scan_request_project");
        codeScanRequestModel.setProjectName("new_scan_request_project");

        CreateScanManageRequest createScanManageRequest = new CreateScanManageRequest();
        createScanManageRequest.setCodeScanRequest(codeScanRequestModel);
        createScanManageRequest.setTestType("code");
        ResponseEntity<Status>  statusResponseEntity = scanManagerService.createScanManageRequest(createScanManageRequest, principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Optional<Project> project = findProjectService.findProjectByName("new_scan_request_project");
        assertTrue(project.isPresent());
        assertTrue(project.get().getCodes().size() > 0);
        project.get().getCodes().stream().map(CodeProject::getInQueue).forEach(Assertions::assertTrue);
    }
    @Test
    @Order(1)
    void createScanManageRequestNetwork() throws Exception {
        Mockito.when(principal.getName()).thenReturn("scan_manage_service");
        Mockito.when(openVasApiClient.canProcessRequest(Mockito.any(RoutingDomain.class))).thenReturn(true);
        List<Scanner> scanner = scannerRepository
                .findByScannerTypeAndRoutingDomain(
                        scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS),
                        createOrGetRoutingDomainService.createOrGetRoutingDomain("default")
                );
        Mockito.when(openVasApiClient.getScannerFromClient(Mockito.any(RoutingDomain.class))).thenReturn(scanner.get(0));
        List<AssetToCreate> assetToCreates = new ArrayList<>();
        for (int i =0; i<5; i++){
            AssetToCreate assetToCreate = AssetToCreate.builder()
                    .routingDomain("default")
                    .hostname("hostname"+i)
                    .ip("10.10.10.1"+i)
                    .build();
            assetToCreates.add(assetToCreate);
        }

        NetworkScanRequestModel networkScanRequestModel = new NetworkScanRequestModel();
        networkScanRequestModel.setCiid("network_scan_request");
        networkScanRequestModel.setProjectName("network_scan_request");
        networkScanRequestModel.setIpAddresses(assetToCreates);

        CreateScanManageRequest createScanManageRequest = new CreateScanManageRequest();
        createScanManageRequest.setNetworkScanRequest(networkScanRequestModel);
        createScanManageRequest.setTestType("network");

        ResponseEntity<Status>  statusResponseEntity = scanManagerService.createScanManageRequest(createScanManageRequest, principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Optional<Project> project = findProjectService.findProjectByName("network_scan_request");
        assertTrue(project.isPresent());
        List<Interface>  interfaces = findInterfaceService.findByAssetIn(new ArrayList<>(project.get().getAssets()));
        assertTrue(interfaces.size() > 0);
        List<InfraScan> infraScan = findInfraScanService.findByProject(project.get());
        assertTrue(infraScan.size()>0);
    }

    @Test
    @Order(2)
    void checkStatusOfRequestedScan() {
        Optional<Project> project = findProjectService.findProjectByName("network_scan_request");
        assertTrue(project.isPresent());
        List<InfraScan> infraScan = findInfraScanService.findByProject(project.get());
        InfraScan scan = infraScan.get(0);
        scan.setRequestId("scan_requestid");
        infraScanRepository.save(scan);
        for(Interface anInterface : scan.getInterfaces()){
            anInterface.getAsset().setRequestId("scan_requestid");
            assetRepository.save(anInterface.getAsset());
        }
        ResponseEntity<Status> statusResponseEntity = scanManagerService.checkStatusOfRequestedScan("scan_requestid");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    @Order(3)
    void getVulnerabilitiesForScanByReqeustId() throws Exception {
        Mockito.when(principal.getName()).thenReturn("scan_manage_service");
        Optional<Project> project = findProjectService.findProjectByName("network_scan_request");
        List<io.mixeway.utils.VulnerabilityModel> vulnerabilityModels = new ArrayList<>();
        for(int i =0; i<10; i ++){
            io.mixeway.utils.VulnerabilityModel vulnerabilityModel = io.mixeway.utils.VulnerabilityModel.builder()
                    .description("test")
                    .filename("test")
                    .name("test"+i)
                    .severity("High")
                    .scannerType(ScannerType.SAST)
                    .line("31").build();
            vulnerabilityModels.add(vulnerabilityModel);
        }
        ciOperationsService.loadVulnerabilitiesFromCICDToProject(vulnerabilityModels,project.get().getId(),"network_scan_request","branch","commitid",principal);
        CodeProject codeProject = findCodeProjectService.findByProject(project.get()).stream().filter(cp -> cp.getName().equals("network_scan_request")).findFirst().get();
        codeProject.setRequestId("code_request_id");
        codeProjectRepository.save(codeProject);

        ResponseEntity<Vulnerabilities> vulnerabilitiesResponseEntity = scanManagerService.getVulnerabilitiesForScanByReqeustId("code_request_id", principal);
        assertEquals(HttpStatus.OK, vulnerabilitiesResponseEntity.getStatusCode());
        assertNotNull(vulnerabilitiesResponseEntity.getBody());
        assertTrue(vulnerabilitiesResponseEntity.getBody().getVulnerabilities().size() > 0);
    }

    @Test
    @Order(4)
    void getRunningSecurityScans() {
        Optional<Project> project = findProjectService.findProjectByName("network_scan_request");
        List<InfraScan> infraScan = findInfraScanService.findByProject(project.get());
        InfraScan scan = infraScan.get(0);
        scan.setRunning(true);
        infraScanRepository.save(scan);

        ResponseEntity<List<SecurityScans>> listResponseEntity = scanManagerService.getRunningSecurityScans();
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size() > 0);

    }

    @Test
    @Order(5)
    void getInQueueSecurityScans() {
        ResponseEntity<List<SecurityScans>> listResponseEntity = scanManagerService.getInQueueSecurityScans();
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }
}