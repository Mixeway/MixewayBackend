package io.mixeway.scanmanager.service.webapp;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.acunetix.apiclient.AcunetixApiClient;
import io.mixeway.scanmanager.model.WebAppScanModel;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.RunScanForWebApps;
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
import org.springframework.test.annotation.DirtiesContext;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WebAppScanServiceTest {
    private final WebAppScanService webAppScanService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final ScannerTypeRepository scannerTypeRepository;
    private final ScannerRepository scannerRepository;
    private final WebAppRepository webAppRepository;
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final UpdateProjectService updateProjectService;
    private final WebAppScanStrategyRepository webAppScanStrategyRepository;

    @Mock
    Principal principal;
    @MockBean
    WebAppScheduler webAppScheduler;
    @MockBean
    AcunetixApiClient acunetixApiClient;

    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("admin_webapp_scan_service");
        User user = new User();
        user.setUsername("admin_webapp_scan_service");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
        scannerRepository.deleteAll();
        Scanner scanner = new Scanner();
        scanner.setStatus(true);
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX));
        scannerRepository.save(scanner);
        WebAppScanStrategy webAppScanStrategy = webAppScanStrategyRepository.findAll().stream().findFirst().get();
        webAppScanStrategy.setApiStrategy(null);
        webAppScanStrategy.setGuiStrategy(null);
        webAppScanStrategy.setScheduledStrategy(null);
        webAppScanStrategyRepository.save(webAppScanStrategy);
    }

    @Test
    void processScanWebAppRequest() {
        Mockito.when(principal.getName()).thenReturn("admin_webapp_scan_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service_project","webapp_service_project",principal);
        List<WebAppScanModel> webAppScanModels = new ArrayList<>();
        for (int i=0; i<5; i++){
            WebAppScanModel webAppScanModel = new WebAppScanModel();
            webAppScanModel.setRoutingDomain("default");
            webAppScanModel.setUrl("https://testingwebsite.pl"+i);
            webAppScanModels.add(webAppScanModel);
        }
        webAppScanService.processScanWebAppRequest(project.getId(), webAppScanModels,"api",principal);
        List<WebApp> webApps = webAppRepository.findByProject(project);
        assertEquals(5, webApps.size());
        webApps.stream().map(WebApp::getInQueue).forEach(Assertions::assertTrue);
    }

    @Test
    void scheduledCheckAndDownloadResults() throws Exception {
        Mockito.when(principal.getName()).thenReturn("admin_webapp_scan_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service_project_2","webapp_service_project_2",principal);
        Mockito.when(acunetixApiClient.isScanDone(Mockito.any(Scanner.class),Mockito.any(WebApp.class))).thenReturn(true);
        Mockito.when(acunetixApiClient.canProcessRequest(Mockito.any(Scanner.class))).thenReturn(true);
        Mockito.when(acunetixApiClient.loadVulnerabilities(Mockito.any(),Mockito.any(),Mockito.any(),Mockito.any())).thenReturn(true);
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        webApp.setRunning(true);
        webApp.setUrl("https://url.pl");
        webApp = webAppRepository.saveAndFlush(webApp);
        for (int i =0 ; i < 15 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setWebApp(webApp);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_WEBAPP);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }

        webAppScanService.scheduledCheckAndDownloadResults();
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByWebApp(webApp);
        assertEquals(0, projectVulnerabilities.size());
    }

    @Test
    @Order(1)
    void scheduledRunWebAppScanFromQueue() throws Exception {
        Scanner scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX)).stream().findFirst().orElse(null);
        int running = scanner.getRunningScans();
        Project project = getOrCreateProjectService.getProjectId("webapp_service_project_3","webapp_service_project_3",principal);
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        webApp.setInQueue(true);
        webApp.setUrl("https://url.pl");
        webApp = webAppRepository.saveAndFlush(webApp);
        Mockito.when(acunetixApiClient.canProcessRequest(Mockito.any(Scanner.class))).thenReturn(true);
        Mockito.doNothing().when(acunetixApiClient).runScan(Mockito.any(),Mockito.any());
        webAppScanService.scheduledRunWebAppScanFromQueue();
        WebApp webApp1 = webAppRepository.findByProjectAndUrl(project,"https://url.pl").get();
        assertFalse(webApp1.getInQueue());
        scanner = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX)).stream().findFirst().orElse(null);
    }

    @Test
    void scheduledRunWebAppScan() {
        Mockito.when(principal.getName()).thenReturn("admin_webapp_scan_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service_project_4","webapp_service_project_4",principal);
        updateProjectService.enableWebAppAutoScan(project);
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        webApp.setUrl("https://url.pl");
        webApp = webAppRepository.saveAndFlush(webApp);
        webAppScanService.scheduledRunWebAppScan(0);
        WebApp webApp1 = webAppRepository.findByProjectAndUrl(project,"https://url.pl").get();
        assertTrue(webApp1.getInQueue());
    }

    @Test
    @Order(3)
    void putSingleWebAppToQueue() {
        Mockito.when(principal.getName()).thenReturn("admin_webapp_scan_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service_project_5","webapp_service_project_5",principal);
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        webApp.setUrl("https://url.pl");
        webApp = webAppRepository.saveAndFlush(webApp);
        ResponseEntity<Status> statusResponseEntity = webAppScanService.putSingleWebAppToQueue(webApp.getId(), principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        WebApp webApp1 = webAppRepository.findByProjectAndUrl(project,"https://url.pl").get();
        assertTrue(webApp1.getInQueue());

    }

    @Test
    @Order(2)
    void putSelectedWebAppsToQueue() {
        Mockito.when(principal.getName()).thenReturn("admin_webapp_scan_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service_project_6","webapp_service_project_6",principal);
        List<RunScanForWebApps> runScanForWebApps = new ArrayList<>();
        for(int i =0; i<5; i++){
            WebApp webApp1 = new WebApp();
            webApp1.setProject(project);
            webApp1.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
            webApp1.setUrl("https://url.plnew"+i);
            webApp1 = webAppRepository.saveAndFlush(webApp1);
            RunScanForWebApps runScanForWebApp = new RunScanForWebApps();
            runScanForWebApp.setWebAppId(webApp1.getId());
            runScanForWebApps.add(runScanForWebApp);
        }
        ResponseEntity<Status> statusResponseEntity =  webAppScanService.putSelectedWebAppsToQueue(project.getId(), runScanForWebApps,principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        List<WebApp> webApps = webAppRepository.findByProject(project);
        webApps.stream().map(WebApp::getInQueue).forEach(Assertions::assertTrue);
    }
}