package io.mixeway.api.project.service;

import io.mixeway.api.project.model.WebAppCard;
import io.mixeway.api.project.model.WebAppPutModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.acunetix.apiclient.AcunetixApiClient;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
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
class WebAppServiceTest {
    private final WebAppService webAppService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final FindWebAppService findWebAppService;
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;

    @Mock
    Principal principal;

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
        Mockito.when(principal.getName()).thenReturn("webapp_service");
        User userToCreate = new User();
        userToCreate.setUsername("webapp_service");
        userToCreate.setCommonName("webapp_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Scanner scanner = new Scanner();
        scanner.setStatus(true);
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_ACUNETIX));
        scannerRepository.save(scanner);

    }

    @Test
    @Order(8)
    void runSingleWebApp() {

        Mockito.when(principal.getName()).thenReturn("webapp_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);
        Optional<WebApp> webApp = findWebAppService.findByProjectAndRul(project, "https://webapp.url");
        assertTrue(webApp.isPresent());

        ResponseEntity<Status> statusResponseEntity = webAppService.runSingleWebApp(webApp.get().getId(), principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        webApp = findWebAppService.findByProjectAndRul(project, "https://webapp.url");
        assertTrue(webApp.isPresent());
        assertTrue(webApp.get().getInQueue());

    }

//    @Test
//    @Order(9)
//    void deleteWebApp() {
//
//        Mockito.when(principal.getName()).thenReturn("webapp_service");
//        Project project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);
//        Optional<WebApp> webApp = findWebAppService.findByProjectAndRul(project, "https://webapp.url");
//        assertTrue(webApp.isPresent());
//
//        ResponseEntity<Status> statusResponseEntity = webAppService.deleteWebApp(webApp.get().getId(), principal);
//        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
//        webApp = findWebAppService.findByProjectAndRul(project, "https://webapp.url");
//        assertFalse(webApp.isPresent());
//
//    }

    @Test
    @Order(7)
    void runAllScanForWebApp() {

        Mockito.when(principal.getName()).thenReturn("webapp_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);

        ResponseEntity<Status> statusResponseEntity = webAppService.runAllScanForWebApp(project.getId(), principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Optional<WebApp> webApp = findWebAppService.findByProjectAndRul(project, "https://webapp.url");
        assertTrue(webApp.isPresent());
        assertTrue(webApp.get().getInQueue());
    }

    @Test
    @Order(6)
    void runSelectedWebApps() {

        Mockito.when(principal.getName()).thenReturn("webapp_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);
        Optional<WebApp> webApp = findWebAppService.findByProjectAndRul(project, "https://webapp.url");
        assertTrue(webApp.isPresent());
        List<RunScanForWebApps> runScanForWebApps = new ArrayList<>();
        RunScanForWebApps runScanForWebApps1= new RunScanForWebApps();
        runScanForWebApps1.setWebAppId(webApp.get().getId());

        ResponseEntity<Status> statusResponseEntity = webAppService.runSelectedWebApps(project.getId(),runScanForWebApps, principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        webApp = findWebAppService.findByProjectAndRul(project, "https://webapp.url");
        assertTrue(webApp.isPresent());

    }

    @Test
    @Order(1)
    void saveWebApp() {

        Mockito.when(principal.getName()).thenReturn("webapp_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);
        WebAppPutModel webAppPutModel = new WebAppPutModel();
        webAppPutModel.setWebAppUrl("https://webapp.url");
        webAppPutModel.setRoutingDomainForAsset(createOrGetRoutingDomainService.createOrGetRoutingDomain("default").getId());

        ResponseEntity<Status>  statusResponseEntity = webAppService.saveWebApp(project.getId(),webAppPutModel,principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Optional<WebApp> webApp = findWebAppService.findByProjectAndRul(project, "https://webapp.url");
        assertTrue(webApp.isPresent());
    }

    @Test
    @Order(4)
    void enableWebAppAutoScan() {

        Mockito.when(principal.getName()).thenReturn("webapp_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);

        ResponseEntity<Status> statusResponseEntity = webAppService.enableWebAppAutoScan(project.getId(), principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);
        assertTrue(project.isAutoWebAppScan());

    }

    @Test
    @Order(3)
    void showWebAppVulns() {

        Mockito.when(principal.getName()).thenReturn("webapp_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);
        Optional<WebApp> webApp = findWebAppService.findByProjectAndRul(project, "https://webapp.url");
        assertTrue(webApp.isPresent());

        for (int i =0 ; i < 5 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setWebApp(webApp.get());
            projectVulnerability.setSeverity("High");
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_WEBAPP);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }

        ResponseEntity<List<ProjectVulnerability>>  listResponseEntity = webAppService.showWebAppVulns(project.getId(), principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size() > 0);

    }

    @Test
    @Order(2)
    void showWebApps() {

        Mockito.when(principal.getName()).thenReturn("webapp_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);

        ResponseEntity<WebAppCard> webAppCardResponseEntity = webAppService.showWebApps(project.getId(), principal);
        assertEquals(HttpStatus.OK, webAppCardResponseEntity.getStatusCode());

    }

    @Test
    @Order(5)
    void disableWebAppAutoScan() {

        Mockito.when(principal.getName()).thenReturn("webapp_service");
        Project project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);

        ResponseEntity<Status> statusResponseEntity = webAppService.disableWebAppAutoScan(project.getId(), principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("webapp_service","webapp_service",principal);
        assertFalse(project.isAutoWebAppScan());
    }
}