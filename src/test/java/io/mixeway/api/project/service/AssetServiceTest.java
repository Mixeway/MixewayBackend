package io.mixeway.api.project.service;

import io.mixeway.api.project.model.AssetCard;
import io.mixeway.api.project.model.AssetPutModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.openvas.apiclient.OpenVasApiClient;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.RunScanForAssets;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.Get;
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
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AssetServiceTest {
    private final AssetService assetService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final VulnTemplate vulnTemplate;
    private final InterfaceRepository interfaceRepository;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;

    @MockBean
    OpenVasApiClient openVasApiClient;

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
        Mockito.when(principal.getName()).thenReturn("asset_service");
        User userToCreate = new User();
        userToCreate.setUsername("asset_service");
        userToCreate.setCommonName("asset_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        scannerRepository.deleteAll();
        Scanner scanner = new Scanner();
        scanner.setStatus(true);
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS));
        scannerRepository.save(scanner);
    }


    @Test
    @Order(2)
    void showAssets() {
        Mockito.when(principal.getName()).thenReturn("asset_service");
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);

        ResponseEntity<AssetCard> assetCardResponseEntity = assetService.showAssets(project.getId(),principal);
        assertEquals(HttpStatus.OK, assetCardResponseEntity.getStatusCode());
        assertNotNull(assetCardResponseEntity.getBody());
        assertTrue(assetCardResponseEntity.getBody().getAssets().size()>0);
    }

    @Test
    @Order(1)
    void saveAsset() {
        Mockito.when(principal.getName()).thenReturn("asset_service");
        RoutingDomain routingDomain = createOrGetRoutingDomainService.createOrGetRoutingDomain("default");
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        AssetPutModel assetPutModel = new AssetPutModel();
        assetPutModel.setAssetName("new_asset");
        assetPutModel.setIpAddresses("9.9.9.9");
        assetPutModel.setRoutingDomainForAsset(routingDomain.getId());
        ResponseEntity<Status> statusResponseEntity = assetService.saveAsset(project.getId(),assetPutModel, principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        assertTrue(project.getAssets().size() > 0);
    }

    @Test
    @Order(5)
    void runScanForAssets() throws Exception {
        Mockito.when(principal.getName()).thenReturn("asset_service");
        Mockito.when(openVasApiClient.canProcessRequest(Mockito.any(RoutingDomain.class))).thenReturn(true);
        List<Scanner> scanner = scannerRepository
                .findByScannerTypeAndRoutingDomain(
                        scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS),
                        createOrGetRoutingDomainService.createOrGetRoutingDomain("default")
                );
        Mockito.when(openVasApiClient.getScannerFromClient(Mockito.any(RoutingDomain.class))).thenReturn(scanner.get(0));
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        List<RunScanForAssets> runScanForAssets = new ArrayList<>();
        for (Asset asset: project.getAssets()){
            RunScanForAssets runScanForAssets1 = new RunScanForAssets();
            assertTrue(asset.getInterfaces().stream().findFirst().isPresent());
            runScanForAssets1.setAssetId(asset.getInterfaces().stream().findFirst().get().getId());
            runScanForAssets.add(runScanForAssets1);
        }

        ResponseEntity<Status> statusResponseEntity = assetService.runScanForAssets(project.getId(), runScanForAssets,principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        project.getAssets().stream().map(Asset::getRequestId).forEach(Assertions::assertNotNull);
    }

    @Test
    @Order(6)
    void runAllAssetScan() throws Exception {
        Mockito.when(principal.getName()).thenReturn("asset_service");
        Mockito.when(openVasApiClient.canProcessRequest(Mockito.any(RoutingDomain.class))).thenReturn(true);
        List<Scanner> scanner = scannerRepository
                .findByScannerTypeAndRoutingDomain(
                        scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS),
                        createOrGetRoutingDomainService.createOrGetRoutingDomain("default")
                );
        Mockito.when(openVasApiClient.getScannerFromClient(Mockito.any(RoutingDomain.class))).thenReturn(scanner.get(0));
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        ResponseEntity<Status> statusResponseEntity = assetService.runAllAssetScan(project.getId(),principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        project.getAssets().stream().map(Asset::getRequestId).forEach(Assertions::assertNotNull);
        List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        interfaces.stream().map(Interface::isScanRunning).forEach(Assertions::assertTrue);

    }

    @Test
    @Order(7)
    void runSingleAssetScan() throws Exception {
        Mockito.when(principal.getName()).thenReturn("asset_service");
        Mockito.when(openVasApiClient.canProcessRequest(Mockito.any(RoutingDomain.class))).thenReturn(true);
        List<Scanner> scanner = scannerRepository
                .findByScannerTypeAndRoutingDomain(
                        scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS),
                        createOrGetRoutingDomainService.createOrGetRoutingDomain("default")
                );
        Mockito.when(openVasApiClient.getScannerFromClient(Mockito.any(RoutingDomain.class))).thenReturn(scanner.get(0));
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        Interface anInterface = project.getAssets().stream().findFirst().get().getInterfaces().stream().findFirst().get();
        anInterface.setScanRunning(false);
        interfaceRepository.save(anInterface);

        ResponseEntity<Status> statusResponseEntity = assetService.runSingleAssetScan(anInterface.getId(),principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        anInterface = project.getAssets().stream().findFirst().get().getInterfaces().stream().findFirst().get();
        assertNotNull(anInterface.getAsset().getRequestId());
    }

    @Test
    @Order(9)
    void deleteAsset() {
        Mockito.when(principal.getName()).thenReturn("asset_service");
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        Interface anInterface = project.getAssets().stream().findFirst().get().getInterfaces().stream().findFirst().get();

        ResponseEntity<Status> statusResponseEntity = assetService.deleteAsset(anInterface.getId(),principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        Optional<Interface> anInterface1 = project.getAssets().stream().findFirst().get().getInterfaces().stream().findFirst();
        assertFalse(anInterface1.isPresent());
    }

    @Test
    @Order(8)
    void showInfraVulns() {
        Mockito.when(principal.getName()).thenReturn("asset_service");
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        Interface anInterface = project.getAssets().stream().findFirst().get().getInterfaces().stream().findFirst().get();
        List<ProjectVulnerability> projectVulnerabilities =new ArrayList<>();
        for (int i=0; i<10; i++){
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setAnInterface(anInterface);
            projectVulnerability.setProject(project);
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_NETWORK);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("networkvuln"));
            projectVulnerability.setSeverity("Critical");
            projectVulnerabilities.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(new ArrayList<>(), projectVulnerabilities);
        ResponseEntity<List<ProjectVulnerability>> listResponseEntity = assetService.showInfraVulns(project.getId(),principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
        assertTrue(listResponseEntity.getBody().size() >= 10);
    }

    @Test
    @Order(3)
    void enableInfraAutoScan() {
        Mockito.when(principal.getName()).thenReturn("asset_service");
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);

        ResponseEntity<Status> statusResponseEntity = assetService.enableInfraAutoScan(project.getId(), principal);
        project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        assertTrue(project.isAutoInfraScan());

    }

    @Test
    @Order(4)
    void disableInfraAutoScan() {
        Mockito.when(principal.getName()).thenReturn("asset_service");
        Project project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);

        ResponseEntity<Status> statusResponseEntity = assetService.disableInfraAutoScan(project.getId(), principal);
        project = getOrCreateProjectService.getProjectId("asset_service","asset_service",principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        assertFalse(project.isAutoInfraScan());
    }
}