package io.mixeway.scanmanager.service.network;

import com.google.common.collect.Multimap;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.domain.exceptions.ScanException;
import io.mixeway.domain.service.asset.GetOrCreateAssetService;
import io.mixeway.domain.service.intf.InterfaceOperations;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.scanmanager.integrations.openvas.apiclient.OpenVasApiClient;
import io.mixeway.scanmanager.model.AssetToCreate;
import io.mixeway.scanmanager.model.NetworkScanRequestModel;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
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
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class NetworkScanServiceTest {
    private final NetworkScanService networkScanService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final ScannerTypeRepository scannerTypeRepository;
    private final ScannerRepository scannerRepository;
    private final InfraScanRepository infraScanRepository;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final InterfaceRepository interfaceRepository;
    private final GetOrCreateAssetService getOrCreateAssetService;
    private final InterfaceOperations interfaceOperations;
    private final UpdateProjectService updateProjectService;

    @Mock
    Principal principal;
    @MockBean
    OpenVasApiClient openVasApiClient;

    @MockBean
    NetworkScanScheduler networkScanScheduler;

    @MockBean
    GlobalScheduler globalScheduler;

    @MockBean
    WebAppScheduler webAppScheduler;

    @MockBean
    CodeScheduler codeScheduler;

    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("admin_network_scan_service");
        User user = new User();
        user.setUsername("admin_network_scan_service");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
        Project project = getOrCreateProjectService.getProjectId("network_scan_service","network_scan_service",principal);
        scannerRepository.deleteAll();
        Scanner scanner = new Scanner();
        scanner.setStatus(true);
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner.setScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS));
        scannerRepository.save(scanner);
    }

    @Test
    void checkScanStatusForCiid() {
        Mockito.when(principal.getName()).thenReturn("admin_network_scan_service");
        Project project = getOrCreateProjectService.getProjectId("network_scan_service","network_scan_service",principal);
        ResponseEntity<Status> statusResponseEntity = networkScanService.checkScanStatusForCiid("network_scan_service");
        assertEquals(statusResponseEntity.getStatusCode(), HttpStatus.OK);
        InfraScan infraScan = new InfraScan();
        infraScan.setRunning(true);
        infraScan.setAutomatic(false);
        infraScan.setProject(project);
        infraScanRepository.save(infraScan);
        statusResponseEntity = networkScanService.checkScanStatusForCiid("network_scan_service");
        assertEquals(HttpStatus.LOCKED, statusResponseEntity.getStatusCode());

    }

    @Test
    void createAndRunNetworkScan() throws Exception {
        Mockito.when(principal.getName()).thenReturn("admin_network_scan_service");
        Mockito.when(openVasApiClient.canProcessRequest(Mockito.any(RoutingDomain.class))).thenReturn(true);
        Mockito.when(openVasApiClient.runScan(Mockito.any(InfraScan.class))).thenReturn(true);
        List<Scanner> scanner = scannerRepository
                .findByScannerTypeAndRoutingDomain(
                        scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS),
                        createOrGetRoutingDomainService.createOrGetRoutingDomain("default")
                );
        Mockito.when(openVasApiClient.getScannerFromClient(Mockito.any(RoutingDomain.class))).thenReturn(scanner.get(0));
        List<AssetToCreate> assetToCreates = new ArrayList<>();
        for (int i=0 ; i<10; i++){
            assetToCreates.add(AssetToCreate.builder()
                    .ip("1.1.1."+i)
                    .hostname("hostname"+i)
                    .routingDomain("default")
                    .build());
        }
        NetworkScanRequestModel networkScanRequestModel = new NetworkScanRequestModel();
        networkScanRequestModel.setCiid("new_network_scan");
        networkScanRequestModel.setProjectName("new_network_scan");
        networkScanRequestModel.setEnableVulnManage(java.util.Optional.of(false));
        networkScanRequestModel.setIpAddresses(assetToCreates);
        ResponseEntity<Status> statusResponseEntity = networkScanService.createAndRunNetworkScan(networkScanRequestModel, principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Project project = getOrCreateProjectService.getProjectId("new_network_scan","new_network_scan", principal);
        List<InfraScan> infraScans = infraScanRepository.findByProject(project);
        assertTrue(infraScans.size()>0);
        infraScans.stream().map(InfraScan::getInQueue).forEach(Assertions::assertTrue);
        List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        assertTrue(interfaces.size()>5);

    }

    @Test
    void configureAndRunManualScanForScope() throws Exception {
        Mockito.when(principal.getName()).thenReturn("admin_network_scan_service");
        Mockito.when(openVasApiClient.canProcessRequest(Mockito.any(RoutingDomain.class))).thenReturn(true);
        List<Scanner> scanner = scannerRepository
                .findByScannerTypeAndRoutingDomain(
                        scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS),
                        createOrGetRoutingDomainService.createOrGetRoutingDomain("default")
                );
        Mockito.when(openVasApiClient.getScannerFromClient(Mockito.any(RoutingDomain.class))).thenReturn(scanner.get(0));
        Project project = getOrCreateProjectService.getProjectId("network_scan_service7","network_scan_service7",principal);
        List<Interface> interfaces = new ArrayList<>();
        for(int i=0; i<10; i++){
            Asset asset = getOrCreateAssetService.getOrCreateAsset("test"+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"),project );
            Interface anInterface = interfaceOperations.createAndReturnInterfaceForAsset(asset, "1.1.1."+i);
            interfaces.add(anInterface);
        }
        project = getOrCreateProjectService.getProjectId("network_scan_service7","network_scan_service7",principal);
        List<InfraScan> infraScans = networkScanService.configureAndRunManualScanForScope(project,interfaces,false, true);
        assertTrue(infraScans.size()>0);
        infraScans.stream().map(InfraScan::getInQueue).forEach(Assertions::assertTrue);
        List<Interface> interfacesToCheck = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        assertTrue(interfacesToCheck.size()>5);

    }

    @Test
    void findNessusForInterfaces() {
        Mockito.when(principal.getName()).thenReturn("admin_network_scan_service");
        Mockito.when(openVasApiClient.canProcessRequest(Mockito.any(RoutingDomain.class))).thenReturn(true);
        Project project = getOrCreateProjectService.getProjectId("network_scan_service2","network_scan_service2",principal);
        List<Interface> interfaces = new ArrayList<>();
        for(int i=0; i<10; i++){
            Asset asset = getOrCreateAssetService.getOrCreateAsset("test"+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"),project );
            Interface anInterface = interfaceOperations.createAndReturnInterfaceForAsset(asset, "1.1.1."+i);
            interfaces.add(anInterface);
        }
        Multimap<NetworkScanClient, Set<Interface>> networkScanClientSetMultimap =  networkScanService.findNessusForInterfaces(new HashSet<>(interfaces));
        assertNotNull(networkScanClientSetMultimap);
        for (Map.Entry<NetworkScanClient, Set<Interface>> keyValue: networkScanClientSetMultimap.entries()) {
            assertTrue(keyValue.getValue().size() > 5);
            assertTrue(keyValue.getKey() instanceof OpenVasApiClient);
        }
    }

    @Test
    void updateAssetsAndPrepareInterfacesForScan() throws ScanException {
        Mockito.when(principal.getName()).thenReturn("admin_network_scan_service");
        Project project = getOrCreateProjectService.getProjectId("network_scan_service3","network_scan_service3",principal);
        List<AssetToCreate> assetToCreates = new ArrayList<>();
        for (int i=0 ; i<10; i++){
            assetToCreates.add(AssetToCreate.builder()
                    .ip("1.1.1."+i)
                    .hostname("hostname"+i)
                    .routingDomain("default")
                    .build());
        }
        NetworkScanRequestModel networkScanRequestModel = new NetworkScanRequestModel();
        networkScanRequestModel.setCiid("network_scan_service3");
        networkScanRequestModel.setProjectName("network_scan_service3");
        networkScanRequestModel.setEnableVulnManage(java.util.Optional.of(false));
        networkScanRequestModel.setIpAddresses(assetToCreates);
        List<Interface> interfaces = networkScanService.updateAssetsAndPrepareInterfacesForScan(networkScanRequestModel,project);
        project = getOrCreateProjectService.getProjectId("network_scan_service3","network_scan_service3",principal);
        List<Interface> interfaceList = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        assertEquals(interfaceList.size(), interfaces.size());
    }

    @Test
    void configureAutomaticScanForProject() {
        Mockito.when(openVasApiClient.canProcessRequest(Mockito.any(InfraScan.class))).thenReturn(true);
        Project project = getOrCreateProjectService.getProjectId("network_scan_service4","network_scan_service4",principal);

        for(int i=0; i<10; i++){
            Asset asset = getOrCreateAssetService.getOrCreateAsset("test"+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"),project );
            interfaceOperations.createAndReturnInterfaceForAsset(asset, "1.1.1."+i);
        }
        project = getOrCreateProjectService.getProjectId("network_scan_service4","network_scan_service4",principal);
        networkScanService.configureAutomaticScanForProject(project);
        List<InfraScan> infraScans = infraScanRepository.findByProject(project);
        assertTrue(infraScans.size() > 0);
        infraScans.stream().map(InfraScan::getIsAutomatic).forEach(Assertions::assertTrue);
    }

    @Test
    void scheduledCheckStatusAndLoadVulns() {
        //TODO how to test this method
        assertFalse(false);
    }

    @Test
    void scheduledRunScans() throws Exception {
        Mockito.when(principal.getName()).thenReturn("admin_network_scan_service");
        List<Scanner> scanner = scannerRepository
                .findByScannerTypeAndRoutingDomain(
                        scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_OPENVAS),
                        createOrGetRoutingDomainService.createOrGetRoutingDomain("default")
                );
        Mockito.when(openVasApiClient.getScannerFromClient(Mockito.any(RoutingDomain.class))).thenReturn(scanner.get(0));
        Project project = getOrCreateProjectService.getProjectId("network_scan_service5","network_scan_servic5",principal);
        updateProjectService.enableInfraAutoScan(project);
        for(int i=0; i<10; i++){
            Asset asset = getOrCreateAssetService.getOrCreateAsset("test"+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"),project );
            interfaceOperations.createAndReturnInterfaceForAsset(asset, "1.1.1."+i);
        }
        Mockito.when(openVasApiClient.canProcessRequest(Mockito.any(RoutingDomain.class))).thenReturn(true);
        networkScanService.scheduledRunScans();
        List<InfraScan> infraScans = infraScanRepository.findByProject(project);
        assertTrue(infraScans.size() > 0);
        infraScans.stream().map(InfraScan::getInQueue).forEach(Assertions::assertTrue);
    }


    @Test
    void verifyInteraceState() {
        Mockito.when(principal.getName()).thenReturn("admin_network_scan_service");
        Project project = getOrCreateProjectService.getProjectId("network_scan_service6","network_scan_servic6",principal);
        for(int i=0; i<10; i++){
            Asset asset = getOrCreateAssetService.getOrCreateAsset("test"+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"),project );
            Interface interfaceForAsset = interfaceOperations.createAndReturnInterfaceForAsset(asset, "1.1.1."+i);
            interfaceForAsset.setScanRunning(true);
            interfaceRepository.save(interfaceForAsset);
        }
        project = getOrCreateProjectService.getProjectId("network_scan_service6","network_scan_servic6",principal);
        networkScanService.verifyInteraceState();
        List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        interfaces.stream().map(Interface::isScanRunning).forEach(Assertions::assertFalse);
    }
}