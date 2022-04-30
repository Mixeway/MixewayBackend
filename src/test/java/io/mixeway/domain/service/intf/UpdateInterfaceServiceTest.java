package io.mixeway.domain.service.intf;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.InfraScanRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.swagger.models.auth.In;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UpdateInterfaceServiceTest {
    private final UpdateInterfaceService updateInterfaceService;
    private final InterfaceOperations interfaceOperations;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final UserRepository userRepository;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final InfraScanRepository infraScanRepository;
    private final InterfaceRepository interfaceRepository;
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final ScannerRepository scannerRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("update_intf");
        User userToCreate = new User();
        userToCreate.setUsername("update_intf");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void changeRunningState() {
        Mockito.when(principal.getName()).thenReturn("update_intf");
        Project project = getOrCreateProjectService.getProjectId("update_intf","update_intf", principal);
        List<Interface> interfaceList = new ArrayList<>();
        for (int i = 0; i<5; i++) {
            interfaceList.add(interfaceOperations.getOrCreateInterface("10.10.10."+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project));
        }
        InfraScan infraScan = new InfraScan();
        infraScan.setProject(project);
        infraScan.setRequestId("test");
        infraScan.setInterfaces(new HashSet<>(interfaceList));
        infraScan = infraScanRepository.save(infraScan);
        updateInterfaceService.changeRunningState(infraScan, false,true);
        infraScan = infraScanRepository.findById(infraScan.getId()).get();
        assertFalse(infraScan.getRunning());
        infraScan.getInterfaces().stream().map(Interface::isScanRunning).forEach(Assertions::assertTrue);
    }

    @Test
    void updateIntfsStateAndAssetRequestId() {
        Mockito.when(principal.getName()).thenReturn("update_intf");
        Project project = getOrCreateProjectService.getProjectId("update_intf2","update_intf2", principal);
        List<Interface> interfaceList = new ArrayList<>();
        for (int i = 0; i<5; i++) {
            interfaceList.add(interfaceOperations.getOrCreateInterface("11.10.10."+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project));
        }
        project = getOrCreateProjectService.getProjectId("update_intf2","update_intf2", principal);
        List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        updateInterfaceService.updateIntfsStateAndAssetRequestId(interfaceList, "new_requestid");
        interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        interfaces.stream().map(Interface::isScanRunning).forEach(Assertions::assertTrue);
        interfaces.stream().map(Interface::getAsset).map(Asset::getRequestId).forEach(Assertions::assertNotNull);
    }

    @Test
    void updateRiskForInterfaces() {
        Mockito.when(principal.getName()).thenReturn("update_intf");
        Project project = getOrCreateProjectService.getProjectId("update_intf3","update_intf3", principal);
        List<ProjectVulnerability> projectVulns =new ArrayList<>();
        List<Interface> interfaces = new ArrayList<>();
        Interface anInterface = interfaceOperations.getOrCreateInterface("13.10.10.1", createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        interfaces.add(anInterface);
        project = getOrCreateProjectService.getProjectId("update_intf3","update_intf3", principal);
        Scanner scanner = new Scanner();
        scanner.setUsePublic(false);
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner = scannerRepository.saveAndFlush(scanner);
        InfraScan infraScan = new InfraScan();
        infraScan.setProject(project);
        infraScan.setNessus(scanner);
        infraScan.setIsAutomatic(false);
        infraScan.setPublicip(false);
        infraScan.setRequestId("test");
        infraScan.setInterfaces(new HashSet<>(interfaces));
        infraScan = infraScanRepository.save(infraScan);
        for (int i=0; i<10; i++){
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setAnInterface(anInterface);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_NETWORK);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"+i));
            projectVulns.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(new ArrayList<>(), projectVulns );
        updateInterfaceService.updateRiskForInterfaces(infraScan);
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByAnInterface(anInterface);
        project = getOrCreateProjectService.getProjectId("update_intf3","update_intf3", principal);
        List<Interface> interfaceList = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        interfaceList.stream().map(Interface::getRisk).forEach(risk -> assertTrue(risk > 0));
    }

    @Test
    void clearState() {
        Mockito.when(principal.getName()).thenReturn("update_intf");
        Project project = getOrCreateProjectService.getProjectId("update_intf4","update_intf4", principal);
        Interface anInterface = interfaceOperations.getOrCreateInterface("14.10.10.1", createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        project = getOrCreateProjectService.getProjectId("update_intf4","update_intf4", principal);
        anInterface.setScanRunning(true);
        anInterface = interfaceRepository.save(anInterface);
        Optional<Interface> anInterface1 = interfaceRepository.findById(anInterface.getId());
        updateInterfaceService.clearState(project);
        anInterface1 = interfaceRepository.findById(anInterface.getId());
        assertTrue(anInterface1.isPresent());
        assertFalse(anInterface1.get().isScanRunning());
    }
}