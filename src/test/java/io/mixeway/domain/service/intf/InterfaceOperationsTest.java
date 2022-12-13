package io.mixeway.domain.service.intf;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.exceptions.ScanException;
import io.mixeway.domain.service.asset.GetOrCreateAssetService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

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
class InterfaceOperationsTest {
    private final InterfaceOperations interfaceOperations;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final GetOrCreateAssetService getOrCreateAssetService;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final InterfaceRepository interfaceRepository;

    @Mock
    Principal principal;
    @BeforeAll
    private void setUpTest(){
        Mockito.when(principal.getName()).thenReturn("interface_operations");
        User user = new User();
        user.setUsername("interface_operations");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
    }

    @Test
    void createInterfaceForAsset() {
        Mockito.when(principal.getName()).thenReturn("interface_operations");
        Project project = getOrCreateProjectService.getProjectId("interface_operations","interface_operations",principal);
        Asset asset = getOrCreateAssetService.getOrCreateAsset("test",createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        Interface anInterface = interfaceOperations.createInterfaceForAsset(asset, "7.7.7.7");
        assertNotNull(anInterface);

    }

    @Test
    void createAndReturnInterfaceForAsset() {
        Mockito.when(principal.getName()).thenReturn("interface_operations");
        Project project = getOrCreateProjectService.getProjectId("interface_operations2","interface_operations2",principal);
        Asset asset = getOrCreateAssetService.getOrCreateAsset("test2",createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        Interface anInterface = interfaceOperations.createAndReturnInterfaceForAsset(asset, "7.7.7.8");
        assertNotNull(anInterface);
    }

    @Test
    void createInterfacesForModel() throws ScanException {

        Mockito.when(principal.getName()).thenReturn("interface_operations");
        Project project = getOrCreateProjectService.getProjectId("interface_operations3","interface_operations3",principal);
        Asset asset = getOrCreateAssetService.getOrCreateAsset("test3",createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        interfaceOperations.createInterfacesForModel(asset,asset.getRoutingDomain(), "1.1.1.1,2.2.2.2,3.3.3.3");
        project = getOrCreateProjectService.getProjectId("interface_operations3","interface_operations3",principal);
        List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        assertTrue(interfaces.size()>2);
    }

    @Test
    void isInterfaceAlreadyDefinedForAsset() {
        Mockito.when(principal.getName()).thenReturn("interface_operations");
        Project project = getOrCreateProjectService.getProjectId("interface_operations4","interface_operations4",principal);
        Asset asset = getOrCreateAssetService.getOrCreateAsset("test4",createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        Interface anInterface = interfaceOperations.createAndReturnInterfaceForAsset(asset, "7.7.7.11");
        project = getOrCreateProjectService.getProjectId("interface_operations4","interface_operations4",principal);
        List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        assertTrue(interfaceOperations.isInterfaceAlreadyDefinedForAsset(asset,"7.7.7.11", interfaces));
        assertFalse(interfaceOperations.isInterfaceAlreadyDefinedForAsset(asset,"1.7.7.11", interfaces));
    }

    @Test
    void verifyInterfacesBeforeScan() throws ScanException {
        Mockito.when(principal.getName()).thenReturn("interface_operations");
        Project project = getOrCreateProjectService.getProjectId("interface_operations5","interface_operations5",principal);
        Asset asset = getOrCreateAssetService.getOrCreateAsset("test5",createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        interfaceOperations.createInterfacesForModel(asset,asset.getRoutingDomain(), "1.1.1.1,2.2.2.2,3.3.3.3");
        project = getOrCreateProjectService.getProjectId("interface_operations4","interface_operations4",principal);
        List<Interface> interfaces = interfaceRepository.findByAssetIn(new ArrayList<>(project.getAssets()));
        assertFalse(interfaceOperations.verifyInterfacesBeforeScan(interfaces));
    }
}