package io.mixeway.domain.service.intf;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.CiOperationsRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import lombok.RequiredArgsConstructor;
import org.checkerframework.checker.nullness.Opt;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FindInterfaceServiceTest {
    private final FindInterfaceService findInterfaceService;
    private final InterfaceOperations interfaceOperations;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final InterfaceRepository interfaceRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("find_intf");
        User userToCreate = new User();
        userToCreate.setUsername("find_intf");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void getInterfacesForProjectAndRoutingDomains() {
        Mockito.when(principal.getName()).thenReturn("find_intf");
        Project project = getOrCreateProjectService.getProjectId("find_intf","find_intf", principal);
        for (int i=0; i<5; i++ ){
            interfaceOperations.getOrCreateInterface("1.1.1."+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        }
        project = getOrCreateProjectService.getProjectId("find_intf","find_intf", principal);
        Set<Interface> interfaceList = findInterfaceService.getInterfacesForProjectAndRoutingDomains(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        assertEquals(5, interfaceList.size());

        interfaceList = findInterfaceService.getInterfacesForProjectAndRoutingDomains(createOrGetRoutingDomainService.createOrGetRoutingDomain("new"), project);
        assertEquals(0, interfaceList.size());

    }

    @Test
    void getInterfacesInProject() {
        Mockito.when(principal.getName()).thenReturn("find_intf");
        Project project = getOrCreateProjectService.getProjectId("find_intf2","find_intf2", principal);
        for (int i=0; i<5; i++ ){
            interfaceOperations.getOrCreateInterface("1.1.2."+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        }
        project = getOrCreateProjectService.getProjectId("find_intf2","find_intf2", principal);
        List<Interface> interfaces = findInterfaceService.getInterfacesInProject(project);
        assertEquals(5, interfaces.size());
    }

    @Test
    void getInterfacesForProjectAndWithIP() {
        Mockito.when(principal.getName()).thenReturn("find_intf");
        Project project = getOrCreateProjectService.getProjectId("find_intf3","find_intf3", principal);
        for (int i=0; i<5; i++ ){
            interfaceOperations.getOrCreateInterface("1.1.3."+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        }
        project = getOrCreateProjectService.getProjectId("find_intf3","find_intf3", principal);
        Optional<Interface> anInterface =  findInterfaceService.getInterfacesForProjectAndWithIP(project,"1.1.3.1");
        assertTrue(anInterface.isPresent());
        anInterface =  findInterfaceService.getInterfacesForProjectAndWithIP(project,"100.1.3.1");
        assertFalse(anInterface.isPresent());
    }

    @Test
    void findByAssetIn() {
        Mockito.when(principal.getName()).thenReturn("find_intf");
        Project project = getOrCreateProjectService.getProjectId("find_int4","find_intf4", principal);
        for (int i=0; i<5; i++ ){
            interfaceOperations.getOrCreateInterface("1.1.4."+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        }
        project = getOrCreateProjectService.getProjectId("find_int4","find_intf4", principal);
        List<Interface> anInterface = findInterfaceService.findByAssetIn(new ArrayList<>(project.getAssets()));
        assertEquals(5, anInterface.size());
    }

    @Test
    void findById() {
        Mockito.when(principal.getName()).thenReturn("find_intf");
        Project project = getOrCreateProjectService.getProjectId("find_int5","find_intf5", principal);
        for (int i=0; i<5; i++ ){
            interfaceOperations.getOrCreateInterface("1.1.5."+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        }
        project = getOrCreateProjectService.getProjectId("find_int5","find_intf5", principal);
        Optional<Interface> anInterface = interfaceRepository.findByAssetInAndPrivateip(project.getAssets(), "1.1.5.2");
        assertTrue(anInterface.isPresent());
        anInterface = findInterfaceService.findById(anInterface.get().getId());
        assertTrue(anInterface.isPresent());
        anInterface = findInterfaceService.findById(10000L);
        assertFalse(anInterface.isPresent());
    }

    @Test
    void findByActive() {
        Mockito.when(principal.getName()).thenReturn("find_intf");
        Project project = getOrCreateProjectService.getProjectId("find_int6","find_intf6", principal);
        for (int i=0; i<5; i++ ){
            interfaceOperations.getOrCreateInterface("1.1.6."+i, createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        }
        project = getOrCreateProjectService.getProjectId("find_int6","find_intf6", principal);
        List<Interface> interfaces = findInterfaceService.findByActive(true);
        assertTrue(interfaces.size() > 4);
    }
}