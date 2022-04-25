package io.mixeway.domain.service.infrascan;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.InfraScanRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.intf.InterfaceOperations;
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
class GetOrCreateInfraScanServiceTest {
    private final GetOrCreateInfraScanService getOrCreateInfraScanService;
    private final UserRepository userRepository;
    private final InterfaceOperations interfaceOperations;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final ScannerRepository scannerRepository;
    private final InfraScanRepository infraScanRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("get_create_infra_scan");
        User userToCreate = new User();
        userToCreate.setUsername("get_create_infra_scan");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void create() {
        Mockito.when(principal.getName()).thenReturn("get_create_infra_scan");
        Project project = getOrCreateProjectService.getProjectId("get_create_infra_scan","get_create_infra_scan", principal);
        List<Interface> interfaces = new ArrayList<>();
        Interface anInterface = interfaceOperations.getOrCreateInterface("14.10.10.1", createOrGetRoutingDomainService.createOrGetRoutingDomain("default"), project);
        interfaces.add(anInterface);
        project = getOrCreateProjectService.getProjectId("get_create_infra_scan","get_create_infra_scan", principal);
        Scanner scanner = new Scanner();
        scanner.setUsePublic(false);
        scanner.setRoutingDomain(createOrGetRoutingDomainService.createOrGetRoutingDomain("default"));
        scanner = scannerRepository.saveAndFlush(scanner);
        InfraScan infraScan = getOrCreateInfraScanService.create(scanner,project,false,new HashSet<>(interfaces), false);
        Optional<InfraScan> infraScanOptional = infraScanRepository.findById(infraScan.getId());
        assertTrue(infraScanOptional.isPresent());
    }

}