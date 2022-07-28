package io.mixeway.api.vulnmanage.service;

import io.mixeway.api.vulnmanage.model.GlobalStatistic;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.softwarepackage.GetOrCreateSoftwarePacketService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.Principal;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class GetVulnerabilitiesServiceTest {

    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final GetOrCreateSoftwarePacketService getOrCreateSoftwarePacketService;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final VulnTemplate vulnTemplate;
    private final GetVulnerabilitiesService getVulnerabilitiesService;

    @Mock
    Principal principal;
    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("get_vulnerabilities");
        User userToCreate = new User();
        userToCreate.setUsername("get_vulnerabilities");
        userToCreate.setCommonName("get_vulnerabilities");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }


}