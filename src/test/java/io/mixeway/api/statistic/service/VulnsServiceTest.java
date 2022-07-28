package io.mixeway.api.statistic.service;

import io.mixeway.api.vulnmanage.model.GlobalStatistic;
import io.mixeway.db.entity.*;
import io.mixeway.db.projection.VulnBarChartProjection;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.softwarepackage.GetOrCreateSoftwarePacketService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetCisRequirementService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.Principal;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class VulnsServiceTest {
    private final VulnsService vulnsService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final CreateOrGetCisRequirementService createOrGetCisRequirementService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final VulnTemplate vulnTemplate;
    private final GetOrCreateSoftwarePacketService getOrCreateSoftwarePacketService;

    @MockBean
    GlobalScheduler globalScheduler;

    @MockBean
    NetworkScanScheduler networkScheduler;

    @MockBean
    CodeScheduler codeScheduler;

    @MockBean
    WebAppScheduler webAppScheduler;
    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        User userToCreate = new User();
        userToCreate.setUsername("vulns_service");
        userToCreate.setCommonName("vulns_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Project project = getOrCreateProjectService.getProjectId("vulns_service", "vulns_service", principal);
    }

    @Test
    void getCodeVulnsTop() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<VulnBarChartProjection>> listResponseEntity = vulnsService.getCodeVulnsTop(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());

    }

    @Test
    void getCodeProjectsTop() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<VulnBarChartProjection>> listResponseEntity = vulnsService.getCodeProjectsTop(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }

    @Test
    void getInfraVulnsTop() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<VulnBarChartProjection>> listResponseEntity = vulnsService.getInfraVulnsTop(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }

    @Test
    void getInfraIntfsTop() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<VulnBarChartProjection>> listResponseEntity = vulnsService.getInfraIntfsTop(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }

    @Test
    void getWebVulnsTop() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<VulnBarChartProjection>> listResponseEntity = vulnsService.getWebVulnsTop(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }

    @Test
    void getWebAppsTop() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<VulnBarChartProjection>> listResponseEntity = vulnsService.getWebAppsTop(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }

    @Test
    void getOpenSourceVulns() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<VulnBarChartProjection>> listResponseEntity = vulnsService.getOpenSourceVulns(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }

    @Test
    void getOpenSourceVulnsForCodeProject() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<VulnBarChartProjection>> listResponseEntity = vulnsService.getOpenSourceVulnsForCodeProject(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }

    @Test
    void getVulnerabilities() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<Vulnerability>> listResponseEntity = vulnsService.getVulnerabilities(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }

    @Test
    void getCisRequirements() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<List<CisRequirement>> listResponseEntity = vulnsService.getCisRequirements(principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }

    @Test
    void setVulnerabilitySeverity() {
        Vulnerability vulnerability = createOrGetVulnerabilityService.createOrGetVulnerability("test_vuln");
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        ResponseEntity<Status> listResponseEntity = vulnsService.setVulnerabilitySeverity(vulnerability.getId(), "Medium", principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        vulnerability = createOrGetVulnerabilityService.createOrGetVulnerability("test_vuln");
        assertEquals("Medium", vulnerability.getSeverity());
    }

    @Test
    void setCisRequirementSeverity() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        CisRequirement cisRequirement = createOrGetCisRequirementService.createOrGetCisRequirement("test","test");
        ResponseEntity<Status> listResponseEntity = vulnsService.setCisRequirementSeverity(cisRequirement.getId(), "Medium", principal);
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        cisRequirement = createOrGetCisRequirementService.createOrGetCisRequirement("test","test");
        assertEquals("Medium", cisRequirement.getSeverity());

    }
    @Test
    void getGlobalStatistics() {
        Mockito.when(principal.getName()).thenReturn("vulns_service");
        Project project = getOrCreateProjectService.getProjectByName("global_stats",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"global_stats","master");
        SoftwarePacket softwarePacket = getOrCreateSoftwarePacketService.getOrCreateSoftwarePacket("test","1.0");
        Vulnerability vulnerability = createOrGetVulnerabilityService.createOrGetVulnerability("testvulnerability");
        for (int i =0 ; i <5 ; i++){
            ProjectVulnerability pv = new ProjectVulnerability();
            pv.setProject(project);
            pv.setCodeProject(codeProject);
            pv.setVulnerability(vulnerability);
            pv.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
            pv.setSeverity("High");
            vulnTemplate.projectVulnerabilityRepository.save(pv);
        }
        for (int i =0 ; i <15 ; i++){
            ProjectVulnerability pv = new ProjectVulnerability();
            pv.setProject(project);
            pv.setCodeProject(codeProject);
            pv.setSoftwarePacket(softwarePacket);
            pv.setVulnerability(vulnerability);
            pv.setVulnerabilitySource(vulnTemplate.SOURCE_OPENSOURCE);
            pv.setSeverity("High");
            vulnTemplate.projectVulnerabilityRepository.save(pv);
        }
        ResponseEntity<List<GlobalStatistic>> globalStatistics = vulnsService.getGlobalStatistics(principal);
        assert globalStatistics != null;
        assertTrue(globalStatistics.getBody().size()>0);
        assertEquals(HttpStatus.OK, globalStatistics.getStatusCode());
    }
}