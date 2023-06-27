package io.mixeway.api.project.service;

import io.mixeway.api.project.model.ContactList;
import io.mixeway.api.project.model.ProjectVulnTrendChart;
import io.mixeway.api.project.model.RiskCards;
import io.mixeway.api.project.model.VulnAuditorSettings;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.ProjectVulnerabilityRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.servicediscovery.plugin.aws.apiclient.AwsApiClient;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ProjectRestServiceTest {
    private final ProjectRestService projectRestService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final VulnTemplate vulnTemplate;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final ProjectVulnerabilityRepository projectVulnerabilityRepository;

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
        Mockito.when(principal.getName()).thenReturn("project_service");
        User userToCreate = new User();
        userToCreate.setUsername("project_service");
        userToCreate.setCommonName("project_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void showProjectRisk() {
        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);

        ResponseEntity<RiskCards> riskCardsResponseEntity = projectRestService.showProjectRisk(project.getId(),principal);
        assertEquals(HttpStatus.OK, riskCardsResponseEntity.getStatusCode());
        assertNotNull(riskCardsResponseEntity.getBody());
    }

    @Test
    void showRoutingDomains() {
        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);

        ResponseEntity<List<RoutingDomain>> riskCardsResponseEntity = projectRestService.showRoutingDomains();
        assertEquals(HttpStatus.OK, riskCardsResponseEntity.getStatusCode());
    }

    @Test
    void showProxies() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);

        ResponseEntity<List<Proxies>> riskCardsResponseEntity = projectRestService.showProxies();
        assertEquals(HttpStatus.OK, riskCardsResponseEntity.getStatusCode());
        assertNotNull(riskCardsResponseEntity.getBody());
    }

    @Test
    void showVulnTrendChart() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);

        ResponseEntity<ProjectVulnTrendChart> showVulnTrendChart = projectRestService.showVulnTrendChart(project.getId(),7 ,principal);
        assertEquals(HttpStatus.OK, showVulnTrendChart.getStatusCode());
        assertNotNull(showVulnTrendChart.getBody());

    }

    @Test
    void showSeverityChart() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);

        ResponseEntity<HashMap<String,Long>> showVulnTrendChart = projectRestService.showSeverityChart(project.getId(),principal);
        assertEquals(HttpStatus.OK, showVulnTrendChart.getStatusCode());
        assertNotNull(showVulnTrendChart.getBody());
    }

    @Test
    void updateContactList() {
        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);

        ContactList contactList = new ContactList();
        contactList.setContactList("example@mail.com,example2@mail.com");

        ResponseEntity<io.mixeway.utils.Status> statusResponseEntity = projectRestService.updateContactList(project.getId(),contactList,principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);
        assertEquals("example@mail.com,example2@mail.com", project.getContactList());


    }

    @Test
    void scannersAvaliable() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);

        ResponseEntity<List<ScannerType>> showVulnTrendChart = projectRestService.scannersAvaliable();
        assertEquals(HttpStatus.OK, showVulnTrendChart.getStatusCode());
        assertNotNull(showVulnTrendChart.getBody());
    }

    @Test
    void showVulnerabilitiesForProject() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);

        ResponseEntity<List<ProjectVulnerability>> showVulnTrendChart = projectRestService.showVulnerabilitiesForProject(project.getId(),principal);
        assertEquals(HttpStatus.OK, showVulnTrendChart.getStatusCode());
        assertNotNull(showVulnTrendChart.getBody());
    }

    @Test
    @Transactional
    @Order(1)
    void showVulnerability() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"code_scan_service","master");
        for (int i =0 ; i < 5 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setCodeProject(codeProject);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }
        ProjectVulnerability projectVulnerability = projectVulnerabilityRepository.findByProject(project).findFirst().get();

        ResponseEntity<ProjectVulnerability> showVulnTrendChart = projectRestService.showVulnerability(project.getId(), projectVulnerability.getId(), principal);
        assertEquals(HttpStatus.OK, showVulnTrendChart.getStatusCode());
        assertNotNull(showVulnTrendChart.getBody());
    }

    @Test
    void showProject() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);

        ResponseEntity<Project> projectResponseEntity = projectRestService.showProject(project.getId(), principal);
        assertEquals(HttpStatus.OK, projectResponseEntity.getStatusCode());
        assertNotNull(projectResponseEntity.getBody());

    }

    @Test
    void updateVulnAuditorSettings() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);
        VulnAuditorSettings vulnAuditorSettings = new VulnAuditorSettings();
        vulnAuditorSettings.setEnableVulnAuditor(true);
        vulnAuditorSettings.setAppClient("local");
        vulnAuditorSettings.setDclocation("remote");

        ResponseEntity<io.mixeway.utils.Status> statusResponseEntity = projectRestService.updateVulnAuditorSettings(project.getId(),vulnAuditorSettings, principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);
        assertTrue(project.isVulnAuditorEnable());
        assertEquals("local", project.getAppClient());
        assertEquals("remote", project.getNetworkdc());

    }

    @Test
    @Transactional
    @Order(2)
    void setGradeForVulnerability() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);
        CodeProject codeProject = createOrGetCodeProjectService.createCodeProject(project,"code_scan_service","master");
        for (int i =0 ; i < 5 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setCodeProject(codeProject);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }
        ProjectVulnerability projectVulnerability = projectVulnerabilityRepository.findByProject(project).findFirst().get();

        ResponseEntity<io.mixeway.utils.Status> statusResponseEntity = projectRestService.setGradeForVulnerability(project.getId(), projectVulnerability.getId(), 1, principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        projectVulnerability = projectVulnerabilityRepository.getOne(projectVulnerability.getId());
        assertEquals(1, projectVulnerability.getGrade());

    }

    @Test
    void showAllRoutingDomains() {

        Mockito.when(principal.getName()).thenReturn("project_service");
        Project project = getOrCreateProjectService.getProjectId("project_service","project_service",principal);
        ResponseEntity<List<RoutingDomain>> listResponseEntity =  projectRestService.showAllRoutingDomains();
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertNotNull(listResponseEntity.getBody());
    }
}