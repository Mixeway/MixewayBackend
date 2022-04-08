package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.User;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.db.repository.WebAppRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.WebAppScanModel;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;
import java.text.ParseException;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class UpdateWebAppServiceTest {
    private final UpdateWebAppService updateWebAppService;

    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final WebAppRepository webAppRepository;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final VulnTemplate vulnTemplate;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("update_webapp");
        User userToCreate = new User();
        userToCreate.setUsername("update_webapp");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void putWebAppToQueue() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("update_webapp");
        Project project = getOrCreateProjectService.getProjectId("update_webapp","update_webapp",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://update_webapp");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp",project, webAppScanModel,"gui", "uuid");
        updateWebAppService.putWebAppToQueue(webApp,"new_request");
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp",project, webAppScanModel,"gui", "uuid");
        assertTrue(webApp.getInQueue());
        assertEquals("new_request", webApp.getRequestId());
    }

    @Test
    void updateUrl() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("update_webapp");
        Project project = getOrCreateProjectService.getProjectId("update_webapp2","update_webapp2",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://update_webapp2");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp2",project, webAppScanModel,"gui", "uuid");
        updateWebAppService.updateUrl(webApp,"https://new_update_url");
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://new_update_url",project, webAppScanModel,"gui", "uuid");
        assertEquals("https://new_update_url", webApp.getUrl());
    }

    @Test
    void endScan() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("update_webapp");
        Project project = getOrCreateProjectService.getProjectId("update_webapp3","update_webapp3",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://update_webapp3");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp3",project, webAppScanModel,"gui", "uuid");
        webApp.setRunning(true);
        webAppRepository.save(webApp);
        updateWebAppService.endScan(webApp);
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp3",project, webAppScanModel,"gui", "uuid");
        assertFalse(webApp.getRunning());

    }

    @Test
    void updateAndPutWebAppToQueue() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("update_webapp");
        Project project = getOrCreateProjectService.getProjectId("update_webapp4","update_webapp4",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://update_webapp4");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp4",project, webAppScanModel,"gui", "uuid");
        updateWebAppService.updateAndPutWebAppToQueue(webApp,webAppScanModel, "new_requestid", true);
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp4",project, webAppScanModel,"gui", "uuid");
        assertTrue(webApp.getInQueue());
    }


    @Test
    void updateRisk() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("update_webapp");
        Project project = getOrCreateProjectService.getProjectId("update_webapp5","update_webapp5",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://update_webapp5");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp5",project, webAppScanModel,"gui", "uuid");
        for (int i =0 ; i < 15 ; i++) {
            ProjectVulnerability projectVulnerability = new ProjectVulnerability();
            projectVulnerability.setProject(project);
            projectVulnerability.setWebApp(webApp);
            projectVulnerability.setSeverity("High");
            projectVulnerability.setAnalysis("Exploitable");
            projectVulnerability.setVulnerabilitySource(vulnTemplate.SOURCE_WEBAPP);
            projectVulnerability.setVulnerability(createOrGetVulnerabilityService.createOrGetVulnerability("test"));
            vulnTemplate.vulnerabilityPersist(new ArrayList<>(), projectVulnerability);
        }
        updateWebAppService.updateRisk(webApp);
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp5",project, webAppScanModel,"gui", "uuid");
        assertTrue(webApp.getRisk()>0);
    }

    @Test
    void removeFromQueue() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("update_webapp");
        Project project = getOrCreateProjectService.getProjectId("update_webapp6","update_webapp6",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://update_webapp6");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp6",project, webAppScanModel,"gui", "uuid");
        webApp.setInQueue(true);
        webAppRepository.save(webApp);
        updateWebAppService.removeFromQueue(webApp);
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://update_webapp6",project, webAppScanModel,"gui", "uuid");
        assertFalse(webApp.getInQueue());
    }
}