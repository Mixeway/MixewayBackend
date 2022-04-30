package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.db.repository.WebAppRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.annotation.DirtiesContext;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FindWebAppServiceTest {
    private final FindWebAppService findWebAppService;
    private final UserRepository userRepository;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final WebAppRepository webAppRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;

    @Mock
    Principal principal;
    @MockBean
    GlobalScheduler globalScheduler;
    @MockBean
    WebAppScheduler webAppScheduler;
    @MockBean
    CodeScheduler codeScheduler;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("find_webapp");
        User userToCreate = new User();
        userToCreate.setUsername("find_webapp");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void findRunningWebApps() {
        Mockito.when(principal.getName()).thenReturn("find_webapp");
        Project project = getOrCreateProjectService.getProjectId("find_webapp","find_webapp",principal);
        assertEquals(0, findWebAppService.findByProject(project).size());
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp.setRunning(true);
        webAppRepository.save(webApp);
        assertTrue(findWebAppService.findRunningWebApps().size() > 0);

    }

    @Test
    void findInQueueWebApps() {

        Mockito.when(principal.getName()).thenReturn("find_webapp");
        Project project = getOrCreateProjectService.getProjectId("find_webapp2","find_webapp2",principal);
        assertEquals(0, findWebAppService.findByProject(project).size());
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp.setInQueue(true);
        webAppRepository.save(webApp);
        assertTrue(findWebAppService.findInQueueWebApps().size() > 0);
    }

    @Test
    void findById() {

        Mockito.when(principal.getName()).thenReturn("find_webapp");
        Project project = getOrCreateProjectService.getProjectId("find_webapp3","find_webapp3",principal);
        assertEquals(0, findWebAppService.findByProject(project).size());
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp.setInQueue(true);
        webApp = webAppRepository.saveAndFlush(webApp);

        Optional<WebApp> newWebApp = findWebAppService.findById(webApp.getId());
        assertTrue(newWebApp.isPresent());
        newWebApp = findWebAppService.findById(666L);
        assertFalse(newWebApp.isPresent());
    }

    @Test
    void findByRequestId() {
        Mockito.when(principal.getName()).thenReturn("find_webapp");
        Project project = getOrCreateProjectService.getProjectId("find_webapp4","find_webapp4",principal);
        assertEquals(0, findWebAppService.findByProject(project).size());
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp.setInQueue(true);
        webApp.setRequestId("requestid");
        webApp = webAppRepository.saveAndFlush(webApp);

        List<WebApp> newWebApp = findWebAppService.findByRequestId("requestid");
        assertTrue(newWebApp.size() > 0 );
        newWebApp = findWebAppService.findByRequestId("requestid_notexisting");
        assertEquals(0, newWebApp.size());

    }
}