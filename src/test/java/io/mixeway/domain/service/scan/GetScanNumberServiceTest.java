package io.mixeway.domain.service.scan;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.db.repository.WebAppRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.GetOrCreateWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.UpdateWebAppService;
import io.mixeway.scanmanager.model.WebAppScanModel;
import liquibase.pro.packaged.W;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GetScanNumberServiceTest {
    private final GetScanNumberService getScanNumberService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final UpdateWebAppService updateWebAppService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final WebAppRepository webAppRepository;

    @Mock
    Principal principal;

    @BeforeAll
    public void setup(){
        Mockito.when(principal.getName()).thenReturn("scan_number");
        User userToCreate = new User();
        userToCreate.setUsername("scan_number");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void getNumberOfScansInQueue() throws ParseException {
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://scan_number");
        Mockito.when(principal.getName()).thenReturn("scan_number");
        Project project = getOrCreateProjectService.getProjectId("scan_number","scan_number", principal);
        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp("https://scan_number", project,webAppScanModel,"www","req");
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"scan_number", "master");
        updateCodeProjectService.putCodeProjectToQueue(codeProject);
        updateWebAppService.putWebAppToQueue(webApp,"req");
        Long scansInQueue = getScanNumberService.getNumberOfScansInQueue();
        assertTrue(scansInQueue >= 2);

    }

    @Test
    void getNumberOfScansRunning() throws ParseException {
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://scan_number2");
        Mockito.when(principal.getName()).thenReturn("scan_number");
        Project project = getOrCreateProjectService.getProjectId("scan_number2","scan_number2", principal);
        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp("https://scan_number2", project,webAppScanModel,"www","req");
        CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project,"scan_numbe2r", "master");
        updateCodeProjectService.startScan(codeProject);
        webApp.setRunning(true);
        webAppRepository.save(webApp);
        Long scansRunning = getScanNumberService.getNumberOfScansRunning();
        assertTrue(scansRunning >= 2);

    }
}