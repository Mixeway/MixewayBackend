package io.mixeway.api.admin.service;

import io.mixeway.api.admin.model.*;
import io.mixeway.api.project.model.VulnAuditorSettings;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.junit.After;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.Principal;
import java.security.Security;
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
class AdminSettingsRestServiceTest {
    private final AdminSettingsRestService adminSettingsRestService;
    private final UserRepository userRepository;
    private final SettingsRepository settingsRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final ProxiesRepository proxiesRepository;
    private final WebAppScanStrategyRepository webAppScanStrategyRepository;
    private final SecurityGatewayRepository securityGatewayRepository;
    private final GitCredentialsRepository gitCredentialsRepository;

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
        Mockito.when(principal.getName()).thenReturn("admin_settings");
        User userToCreate = new User();
        userToCreate.setUsername("admin_settings");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }
    @AfterAll
    private void cleanup(){
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        settings.setSmtpHost(null);
        settingsRepository.save(settings);
    }

    @Test
    void getSettings() {

        ResponseEntity<Settings> settingsResponseEntity = adminSettingsRestService.getSettings();
        assertEquals(HttpStatus.OK, settingsResponseEntity.getStatusCode());
        assertNotNull(settingsResponseEntity.getBody());
    }

    @Test
    void updateSmtpSettings() {
        Mockito.when(principal.getName()).thenReturn("admin_settings");
        SmtpSettingsModel smtpSettingsModel = new SmtpSettingsModel();
        smtpSettingsModel.setSmtpHost("host");
        smtpSettingsModel.setSmtpPort(443);
        smtpSettingsModel.setSmtpPassword("pass");
        smtpSettingsModel.setSmtpUsername("user");
        smtpSettingsModel.setDomain("domain");
        smtpSettingsModel.setSmtpAuth(true);
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.updateSmtpSettings(smtpSettingsModel,"admin_settings");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        assertNotNull(settings.getSmtpHost());
    }

    @Test
    void updateAuthSettings() {

        Mockito.when(principal.getName()).thenReturn("admin_settings");
        AuthSettingsModel authSettingsModel = new AuthSettingsModel();
        authSettingsModel.setCertificateAuth(true);
        authSettingsModel.setPasswordAuth(true);
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.updateAuthSettings(authSettingsModel,"admin_settings");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        assertTrue(settings.getPasswordAuth());
        assertTrue(settings.getCertificateAuth());
    }

    @Test
    @Order(1)
    void createRoutingDomain() {

        Mockito.when(principal.getName()).thenReturn("admin_settings");
        RoutingDomain routingDomain = new RoutingDomain();
        routingDomain.setName("new_domain");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.createRoutingDomain(routingDomain,"admin_settings");
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        RoutingDomain routingDomain1 = routingDomainRepository.findByName("new_domain");
        assertNotNull(routingDomain1);
    }

    @Test
    @Order(2)
    void deleteRoutingDomain() {
        RoutingDomain routingDomain1 = routingDomainRepository.findByName("new_domain");
        assertNotNull(routingDomain1);
        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.deleteRoutingDomain(routingDomain1.getId(),"admin_settings");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        routingDomain1 = routingDomainRepository.findByName("new_domain");
        assertNull(routingDomain1);
    }

    @Test
    @Order(3)
    void createProxy() {

        Mockito.when(principal.getName()).thenReturn("admin_settings");
        Proxies proxies = new Proxies();
        proxies.setIp("1.1.1.1");
        proxies.setPort("3128");
        proxies.setDescription("test");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.createProxy(proxies,"admin_settings");
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Optional<Proxies> proxies1 = proxiesRepository.findByIpAndPort("1.1.1.1","3128");
        assertTrue(proxies1.isPresent());
    }

    @Test
    @Order(4)
    void deleteProxy() {
        Optional<Proxies> proxies1 = proxiesRepository.findByIpAndPort("1.1.1.1","3128");
        assertTrue(proxies1.isPresent());
        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.deleteProxy(proxies1.get().getId(),"admin_settings");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        Optional<Proxies> proxies = proxiesRepository.findByIpAndPort("1.1.1.1","3128");
        assertFalse(proxies.isPresent());
    }

    @Test
    void generateApiKey() {

        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.generateApiKey("admin_settings");
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        assertNotNull(settings.getMasterApiKey());
    }

    @Test
    void deleteApiKey() {

        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.deleteApiKey("admin_settings");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        assertNull(settings.getMasterApiKey());
    }

    @Test
    void changeInfraCron() {
        CronSettings cronSettings = new CronSettings();
        cronSettings.setExpression("0 40 23 * * ?");
        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.changeInfraCron("admin_settings", cronSettings);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    void changeWebAppCron() {
        CronSettings cronSettings = new CronSettings();
        cronSettings.setExpression("0 40 23 * * ?");
        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.changeWebAppCron("admin_settings", cronSettings);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    void changeCodeCron() {
        CronSettings cronSettings = new CronSettings();
        cronSettings.setExpression("0 40 23 * * ?");
        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.changeCodeCron("admin_settings", cronSettings);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    void changeTrendCron() {
        CronSettings cronSettings = new CronSettings();
        cronSettings.setExpression("0 40 23 * * ?");
        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.changeTrendCron("admin_settings", cronSettings);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    void changeWebAppStrategy() {
        WebAppScanStrategyModel webAppScanStrategyModel = new WebAppScanStrategyModel();
        webAppScanStrategyModel.setApiStrategy("Acunetix");
        webAppScanStrategyModel.setScheduledStrategy("Acunetix");
        webAppScanStrategyModel.setGuiStrategy("Acunetix");

        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.changeWebAppStrategy("admin_settings",webAppScanStrategyModel);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        WebAppScanStrategy webAppScanStrategy = webAppScanStrategyRepository.findAll().stream().findFirst().get();
        assertNotNull(webAppScanStrategy);
        assertEquals("Acunetix",webAppScanStrategy.getApiStrategy().getName());
    }

    @Test
    void getWebAppStrategies() {


        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<WebAppScanStrategy> statusResponseEntity = adminSettingsRestService.getWebAppStrategies();
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        assertNotNull(statusResponseEntity.getBody());
    }

    @Test
    void updateVulnAuditorSettings() {
        VulnAuditorEditSettings vulnAuditorSettings = new VulnAuditorEditSettings();
        vulnAuditorSettings.setEnabled(true);
        vulnAuditorSettings.setUrl("https://auditor");

        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.updateVulnAuditorSettings(vulnAuditorSettings,"admin_settings");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    void getVulnAuditorSettings() {


        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<VulnAuditorEditSettings> statusResponseEntity = adminSettingsRestService.getVulnAuditorSettings();
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        assertNotNull(statusResponseEntity.getBody());

    }

    @Test
    void updateSecurityGatewaySettings() {
        SecurityGateway securityGateway = new SecurityGateway();
        securityGateway.setCritical(5);
        securityGateway.setGrade(true);

        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.updateSecurityGatewaySettings("admin_settings", securityGateway);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        SecurityGateway securityGateway1 = securityGatewayRepository.findAll().stream().findFirst().get();
        assertNotNull(securityGateway1);
        assertEquals(5, securityGateway1.getCritical());
        assertTrue(securityGateway1.isGrade());
    }

    @Test
    void getSecurityGatewaySettings() {

        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<SecurityGateway> statusResponseEntity = adminSettingsRestService.getSecurityGatewaySettings();
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        assertNotNull(statusResponseEntity.getBody());
    }

    @Test
    @Order(6)
    void getGitCredentials() {


        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<List<GitCredentials>> statusResponseEntity = adminSettingsRestService.getGitCredentials();
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        assertNotNull(statusResponseEntity.getBody());
    }

    @Test
    @Order(5)
    void addGitCredentials() {
        GitCredentials gitCredentials = new GitCredentials();
        gitCredentials.setUrl("https://git");
        gitCredentials.setPassword("pass");
        gitCredentials.setUsername("user");


        Mockito.when(principal.getName()).thenReturn("admin_settings");
        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.addGitCredentials(gitCredentials, "admin_settings");
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Optional<GitCredentials> gitCredentials1 = gitCredentialsRepository.findByUrl("https://git");
        assertTrue(gitCredentials1.isPresent());
    }

//    @Test
//    @Order(7)
//    void editGitCredentials() {
//
//        GitCredentials gitCredentials = new GitCredentials();
//        gitCredentials.setUrl("https://new_git");
//        Mockito.when(principal.getName()).thenReturn("admin_settings");
//        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.editGitCredentials(1L, gitCredentials, "admin_settings");
//        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
//        Optional<GitCredentials> gitCredentials1 = gitCredentialsRepository.findByUrl("https://new_git");
//        assertTrue(gitCredentials1.isPresent());
//    }

//    @Test
//    @Order(9)
//    void deleteGitCredentials() {
//        Optional<GitCredentials> gitCredentials1 = gitCredentialsRepository.findByUrl("https://new_git");
//        assertTrue(gitCredentials1.isPresent());
//        Mockito.when(principal.getName()).thenReturn("admin_settings");
//        ResponseEntity<Status> statusResponseEntity = adminSettingsRestService.deleteGitCredentials(gitCredentials1.get().getId(), "admin_settings");
//        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
//        gitCredentials1 = gitCredentialsRepository.findByUrl("https://new_git");
//        assertFalse(gitCredentials1.isPresent());
//    }
}