package io.mixeway.rest.admin.service;

import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.admin.model.AuthSettingsModel;
import io.mixeway.rest.admin.model.SmtpSettingsModel;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.vault.core.VaultOperations;
import io.mixeway.config.TestConfig;
import io.mixeway.db.entity.Proxies;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.ProxiesRepository;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.pojo.Status;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.transaction.Transactional;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
@Transactional
public class AdminSettingsRestServiceTest {
    @Autowired
    SettingsRepository settingsRepository;
    @Autowired
    RoutingDomainRepository routingDomainRepository;
    @Autowired
    ProxiesRepository proxiesRepository;
    private AdminSettingsRestService adminSettingsRestService;
    @Mock
    VaultHelper vaultHelper;

    @Before
    public void setUp(){
        MockitoAnnotations.initMocks(this);
        adminSettingsRestService = new AdminSettingsRestService(settingsRepository,vaultHelper,null,routingDomainRepository,proxiesRepository,null);
    }


    @Test
    public void getSettings() {
        ResponseEntity<Settings> test = adminSettingsRestService.getSettings();
        Assertions.assertThat(test.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(test.getBody()).isNotNull();

    }

    @Test
    public void updateSmtpSettings() {
        Mockito.when(vaultHelper.savePassword(any(String.class), any(String.class))).thenReturn(true);
        SmtpSettingsModel smtpSettingsModel = new SmtpSettingsModel();
        smtpSettingsModel.setSmtpAuth(true);
        smtpSettingsModel.setSmtpHost("test");
        smtpSettingsModel.setSmtpPassword("dsadsa");
        smtpSettingsModel.setSmtpPort(80);
        smtpSettingsModel.setSmtpTls(true);
        smtpSettingsModel.setSmtpUsername("test");
        ResponseEntity<Status> test = adminSettingsRestService.updateSmtpSettings(smtpSettingsModel,"test");
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        Assertions.assertThat(settings.getSmtpHost()).isEqualTo("test");
        Assertions.assertThat(settings.getSmtpPort()).isEqualTo(80);
        Assertions.assertThat(settings.getSmtpAuth()).isEqualTo(true);
        Assertions.assertThat(settings.getSmtpTls()).isEqualTo(true);
        Assertions.assertThat(settings.getSmtpUsername()).isEqualTo("test");

    }

    @Test
    public void updateAuthSettings() {
        AuthSettingsModel authSettingsModel = new AuthSettingsModel();
        authSettingsModel.setCertificateAuth(true);
        authSettingsModel.setPasswordAuth(false);
        ResponseEntity<Status> test = adminSettingsRestService.updateAuthSettings(authSettingsModel,"test");
        Assertions.assertThat(test.getStatusCode()).isEqualTo(HttpStatus.OK);
        authSettingsModel.setCertificateAuth(false);
        test = adminSettingsRestService.updateAuthSettings(authSettingsModel,"test");
        Assertions.assertThat(test.getStatusCode()).isEqualTo(HttpStatus.EXPECTATION_FAILED);

    }

    @Test
    public void createRoutingDomain() {
        RoutingDomain routingDomain = new RoutingDomain();
        routingDomain.setName("test");
        ResponseEntity<Status> response = adminSettingsRestService.createRoutingDomain(routingDomain,"tes");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    public void deleteRoutingDomain() {
        RoutingDomain routingDomain = new RoutingDomain();
        routingDomain.setName("test");
        ResponseEntity<Status> response = adminSettingsRestService.createRoutingDomain(routingDomain,"tes");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Optional<RoutingDomain> optionalRoutingDomain = Optional.ofNullable(routingDomainRepository.findByName("test"));
        response = adminSettingsRestService.deleteRoutingDomain(optionalRoutingDomain.get().getId(),"test");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        optionalRoutingDomain = Optional.ofNullable(routingDomainRepository.findByName("test"));
        Assertions.assertThat(optionalRoutingDomain.isPresent()).isEqualTo(false);
    }

    @Test
    public void createProxy() {
        Proxies proxies = new Proxies();
        proxies.setDescription("testproxy");
        proxies.setIp("1.1.1.1");
        proxies.setPort("80");
        ResponseEntity<Status> response = adminSettingsRestService.createProxy(proxies,"test");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    public void deleteProxy() {
        Proxies proxies = new Proxies();
        proxies.setDescription("testproxy");
        proxies.setIp("1.1.1.1");
        proxies.setPort("80");
        ResponseEntity<Status> response = adminSettingsRestService.createProxy(proxies,"test");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Optional<Proxies> proxies1 = proxiesRepository.findByIpAndPort("1.1.1.1","80");
        response = adminSettingsRestService.deleteProxy(proxies1.get().getId(),"test");
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        proxies1 = proxiesRepository.findByIpAndPort("1.1.1.1","80");
        Assertions.assertThat(proxies1.isPresent()).isEqualTo(false);
    }

    @Test
    public void generateApiKey() {
        ResponseEntity<Status> response = adminSettingsRestService.generateApiKey("test");
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Assertions.assertThat(settings.getMasterApiKey()).isNotNull();
    }

    @Test
    public void deleteApiKey() {
        ResponseEntity<Status> response = adminSettingsRestService.deleteApiKey("test");
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(settings.getMasterApiKey()).isNull();
    }
}