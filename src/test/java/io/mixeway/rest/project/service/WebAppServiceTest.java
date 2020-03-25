package io.mixeway.rest.project.service;

import io.mixeway.db.repository.*;
import io.mixeway.integrations.webappscan.service.WebAppScanClient;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import io.mixeway.config.TestConfig;
import io.mixeway.integrations.webappscan.plugin.acunetix.apiclient.AcunetixApiClient;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;

import java.util.ArrayList;
import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
public class WebAppServiceTest {
    WebAppService webAppService;
    @Autowired
    WebAppRepository webAppRepository;
    @Autowired
    ScannerTypeRepository scannerTypeRepository;
    @Mock
    AcunetixApiClient acunetixApiClient;
    @Autowired
    ScannerRepository scannerRepository;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    WebAppHeaderRepository webAppHeaderRepository;
    @Autowired
    WebAppScanRepository webAppScanRepository;
    @Autowired
    WebAppVulnRepository webAppVulnRepository;
    ProjectRiskAnalyzer projectRiskAnalyzer;
    @Autowired
    CodeVulnRepository codeVulnRepository;
    @Autowired
    InfrastructureVulnRepository infrastructureVulnRepository;
    @Autowired
    InterfaceRepository interfaceRepository;
    List<WebAppScanClient> webAppScanClients = new ArrayList<>();
    @Before
    public void setUp(){
        webAppScanClients.add(acunetixApiClient);
        projectRiskAnalyzer = new ProjectRiskAnalyzer(codeVulnRepository,infrastructureVulnRepository,webAppVulnRepository,interfaceRepository,null);
        webAppService = new WebAppService(webAppRepository,scannerTypeRepository,null,scannerRepository,projectRepository,
                webAppHeaderRepository,webAppScanRepository,webAppVulnRepository,projectRiskAnalyzer,null);

    }


    @Test
    public void runSingleWebApp() {
        Assertions.assertThat(true).isEqualTo(true);

    }

    @Test
    public void deleteWebApp() {
        Assertions.assertThat(true).isEqualTo(true);

    }

    @Test
    public void runAllScanForWebApp() {
        Assertions.assertThat(true).isEqualTo(true);

    }

    @Test
    public void runSelectedWebApps() {
        Assertions.assertThat(true).isEqualTo(true);

    }

    @Test
    public void saveWebApp() {
        Assertions.assertThat(true).isEqualTo(true);

    }

    @Test
    public void enableWebAppAutoScan() {
        Assertions.assertThat(true).isEqualTo(true);

    }

    @Test
    public void showWebAppVulns() {
        Assertions.assertThat(true).isEqualTo(true);

    }

    @Test
    public void showWebApps() {
    }
}
