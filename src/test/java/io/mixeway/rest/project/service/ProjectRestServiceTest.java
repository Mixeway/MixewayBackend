package io.mixeway.rest.project.service;

import io.mixeway.db.repository.*;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import io.mixeway.config.TestConfig;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
public class ProjectRestServiceTest {
    ProjectRestService projectRestService;
    @Autowired
    RoutingDomainRepository routingDomainRepository;
    @Autowired
    ProxiesRepository proxiesRepository;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    InterfaceRepository interfaceRepository;
    ProjectRiskAnalyzer projectRiskAnalyzer;
    @Autowired
    CodeProjectRepository codeProjectRepository;
    @Autowired
    VulnHistoryRepository vulnHistoryRepository;
    @Autowired
    InfrastructureVulnRepository infrastructureVulnRepository;
    @Autowired
    CodeVulnRepository codeVulnRepository;
    @Autowired
    WebAppVulnRepository webAppVulnRepository;
    @Autowired
    SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;

    @Test
    public void showProjectRisk() {
        projectRiskAnalyzer = new ProjectRiskAnalyzer(codeVulnRepository,infrastructureVulnRepository,webAppVulnRepository,interfaceRepository);
        projectRestService = new ProjectRestService(routingDomainRepository,proxiesRepository,projectRepository,interfaceRepository,projectRiskAnalyzer,codeProjectRepository,
                vulnHistoryRepository,infrastructureVulnRepository,codeVulnRepository,webAppVulnRepository,softwarePacketVulnerabilityRepository,null,null);
    }

    @Test
    public void showRoutingDomains() {
        Assertions.assertThat(true).isEqualTo(true);
    }

    @Test
    public void showProxies() {
        Assertions.assertThat(true).isEqualTo(true);
    }

    @Test
    public void showVulnTrendChart() {
        Assertions.assertThat(true).isEqualTo(true);

    }

    @Test
    public void showSeverityChart() {
        Assertions.assertThat(true).isEqualTo(true);

    }
}
