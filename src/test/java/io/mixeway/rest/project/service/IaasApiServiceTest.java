package io.mixeway.rest.project.service;

import io.mixeway.pojo.VaultHelper;
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
import org.springframework.vault.core.VaultOperations;
import io.mixeway.config.TestConfig;
import io.mixeway.db.repository.IaasApiRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.plugins.servicediscovery.openstack.apiclient.OpenStackApiClient;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
public class IaasApiServiceTest {
    IaasApiService iaasApiService;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    RoutingDomainRepository routingDomainRepository;
    @Autowired
    IaasApiRepository iaasApiRepository;
    @Mock
    OpenStackApiClient openStackApiClient;
    @Mock
    VaultHelper vaultHelper;

    @Before
    public void setUp(){

        iaasApiService = new IaasApiService(projectRepository,routingDomainRepository,iaasApiRepository, vaultHelper, openStackApiClient);
    }

    @Test
    public void showIaasApi() {
    }

    @Test
    public void saveIaasApi() {
    }

    @Test
    public void testIaasApi() {
    }

    @Test
    public void iaasApiEnableSynchro() {
    }

    @Test
    public void iaasApiDisableSynchro() {
    }

    @Test
    public void iaasApiDelete() {
    }
}
