package io.mixeway.rest.project.service;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.InfrastructureVuln;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.*;
import io.mixeway.pojo.ScanHelper;
import io.mixeway.rest.project.model.AssetCard;
import io.mixeway.rest.project.model.AssetPutModel;
import io.mixeway.rest.project.model.RunScanForAssets;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import static org.mockito.ArgumentMatchers.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractTransactionalJUnit4SpringContextTests;
import org.springframework.test.context.junit4.SpringRunner;
import io.mixeway.config.TestConfig;
import io.mixeway.integrations.infrastructurescan.service.NetworkScanService;
import io.mixeway.pojo.Status;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;


@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
public class AssetServiceTest extends AbstractTransactionalJUnit4SpringContextTests {
    @Autowired
    CodeVulnRepository codeVulnRepository;
    @Autowired
    InfrastructureVulnRepository infrastructureVulnRepository;
    @Autowired
    WebAppVulnRepository webAppVulnRepository;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    InterfaceRepository interfaceRepository;
    ProjectRiskAnalyzer projectRiskAnalyzer;
    @Autowired
    RoutingDomainRepository routingDomainRepository;
    @Autowired
    AssetRepository assetRepository;
    @Mock
    ScanHelper scanHelper;
    @Mock
    NetworkScanService networkScanService;
    @Autowired
    NessusScanRepository nessusScanRepository;


    AssetService assetService;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        assetService = new AssetService(projectRepository,interfaceRepository,routingDomainRepository,assetRepository,
                scanHelper,infrastructureVulnRepository,networkScanService,null);
        createProjectAndAssetAndInterfaces();
    }

    private void createProjectAndAssetAndInterfaces() {
        Project project = new Project();
        project.setName("tes");
        project = projectRepository.save(project);
        //project = projectRepository.findById(project.getId()).get();
        Asset a = new Asset();
        a.setName("test");
        a.setProject(project);
        a.setRoutingDomain(routingDomainRepository.findAll().get(0));
        a = assetRepository.save(a);
        Interface i = new Interface();
        i.setPrivateip("1.1.1.1");
        i.setActive(true);
        i.setRoutingDomain(a.getRoutingDomain());
        i.setAsset(a);
        interfaceRepository.save(i);
        a.setInterfaces(new HashSet<>(interfaceRepository.findAll()));
        project.setAssets(new HashSet<>(assetRepository.findAll()));
        project = projectRepository.save(project);
        assetRepository.save(a);
        InfrastructureVuln iv = new InfrastructureVuln();
        iv.setIntf(i);
        iv.setDescription("testdesc");
        iv.setName("testvuln");
        iv.setSeverity("Critical");
        infrastructureVulnRepository.save(iv);

    }

    @Test
    public void showAssets() {
        ResponseEntity<AssetCard> assets = assetService.showAssets(projectRepository.findAll().get(0).getId(),null);
        Assertions.assertThat(assets.getBody().getAssets().size()).isGreaterThan(0);
        Assertions.assertThat(assets.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void saveAsset() {
        AssetPutModel am = new AssetPutModel();
        am.setAssetName("test2");
        am.setIpAddresses("1.1.1.1,2.2.2.2-2.2.2.4,192.168.1.1/30");
        am.setRoutingDomainForAsset(routingDomainRepository.findAll().get(0).getId());
        Long projectId = projectRepository.findAll().get(0).getId();
        ResponseEntity<Status> response = assetService.saveAsset(projectRepository.findAll().get(0).getId(), am, "test");
        Optional<Asset> a = assetRepository.findByNameAndProject("test2", projectRepository.findById(projectId).get());
        a.get().setInterfaces(new HashSet<>(interfaceRepository.findByAsset(a.get())));
        assetRepository.flush();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Assertions.assertThat(a.isPresent()).isTrue();
        Assertions.assertThat(a.get().getInterfaces().size()).isEqualTo(6);
    }

    @Test
    public void runScanForAssets() {
    }

    @Test
    public void runAllAssetScan() {

    }

    @Test
    public void runSingleAssetScan() {
    }

    @Test
    public void deleteAsset() {
        AssetPutModel am = new AssetPutModel();
        am.setAssetName("test3");
        am.setIpAddresses("1.1.1.1");
        am.setRoutingDomainForAsset(routingDomainRepository.findAll().get(0).getId());
        Long projectId = projectRepository.findAll().get(0).getId();
        ResponseEntity<Status> response = assetService.saveAsset(projectRepository.findAll().get(0).getId(), am, "test");
        Optional<Asset> a = assetRepository.findByNameAndProject("test3", projectRepository.findById(projectId).get());
        Assertions.assertThat(a.isPresent()).isTrue();
        Optional<Interface> i = interfaceRepository.findByAssetAndPrivateip(a.get(),am.getIpAddresses());
        Assertions.assertThat(i.isPresent()).isTrue();
        assetService.deleteAsset(i.get().getId(),"test");
        i = interfaceRepository.findByAssetAndPrivateip(a.get(),am.getIpAddresses());
        Assertions.assertThat(i.isPresent()).isFalse();
    }

    @Test
    public void showInfraVulns() {
        Optional<List<Project>> project = projectRepository.findByName("tes");
        Assertions.assertThat(project.isPresent()).isTrue();
        Assertions.assertThat(project.get().size()).isEqualTo(1);
    }

    @Test
    public void enableInfraAutoScan() {
        Mockito.doNothing().when(networkScanService); // correct
        Optional<List<Project>> project = projectRepository.findByName("tes");
        Assertions.assertThat(project.isPresent()).isTrue();
        Assertions.assertThat(project.get().size()).isEqualTo(1);
        assetService.enableInfraAutoScan(project.get().get(0).getId(),"test");
        project = projectRepository.findByName("tes");
        Assertions.assertThat(project.get().get(0).isAutoInfraScan()).isTrue();
    }
}

