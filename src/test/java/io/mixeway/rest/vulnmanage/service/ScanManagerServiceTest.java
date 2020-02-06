package io.mixeway.rest.vulnmanage.service;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.codescan.service.CodeScanService;
import io.mixeway.plugins.infrastructurescan.model.NetworkScanRequestModel;
import io.mixeway.plugins.webappscan.model.WebAppScanModel;
import io.mixeway.plugins.webappscan.model.WebAppScanRequestModel;
import io.mixeway.rest.vulnmanage.model.CreateScanManageRequest;
import org.assertj.core.api.Assertions;
import org.codehaus.jettison.json.JSONException;
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
import io.mixeway.config.Constants;
import io.mixeway.config.TestConfig;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanService;
import io.mixeway.plugins.webappscan.service.WebAppScanService;
import io.mixeway.pojo.Status;
import io.mixeway.rest.vulnmanage.model.Vulnerabilities;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.transaction.Transactional;
import javax.xml.bind.JAXBException;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
public class ScanManagerServiceTest {
    ScanManagerService scanManagerService;
    @Autowired
    AssetRepository assetRepository;
    @Autowired
    InfrastructureVulnRepository infrastructureVulnRepository;
    @Autowired
    InterfaceRepository interfaceRepository;
    @Autowired
    CodeProjectRepository codeProjectRepository;
    @Autowired
    WebAppRepository webAppRepository;
    @Autowired
    WebAppVulnRepository webAppVulnRepository;
    @Autowired
    CodeVulnRepository codeVulnRepository;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    CodeGroupRepository codeGroupRepository;

    @Autowired
    private EntityManager entityManager;
    @Mock
    NetworkScanService networkScanService;
    @Mock
    WebAppScanService acunetixService;
    @Mock
    CodeScanService codeScanService;
    Boolean toInitialize = true;
    @Before
    public void setUp(){
        if (toInitialize) {
            MockitoAnnotations.initMocks(this);
            this.scanManagerService = new ScanManagerService(assetRepository, infrastructureVulnRepository, interfaceRepository, codeProjectRepository,
                    webAppRepository, webAppVulnRepository, codeVulnRepository, networkScanService, projectRepository, acunetixService, codeScanService);
            this.initializeDB();
        }
    }
    @Transactional
    void initializeDB() {
        Project project = new Project();
        project.setName("testProject");
        project = projectRepository.save(project);
        WebApp webApp = new WebApp();
        webApp.setUrl("https://testurl1.compute1/"+ UUID.randomUUID().toString());
        webApp.setRunning(true);
        webApp.setInQueue(false);
        webApp.setRequestId("00000000-0000-0000-0000-000000000000");
        webApp.setProject(project);
        webApp = webAppRepository.save(webApp);
        WebApp webApp2 = new WebApp();
        webApp2.setUrl("https://testurl2.compute2"+ UUID.randomUUID().toString());
        webApp2.setRunning(false);
        webApp2.setInQueue(false);
        webApp2.setRequestId("00000000-0000-0000-0000-000000000003");
        webApp2.setProject(project);
        webApp2 = webAppRepository.save(webApp2);
        WebAppVuln webAppVuln = new WebAppVuln();
        webAppVuln.setWebApp(webApp);
        webAppVuln.setSeverity(Constants.API_SEVERITY_CRITICAL);
        webAppVuln.setName("testWebAppVuln");
        webAppVulnRepository.save(webAppVuln);
        CodeGroup codeGroup = new CodeGroup();
        codeGroup.setName("testCodeGroup");
        codeGroup.setHasProjects(true);
        codeGroup.setProject(project);
        codeGroupRepository.save(codeGroup);
        CodeProject codeProject = new CodeProject();
        codeProject.setCodeGroup(codeGroup);
        codeProject.setName("tesCodeProject");
        codeProject.setInQueue(false);
        codeProject.setRunning(true);
        codeProject.setRequestId("00000000-0000-0000-0000-000000000001");
        codeProject = codeProjectRepository.save(codeProject);
        CodeProject codeProject2 = new CodeProject();
        codeProject2.setCodeGroup(codeGroup);
        codeProject2.setName("tesCodeProject2");
        codeProject2.setInQueue(false);
        codeProject2.setRunning(false);
        codeProject2.setRequestId("00000000-0000-0000-0000-000000000004");
        codeProjectRepository.save(codeProject2);
        CodeVuln codeVuln = new CodeVuln();
        codeVuln.setCodeGroup(codeGroup);
        codeVuln.setCodeProject(codeProject);
        codeVuln.setAnalysis(Constants.FORTIFY_ANALYSIS_EXPLOITABLE);
        codeVuln.setSeverity(Constants.API_SEVERITY_CRITICAL);
        codeVuln.setName("testCodeVuln");
        codeVulnRepository.save(codeVuln);
        Asset a = new Asset();
        a.setName("test");
        a.setRequestId("00000000-0000-0000-0000-000000000002");
        a.setProject(project);
        a = assetRepository.save(a);
        Asset a2 = new Asset();
        a2.setName("test");
        a2.setRequestId("00000000-0000-0000-0000-000000000005");
        a2.setProject(project);
        a2 = assetRepository.save(a2);
        Interface i2= new Interface();
        i2.setPrivateip("1.1.1.1");
        i2.setActive(true);
        i2.setScanRunning(false);
        i2.setRoutingDomain(a.getRoutingDomain());
        i2.setAsset(a2);
        Interface i = new Interface();
        i.setPrivateip("1.1.1.1");
        i.setActive(true);
        i.setScanRunning(true);
        i.setRoutingDomain(a.getRoutingDomain());
        i.setAsset(a);
        interfaceRepository.save(i);
        InfrastructureVuln iv = new InfrastructureVuln();
        iv.setIntf(i);
        iv.setPort("4443/www/tcp");
        iv.setDescription("testdesc");
        iv.setName("testInfraVuln");
        iv.setSeverity("Critical");
        infrastructureVulnRepository.save(iv);
        toInitialize = false;
    }

    @Test
    public void createScanManageRequest() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, IOException, JAXBException, ParseException {
        Mockito.when(networkScanService.createAndRunNetworkScan(any(NetworkScanRequestModel.class))).thenReturn(new ResponseEntity<>(new Status("OK","1"), HttpStatus.CREATED));
        Mockito.when(acunetixService.processScanWebAppRequest(any(Long.class), anyList())).thenReturn(new ResponseEntity<>(new Status("ok","1"), HttpStatus.CREATED));
        CreateScanManageRequest createScanManageRequest = new CreateScanManageRequest();
        createScanManageRequest.setTestType(Constants.REQUEST_SCAN_WEBAPP);
        WebAppScanRequestModel webAppScanRequestModel = new WebAppScanRequestModel();
        webAppScanRequestModel.setCiid(Optional.of("test"));
        webAppScanRequestModel.setProjectName(Optional.of("testProject"));
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanRequestModel.setWebApp(Arrays.asList(webAppScanModel));
        createScanManageRequest.setWebAppScanRequest(webAppScanRequestModel);
        ResponseEntity<Status> statusResponseEntity = scanManagerService.createScanManageRequest(createScanManageRequest);
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        createScanManageRequest.setTestType(Constants.REQUEST_SCAN_NETWORK);
        createScanManageRequest.setNetworkScanRequest(new NetworkScanRequestModel());
        createScanManageRequest.setWebAppScanRequest(null);
        statusResponseEntity = scanManagerService.createScanManageRequest(createScanManageRequest);
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        createScanManageRequest.setTestType(Constants.REQUEST_SCAN_NETWORK);
    }

    @Test
    public void checkStatusOfRequestedScan() {
        ResponseEntity<Status> statusResponseEntity = scanManagerService.checkStatusOfRequestedScan("00000000-0000-0000-0000-000000000009");
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        statusResponseEntity = scanManagerService.checkStatusOfRequestedScan("00000000-0000-0000-0000-000000000000");
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(statusResponseEntity.getBody().getStatus()).isEqualTo(Constants.STATUS_RUNNING);
        statusResponseEntity = scanManagerService.checkStatusOfRequestedScan("00000000-0000-0000-0000-000000000003");
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(statusResponseEntity.getBody().getStatus()).isEqualTo(Constants.STATUS_DONE);
        statusResponseEntity = scanManagerService.checkStatusOfRequestedScan("00000000-0000-0000-0000-000000000001");
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(statusResponseEntity.getBody().getStatus()).isEqualTo(Constants.STATUS_RUNNING);
        statusResponseEntity = scanManagerService.checkStatusOfRequestedScan("00000000-0000-0000-0000-000000000004");
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(statusResponseEntity.getBody().getStatus()).isEqualTo(Constants.STATUS_DONE);
        statusResponseEntity = scanManagerService.checkStatusOfRequestedScan("00000000-0000-0000-0000-000000000002");
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(statusResponseEntity.getBody().getStatus()).isEqualTo(Constants.STATUS_RUNNING);
        statusResponseEntity = scanManagerService.checkStatusOfRequestedScan("00000000-0000-0000-0000-000000000005");
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(statusResponseEntity.getBody().getStatus()).isEqualTo(Constants.STATUS_DONE);


    }

    @Test
    public void getMetaDataForProject() {
    }

    @Test
    @Transactional
    public void getVulnerabilitiesForScanByReqeustId() throws UnknownHostException {
        ResponseEntity<Vulnerabilities> vulnResponseEntity = scanManagerService.getVulnerabilitiesForScanByReqeustId("d4a020f6-ffdd-11e9-8d71-362b9e155661");
        Assertions.assertThat(vulnResponseEntity.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        vulnResponseEntity = scanManagerService.getVulnerabilitiesForScanByReqeustId("00000000-0000-0000-0000-000000000000");
        Assertions.assertThat(vulnResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(vulnResponseEntity.getBody().getVulnerabilities().stream().findFirst().get().getVulnerabilityName()).isEqualTo("testWebAppVuln");
        vulnResponseEntity = scanManagerService.getVulnerabilitiesForScanByReqeustId("00000000-0000-0000-0000-000000000001");
        Assertions.assertThat(vulnResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(vulnResponseEntity.getBody().getVulnerabilities().stream().findFirst().get().getVulnerabilityName()).isEqualTo("testCodeVuln");
        vulnResponseEntity = scanManagerService.getVulnerabilitiesForScanByReqeustId("00000000-0000-0000-0000-000000000002");
        Assertions.assertThat(vulnResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(vulnResponseEntity.getBody().getVulnerabilities().stream().findFirst().get().getVulnerabilityName()).isEqualTo("testInfraVuln");


    }
}