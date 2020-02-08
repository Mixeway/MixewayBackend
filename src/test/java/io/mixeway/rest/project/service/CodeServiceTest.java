package io.mixeway.rest.project.service;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeVuln;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.codescan.service.CodeScanClient;
import io.mixeway.rest.project.model.CodeCard;
import io.mixeway.rest.project.model.CodeGroupPutModel;
import io.mixeway.rest.project.model.CodeProjectPutModel;
import io.mixeway.rest.project.model.RunScanForCodeProject;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
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
import io.mixeway.config.Constants;
import io.mixeway.config.TestConfig;
import io.mixeway.plugins.codescan.fortify.apiclient.FortifyApiClient;
import io.mixeway.pojo.Status;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.transaction.Transactional;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
@SpringBootTest()
@Transactional
public class CodeServiceTest {
    CodeService codeService;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    CodeProjectRepository codeProjectRepository;
    ProjectRiskAnalyzer projectRiskAnalyzer;
    @Autowired
    CodeGroupRepository codeGroupRepository;
    @Mock
    VaultOperations operations;
    @Mock
    FortifyApiClient fortifyApiClient;
    @Autowired
    CodeVulnRepository codeVulnRepository;
    @Autowired
    InfrastructureVulnRepository infrastructureVulnRepository;
    @Autowired
    WebAppVulnRepository webAppVulnRepository;
    @Autowired
    InterfaceRepository interfaceRepository;
    List<CodeScanClient> codeScanClients = new ArrayList<>();
    @Before
    public void setUp(){
        MockitoAnnotations.initMocks(this);
        codeScanClients.add(fortifyApiClient);
        projectRiskAnalyzer = new ProjectRiskAnalyzer(codeVulnRepository,infrastructureVulnRepository,webAppVulnRepository,interfaceRepository);
        codeService = new CodeService(projectRepository,codeProjectRepository,projectRiskAnalyzer,codeGroupRepository,operations,codeScanClients,codeVulnRepository,null,
                null, null);
        initializeDB();
    }

    private void initializeDB() {
        Project project = new Project();
        project.setName("test");
        projectRepository.save(project);
        CodeGroup codeGroup = new CodeGroup();
        codeGroup.setName("testCodeGroup");
        codeGroup.setHasProjects(true);
        codeGroup.setProject(project);
        codeGroupRepository.save(codeGroup);
        CodeProject codeProject = new CodeProject();
        codeProject.setCodeGroup(codeGroup);
        codeProject.setName("tesCodeProject");
        codeProjectRepository.save(codeProject);
        CodeVuln codeVuln = new CodeVuln();
        codeVuln.setCodeGroup(codeGroup);
        codeVuln.setCodeProject(codeProject);
        codeVuln.setAnalysis(Constants.FORTIFY_ANALYSIS_EXPLOITABLE);
        codeVuln.setSeverity(Constants.API_SEVERITY_CRITICAL);
        codeVuln.setName("testCodeVuln");
        codeVulnRepository.save(codeVuln);
        project.setCodes(new HashSet<>(codeGroupRepository.findAll()));
        projectRepository.save(project);
        codeGroup.setProjects(new HashSet<>(codeProjectRepository.findAll()));
        codeGroupRepository.save(codeGroup);
        codeProject.setVulns(new HashSet<>(codeVulnRepository.findAll()));
        codeProjectRepository.save(codeProject);

    }

    @Test
    public void showCodeRepos() {
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(project.isPresent()).isTrue();
        ResponseEntity<CodeCard> test = codeService.showCodeRepos(project.get().getId());
        Assertions.assertThat(test.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(test.getBody().getCodeModels().size()).isEqualTo(1);
    }

    @Test
    public void showCodeGroups() {
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(project.isPresent()).isTrue();
        ResponseEntity<List<CodeGroup>> test = codeService.showCodeGroups(project.get().getId());
        Assertions.assertThat(test.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(test.getBody().size()).isEqualTo(1);
    }

    @Test
    public void saveCodeGroup() {
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(project.isPresent()).isTrue();
        CodeGroupPutModel codeGroupPutModel = new CodeGroupPutModel();
        codeGroupPutModel.setAutoScan(false);
        codeGroupPutModel.setChilds(true);
        codeGroupPutModel.setCodeGroupName("https://test.com");
        codeGroupPutModel.setGitpassword("test");
        codeGroupPutModel.setGitusername("test");
        codeGroupPutModel.setCodeGroupName("testCodeGroup2");
        ResponseEntity<Status> test = codeService.saveCodeGroup(project.get().getId(),codeGroupPutModel,"test");
        Assertions.assertThat(test.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    public void saveCodeProject() {
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(project.isPresent()).isTrue();
        CodeProjectPutModel codeProjectPutModel = new CodeProjectPutModel();
        codeProjectPutModel.setCodeGroup(project.get().getCodes().stream().findFirst().get().getId());
        codeProjectPutModel.setProjectTech("MVN");
        codeProjectPutModel.setCodeProjectName("testCodeProjectSaved");
        codeProjectPutModel.setBranch("master");
        codeProjectPutModel.setProjectGiturl("https://test.com");
        ResponseEntity<Status> test = codeService.saveCodeProject(project.get().getId(),codeProjectPutModel,"test");
        Assertions.assertThat(test.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        test = codeService.saveCodeProject(666L,codeProjectPutModel,"test");
        Assertions.assertThat(test.getStatusCode()).isEqualTo(HttpStatus.EXPECTATION_FAILED);
    }

    @Test
    public void runSelectedCodeProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(project.isPresent()).isTrue();
        Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(project.get().getCodes().stream().findFirst().get(), "tesCodeProject");
        List<RunScanForCodeProject> runScanForCodeProjects = new ArrayList<>();
        ResponseEntity<Status> statusResponseEntity = codeService.runSelectedCodeProjects(project.get().getId(),runScanForCodeProjects,"test");
        Assertions.assertThat(statusResponseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);


    }

    @Test
    public void enableAutoScanForCodeProjects() {
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(project.isPresent()).isTrue();
        ResponseEntity<Status> i = codeService.enableAutoScanForCodeProjects(project.get().getId(),"test");
        project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(i.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(project.get().isAutoCodeScan()).isTrue();
    }

    @Test
    public void runSingleCodeProjectScan() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        //Mockito.when(fortifyApiClient.runScan())
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(project.isPresent()).isTrue();
        Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(project.get().getCodes().stream().findFirst().get(), "tesCodeProject");
        Assertions.assertThat(project.isPresent()).isTrue();
        ResponseEntity<Status> test = codeService.runSingleCodeProjectScan(codeProject.get().getId(),"tets");
        Assertions.assertThat(test.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void deleteCodeProject() {
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(project.get().getCodes().stream().findFirst().get(), "tesCodeProject");
        Assertions.assertThat(project.isPresent()).isTrue();
        Assertions.assertThat(codeProject.isPresent()).isTrue();
        ResponseEntity<Status> response =codeService.deleteCodeProject(codeProject.get().getId(),"test");
        codeProject = codeProjectRepository.findByCodeGroupAndName(project.get().getCodes().stream().findFirst().get(), "tesCodeProject");
        Assertions.assertThat(codeProject.isPresent()).isFalse();
    }

    @Test
    public void showCodeVulns() {
        Optional<Project> project = Optional.of(projectRepository.findByName("test").get().get(0));
        Assertions.assertThat(project.isPresent()).isTrue();
        ResponseEntity<List<CodeVuln>> i = codeService.showCodeVulns(project.get().getId());
        Assertions.assertThat(i.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(i.getBody().size()).isEqualTo(1);
    }
}
