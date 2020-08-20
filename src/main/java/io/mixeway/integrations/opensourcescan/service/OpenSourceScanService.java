package io.mixeway.integrations.opensourcescan.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.opensourcescan.model.Projects;
import io.mixeway.integrations.opensourcescan.plugins.mvndependencycheck.model.SASTRequestVerify;
import io.mixeway.integrations.utils.CodeAccessVerifier;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.cioperations.service.CiOperationsService;
import io.mixeway.rest.project.model.CodeGroupPutModel;
import io.mixeway.rest.project.model.OpenSourceConfig;
import io.mixeway.rest.project.service.CodeService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Component
public class OpenSourceScanService {
    private final ProjectRepository projectRepository;
    private final CodeAccessVerifier codeAccessVerifier;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final VaultHelper vaultHelper;
    private final List<OpenSourceScanClient> openSourceScanClients;
    private final VulnTemplate vulnTemplate;
    private final CodeProjectRepository codeProjectRepository;
    private final CodeService codeService;
    private static final Logger log = LoggerFactory.getLogger(OpenSourceScanService.class);
    OpenSourceScanService(ProjectRepository projectRepository, CodeAccessVerifier codeAccessVerifier, ScannerRepository scannerRepository,
                          ScannerTypeRepository scannerTypeRepository, VaultHelper vaultHelper, List<OpenSourceScanClient> openSourceScanClients,
                          VulnTemplate vulnTemplate,CodeProjectRepository codeProjectRepository, @Lazy CodeService codeService){
        this.projectRepository = projectRepository;
        this.codeAccessVerifier = codeAccessVerifier;
        this.scannerRepository = scannerRepository;
        this.scannerTypeRepository =scannerTypeRepository;
        this.vaultHelper = vaultHelper;
        this.openSourceScanClients = openSourceScanClients;
        this.vulnTemplate = vulnTemplate;
        this.codeProjectRepository = codeProjectRepository;
        this.codeService = codeService;
    }


    /**
     * Method witch get information about configured OpenSource scanner which is proper for particular project
     * and check if project can is integrated with OpenSource scanner.
     * Data shared in response is:
     * Scanner URL
     * Scanner API KEY
     * Project dTrack projectId
     * @param id of Project
     * @param codeGroup name of CodeGroup to be checked
     * @param codeProject name of CodeProject ot be Checked
     * @return
     */
    public ResponseEntity<OpenSourceConfig> getOpenSourceScannerConfiguration(Long id, String codeGroup, String codeProject) {
        Optional<Project> project = projectRepository.findById(id);
        SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyPermissions(id,codeGroup,codeProject,true);
        if (project.isPresent() && sastRequestVerify.getValid()) {
            //TODO Fix it so it can be flexible ATM works only for dTrack
            Scanner openSourceScanner = scannerRepository
                    .findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_DEPENDENCYTRACK))
                    .stream()
                    .findFirst()
                    .orElse(null);
            OpenSourceConfig openSourceConfig = new OpenSourceConfig();
            if (StringUtils.isNotBlank(sastRequestVerify.getCp().getdTrackUuid()) && openSourceScanner != null){
                openSourceConfig.setOpenSourceScannerApiUrl(openSourceScanner.getApiUrl());
                openSourceConfig.setOpenSourceScannerCredentials(vaultHelper.getPassword(openSourceScanner.getApiKey()));
                openSourceConfig.setOpenSourceScannerProjectId(sastRequestVerify.getCp().getdTrackUuid());
                openSourceConfig.setTech(sastRequestVerify.getCp().getTechnique());
                openSourceConfig.setScannerType(openSourceScanner.getScannerType().getName());
                openSourceConfig.setOpenSourceScannerIntegration(true);
            } else {
                openSourceConfig.setOpenSourceScannerIntegration(false);
            }
            return new ResponseEntity<>(openSourceConfig, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
    }

    /**
     * Based on Repo URL create project, codeproject or return already existing
     *
     * @param url repo url
     * @return codeproject
     */
    public CodeProject getCodeProjectByRepoUrl(String url, String branch) throws Exception {
        URL repoUrl = new URL(url.split("\\.git")[0]);
        String projectName, codeProjectName = null;
        String[] repoUrlParts = repoUrl.getPath().split("/");
        // If url contains both Organization and Project Name
        if (repoUrlParts.length == 3){
            projectName = repoUrlParts[1];
            codeProjectName = repoUrlParts[2] +"_"+branch;
            Optional<CodeProject> codeProject = codeProjectRepository.findByNameAndBranch(codeProjectName, branch);
            //If CodeProject with name already exists
            if (codeProject.isPresent()){
                return codeProject.get();
            }
            // else Create CodeProject and possibliy project
            else {
                Optional<Project> project = projectRepository.getProjectByName(projectName);
                // If project exist only add codeproject to it
                if (project.isPresent() ){
                    codeService.saveCodeGroup(
                            project.get().getId(),
                            new CodeGroupPutModel(codeProjectName, url, false, false, branch),
                            Constants.CICD);
                    Optional<CodeProject> justCreatedCodeProject = codeProjectRepository.findByNameAndBranch(codeProjectName, branch);
                    if (justCreatedCodeProject.isPresent()){
                        log.info("CICD job - Project present, CodeProject just created");
                        return justCreatedCodeProject.get();
                    } else{
                        throw new Exception("Just created codeProject is not present");
                    }

                } else {
                    Project projectToCreate = projectRepository
                            .save(new Project(
                                    projectName + "_" + branch,
                                    "Project created by CICD, branch: "+branch,
                                    false,
                                    "none"));
                    codeService.saveCodeGroup(
                            projectToCreate.getId(),
                            new CodeGroupPutModel(codeProjectName, url, false, false, branch),
                            Constants.CICD);
                    Optional<CodeProject> justCreatedCodeProject = codeProjectRepository.findByNameAndBranch(codeProjectName, branch);
                    if (justCreatedCodeProject.isPresent()){
                        log.info("CICD job - Project just created, CodeProject just created");
                        return justCreatedCodeProject.get();
                    } else{
                        throw new Exception("Just created codeProject is not present");
                    }
                }
            }

        } else if (repoUrlParts.length == 2){
            codeProjectName = repoUrlParts[1] + "_" + branch;
            Optional<CodeProject> codeProject = codeProjectRepository.findByNameAndBranch(codeProjectName, branch);
            if (codeProject.isPresent()) {
                return codeProject.get();
            } else {
                Optional<Project> project = projectRepository.getProjectByName("unknown");
                if (project.isPresent()){
                    codeService.saveCodeGroup(
                            project.get().getId(),
                            new CodeGroupPutModel(codeProjectName, url, false, false,branch),
                            Constants.CICD);
                    Optional<CodeProject> justCreatedCodeProject = codeProjectRepository.findByNameAndBranch(codeProjectName, branch);
                    if (justCreatedCodeProject.isPresent()){
                        log.info("CICD job - Project present (unknown), CodeProject just created");
                        return justCreatedCodeProject.get();
                    } else{
                        throw new Exception("Just created codeProject is not present");
                    }
                } else {
                    Project projectToCreate = projectRepository
                            .save(new Project(
                                    "unknown",
                                    "unknown project (created by CICD)",
                                    false,
                                    "none"));
                    codeService.saveCodeGroup(
                            projectToCreate.getId(),
                            new CodeGroupPutModel(codeProjectName, url, false, false,branch),
                            Constants.CICD);
                    Optional<CodeProject> justCreatedCodeProject = codeProjectRepository.findByNameAndBranch(codeProjectName,branch);
                    if (justCreatedCodeProject.isPresent()){
                        log.info("CICD job - Project just created, CodeProject just created");
                        return justCreatedCodeProject.get();
                    } else{
                        throw new Exception("Just created codeProject is not present");
                    }
                }
            }

        } else {
            throw new Exception("Unknown Repo Url format " + url);
        }
    }

    /**
     * Using configured OpenSource Vulnerability Scanner and loading vulnerabilities for given codeproject
     *
     * @param codeProjectToVerify CodeProject to load opensource vulnerabilities
     */
    @Async
    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void loadVulnerabilities(CodeProject codeProjectToVerify) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        for (OpenSourceScanClient openSourceScanClient : openSourceScanClients){
            if (openSourceScanClient.canProcessRequest(codeProjectToVerify)){
                List<ProjectVulnerability> oldVulns = vulnTemplate.projectVulnerabilityRepository.
                        findByCodeProjectAndVulnerabilitySource(codeProjectToVerify, vulnTemplate.SOURCE_OPENSOURCE).collect(Collectors.toList());
                List<Long> vulnsToUpdate = oldVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList());
                if (vulnsToUpdate.size() >  0)
                    vulnTemplate.projectVulnerabilityRepository.updateVulnState(vulnsToUpdate,
                            vulnTemplate.STATUS_REMOVED.getId());
                openSourceScanClient.loadVulnerabilities(codeProjectToVerify);
                vulnTemplate.projectVulnerabilityRepository.deleteByStatusAndCodeProject(vulnTemplate.STATUS_REMOVED, codeProjectToVerify);
                break;
            }
        }
    }

    /**
     * Using configured OpenSource Vulnerability Scanner and geting defined properties
     *
     */
    public List<Projects> getOpenSourceProjectFromScanner() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        for (OpenSourceScanClient openSourceScanClient : openSourceScanClients){
            if (openSourceScanClient.canProcessRequest()){
                return openSourceScanClient.getProjects();
            }
        }
        return new ArrayList<>();
    }

    /**
     * Method is using OpenSource Scanner REST API in order to create Project and save id to codeProject
     *
     * @param codeProject which will be used to create informations on OpenSource Scanner instance
     * @return true if project is created
     */
    public boolean createProjectOnOpenSourceScanner(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        for (OpenSourceScanClient openSourceScanClient : openSourceScanClients){
            if (openSourceScanClient.canProcessRequest()){
                return openSourceScanClient.createProject(codeProject);
            }
        }
        return false;
    }

}
