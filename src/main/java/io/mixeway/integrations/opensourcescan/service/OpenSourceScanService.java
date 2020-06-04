package io.mixeway.integrations.opensourcescan.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.opensourcescan.model.Projects;
import io.mixeway.integrations.opensourcescan.plugins.mvndependencycheck.model.SASTRequestVerify;
import io.mixeway.integrations.utils.CodeAccessVerifier;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.project.model.OpenSourceConfig;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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

    OpenSourceScanService(ProjectRepository projectRepository, CodeAccessVerifier codeAccessVerifier, ScannerRepository scannerRepository,
                          ScannerTypeRepository scannerTypeRepository, VaultHelper vaultHelper, List<OpenSourceScanClient> openSourceScanClients,
                          VulnTemplate vulnTemplate){
        this.projectRepository = projectRepository;
        this.codeAccessVerifier = codeAccessVerifier;
        this.scannerRepository = scannerRepository;
        this.scannerTypeRepository =scannerTypeRepository;
        this.vaultHelper = vaultHelper;
        this.openSourceScanClients = openSourceScanClients;
        this.vulnTemplate = vulnTemplate;
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
     * Using configured OpenSource Vulnerability Scanner and loading vulnerabilities for given codeproject
     *
     * @param codeProjectToVerify CodeProject to load opensource vulnerabilities
     */
    public void loadVulnerabilities(CodeProject codeProjectToVerify) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        for (OpenSourceScanClient openSourceScanClient : openSourceScanClients){
            if (openSourceScanClient.canProcessRequest(codeProjectToVerify)){
                List<Long> vulnsToUpdate = vulnTemplate.projectVulnerabilityRepository.
                        findByCodeProjectAndVulnerabilitySource(codeProjectToVerify, vulnTemplate.SOURCE_OPENSOURCE).map(ProjectVulnerability::getId).collect(Collectors.toList());
                if (vulnsToUpdate.size() >  0)
                    vulnTemplate.projectVulnerabilityRepository.updateVulnState(vulnsToUpdate,
                            vulnTemplate.STATUS_REMOVED.getId());
                openSourceScanClient.loadVulnerabilities(codeProjectToVerify);
                vulnTemplate.projectVulnerabilityRepository.deleteByStatus(vulnTemplate.STATUS_REMOVED);
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
