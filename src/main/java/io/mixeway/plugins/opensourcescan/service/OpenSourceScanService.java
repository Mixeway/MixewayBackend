package io.mixeway.plugins.opensourcescan.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.ScannerRepository;
import io.mixeway.db.repository.ScannerTypeRepository;
import io.mixeway.plugins.opensourcescan.dependencytrack.apiclient.DependencyTrackApiClient;
import io.mixeway.plugins.opensourcescan.mvndependencycheck.model.SASTRequestVerify;
import io.mixeway.plugins.utils.CodeAccessVerifier;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.project.model.OpenSourceConfig;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Optional;

@Component
public class OpenSourceScanService {
    private final ProjectRepository projectRepository;
    private final CodeAccessVerifier codeAccessVerifier;
    private final ScannerRepository scannerRepository;
    private final ScannerTypeRepository scannerTypeRepository;
    private final VaultHelper vaultHelper;
    //TODO create OpenSourceGeneric client
    private final DependencyTrackApiClient dependencyTrackApiClient;

    OpenSourceScanService(ProjectRepository projectRepository, CodeAccessVerifier codeAccessVerifier, ScannerRepository scannerRepository,
                          ScannerTypeRepository scannerTypeRepository, VaultHelper vaultHelper, DependencyTrackApiClient dependencyTrackApiClient){
        this.projectRepository = projectRepository;
        this.codeAccessVerifier = codeAccessVerifier;
        this.scannerRepository = scannerRepository;
        this.scannerTypeRepository =scannerTypeRepository;
        this.vaultHelper = vaultHelper;
        this.dependencyTrackApiClient = dependencyTrackApiClient;
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

    public void loadVulnerabilities(CodeProject codeProjectToVerify) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        dependencyTrackApiClient.loadVulnerabilities(codeProjectToVerify);
    }
}
