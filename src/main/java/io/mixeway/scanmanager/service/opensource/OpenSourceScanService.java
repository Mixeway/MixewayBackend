package io.mixeway.scanmanager.service.opensource;

import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.db.entity.*;
import io.mixeway.domain.service.cioperations.UpdateCiOperationsService;
import io.mixeway.domain.service.opensource.CreateOpenSourceConfigService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.projectvulnerability.DeleteProjectVulnerabilityService;
import io.mixeway.domain.service.projectvulnerability.GetProjectVulnerabilitiesService;
import io.mixeway.domain.service.scanner.GetScannerService;
import io.mixeway.domain.service.softwarepackage.GetOrCreateSoftwarePacketService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.CodeAccessVerifier;
import io.mixeway.scanmanager.model.OSSVulnerabilityModel;
import io.mixeway.scanmanager.model.Projects;
import io.mixeway.scanmanager.model.SASTRequestVerify;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.VulnerabilityModel;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
@Log4j2
@RequiredArgsConstructor
public class OpenSourceScanService {
    private final CodeAccessVerifier codeAccessVerifier;
    private final List<OpenSourceScanClient> openSourceScanClients;
    private final VulnTemplate vulnTemplate;
    private final PermissionFactory permissionFactory;
    private final UpdateCiOperationsService updateCiOperations;
    private final FindProjectService findProjectService;
    private final GetScannerService getScannerService;
    private final CreateOpenSourceConfigService createOpenSourceConfigService;
    private final GetProjectVulnerabilitiesService getProjectVulnerabilitiesService;
    private final GetOrCreateSoftwarePacketService getOrCreateSoftwarePacketService;
    private final DeleteProjectVulnerabilityService deleteProjectVulnerabilityService;

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
    public ResponseEntity<OpenSourceConfig> getOpenSourceScannerConfiguration(Long id, String codeGroup, String codeProject, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyIfCodeProjectInProject(id,codeProject);
        Scanner openSourceScanner = getScannerService.getOpenSourceScanner();
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get()) && sastRequestVerify.getValid() && openSourceScanner!=null) {
            //TODO Fix it so it can be flexible ATM works only for dTrack
            OpenSourceConfig openSourceConfig = createOpenSourceConfigService.create(sastRequestVerify,openSourceScanner);
            return new ResponseEntity<>(openSourceConfig, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
    }

    /**
     * Using configured OpenSource Vulnerability Scanner and loading vulnerabilities for given codeproject
     *
     * @param codeProjectToVerify CodeProject to load opensource vulnerabilities
     */
    @Transactional()
    public void loadVulnerabilities(CodeProject codeProjectToVerify) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {

        for (OpenSourceScanClient openSourceScanClient : openSourceScanClients){
            if (openSourceScanClient.canProcessRequest(codeProjectToVerify)){
                List<ProjectVulnerability> oldVulns = getProjectVulnerabilitiesService.getOldVulnsForCodeProjectAndSource(codeProjectToVerify,vulnTemplate.SOURCE_OPENSOURCE );

                List<Long> vulnsToUpdate = oldVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList());
                if (vulnsToUpdate.size() >  0)
                    vulnTemplate.projectVulnerabilityRepository.updateVulnState(vulnsToUpdate,
                            vulnTemplate.STATUS_REMOVED.getId());
                openSourceScanClient.loadVulnerabilities(codeProjectToVerify);
                updateCiOperations.updateCiOperationsForOpenSource(codeProjectToVerify);
                vulnTemplate.projectVulnerabilityRepository.deleteByStatusAndCodeProjectAndVulnerabilitySource(vulnTemplate.STATUS_REMOVED, codeProjectToVerify, vulnTemplate.SOURCE_OPENSOURCE);
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

    /**
     * Loading vulns from Mixeway scanner push to db
     * @param codeProject project with vulns
     * @param openSourceVulns list of vulns
     */
   // @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void loadVulnsFromCICDToCodeProject(CodeProject codeProject, List<VulnerabilityModel> openSourceVulns) {
        if (openSourceVulns.isEmpty())
            return;
        List<ProjectVulnerability> oldVulns = getProjectVulnerabilitiesService.getOldVulnsForCodeProjectAndSource(codeProject, vulnTemplate.SOURCE_OPENSOURCE);
        List<ProjectVulnerability> vulnToPersist = new ArrayList<>();
        for (VulnerabilityModel oSSVulnerabilityModel : openSourceVulns){
            SoftwarePacket softwarePacket = getOrCreateSoftwarePacketService.getOrCreateSoftwarePacket(oSSVulnerabilityModel.getName(), oSSVulnerabilityModel.getPackageVersion());

            Vulnerability vuln = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerabilityWithDescAndReferences(
                    oSSVulnerabilityModel.getName(), oSSVulnerabilityModel.getDescription(),
                    oSSVulnerabilityModel.getReferences(), oSSVulnerabilityModel.getRecomendations());

            ProjectVulnerability projectVulnerability = new ProjectVulnerability(codeProject, vuln, oSSVulnerabilityModel, softwarePacket, vulnTemplate.SOURCE_OPENSOURCE);
            vulnToPersist.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(oldVulns,vulnToPersist);
        deleteProjectVulnerabilityService.deleteRemovedVulnerabilitiesInCodeProject(codeProject);
        log.info("[CICD] SourceCode - Loading Vulns for {} completed type of DEPENDENCY CHECK", codeProject.getName());
    }

}
