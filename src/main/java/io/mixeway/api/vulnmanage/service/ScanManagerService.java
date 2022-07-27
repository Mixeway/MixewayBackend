package io.mixeway.api.vulnmanage.service;

import io.mixeway.api.vulnmanage.model.*;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.domain.service.asset.FindAssetService;
import io.mixeway.domain.service.infrascan.FindInfraScanService;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import io.mixeway.scanmanager.model.NetworkScanRequestModel;
import io.mixeway.scanmanager.model.WebAppScanRequestModel;
import io.mixeway.scanmanager.service.code.CodeScanService;
import io.mixeway.scanmanager.service.network.NetworkScanService;
import io.mixeway.scanmanager.service.webapp.WebAppScanService;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.codehaus.jettison.json.JSONException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.validation.constraints.Null;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Log4j2
@RequiredArgsConstructor
public class ScanManagerService {
    private final NetworkScanService networkScanService;
    private final WebAppScanService webAppScanService;
    private final CodeScanService codeScanService;
    private final VulnTemplate vulnTemplate;
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;
    private final FindCodeProjectService findCodeProjectService;
    private final FindWebAppService findWebAppService;
    private final FindInterfaceService findInterfaceService;
    private final FindAssetService findAssetService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final FindInfraScanService findInfraScanService;

    ArrayList<String> severitiesNot = new ArrayList<String>() {{
        add("Log");
        add("Info");
    }};

    public ResponseEntity<Status> createScanManageRequest(CreateScanManageRequest createScanManageRequest, Principal principal) throws Exception {
        if (createScanManageRequest.getTestType().equals(Constants.REQUEST_SCAN_NETWORK)){
            return processNetworkScanRequest(createScanManageRequest.getNetworkScanRequest(), principal);
        } else if (createScanManageRequest.getTestType().equals(Constants.REQUEST_SCAN_CODE)){
            return processCodeScanRequest(createScanManageRequest.getCodeScanRequest(),principal);
        } else if (createScanManageRequest.getTestType().equals(Constants.REQUEST_SCAN_WEBAPP)){
            return processWebAppScanRequest(createScanManageRequest.getWebAppScanRequest(),principal);
        } else {
            return new ResponseEntity<>(new Status("Unknown request"), HttpStatus.BAD_REQUEST);
        }
    }

    private ResponseEntity<Status> processWebAppScanRequest(WebAppScanRequestModel webAppScanRequest, Principal principal) {
        try {
            if (webAppScanRequest.getCiid().isPresent()) {
                Optional<Project> projectFromReq = findProjectService.findProjectByCiid(webAppScanRequest.getCiid().get());
                Project project;
                if ( projectFromReq.isPresent()) {
                    project = projectFromReq.get();
                } else {
                    project = getOrCreateProjectService.getProjectId(webAppScanRequest.getCiid().get(),
                            webAppScanRequest.getProjectName().isPresent()? webAppScanRequest.getProjectName().get(): "Autogen name for ciid: "+webAppScanRequest.getCiid().get(),
                            principal);
                }
                return webAppScanService.processScanWebAppRequest(project.getId(), webAppScanRequest.getWebApp(), Constants.STRATEGY_GUI, principal);
            } else {
                return new ResponseEntity<>(new Status("Request contains no information about project. projectName and ciid are required."), HttpStatus.BAD_REQUEST);
            }
        } catch (Exception ex){
            log.error("[Scan Manager] Error during WebApp Scan creation {}", ex.getLocalizedMessage());
            ex.printStackTrace();
            return new ResponseEntity<>(new Status("Request contains no information about project. projectName and ciid are required."), HttpStatus.BAD_REQUEST);
        }
    }

    private ResponseEntity<Status> processCodeScanRequest(CodeScanRequestModel codeScanRequest, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {

        return codeScanService.performScanFromScanManager(codeScanRequest, principal);
    }

    private ResponseEntity<Status> processNetworkScanRequest(NetworkScanRequestModel networkScanRequest, Principal principal) throws Exception {

        return networkScanService.createAndRunNetworkScan(networkScanRequest, principal);
    }

    @Transactional
    public ResponseEntity<Status> checkStatusOfRequestedScan(String requestId) {
        List<Asset> assets = findAssetService.findByRequestId(requestId);
        List<Interface> interfaces = findInterfaceService.findByAssetIn(new ArrayList<>(assets));
        List<CodeProject> codeProjects = findCodeProjectService.findByRequestId(requestId);
        List<WebApp> webApps = findWebAppService.findByRequestId(requestId);
        String status = Constants.STATUS_DONE;

        if (assets.isEmpty() && codeProjects.isEmpty() && webApps.isEmpty())
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        if (interfaces.stream().anyMatch(Interface::isScanRunning))
            status = Constants.STATUS_RUNNING;
        else if (codeProjects.stream().anyMatch((CodeProject::getRunning)))
            status = Constants.STATUS_RUNNING;
        else if (codeProjects.stream().anyMatch(CodeProject::getInQueue))
            status = Constants.STATUS_QUEUED;
        else if (webApps.stream().anyMatch(WebApp::getRunning))
            status = Constants.STATUS_RUNNING;
        else if (webApps.stream().anyMatch(WebApp::getInQueue))
            status = Constants.STATUS_QUEUED;


        return new ResponseEntity<>(new Status(status,requestId), HttpStatus.OK);
    }

    public ResponseEntity<InfraScanMetadata> getMetaDataForProject(String requestId) {
        return null;
    }

    @Transactional
    public ResponseEntity<Vulnerabilities> getVulnerabilitiesForScanByReqeustId(String requestId, Principal principal) throws UnknownHostException {
        List<Asset> assets = findAssetService.findByRequestId(requestId);
        List<CodeProject> codeProjects = findCodeProjectService.findByRequestId(requestId);
        List<WebApp> webApps = findWebAppService.findByRequestId(requestId);
        Vulnerabilities vulnerabilities = new Vulnerabilities();
        List<Vuln> vulnList = new ArrayList<>();
        if (assets.size()>0 && permissionFactory.canUserAccessProject(principal, assets.get(0).getProject())) {
            getInfrastructureVulnerabilities(vulnList, assets);
        } else if (codeProjects.size() >0 && permissionFactory.canUserAccessProject(principal, codeProjects.get(0).getProject())) {
            getCodeVulns(vulnList, codeProjects);
        } else if (webApps.size()>0 && permissionFactory.canUserAccessProject(principal, webApps.get(0).getProject())) {
            getWebAppVulns(vulnList, webApps);
        } else
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);


        vulnerabilities.setVulnerabilities(vulnList);
        return new ResponseEntity<>(vulnerabilities, HttpStatus.OK);
    }

    private List<Vuln> getWebAppVulns(List<Vuln> vulnList, List<WebApp> webApps) throws UnknownHostException {
        List<ProjectVulnerability> webAppVulns = vulnTemplate.projectVulnerabilityRepository.findByWebAppInAndVulnerabilitySource(webApps, vulnTemplate.SOURCE_WEBAPP);
        for (ProjectVulnerability wav : webAppVulns) {
            String hostname, port;
            Vuln v = new Vuln(wav,null,null, new WebApp(), Constants.API_SCANNER_WEBAPP);
            vulnList.add(v);
        }
        return vulnList;
    }

    private List<Vuln> getCodeVulns(List<Vuln> vulnList, List<CodeProject> codeProjects) throws UnknownHostException {
        List<ProjectVulnerability> codeVulns = vulnTemplate.projectVulnerabilityRepository.findByCodeProjectInAndAnalysisNot(codeProjects, Constants.FORTIFY_NOT_AN_ISSUE);
        for (ProjectVulnerability cv : codeVulns) {
            Vuln v = new Vuln(cv,null,null,new CodeProject(),Constants.API_SCANNER_CODE);
            vulnList.add(v);
        }
        return vulnList;
    }

    private List<Vuln> getInfrastructureVulnerabilities(List<Vuln> vulns, List<Asset> assets) throws UnknownHostException {
        List<ProjectVulnerability> projectVulnerabilities;
        try (Stream<ProjectVulnerability> infraVulns = vulnTemplate.projectVulnerabilityRepository
                .findByanInterfaceIn(findInterfaceService.findByAssetIn(new ArrayList<>(assets)))){
            projectVulnerabilities = infraVulns.collect(Collectors.toList());
        }

        for (ProjectVulnerability iv : projectVulnerabilities) {
            Vuln v = new Vuln(iv,null,null,iv.getAnInterface(),Constants.API_SCANNER_OPENVAS);
            vulns.add(v);
        }
        return vulns;
    }

    /**
     * @return list of all security scans with status running
     */
    public ResponseEntity<List<SecurityScans>> getRunningSecurityScans() {
        List<InfraScan> nessusScans = findInfraScanService.findByRunning(true);
        List<WebApp> webApps = findWebAppService.findByRunning(true);
        List<CodeProject> codeProjects = findCodeProjectService.findByRunning(true);
        List<SecurityScans> securityScans = new ArrayList<>();
        for (InfraScan nessusScan : nessusScans){
            securityScans.add(
                    SecurityScans
                            .builder()
                            .scanType("Network Scan")
                            .scope(String.join(",",nessusScan.getInterfaces().stream().map(Interface::getPrivateip).collect(Collectors.toList())))
                            .project(nessusScan.getProject().getName())
                            .build());
        }
        for (WebApp webApp : webApps) {
            securityScans.add(
                    SecurityScans
                            .builder()
                            .scanType("Web App Scan")
                            .scope(webApp.getUrl())
                            .project(webApp.getProject().getName())
                            .build());
        }
        for (CodeProject codeProject : codeProjects) {
            if (codeProject.getProject() != null)
                securityScans.add(
                        SecurityScans
                                .builder()
                                .scanType("Code Repository")
                                .scope(codeProject.getRepoUrl())
                                .project(codeProject.getProject().getName())
                                .build());
        }
        return new ResponseEntity<>(securityScans, HttpStatus.OK);
    }
    /**
     * @return list of all security scans with status running
     */
    public ResponseEntity<List<SecurityScans>> getInQueueSecurityScans() {
        List<InfraScan> nessusScans = findInfraScanService.findByInQueue(true);
        List<WebApp> webApps = findWebAppService.findByInQueue(true);
        List<CodeProject> codeProjects = findCodeProjectService.findByInQueue(true);
        List<SecurityScans> securityScans = new ArrayList<>();
        for (InfraScan nessusScan : nessusScans){
            securityScans.add(
                    SecurityScans
                            .builder()
                            .scanType("Network Scan")
                            .scope(String.join(",",nessusScan.getInterfaces().stream().map(Interface::getPrivateip).collect(Collectors.toList())))
                            .project(nessusScan.getProject().getName())
                            .build());
        }
        for (WebApp webApp : webApps) {
            securityScans.add(
                    SecurityScans
                            .builder()
                            .scanType("Web App Scan")
                            .scope(webApp.getUrl())
                            .project(webApp.getProject().getName())
                            .build());
        }
        for (CodeProject codeProject : codeProjects) {
            try {
                securityScans.add(
                        SecurityScans
                                .builder()
                                .scanType("Code Repository")
                                .scope(codeProject.getRepoUrl())
                                .project(codeProject.getProject().getName())
                                .build());
            } catch (NullPointerException e){
                log.warn("[Scan Manager] Nullpointer during adding security scan for code repository");
            }
        }
        return new ResponseEntity<>(securityScans, HttpStatus.OK);
    }

}
