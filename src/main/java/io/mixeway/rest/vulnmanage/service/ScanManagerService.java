package io.mixeway.rest.vulnmanage.service;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.rest.vulnmanage.model.CreateScanManageRequest;
import io.mixeway.rest.vulnmanage.model.SecurityScans;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.config.Constants;
import io.mixeway.integrations.codescan.model.CodeScanRequestModel;
import io.mixeway.integrations.codescan.service.CodeScanService;
import io.mixeway.integrations.infrastructurescan.model.NetworkScanRequestModel;
import io.mixeway.integrations.infrastructurescan.service.NetworkScanService;
import io.mixeway.integrations.webappscan.service.WebAppScanService;
import io.mixeway.integrations.webappscan.model.WebAppScanRequestModel;
import io.mixeway.pojo.InfraScanMetadata;
import io.mixeway.pojo.Status;
import io.mixeway.rest.vulnmanage.model.Vuln;
import io.mixeway.rest.vulnmanage.model.Vulnerabilities;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class ScanManagerService {
    private static final Logger log = LoggerFactory.getLogger(ScanManagerService.class);
    private final AssetRepository assetRepository;
    private final InterfaceRepository interfaceRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final WebAppRepository webAppRepository;
    private final NetworkScanService networkScanService;
    private final ProjectRepository projectRepository;
    private final WebAppScanService acunetixService;
    private final CodeScanService codeScanService;
    private final VulnTemplate vulnTemplate;
    private final PermissionFactory permissionFactory;
    private final NessusScanRepository nessusScanRepository;
    ArrayList<String> severitiesNot = new ArrayList<String>() {{
        add("Log");
        add("Info");
    }};

    public ScanManagerService(AssetRepository assetRepository,
                              InterfaceRepository interfaceRepository,CodeProjectRepository codeProjectRepository,
                              WebAppRepository webAppRepository, VulnTemplate vulnTemplate, NetworkScanService networkScanService,
                              ProjectRepository projectRepository, WebAppScanService acunetixService,
                              CodeScanService codeScanService, PermissionFactory permissionFactory,
                              NessusScanRepository nessusScanRepository){
        this.assetRepository = assetRepository;
        this.interfaceRepository = interfaceRepository;
        this.webAppRepository = webAppRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.networkScanService = networkScanService;
        this.projectRepository = projectRepository;
        this.acunetixService = acunetixService;
        this.codeScanService = codeScanService;
        this.vulnTemplate = vulnTemplate;
        this.permissionFactory = permissionFactory;
        this.nessusScanRepository = nessusScanRepository;
    }
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
                Optional<List<Project>> projectFromReq = projectRepository.findByCiid(webAppScanRequest.getCiid().get());
                Project project;
                if ( projectFromReq.isPresent() && projectFromReq.get().size() > 0) {
                    project = projectFromReq.get().get(0);
                } else {
                    project = new Project();
                    if (webAppScanRequest.getProjectName().isPresent()){
                        project.setName(webAppScanRequest.getProjectName().get());
                    } else {
                        project.setName("Autogen name for ciid: "+webAppScanRequest.getCiid().get());
                    }
                    project.setOwner(permissionFactory.getUserFromPrincipal(principal));
                    project.setCiid(webAppScanRequest.getCiid().get());
                    project.setEnableVulnManage(webAppScanRequest.getEnableVulnManage().isPresent() ? webAppScanRequest.getEnableVulnManage().get() : true);
                    project = projectRepository.save(project);
                    permissionFactory.grantPermissionToProjectForUser(project,principal);
                }
                return acunetixService.processScanWebAppRequest(project.getId(), webAppScanRequest.getWebApp(), Constants.STRATEGY_GUI, principal);
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
        List<Asset> assets = assetRepository.findByRequestId(requestId);
        List<Interface> interfaces = interfaceRepository.findByAssetIn(assets);
        List<CodeProject> codeProjects = codeProjectRepository.findByRequestId(requestId);
        List<WebApp> webApps = webAppRepository.findByRequestId(requestId);
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
        List<Asset> assets = assetRepository.findByRequestId(requestId);
        List<CodeProject> codeProjects = codeProjectRepository.findByRequestId(requestId);
        List<WebApp> webApps = webAppRepository.findByRequestId(requestId);
        Vulnerabilities vulnerabilities = new Vulnerabilities();
        List<Vuln> vulnList = new ArrayList<>();
        if (assets.size()>0 && permissionFactory.canUserAccessProject(principal, assets.get(0).getProject()))
            vulnList = getInfrastructureVulnerabilities(vulnList, assets);
        else if (codeProjects.size() >0 && permissionFactory.canUserAccessProject(principal, codeProjects.get(0).getCodeGroup().getProject()))
            vulnList = getCodeVulns(vulnList, codeProjects);
        else if (webApps.size()>0 && permissionFactory.canUserAccessProject(principal, webApps.get(0).getProject()))
            vulnList=getWebAppVulns(vulnList, webApps);
        else
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
                .findByanInterfaceIn(interfaceRepository.findByAssetIn(assets))){
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
        List<NessusScan> nessusScans = nessusScanRepository.findByRunning(true);
        List<WebApp> webApps = webAppRepository.findByRunning(true);
        List<CodeProject> codeProjects = codeProjectRepository.findByRunning(true);
        List<SecurityScans> securityScans = new ArrayList<>();
        for (NessusScan nessusScan : nessusScans){
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
            securityScans.add(
                    SecurityScans
                            .builder()
                            .scanType("Code Repository")
                            .scope(codeProject.getRepoUrl())
                            .project(codeProject.getCodeGroup().getProject().getName())
                            .build());
        }
        return new ResponseEntity<>(securityScans, HttpStatus.OK);
    }
    /**
     * @return list of all security scans with status running
     */
    public ResponseEntity<List<SecurityScans>> getInQueueSecurityScans() {
        List<NessusScan> nessusScans = nessusScanRepository.findByInQueue(true);
        List<WebApp> webApps = webAppRepository.findByInQueue(true);
        List<CodeProject> codeProjects = codeProjectRepository.findByInQueue(true);
        List<SecurityScans> securityScans = new ArrayList<>();
        for (NessusScan nessusScan : nessusScans){
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
            securityScans.add(
                    SecurityScans
                            .builder()
                            .scanType("Code Repository")
                            .scope(codeProject.getRepoUrl())
                            .project(codeProject.getCodeGroup().getProject().getName())
                            .build());
        }
        return new ResponseEntity<>(securityScans, HttpStatus.OK);
    }

}
