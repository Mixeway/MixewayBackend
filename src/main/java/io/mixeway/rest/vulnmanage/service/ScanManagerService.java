package io.mixeway.rest.vulnmanage.service;

import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.rest.vulnmanage.model.CreateScanManageRequest;
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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ScanManagerService {
    private static final Logger log = LoggerFactory.getLogger(ScanManagerService.class);
    private final AssetRepository assetRepository;
    private final InfrastructureVulnRepository infrastructureVulnRepository;
    private final InterfaceRepository interfaceRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final WebAppRepository webAppRepository;
    private final WebAppVulnRepository webAppVulnRepository;
    private final CodeVulnRepository codeVulnRepository;
    private final NetworkScanService networkScanService;
    private final ProjectRepository projectRepository;
    private final WebAppScanService acunetixService;
    private final CodeScanService codeScanService;


    public ScanManagerService(AssetRepository assetRepository,InfrastructureVulnRepository infrastructureVulnRepository,
                              InterfaceRepository interfaceRepository,CodeProjectRepository codeProjectRepository,
                              WebAppRepository webAppRepository, WebAppVulnRepository webAppVulnRepository,
                              CodeVulnRepository codeVulnRepository, NetworkScanService networkScanService,
                              ProjectRepository projectRepository, WebAppScanService acunetixService,
                              CodeScanService codeScanService){
        this.assetRepository = assetRepository;
        this.infrastructureVulnRepository = infrastructureVulnRepository;
        this.interfaceRepository = interfaceRepository;
        this.webAppRepository = webAppRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.webAppVulnRepository = webAppVulnRepository;
        this.networkScanService = networkScanService;
        this.projectRepository = projectRepository;
        this.acunetixService = acunetixService;
        this.codeScanService = codeScanService;
    }
    public ResponseEntity<Status> createScanManageRequest(CreateScanManageRequest createScanManageRequest) throws Exception {
        if (createScanManageRequest.getTestType().equals(Constants.REQUEST_SCAN_NETWORK)){
            return processNetworkScanRequest(createScanManageRequest.getNetworkScanRequest());
        } else if (createScanManageRequest.getTestType().equals(Constants.REQUEST_SCAN_CODE)){
            return processCodeScanRequest(createScanManageRequest.getCodeScanRequest());
        } else if (createScanManageRequest.getTestType().equals(Constants.REQUEST_SCAN_WEBAPP)){
            return processWebAppScanRequest(createScanManageRequest.getWebAppScanRequest());
        } else {
            return new ResponseEntity<>(new Status("Unknown request"), HttpStatus.BAD_REQUEST);
        }
    }

    private ResponseEntity<Status> processWebAppScanRequest(WebAppScanRequestModel webAppScanRequest) {
        try {
            if (webAppScanRequest.getCiid().isPresent()) {
                Optional<List<Project>> projectFromReq = projectRepository.findByCiid(webAppScanRequest.getCiid().get());
                Project project;
                if (projectFromReq.isPresent()) {
                    project = projectFromReq.get().get(0);
                } else {
                    project = new Project();
                    if (webAppScanRequest.getProjectName().isPresent()){
                        project.setName(webAppScanRequest.getProjectName().get());
                    } else {
                        project.setName("Autogen name for ciid: "+webAppScanRequest.getCiid().get());
                    }
                    project.setCiid(webAppScanRequest.getCiid().get());
                    project.setEnableVulnManage(webAppScanRequest.getEnableVulnManage().isPresent() ? webAppScanRequest.getEnableVulnManage().get() : true);
                    project = projectRepository.save(project);
                }
                return acunetixService.processScanWebAppRequest(project.getId(), webAppScanRequest.getWebApp(), Constants.STRATEGY_GUI);
            } else {
                return new ResponseEntity<>(new Status("Request contains no information about project. projectName and ciid are required."), HttpStatus.BAD_REQUEST);
            }
        } catch (Exception ex){
            return new ResponseEntity<>(new Status("Request contains no information about project. projectName and ciid are required."), HttpStatus.BAD_REQUEST);
        }
    }

    private ResponseEntity<Status> processCodeScanRequest(CodeScanRequestModel codeScanRequest) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {

        return codeScanService.performScanFromScanManager(codeScanRequest);
    }

    private ResponseEntity<Status> processNetworkScanRequest(NetworkScanRequestModel networkScanRequest) throws Exception {

        return networkScanService.createAndRunNetworkScan(networkScanRequest);
    }

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

    public ResponseEntity<Vulnerabilities> getVulnerabilitiesForScanByReqeustId(String requestId) throws UnknownHostException {
        List<Asset> assets = assetRepository.findByRequestId(requestId);
        List<CodeProject> codeProjects = codeProjectRepository.findByRequestId(requestId);
        List<WebApp> webApps = webAppRepository.findByRequestId(requestId);
        Vulnerabilities vulnerabilities = new Vulnerabilities();
        List<Vuln> vulnList = new ArrayList<>();
        if (assets.size()>0)
            vulnList = getInfrastructureVulnerabilities(vulnList, assets);
        else if (codeProjects.size() >0)
            vulnList = getCodeVulns(vulnList, codeProjects);
        else if (webApps.size()>0)
            vulnList=getWebAppVulns(vulnList, webApps);
        else
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);


        vulnerabilities.setVulnerabilities(vulnList);
        return new ResponseEntity<>(vulnerabilities, HttpStatus.OK);
    }

    private List<Vuln> getWebAppVulns(List<Vuln> vulnList, List<WebApp> webApps) throws UnknownHostException {
        List<WebAppVuln> webAppVulns = new ArrayList<>(webAppVulnRepository.findByWebAppIn(new HashSet<>(webApps)));
        for (WebAppVuln wav : webAppVulns) {
            Vuln v = new Vuln();
            v.setVulnerabilityName(wav.getName());
            v.setSeverity(wav.getSeverity());
            v.setDescription(wav.getDescription() + "\n\n" + wav.getRecommendation());
            v.setBaseURL(wav.getWebApp().getUrl());
            v.setLocation(wav.getLocation());
            String ipA = getIpAddressFromUrl(wav.getWebApp().getUrl());
            String ipP = getPortFromUrl(wav.getWebApp().getUrl());
            v.setIpAddress(ipA);
            if (wav.getWebApp().getProject().getCiid() != null && !wav.getWebApp().getProject().getCiid().isEmpty())
                v.setCiid(wav.getWebApp().getProject().getCiid());
            //TODO
            v.setDateCreated(wav.getWebApp().getLastExecuted());
            v.setPort(ipP);
            v.setType(Constants.API_SCANNER_WEBAPP);
            vulnList.add(v);
        }
        return vulnList;
    }

    private List<Vuln> getCodeVulns(List<Vuln> vulnList, List<CodeProject> codeProjects) {
        List<CodeVuln> codeVulns = codeVulnRepository.findByCodeProjectInAndAnalysisNot(codeProjects, Constants.FORTIFY_NOT_AN_ISSUE);
        for (CodeVuln cv : codeVulns) {
            Vuln v = new Vuln();
            v.setVulnerabilityName(cv.getName());
            v.setSeverity(cv.getSeverity());
            //TODO: zrobienie opisu dla fortify
            v.setDescription(cv.getDescription());
            if (cv.getCodeProject() == null) {
                v.setProject(cv.getCodeGroup().getName());
                if (cv.getCodeGroup().getProject().getCiid() != null && !cv.getCodeGroup().getProject().getCiid().isEmpty())
                    v.setCiid(cv.getCodeGroup().getProject().getCiid());
            }
            else {
                v.setProject(cv.getCodeProject().getName());
                if (cv.getCodeProject().getCodeGroup().getProject().getCiid() != null && !cv.getCodeProject().getCodeGroup().getProject().getCiid().isEmpty())
                    v.setCiid(cv.getCodeProject().getCodeGroup().getProject().getCiid());
            }
            v.setLocation(cv.getFilePath());
            v.setAnalysis(cv.getAnalysis());
            v.setDateCreated(cv.getInserted());
            v.setType(Constants.API_SCANNER_CODE);
            vulnList.add(v);
        }
        return vulnList;
    }

    private List<Vuln> getInfrastructureVulnerabilities(List<Vuln> vulns, List<Asset> assets){
        List<InfrastructureVuln> infraVulns = infrastructureVulnRepository
                .findByIntfInAndSeverityNot(interfaceRepository.findByAssetIn(assets),Constants.LOG_SEVERITY);

        for (InfrastructureVuln iv : infraVulns) {
            Vuln v = new Vuln();
            v.setVulnerabilityName(iv.getName());
            v.setSeverity(iv.getSeverity());
            v.setDescription(iv.getDescription());
            try {
                if ( iv.getIntf().getPrivateip() == null && iv.getIntf().getPrivateip().equals("") )
                    v.setIpAddress(iv.getIntf().getFloatingip());
                else
                    v.setIpAddress(iv.getIntf().getPrivateip());
            } catch (NullPointerException e) {
                v.setIpAddress("null ");
            }
            v.setDateCreated(iv.getInserted());
            if (iv.getIntf().getAsset().getProject().getCiid() != null && !iv.getIntf().getAsset().getProject().getCiid().isEmpty())
                v.setCiid(iv.getIntf().getAsset().getProject().getCiid());
            v.setPort(iv.getPort().split("/")[0].trim().replace(" ",""));
            v.setIpProtocol(iv.getPort().split("/")[1].trim().replace(" ",""));
            v.setType(Constants.API_SCANNER_OPENVAS);
            vulns.add(v);
        }
        return vulns;
    }
    private String getPortFromUrl(String url){
        String port = null;
        try {
            port = url.split(":")[2].split("/")[0];
        } catch(Exception e){
            log.debug("Port is not visible on {}", url);
        }
        if (port==null){
            if (url.split(":")[0].equals("http")){
                port="80";
            } else{
                port = "443";
            }
        }
        return port;
    }
    private String getIpAddressFromUrl(String url) {
        String ipA = null;
        Pattern p = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?:\\/\\d{2})?");
        Matcher m = p.matcher(url);
        try {
            if (m.find())
                ipA = m.group(0);
            else {
                String tmp;
                if (url.split("://")[1].contains(":")) {
                    tmp = url.split("://")[1].split(":")[0];
                } else if (url.split("://")[1].contains("/")) {
                    tmp = url.split("://")[1].split("/")[0];
                } else
                    tmp = url.split("://")[1];
                InetAddress address = InetAddress.getByName(tmp);
                ipA = address.getHostAddress();
            }
        }catch (Exception e){
            log.debug("Exception during hostname resolution for {}",url);
        }
        return ipA;
    }
}
