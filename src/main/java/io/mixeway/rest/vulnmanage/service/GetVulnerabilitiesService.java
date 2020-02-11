package io.mixeway.rest.vulnmanage.service;

import com.google.gson.Gson;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.pojo.*;
import io.mixeway.rest.vulnmanage.model.Vuln;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.plugins.webappscan.acunetix.apiclient.AcunetixApiClient;
import io.mixeway.plugins.infrastructurescan.nessus.apiclient.NessusApiClient;
import io.mixeway.plugins.infrastructurescan.openvas.apiclient.OpenVasApiClient;
import io.mixeway.rest.vulnmanage.model.Vulnerabilities;
import org.springframework.transaction.annotation.Transactional;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class GetVulnerabilitiesService {
    private static final Logger log = LoggerFactory.getLogger(GetVulnerabilitiesService.class);
    @Autowired
    OpenVasApiClient openVasApiClient;
    @Autowired
    NessusApiClient nessusApiClient;
    @Autowired
    NessusScanTemplateRepository nessusScanTemplateRepository;
    @Autowired
    ApiTypeRepository apiTypeRepository;
    @Autowired
    ScannerRepository nessusRepository;
    @Autowired
    RoutingDomainRepository routingDomainRepository;
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    ApiPermisionRepository apiPermisionRepository;
    @Autowired
    NodeRepository nodeRepository;
    @Autowired
    NodeAuditRepository nodeAuditRepository;
    @Autowired
    RequirementRepository requirementRepository;
    @Autowired
    ActivityRepository activityRepository;
    @Autowired
    WebAppRepository waRepository;
    @Autowired
    WebAppHeaderRepository webAppHeaderRepository;
    @Autowired
    InterfaceRepository interfaceRepository;
    @Autowired
    AssetRepository assetRepository;
    @Autowired
    SoftwarePacketRepository softwarePacketRepository;
    @Autowired
    ScannerRepository scannerRepository;
    @Autowired
    ScannerTypeRepository scannerTypeRepository;
    @Autowired
    AcunetixApiClient acunetixApiClient;
    @Autowired
    InfrastructureVulnRepository infrastractureVulnRepository;
    @Autowired
    WebAppVulnRepository webAppVulnRepository;
    @Autowired
    CodeVulnRepository codeVulnRepository;
    @Autowired
    NessusScanRepository nessusScanRepository;
    @Autowired
    SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityReposutitory;
    @Autowired
    CodeProjectRepository codeProjectRepository;
    @Autowired
    CiOperationsRepository ciOperationsRepository;
    @Autowired
    StatusRepository statusRepository;
    @Autowired
    ServiceRepository serviceRepository;
    @Autowired
    CodeGroupRepository codeGroupRepository;
    @Autowired
    SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;

    DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private final List<String> scannerTypes = Arrays.asList(Constants.API_SCANNER_AUDIT, Constants.API_SCANNER_CODE, Constants.API_SCANNER_OPENVAS,
            Constants.API_SCANNER_PACKAGE,Constants.API_SCANNER_WEBAPP);
    private final List<String> severities = Arrays.asList(Constants.API_SEVERITY_CRITICAL,Constants.API_SEVERITY_HIGH, Constants.API_SEVERITY_INFO,
            Constants.API_SEVERITY_LOW, Constants.API_SEVERITY_MEDIUM);

    @Transactional
    public ResponseEntity<Vulnerabilities> getAllVulnerabilities() throws UnknownHostException {
        Vulnerabilities vulns = new Vulnerabilities();
        log.debug("Vulnerabilities access granted: ");
        List<Vuln> vulnList = new ArrayList<>();
        vulns.setVulnerabilities(vulnList);
        vulns = setInfrastructureVulns(vulns,null);
        vulns = setWebApplicationVulns(vulns,null);
        vulns = setCodeVulns(vulns,null);
        vulns = setAuditResults(vulns,null);
        vulns = setPackageVulns(vulns,null);
        return new ResponseEntity<>(vulns, HttpStatus.OK);
    }
    private Vulnerabilities setPackageVulns(Vulnerabilities vulns, Project project) {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<SoftwarePacketVulnerability> softVuln = null;
        if (project != null)
            softVuln = new ArrayList<SoftwarePacketVulnerability>();
        else
            softVuln = softwarePacketVulnerabilityReposutitory.findAll();
        for (SoftwarePacketVulnerability spv : softVuln) {
            for (Asset a : spv.getSoftwarepacket().getAssets()) {
                Vuln v = new Vuln();
                v.setType(Constants.API_SCANNER_PACKAGE);
                v.setVulnerabilityName(spv.getName());
                v.setSeverity(setSeverity(spv.getScore()));
                v.setDescription(spv.getFix());
                v.setHostname(a.getName());
                if (a.getProject().getCiid() != null && !a.getProject().getCiid().isEmpty())
                	v.setCiid(a.getProject().getCiid());
                v.setDateCreated(spv.getInserted());
                Optional<Interface> interfaceToAdd = a.getInterfaces().stream().findFirst();
                interfaceToAdd.ifPresent(anInterface -> v.setIpAddress(anInterface.getPrivateip()));
                v.setPacketName(spv.getSoftwarepacket().getName());
                tmpVulns.add(v);
            }
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }
    private String setSeverity(Double score) {
        if (score < 1)
            return Constants.API_SEVERITY_INFO;
        else if (score > 1 && score < 3)
            return Constants.API_SEVERITY_LOW;
        else if (score >3 && score <5)
            return Constants.API_SEVERITY_MEDIUM;
        else if (score > 5 && score < 8)
            return Constants.API_SEVERITY_HIGH;
        else
            return Constants.API_SEVERITY_CRITICAL;
    }
    private Vulnerabilities setAuditResults(Vulnerabilities vulns,Project project) {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<NodeAudit> audit = null;
        if (project != null)
            audit = nodeAuditRepository.findByNodeInAndScore(project.getNodes(),"WARN");
        else
            audit = nodeAuditRepository.findByScore("WARN");
        for (NodeAudit aud : audit) {
            Vuln v = new Vuln();
            v.setVulnerabilityName(aud.getRequirement().getCode()+"-"+aud.getRequirement().getName());
            //TODO: zrobienie krytycznosci dla audit
            v.setSeverity(Constants.API_SEVERITY_HIGH);
            v.setDescription("mock Description");
            v.setHostname(aud.getNode().getName());
            v.setHostType(aud.getNode().getType());
            v.setDateCreated(aud.getUpdated());
            if (aud.getNode().getProject().getCiid() != null && !aud.getNode().getProject().getCiid().isEmpty())
            	v.setCiid(aud.getNode().getProject().getCiid());
            v.setRequirementCode(aud.getRequirement().getCode());
            v.setRequirement(aud.getRequirement().getName());
            v.setType(Constants.API_SCANNER_AUDIT);
            tmpVulns.add(v);
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }

    @Transactional
    Vulnerabilities setCodeVulns(Vulnerabilities vulns, Project project) {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<CodeVuln> codeVulns = null;
        if (project != null) {
            try (Stream<CodeVuln> vulnsForProject = codeVulnRepository.findByCodeGroupInAndAnalysisNot(project.getCodes(), "Not an Issue")) {
                codeVulns = vulnsForProject.collect(Collectors.toList());
            }
        }
        else {
            try (Stream<CodeVuln> vulnsForProject = codeVulnRepository.findAllCodeVulns("Not an Issue")){
                codeVulns = vulnsForProject.collect(Collectors.toList());
            }
        }
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
            tmpVulns.add(v);
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }
    private Vulnerabilities setWebApplicationVulns(Vulnerabilities vulns,Project project) throws UnknownHostException {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<WebAppVuln> webAppVulns = null;
        if (project != null)
            webAppVulns = new ArrayList<>(webAppVulnRepository.findByWebAppIn(project.getWebapps()));
        else
            webAppVulns = webAppVulnRepository.findAll();
        for (WebAppVuln wav : webAppVulns) {
            Vuln v = new Vuln();
            v.setVulnerabilityName(wav.getName());
            v.setSeverity(wav.getSeverity());
            v.setDescription(wav.getDescription()+"\n\n"+wav.getRecommendation());
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
            tmpVulns.add(v);
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }
    public String getPortFromUrl(String url){
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
    public String getIpAddressFromUrl(String url) throws UnknownHostException {
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
    private Vulnerabilities setInfrastructureVulns(Vulnerabilities vulns,Project project) {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<InfrastructureVuln> infraVulns = null;
        if (project != null) {
            infraVulns = infrastractureVulnRepository
                    .findByIntfInAndSeverityNot(interfaceRepository.findByAssetInAndActive(new ArrayList<>(project.getAssets()), true),"Log");
        } else
            infraVulns = infrastractureVulnRepository.findBySeverityNot("Log");
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
            v.setRoutingDomainName(iv.getIntf().getRoutingDomain() != null ? iv.getIntf().getRoutingDomain().getName() : "");
            v.setPort(iv.getPort().split("/")[0].trim().replace(" ",""));
            v.setIpProtocol(iv.getPort().split("/")[1].trim().replace(" ",""));
            v.setType(Constants.API_SCANNER_OPENVAS);
            tmpVulns.add(v);
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }
    private Vulnerabilities setInfrastructureVulnsForRequestId(Vulnerabilities vulns,String requestId) {
        List<Vuln> tmpVulns = new ArrayList<>();
        List<InfrastructureVuln> infraVulns = null;
        List<Asset> assetsWithRequestId = assetRepository.findByRequestId(requestId);
        if (assetsWithRequestId.size() == 0)
            throw new NullPointerException();

        infraVulns = infrastractureVulnRepository
                    .findByIntfInAndSeverityNot(interfaceRepository.findByAssetIn(assetsWithRequestId),"Log");
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
            tmpVulns.add(v);
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }

    public ResponseEntity<String> getVulnerabilitiesByProjectAndType(String type, Long id) throws UnknownHostException {
        Project project = projectRepository.getOne(id);
        if (scannerTypes.contains(type) && project != null) {
            log.debug("Vulnerabilities access granted for ProjectID: {} - {}",type, project.getName());
            Vulnerabilities vulns = new Vulnerabilities();
            List<Vuln> vulnList = new ArrayList<>();
            vulns.setVulnerabilities(vulnList);
            switch (type) {
                case Constants.API_SCANNER_OPENVAS:
                    vulns = setInfrastructureVulns(vulns, project);
                    break;
                case Constants.API_SCANNER_WEBAPP:
                    vulns = setWebApplicationVulns(vulns, project);
                    break;
                case Constants.API_SCANNER_CODE:
                    vulns = setCodeVulns(vulns, project);
                    break;
                case Constants.API_SCANNER_AUDIT:
                    vulns = setAuditResults(vulns, project);
                    break;
                default:
                    vulns = setPackageVulns(vulns, project);
                    break;
            }
            return new ResponseEntity(new Gson().toJson(vulns), HttpStatus.OK);
        } else
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Proper scanner type is: networkScanner,webApplicationScanner,codeScanner, audit,packageScan");

    }
    public ResponseEntity<String> getVulnerabilitiesByType(String type) throws UnknownHostException {
        if (scannerTypes.contains(type)) {
            log.info("Vulnerabilities access granted: {}",type);
            Vulnerabilities vulns = new Vulnerabilities();
            List<Vuln> vulnList = new ArrayList<>();
            vulns.setVulnerabilities(vulnList);
            switch (type) {
                case Constants.API_SCANNER_OPENVAS:
                    vulns = setInfrastructureVulns(vulns, null);
                    break;
                case Constants.API_SCANNER_WEBAPP:
                    vulns = setWebApplicationVulns(vulns, null);
                    break;
                case Constants.API_SCANNER_CODE:
                    vulns = setCodeVulns(vulns, null);
                    break;
                case Constants.API_SCANNER_AUDIT:
                    vulns = setAuditResults(vulns, null);
                    break;
                default:
                    vulns = setPackageVulns(vulns, null);
                    break;
            }
            return new ResponseEntity(new Gson().toJson(vulns).toString(), HttpStatus.OK);
        } else
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Proper scanner type is: networkScanner,webApplicationScanner,codeScanner, audit,packageScan");

    }
    public ResponseEntity<CIVulnManageResponse> getCiScoreForCodeProject(String codeGroup, String codeProject, Long id){
        Optional<CodeProject> cp = codeProjectRepository.getCodeProjectByNameCodeGroupNameAndProjectId(codeProject,codeGroup,id);
        CIVulnManageResponse ciVulnManageResponse = new CIVulnManageResponse();
        if (cp.isPresent()){
            List<VulnManageResponse> vmr = createVulnManageResponseForCodeProject(cp.get());
            ciVulnManageResponse.setVulnManageResponseList(vmr);
            if (vmr.size()>3){
                ciVulnManageResponse.setResult("Not Ok");
            } else {
                ciVulnManageResponse.setResult("Ok");
            }
            ciVulnManageResponse.setInQueue(cp.get().getInQueue());
            ciVulnManageResponse.setRunning(cp.get().getRunning());
            ciVulnManageResponse.setCommitId(cp.get().getCommitid());
            prepareOperationForRequest(ciVulnManageResponse, cp.get());
            return new ResponseEntity<>(ciVulnManageResponse,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.NOT_FOUND);
        }
    }

    private void prepareOperationForRequest(CIVulnManageResponse ciVulnManageResponse, CodeProject codeProject){
        CiOperations ciOperations = new CiOperations();
        ciOperations.setProject(codeProject.getCodeGroup().getProject());
        ciOperations.setCodeGroup(codeProject.getCodeGroup());
        ciOperations.setCodeProject(codeProject);
        ciOperations.setResult(ciVulnManageResponse.getResult());
        ciOperations.setVulnNumber(ciVulnManageResponse.getVulnManageResponseList().size());
        ciOperationsRepository.save(ciOperations);
    }
    private List<VulnManageResponse> createVulnManageResponseForCodeProject(CodeProject cp){
        List<VulnManageResponse> vulnManageResponses = new ArrayList<>();
        List<WebAppVuln> vulnsForCP = cp.getWebAppVulns().stream()
                .filter(wav -> wav.getSeverity().equals(Constants.API_SEVERITY_HIGH))
                .collect(Collectors.toList());
        List<CodeVuln> codeVulnsForCP = cp.getVulns().stream()
                .filter (cv -> cv.getSeverity().equals(Constants.API_SEVERITY_CRITICAL))
                .filter (cv -> cv.getAnalysis().equals(Constants.FORTIFY_ANALYSIS_EXPLOITABLE))
                .collect(Collectors.toList());
        List<SoftwarePacketVulnerability> softVulnForCP = softwarePacketVulnerabilityReposutitory.getSoftwareVulnsForCodeProject(cp.getId())
                .stream().filter(v -> v.getScore() > 7).collect(Collectors.toList());
        // petla po webappvuln
        for (WebAppVuln wav : vulnsForCP){
            VulnManageResponse vmr = new VulnManageResponse();
            vmr.setDateDiscovered(wav.getWebApp().getLastExecuted());
            vmr.setSeverity(wav.getSeverity());
            vmr.setVulnerabilityName(wav.getName());
            vulnManageResponses.add(vmr);
        }
        // petla po code vuln
        for (CodeVuln cv : codeVulnsForCP){
            VulnManageResponse vmr = new VulnManageResponse();
            vmr.setVulnerabilityName(cv.getName());
            vmr.setSeverity(cv.getSeverity());
            vmr.setDateDiscovered(cv.getInserted());
            vulnManageResponses.add(vmr);
        }
        //pentla po softvu
        for (SoftwarePacketVulnerability spv : softVulnForCP){
            VulnManageResponse vmr = new VulnManageResponse();
            vmr.setVulnerabilityName(spv.getName());
            vmr.setSeverity(spv.getSeverity());
            vmr.setDateDiscovered(spv.getInserted());
            vulnManageResponses.add(vmr);
        }
        return vulnManageResponses;
    }

    public ResponseEntity<Vulnerabilities> getVulnerabilitiesByProject(Long id) throws UnknownHostException {
        Vulnerabilities vulns = new Vulnerabilities();
        Project project = projectRepository.getOne(id);

        List<Vuln> vulnList = new ArrayList<>();
        vulns.setVulnerabilities(vulnList);
        vulns = setInfrastructureVulns(vulns,project);
        vulns = setWebApplicationVulns(vulns,project);
        vulns = setCodeVulns(vulns,project);
        vulns = setAuditResults(vulns,project);
        vulns = setPackageVulns(vulns,project);
        return new ResponseEntity<>(vulns,HttpStatus.OK);
    }

    public ResponseEntity<InfraScanMetadata> getMetaDataForProject(String requestId) {
        List<ScannedAddress> scannedAddresses = new ArrayList<>();
        List<NetworkService> networkServices = new ArrayList<>();
        for (Asset asset : assetRepository.findByRequestId(requestId)){

            //TODO verify
            Interface intf = asset.getInterfaces().stream().findFirst().orElse(null);

            ScannedAddress scannedAddress = new ScannedAddress();
            scannedAddress.setOs(asset.getOs());
            assert intf != null;
            scannedAddress.setIp(intf.getPrivateip());
            for (io.mixeway.db.entity.Service service: serviceRepository.findByAnInterface(intf)){
                NetworkService networkService = new NetworkService();
                networkService.setAppProto(service.getAppProto());
                networkService.setNetProto(service.getNetProto());
                networkService.setPort(service.getPort());
                networkService.setStatus(service.getStatus().getName());
                networkServices.add(networkService);

            }
            scannedAddress.setNetworkServices(networkServices);
            scannedAddresses.add(scannedAddress);

        }
        InfraScanMetadata infraScanMetadata = new InfraScanMetadata();
        infraScanMetadata.setScannedAddresses(scannedAddresses);
        return new ResponseEntity<>(infraScanMetadata,HttpStatus.OK);
    }


    public ResponseEntity<Vulnerabilities> getNetworkVulnerabilitiesByRequestId(String requestId) {
        try {
            return new ResponseEntity<>(this.setInfrastructureVulnsForRequestId(new Vulnerabilities(), requestId), HttpStatus.OK);
        } catch (NullPointerException ex){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
}
