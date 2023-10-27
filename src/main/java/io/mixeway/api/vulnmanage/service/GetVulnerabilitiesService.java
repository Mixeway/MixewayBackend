package io.mixeway.api.vulnmanage.service;

import com.google.gson.Gson;
import io.mixeway.api.cioperations.model.CIVulnManageResponse;
import io.mixeway.api.cioperations.model.VulnManageResponse;
import io.mixeway.api.vulnmanage.model.*;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.service.opensource.OpenSourceScanService;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Log4j2
public class GetVulnerabilitiesService {
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
    CodeProjectRepository codeProjectRepository;
    @Autowired
    CiOperationsRepository ciOperationsRepository;
    @Autowired
    StatusRepository statusRepository;
    @Autowired
    ServiceRepository serviceRepository;
    @Autowired
    OpenSourceScanService openSourceScanService;
    @Autowired
    VulnTemplate vulnTemplate;
    @Autowired
    SecurityGatewayRepository securityGatewayRepository;

    @Autowired
    FindCodeProjectService findCodeProjectService;

    ArrayList<String> severitiesNot = new ArrayList<String>() {{
        add("Log");
        add("Info");
    }};
    ArrayList<String> severitiesHigh = new ArrayList<String>() {{
        add("Critical");
        add("High");
    }};
    DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private final List<String> scannerTypes = Arrays.asList(Constants.API_SCANNER_AUDIT, Constants.API_SCANNER_CODE, Constants.API_SCANNER_OPENVAS,
            Constants.API_SCANNER_PACKAGE,Constants.API_SCANNER_WEBAPP, Constants.API_SCANNER_OPENSOURCE);
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
    private Vulnerabilities setPackageVulns(Vulnerabilities vulns, Project project) throws UnknownHostException {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<ProjectVulnerability> softVuln = null;
        if (project != null) {
            try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository.findByProjectAndVulnerabilitySource(project, vulnTemplate.SOURCE_OPENSOURCE).filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))) {
                softVuln = vulnsForProject.collect(Collectors.toList());
            }
        }
        else {
            try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectInAndVulnerabilitySource(projectRepository.findByEnableVulnManage(true),vulnTemplate.SOURCE_OPENSOURCE)
                    .filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))) {
                softVuln = vulnsForProject.collect(Collectors.toList());
            }
        }
        softVuln.removeIf(projectVulnerability -> projectVulnerability.getGrade() == 0);


        // Usuniecie duplikatach w branchach
        Map<String, ProjectVulnerability> uniqueVulnsMap = new HashMap<>();

        for (ProjectVulnerability projectVulnerability : softVuln) {
            CodeProjectBranch codeProjectBranch = projectVulnerability.getCodeProjectBranch();
            CodeProject codeProject = projectVulnerability.getCodeProject();

            if (codeProjectBranch != null && codeProject != null) {
                String branchName = codeProjectBranch.getName();
                String projectBranch = codeProject.getBranch();

                if (branchName != null && branchName.equals(projectBranch)) {
                    String uniqueKey = branchName + "_" + projectBranch + "_" + projectVulnerability.getId(); // Tworzenie unikalnego klucza
                    uniqueVulnsMap.put(uniqueKey, projectVulnerability);
                }
            } else if ( codeProjectBranch == null && codeProject != null ){
                String uniqueKey = UUID.randomUUID().toString();
                uniqueVulnsMap.put(uniqueKey, projectVulnerability);
            }
        }

        List<ProjectVulnerability> uniqueVulns = new ArrayList<>(uniqueVulnsMap.values());


        for (ProjectVulnerability projectVulnerability : uniqueVulns) {
//            for (Asset a : projectVulnerability.getSoftwarePacket().getAssets()) {
//                String hostname;
//                AtomicReference<String> ipAddress = null;
//                hostname = a.getName();
//                Optional<Interface> interfaceToAdd = a.getInterfaces().stream().findFirst();
//                interfaceToAdd.ifPresent(anInterface -> ipAddress.set(anInterface.getPrivateip()));
//                Vuln v = new Vuln(projectVulnerability, hostname, ipAddress.get(), a, Constants.API_SCANNER_PACKAGE);
//                tmpVulns.add(v);
//            }
            try {
                Vuln v = new Vuln(projectVulnerability, null, null, projectVulnerability.getCodeProject(), Constants.API_SCANNER_PACKAGE);
                tmpVulns.add(v);
            } catch (NullPointerException e ){
                e.printStackTrace();
                log.error("[Export for SCA Vulns] Error during exporting vuln for {}", projectVulnerability.getProject().getName());
            }
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
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

    private Vulnerabilities setCodeVulns(Vulnerabilities vulns, Project project) throws UnknownHostException {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<ProjectVulnerability> codeVulns = new ArrayList<>();
        if (project != null) {
            List<VulnerabilitySource> sastSources = Arrays.asList(vulnTemplate.SOURCE_SOURCECODE, vulnTemplate.SOURCE_GITLEAKS, vulnTemplate.SOURCE_IAC);
            List<Project> projects = Collections.singletonList(project);
            List<CodeProject> codeProjectsWithVulnManageEnabled = findCodeProjectService.getCodeProjectsInListOfProjects(projects);
            List<ProjectVulnerability> projectVulnerabilities =
                    vulnTemplate.projectVulnerabilityRepository.findVulnerabilitiesForCode(codeProjectsWithVulnManageEnabled, sastSources)
                            .stream()
                            .filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))
                            .collect(Collectors.toList());
            codeVulns.addAll(projectVulnerabilities);
        }
        else {
            List<Project> enabledVulnManageProjects = projectRepository.findByEnableVulnManage(true);
            List<CodeProject> codeProjectsWithVulnManageEnabled = findCodeProjectService.getCodeProjectsInListOfProjects(enabledVulnManageProjects);
            List<VulnerabilitySource> sastSources = Arrays.asList(vulnTemplate.SOURCE_SOURCECODE, vulnTemplate.SOURCE_GITLEAKS, vulnTemplate.SOURCE_IAC);
            List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findVulnerabilitiesForCode(codeProjectsWithVulnManageEnabled, sastSources)
                    .stream()
                    .filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))
                    .collect(Collectors.toList());;
            codeVulns.addAll(projectVulnerabilities);
        }

        codeVulns.removeIf(projectVulnerability -> projectVulnerability.getGrade() == 0);

        // Return only vulnerabilities in default branch
        Map<String, ProjectVulnerability> uniqueVulnsMap = new HashMap<>();

        for (ProjectVulnerability projectVulnerability : codeVulns) {
            CodeProjectBranch codeProjectBranch = projectVulnerability.getCodeProjectBranch();
            CodeProject codeProject = projectVulnerability.getCodeProject();

            if (codeProjectBranch != null && codeProject != null) {
                String branchName = codeProjectBranch.getName();
                String projectBranch = codeProject.getBranch();

                if (branchName != null && branchName.equals(projectBranch)) {
                    String uniqueKey = branchName + "_" + projectBranch + "_" + projectVulnerability.getId(); // Tworzenie unikalnego klucza
                    uniqueVulnsMap.put(uniqueKey, projectVulnerability);
                }
            } else if ( codeProjectBranch == null && codeProject != null ){
                String uniqueKey = UUID.randomUUID().toString();
                uniqueVulnsMap.put(uniqueKey, projectVulnerability);
            }
        }

        List<ProjectVulnerability> uniqueVulns = new ArrayList<>(uniqueVulnsMap.values());


        for (ProjectVulnerability cv : uniqueVulns) {
            Vuln v = new Vuln(cv, null, null,new CodeProject(), Constants.API_SCANNER_PACKAGE);
            tmpVulns.add(v);
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }
    private Vulnerabilities setWebApplicationVulns(Vulnerabilities vulns,Project project) throws UnknownHostException {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<ProjectVulnerability> webAppVulns = null;
        if (project != null) {
            //webAppVulns = new ArrayList<>(webAppVulnRepository.findByWebAppIn(project.getWebapps()));
            try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectAndVulnerabilitySource(project, vulnTemplate.SOURCE_WEBAPP).filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))) {
                webAppVulns = vulnsForProject.collect(Collectors.toList());
            }
        }
        else {
            try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectInAndVulnerabilitySource(projectRepository.findByEnableVulnManage(true),vulnTemplate.SOURCE_WEBAPP).filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))) {
                webAppVulns = vulnsForProject.collect(Collectors.toList());
            }
        }
        for (ProjectVulnerability wav : webAppVulns) {
            Vuln v = new Vuln(wav, null, null,new WebApp(), Constants.API_SCANNER_WEBAPP);
            tmpVulns.add(v);
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }
    private Vulnerabilities setInfrastructureVulns(Vulnerabilities vulns,Project project) throws UnknownHostException {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<ProjectVulnerability> infraVulns = null;
        if (project != null) {
            try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectAndVulnerabilitySource(project,vulnTemplate.SOURCE_NETWORK).filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))) {
                infraVulns = vulnsForProject.collect(Collectors.toList());
            }
        } else {
            try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectInAndVulnerabilitySource(projectRepository.findByEnableVulnManage(true),vulnTemplate.SOURCE_NETWORK).filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))) {
                infraVulns = vulnsForProject.collect(Collectors.toList());
            }
        }
        for (ProjectVulnerability iv : infraVulns) {
            if (iv.getVulnerability().getSeverity() == null ||
                    (iv.getVulnerability().getSeverity() != null && !iv.getVulnerability().getSeverity().equals(Constants.SKIP_VULENRABILITY))) {
                Vuln v = new Vuln(iv, null, null, new Interface(), Constants.API_SCANNER_OPENVAS);
                tmpVulns.add(v);
            }
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }
    private Vulnerabilities setInfrastructureVulnsForRequestId(Vulnerabilities vulns,String requestId) throws UnknownHostException {
        List<Vuln> tmpVulns = new ArrayList<>();
        List<ProjectVulnerability> infraVulns = null;
        List<Asset> assetsWithRequestId = assetRepository.findByRequestId(requestId);
        if (assetsWithRequestId.size() == 0)
            throw new NullPointerException();

        try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                .findByanInterfaceIn(interfaceRepository.findByAssetIn(assetsWithRequestId))) {
            infraVulns = vulnsForProject.collect(Collectors.toList());
        }
        for (ProjectVulnerability iv : infraVulns) {
            Vuln v = new Vuln(iv, null, null,new Interface(), Constants.API_SCANNER_OPENVAS);
            tmpVulns.add(v);
        }
        vulns.setVulnerabilities(tmpVulns);
        return vulns;
    }
    @Transactional
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
                case Constants.API_SCANNER_OPENSOURCE:
                    vulns = setOpenSourceResults(vulns, project);
                    break;
                case Constants.API_SCANNER_PACKAGE:
                    vulns = setPackageVulns(vulns, project);
                    break;
            }
            return new ResponseEntity(new Gson().toJson(vulns), HttpStatus.OK);
        } else
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Proper scanner type is: networkScanner,webApplicationScanner,codeScanner, audit,packageScan");

    }

    private Vulnerabilities setOpenSourceResults(Vulnerabilities vulns, Project project) throws UnknownHostException {
        List<Vuln> tmpVulns = vulns.getVulnerabilities();
        List<ProjectVulnerability> osVulns = null;
        if (project != null) {
            for (CodeProject cp : project.getCodes()){
                try (Stream<ProjectVulnerability> softwarePacketVulnerabilities = vulnTemplate.projectVulnerabilityRepository
                        .findByCodeProjectAndVulnerabilitySource(cp, vulnTemplate.SOURCE_OPENSOURCE)) {
                    for (ProjectVulnerability spv : softwarePacketVulnerabilities.collect(Collectors.toList())){
                        Vuln v = new Vuln(spv, null, null,cp, Constants.API_SCANNER_PACKAGE);
                        tmpVulns.add(v);
                    }
                }
            }
            vulns.setVulnerabilities(tmpVulns);
        }
        return vulns;
    }

    @Transactional
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
                case Constants.API_SCANNER_PACKAGE:
                    vulns = setPackageVulns(vulns, null);
                    break;
            }
            return new ResponseEntity(new Gson().toJson(vulns).toString(), HttpStatus.OK);
        } else
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Proper scanner type is: networkScanner,webApplicationScanner,codeScanner, audit,packageScan");

    }
    @Transactional
    public ResponseEntity<CIVulnManageResponse> getCiScoreForCodeProject(String codeGroup, String codeProject, Long id) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Optional<CodeProject> cp = codeProjectRepository.getCodeProjectByNameCodeGroupNameAndProjectId(codeProject,codeGroup,id);
        SecurityGateway securityGateway = securityGatewayRepository.findAll().stream().findFirst().orElse(null);
        CIVulnManageResponse ciVulnManageResponse = new CIVulnManageResponse();
        if (securityGateway !=null && cp.isPresent()){
            if (StringUtils.isNotBlank(cp.get().getdTrackUuid())){
                openSourceScanService.loadVulnerabilities(cp.get());
            }
            List<VulnManageResponse> vmr = createVulnManageResponseForCodeProject(cp.get());
            ciVulnManageResponse.setVulnManageResponseList(vmr);
            ciVulnManageResponse.setResult(calculateResultForCI(securityGateway, vmr));
            ciVulnManageResponse.setInQueue(cp.get().getInQueue());
            ciVulnManageResponse.setRunning(cp.get().getRunning());
            ciVulnManageResponse.setCommitId(cp.get().getCommitid());
            prepareOperationForRequest(ciVulnManageResponse, cp.get());
            return new ResponseEntity<>(ciVulnManageResponse,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    private String calculateResultForCI(SecurityGateway securityGateway, List<VulnManageResponse> vmr) {
        if (securityGateway.isGrade() && vmr.stream().filter(vuln -> vuln.getGrade()==1).count() >= securityGateway.getVuln()){
            return "Not OK - limit exceeded";
        } else if (securityGateway.isGrade() && vmr.stream().filter(vuln -> vuln.getGrade()==1).count() < securityGateway.getVuln()){
            return "OK";
        } else if (!securityGateway.isGrade() && (
                vmr.stream().filter(vuln -> vuln.getSeverity().equals(Constants.API_SEVERITY_CRITICAL)).count() < securityGateway.getCritical()
                && vmr.stream().filter(vuln -> vuln.getSeverity().equals(Constants.API_SEVERITY_HIGH)).count() < securityGateway.getHigh())){
            return "OK";
        } else {
            return "Not OK - limit exceeded";
        }
    }

    private void prepareOperationForRequest(CIVulnManageResponse ciVulnManageResponse, CodeProject codeProject){
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject, codeProject.getCommitid());
        if (ciOperations.isPresent()) {
            ciOperations.get().setResult(ciVulnManageResponse.getResult());
            ciOperations.get().setVulnNumber(ciVulnManageResponse.getVulnManageResponseList().size());
            if (!codeProject.getRunning() && !codeProject.getInQueue())
                ciOperations.get().setEnded(new Date());
            ciOperationsRepository.save(ciOperations.get());
        }
    }
    private List<VulnManageResponse> createVulnManageResponseForCodeProject(CodeProject cp){
        List<VulnManageResponse> vulnManageResponses = new ArrayList<>();
        List<ProjectVulnerability> codeVulns = new ArrayList<>();
        try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                .findByCodeProjectAndVulnerabilitySourceAndSeverityAndAnalysisNot(cp, vulnTemplate.SOURCE_SOURCECODE,
                        Constants.VULN_CRITICALITY_CRITICAL,
                        Constants.FORTIFY_NOT_AN_ISSUE)) {
            codeVulns.addAll(vulnsForProject.collect(Collectors.toList()));
        }
        try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                .findByCodeProjectAndVulnerabilitySourceAndSeverityIn(cp, vulnTemplate.SOURCE_OPENSOURCE,
                        severitiesHigh)) {
            codeVulns.addAll(vulnsForProject.collect(Collectors.toList()));
        }
        try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                .findByCodeProjectAndVulnerabilitySourceAndSeverityIn(cp, vulnTemplate.SOURCE_WEBAPP,
                        severitiesHigh)) {
            codeVulns.addAll(vulnsForProject.collect(Collectors.toList()));
        }
        //pentla po softvu
        for (ProjectVulnerability spv : codeVulns){
            VulnManageResponse vmr = new VulnManageResponse();
            vmr.setVulnerabilityName(spv.getVulnerability().getName());
            vmr.setSeverity(spv.getSeverity());
            vmr.setGrade(spv.getGrade());
            vmr.setDateDiscovered(spv.getInserted());
            vulnManageResponses.add(vmr);
        }
        return vulnManageResponses;
    }
    @Transactional
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
    @Transactional
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

    @Transactional
    public ResponseEntity<Vulnerabilities> getNetworkVulnerabilitiesByRequestId(String requestId) {
        try {
            return new ResponseEntity<>(this.setInfrastructureVulnsForRequestId(new Vulnerabilities(), requestId), HttpStatus.OK);
        } catch (NullPointerException | UnknownHostException ex){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ResponseEntity setGradeForVulnerabiility(String type, Long id, int grade) {
        Optional<ProjectVulnerability> projectVulnerability = vulnTemplate.projectVulnerabilityRepository.findById(id);
        if (projectVulnerability.isPresent()){
            projectVulnerability.get().setGrade(grade);
        }
        return new ResponseEntity(HttpStatus.OK);
    }
}
