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
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Log4j2
public class GetVulnerabilitiesService {

    private static final List<String> SCANNER_TYPES = Arrays.asList(Constants.API_SCANNER_AUDIT, Constants.API_SCANNER_CODE,
            Constants.API_SCANNER_OPENVAS, Constants.API_SCANNER_PACKAGE,Constants.API_SCANNER_WEBAPP,
            Constants.API_SCANNER_OPENSOURCE);
    private static final List<String> SEVERITIES_HIGH = Arrays.asList(Constants.API_SEVERITY_CRITICAL, Constants.API_SEVERITY_HIGH);

    @Autowired
    private ApiTypeRepository apiTypeRepository;
    @Autowired
    private ScannerRepository nessusRepository;
    @Autowired
    private RoutingDomainRepository routingDomainRepository;
    @Autowired
    private ProjectRepository projectRepository;
    @Autowired
    private ApiPermisionRepository apiPermisionRepository;
    @Autowired
    private NodeRepository nodeRepository;
    @Autowired
    private NodeAuditRepository nodeAuditRepository;
    @Autowired
    private RequirementRepository requirementRepository;
    @Autowired
    private ActivityRepository activityRepository;
    @Autowired
    private WebAppRepository waRepository;
    @Autowired
    private WebAppHeaderRepository webAppHeaderRepository;
    @Autowired
    private InterfaceRepository interfaceRepository;
    @Autowired
    private AssetRepository assetRepository;
    @Autowired
    private SoftwarePacketRepository softwarePacketRepository;
    @Autowired
    private ScannerRepository scannerRepository;
    @Autowired
    private ScannerTypeRepository scannerTypeRepository;
    @Autowired
    private CodeProjectRepository codeProjectRepository;
    @Autowired
    private CiOperationsRepository ciOperationsRepository;
    @Autowired
    private StatusRepository statusRepository;
    @Autowired
    private ServiceRepository serviceRepository;
    @Autowired
    private OpenSourceScanService openSourceScanService;
    @Autowired
    private VulnTemplate vulnTemplate;
    @Autowired
    private SecurityGatewayRepository securityGatewayRepository;
    @Autowired
    private FindCodeProjectService findCodeProjectService;

    @Transactional
    public ResponseEntity<Vulnerabilities> getAllVulnerabilities() throws UnknownHostException, URISyntaxException {
        log.debug("Vulnerabilities access granted: ");
        Vulnerabilities vulnerabilities = new Vulnerabilities();
        List<Vuln> vulnList = new ArrayList<>();
        vulnerabilities.setVulnerabilities(vulnList);
        setInfrastructureVulns(vulnerabilities, null);
        setWebApplicationVulns(vulnerabilities, null);
        setCodeVulns(vulnerabilities, null);
        setAuditResults(vulnerabilities, null);
        setPackageVulns(vulnerabilities, null);
        return new ResponseEntity<>(vulnerabilities, HttpStatus.OK);
    }

    private void setPackageVulns(Vulnerabilities vulnerabilities, Project project) throws UnknownHostException {
        List<Vuln> vulnList = vulnerabilities.getVulnerabilities();
        List<ProjectVulnerability> projectVulnerabilities = getProjectVulnerabilitiesBySource(project, vulnTemplate.SOURCE_OPENSOURCE);

        projectVulnerabilities.removeIf(projectVulnerability -> projectVulnerability.getGrade() == 0);

        // Remove duplicates in branches
        Map<String, ProjectVulnerability> uniqueVulnsMap = new HashMap<>();
        for (ProjectVulnerability projectVulnerability : projectVulnerabilities) {
            CodeProjectBranch codeProjectBranch = projectVulnerability.getCodeProjectBranch();
            CodeProject codeProject = projectVulnerability.getCodeProject();

            if (codeProjectBranch != null && codeProject != null) {
                String branchName = codeProjectBranch.getName();
                String projectBranch = codeProject.getBranch();

                if (branchName != null && branchName.equals(projectBranch)) {
                    String uniqueKey = branchName + "_" + projectBranch + "_" + projectVulnerability.getId();
                    uniqueVulnsMap.put(uniqueKey, projectVulnerability);
                }
            } else if (codeProject != null) {
                String uniqueKey = UUID.randomUUID().toString();
                uniqueVulnsMap.put(uniqueKey, projectVulnerability);
            }
        }

        List<ProjectVulnerability> uniqueVulns = new ArrayList<>(uniqueVulnsMap.values());
        for (ProjectVulnerability projectVulnerability : uniqueVulns) {
            try {
                Vuln vuln = new Vuln(projectVulnerability, null, null, projectVulnerability.getCodeProject(), Constants.API_SCANNER_PACKAGE);
                vulnList.add(vuln);
            } catch (NullPointerException | URISyntaxException e) {
                log.error("[Export for SCA Vulns] Error during exporting vuln for {}",
                        projectVulnerability.getProject().getName());
            }
        }
    }

    private List<ProjectVulnerability> getProjectVulnerabilitiesBySource(Project project, VulnerabilitySource source) {
        if (project != null) {
            try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectAndVulnerabilitySource(project, source)
                    .filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))) {
                return vulnsForProject.collect(Collectors.toList());
            }
        } else {
            try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectInAndVulnerabilitySource(projectRepository.findByEnableVulnManage(true), source)
                    .filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))) {
                return vulnsForProject.collect(Collectors.toList());
            }
        }
    }

    private void setAuditResults(Vulnerabilities vulnerabilities, Project project) {
        List<Vuln> vulnList = vulnerabilities.getVulnerabilities();
        List<NodeAudit> nodeAudits = project != null
                ? nodeAuditRepository.findByNodeInAndScore(project.getNodes(), "WARN")
                : nodeAuditRepository.findByScore("WARN");

        for (NodeAudit nodeAudit : nodeAudits) {
            Vuln vuln = new Vuln();
            vuln.setVulnerabilityName(nodeAudit.getRequirement().getCode() + "-" + nodeAudit.getRequirement().getName());
            vuln.setDescription("mock Description");
            vuln.setHostname(nodeAudit.getNode().getName());
            vuln.setHostType(nodeAudit.getNode().getType());
            vuln.setDateCreated(nodeAudit.getUpdated());
            if (nodeAudit.getNode().getProject().getCiid() != null && !nodeAudit.getNode().getProject().getCiid().isEmpty()) {
                vuln.setCiid(nodeAudit.getNode().getProject().getCiid());
            }
            vuln.setRequirementCode(nodeAudit.getRequirement().getCode());
            vuln.setRequirement(nodeAudit.getRequirement().getName());
            vuln.setType(Constants.API_SCANNER_AUDIT);
            vulnList.add(vuln);
        }
    }

    private void setCodeVulns(Vulnerabilities vulnerabilities, Project project) throws UnknownHostException, URISyntaxException {
        List<Vuln> vulnList = vulnerabilities.getVulnerabilities();
        List<ProjectVulnerability> codeVulns = getCodeVulnerabilities(project);

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
                    String uniqueKey = branchName + "_" + projectBranch + "_" + projectVulnerability.getId();
                    uniqueVulnsMap.put(uniqueKey, projectVulnerability);
                }
            } else if (codeProject != null) {
                String uniqueKey = UUID.randomUUID().toString();
                uniqueVulnsMap.put(uniqueKey, projectVulnerability);
            }
        }

        List<ProjectVulnerability> uniqueVulns = new ArrayList<>(uniqueVulnsMap.values());
        for (ProjectVulnerability cv : uniqueVulns) {
            Vuln vuln = new Vuln(cv, null, null, new CodeProject(), Constants.API_SCANNER_PACKAGE);
            vulnList.add(vuln);
        }
    }

    private List<ProjectVulnerability> getCodeVulnerabilities(Project project) {
        List<VulnerabilitySource> sastSources = Arrays.asList(vulnTemplate.SOURCE_SOURCECODE, vulnTemplate.SOURCE_GITLEAKS,
                vulnTemplate.SOURCE_IAC);
        if (project != null) {
            List<CodeProject> codeProjectsWithVulnManageEnabled = findCodeProjectService.getCodeProjectsInListOfProjects(Collections.singletonList(project));
            return vulnTemplate.projectVulnerabilityRepository.findVulnerabilitiesForCode(codeProjectsWithVulnManageEnabled, sastSources)
                    .stream()
                    .filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))
                    .collect(Collectors.toList());
        } else {
            List<Project> enabledVulnManageProjects = projectRepository.findByEnableVulnManage(true);
            List<CodeProject> codeProjectsWithVulnManageEnabled = findCodeProjectService.getCodeProjectsInListOfProjects(enabledVulnManageProjects);
            return vulnTemplate.projectVulnerabilityRepository.findVulnerabilitiesForCode(codeProjectsWithVulnManageEnabled, sastSources)
                    .stream()
                    .filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED))
                    .collect(Collectors.toList());
        }
    }


    private void setWebApplicationVulns(Vulnerabilities vulnerabilities, Project project) throws UnknownHostException, URISyntaxException {
        List<Vuln> vulnList = vulnerabilities.getVulnerabilities();
        List<ProjectVulnerability> webAppVulns = getProjectVulnerabilitiesBySource(project, vulnTemplate.SOURCE_WEBAPP);
        for (ProjectVulnerability wav : webAppVulns) {
            Vuln vuln = new Vuln(wav, null, null, new WebApp(), Constants.API_SCANNER_WEBAPP);
            vulnList.add(vuln);
        }
    }

    private void setInfrastructureVulns(Vulnerabilities vulnerabilities, Project project) throws UnknownHostException, URISyntaxException {
        List<Vuln> vulnList = vulnerabilities.getVulnerabilities();
        List<ProjectVulnerability> infraVulns = getProjectVulnerabilitiesBySource(project, vulnTemplate.SOURCE_NETWORK);

        for (ProjectVulnerability iv : infraVulns) {
            if (iv.getVulnerability().getSeverity() == null ||
                    (iv.getVulnerability().getSeverity() != null
                            && !iv.getVulnerability().getSeverity().equals(Constants.SKIP_VULENRABILITY))) {
                Vuln vuln = new Vuln(iv, null, null, new Interface(), Constants.API_SCANNER_OPENVAS);
                vulnList.add(vuln);
            }
        }
    }

    private void setInfrastructureVulnsForRequestId(Vulnerabilities vulnerabilities, String requestId) throws UnknownHostException, URISyntaxException {
        List<Vuln> vulnList = new ArrayList<>();
        List<Asset> assetsWithRequestId = assetRepository.findByRequestId(requestId);
        if (assetsWithRequestId.isEmpty()) {
            throw new NullPointerException();
        }
        List<ProjectVulnerability> infraVulns = null;
        try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                .findByanInterfaceIn(interfaceRepository.findByAssetIn(assetsWithRequestId))) {
            infraVulns = vulnsForProject.collect(Collectors.toList());
        }
        for (ProjectVulnerability iv : infraVulns) {
            Vuln v = new Vuln(iv, null, null, new Interface(), Constants.API_SCANNER_OPENVAS);
            vulnList.add(v);
        }
        vulnerabilities.setVulnerabilities(vulnList);
    }

    @Transactional
    public ResponseEntity<String> getVulnerabilitiesByProjectAndType(String type, Long id) throws UnknownHostException, URISyntaxException {
        Project project = projectRepository.getOne(id);
        if (SCANNER_TYPES.contains(type) && project != null) {
            log.debug("Vulnerabilities access granted for ProjectID: {} - {}", type, project.getName());
            Vulnerabilities vulnerabilities = new Vulnerabilities();
            List<Vuln> vulnList = new ArrayList<>();
            vulnerabilities.setVulnerabilities(vulnList);
            switch (type) {
                case Constants.API_SCANNER_OPENVAS:
                    setInfrastructureVulns(vulnerabilities, project);
                    break;
                case Constants.API_SCANNER_WEBAPP:
                    setWebApplicationVulns(vulnerabilities, project);
                    break;
                case Constants.API_SCANNER_CODE:
                    setCodeVulns(vulnerabilities, project);
                    break;
                case Constants.API_SCANNER_AUDIT:
                    setAuditResults(vulnerabilities, project);
                    break;
                case Constants.API_SCANNER_OPENSOURCE:
                    setOpenSourceResults(vulnerabilities, project);
                    break;
                case Constants.API_SCANNER_PACKAGE:
                    setPackageVulns(vulnerabilities, project);
                    break;
            }
            return new ResponseEntity<>(new Gson().toJson(vulnerabilities), HttpStatus.OK);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Proper scanner type is: networkScanner,webApplicationScanner,codeScanner, audit,packageScan");
        }
    }

    private void setOpenSourceResults(Vulnerabilities vulnerabilities, Project project) throws UnknownHostException, URISyntaxException {
        if (project != null) {
            List<Vuln> vulnList = vulnerabilities.getVulnerabilities();
            for (CodeProject cp : project.getCodes()) {
                try (Stream<ProjectVulnerability> softwarePacketVulnerabilities = vulnTemplate.projectVulnerabilityRepository
                        .findByCodeProjectAndVulnerabilitySource(cp, vulnTemplate.SOURCE_OPENSOURCE)) {
                    for (ProjectVulnerability spv : softwarePacketVulnerabilities.collect(Collectors.toList())) {
                        Vuln v = new Vuln(spv, null, null, cp, Constants.API_SCANNER_PACKAGE);
                        vulnList.add(v);
                    }
                }
            }
        }
    }

    @Transactional
    public ResponseEntity<String> getVulnerabilitiesByType(String type) throws UnknownHostException, URISyntaxException {
        if (SCANNER_TYPES.contains(type)) {
            log.info("Vulnerabilities access granted: {}", type);
            Vulnerabilities vulnerabilities = new Vulnerabilities();
            List<Vuln> vulnList = new ArrayList<>();
            vulnerabilities.setVulnerabilities(vulnList);
            switch (type) {
                case Constants.API_SCANNER_OPENVAS:
                    setInfrastructureVulns(vulnerabilities, null);
                    break;
                case Constants.API_SCANNER_WEBAPP:
                    setWebApplicationVulns(vulnerabilities, null);
                    break;
                case Constants.API_SCANNER_CODE:
                    setCodeVulns(vulnerabilities, null);
                    break;
                case Constants.API_SCANNER_AUDIT:
                    setAuditResults(vulnerabilities, null);
                    break;
                case Constants.API_SCANNER_PACKAGE:
                    setPackageVulns(vulnerabilities, null);
                    break;
            }
            return new ResponseEntity<>(new Gson().toJson(vulnerabilities).toString(), HttpStatus.OK);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Proper scanner type is: networkScanner,webApplicationScanner,codeScanner, audit,packageScan");
        }
    }

    @Transactional
    public ResponseEntity<CIVulnManageResponse> getCiScoreForCodeProject(String codeGroup, String codeProject, Long id)
            throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException,
            KeyStoreException, IOException {
        Optional<CodeProject> cp = codeProjectRepository.getCodeProjectByNameCodeGroupNameAndProjectId(codeProject, codeGroup, id);
        SecurityGateway securityGateway = securityGatewayRepository.findAll().stream().findFirst().orElse(null);
        if (securityGateway != null && cp.isPresent()) {
            if (StringUtils.isNotBlank(cp.get().getdTrackUuid())) {
                openSourceScanService.loadVulnerabilities(cp.get(),null,null);
            }
            List<VulnManageResponse> vulnManageResponses = createVulnManageResponseForCodeProject(cp.get());
            CIVulnManageResponse ciVulnManageResponse = new CIVulnManageResponse();
            ciVulnManageResponse.setVulnManageResponseList(vulnManageResponses);
            ciVulnManageResponse.setResult(calculateResultForCI(securityGateway, vulnManageResponses));
            ciVulnManageResponse.setInQueue(cp.get().getInQueue());
            ciVulnManageResponse.setRunning(cp.get().getRunning());
            ciVulnManageResponse.setCommitId(cp.get().getCommitid());
            prepareOperationForRequest(ciVulnManageResponse, cp.get());
            return new ResponseEntity<>(ciVulnManageResponse, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    private String calculateResultForCI(SecurityGateway securityGateway, List<VulnManageResponse> vulnManageResponses) {
        if (securityGateway.isGrade()
                && vulnManageResponses.stream().filter(vuln -> vuln.getGrade() == 1).count() >= securityGateway.getVuln()) {
            return "Not OK - limit exceeded";
        } else if (securityGateway.isGrade()
                && vulnManageResponses.stream().filter(vuln -> vuln.getGrade() == 1).count() < securityGateway.getVuln()) {
            return "OK";
        } else if (!securityGateway.isGrade() && (
                vulnManageResponses.stream().filter(vuln -> vuln.getSeverity().equals(Constants.API_SEVERITY_CRITICAL)).count() < securityGateway.getCritical()
                        && vulnManageResponses.stream().filter(vuln -> vuln.getSeverity().equals(Constants.API_SEVERITY_HIGH)).count() < securityGateway.getHigh())) {
            return "OK";
        } else {
            return "Not OK - limit exceeded";
        }
    }

    private void prepareOperationForRequest(CIVulnManageResponse ciVulnManageResponse, CodeProject codeProject) {
        Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject, codeProject.getCommitid());
        if (ciOperations.isPresent()) {
            ciOperations.get().setResult(ciVulnManageResponse.getResult());
            ciOperations.get().setVulnNumber(ciVulnManageResponse.getVulnManageResponseList().size());
            if (!codeProject.getRunning() && !codeProject.getInQueue()) {
                ciOperations.get().setEnded(new Date());
            }
            ciOperationsRepository.save(ciOperations.get());
        }
    }

    private List<VulnManageResponse> createVulnManageResponseForCodeProject(CodeProject codeProject) {
        List<VulnManageResponse> vulnManageResponses = new ArrayList<>();
        List<ProjectVulnerability> codeVulns = new ArrayList<>();
        try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                .findByCodeProjectAndVulnerabilitySourceAndSeverityAndAnalysisNot(codeProject, vulnTemplate.SOURCE_SOURCECODE,
                        Constants.VULN_CRITICALITY_CRITICAL,
                        Constants.FORTIFY_NOT_AN_ISSUE)) {
            codeVulns.addAll(vulnsForProject.collect(Collectors.toList()));
        }
        try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                .findByCodeProjectAndVulnerabilitySourceAndSeverityIn(codeProject, vulnTemplate.SOURCE_OPENSOURCE,
                        SEVERITIES_HIGH)) {
            codeVulns.addAll(vulnsForProject.collect(Collectors.toList()));
        }
        try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                .findByCodeProjectAndVulnerabilitySourceAndSeverityIn(codeProject, vulnTemplate.SOURCE_WEBAPP,
                        SEVERITIES_HIGH)) {
            codeVulns.addAll(vulnsForProject.collect(Collectors.toList()));
        }
        // Loop through software vulnerabilities
        for (ProjectVulnerability spv : codeVulns) {
            VulnManageResponse vmr = new VulnManageResponse();
            vmr.setVulnerabilityName(spv.getVulnerability().getName());
            vmr.setSeverity(spv.getSeverity());
            vmr.setGrade(spv.getGrade());
            vmr.setDateDiscovered(spv.getInserted().toString());
            vulnManageResponses.add(vmr);
        }
        return vulnManageResponses;
    }

    @Transactional
    public ResponseEntity<Vulnerabilities> getVulnerabilitiesByProject(Long id) throws UnknownHostException, URISyntaxException {
        Vulnerabilities vulnerabilities = new Vulnerabilities();
        Project project = projectRepository.getOne(id);

        List<Vuln> vulnList = new ArrayList<>();
        vulnerabilities.setVulnerabilities(vulnList);
        setInfrastructureVulns(vulnerabilities, project);
        setWebApplicationVulns(vulnerabilities, project);
        setCodeVulns(vulnerabilities, project);
        setAuditResults(vulnerabilities, project);
        setPackageVulns(vulnerabilities, project);
        return new ResponseEntity<>(vulnerabilities, HttpStatus.OK);
    }

    @Transactional
    public ResponseEntity<InfraScanMetadata> getMetaDataForProject(String requestId) {
        List<ScannedAddress> scannedAddresses = new ArrayList<>();
        for (Asset asset : assetRepository.findByRequestId(requestId)) {
            Interface intf = asset.getInterfaces().stream().findFirst().orElse(null);
            ScannedAddress scannedAddress = new ScannedAddress();
            scannedAddress.setOs(asset.getOs());
            if (intf != null) {
                scannedAddress.setIp(intf.getPrivateip());
                List<NetworkService> networkServices = new ArrayList<>();
                for (io.mixeway.db.entity.Service service : serviceRepository.findByAnInterface(intf)) {
                    NetworkService networkService = new NetworkService();
                    networkService.setAppProto(service.getAppProto());
                    networkService.setNetProto(service.getNetProto());
                    networkService.setPort(service.getPort());
                    networkService.setStatus(service.getStatus().getName());
                    networkServices.add(networkService);
                }
                scannedAddress.setNetworkServices(networkServices);
            }
            scannedAddresses.add(scannedAddress);
        }
        InfraScanMetadata infraScanMetadata = new InfraScanMetadata();
        infraScanMetadata.setScannedAddresses(scannedAddresses);
        return new ResponseEntity<>(infraScanMetadata, HttpStatus.OK);
    }

    @Transactional
    public ResponseEntity<Vulnerabilities> getNetworkVulnerabilitiesByRequestId(String requestId) {
        try {
            Vulnerabilities vulnerabilities = new Vulnerabilities();
            setInfrastructureVulnsForRequestId(vulnerabilities, requestId);
            return new ResponseEntity<>(vulnerabilities, HttpStatus.OK);
        } catch (NullPointerException | UnknownHostException | URISyntaxException ex) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @Transactional
    public ResponseEntity setGradeForVulnerability(String type, Long id, int grade) {
        Optional<ProjectVulnerability> projectVulnerability = vulnTemplate.projectVulnerabilityRepository.findById(id);
        if (projectVulnerability.isPresent()) {
            projectVulnerability.get().setGrade(grade);
        }
        return new ResponseEntity(HttpStatus.OK);
    }
}