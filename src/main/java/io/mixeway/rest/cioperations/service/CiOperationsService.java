package io.mixeway.rest.cioperations.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.codescan.service.CodeScanService;
import io.mixeway.integrations.opensourcescan.plugins.mvndependencycheck.model.SASTRequestVerify;
import io.mixeway.integrations.opensourcescan.service.OpenSourceScanService;
import io.mixeway.integrations.utils.CodeAccessVerifier;
import io.mixeway.pojo.*;
import io.mixeway.pojo.Status;
import io.mixeway.rest.cioperations.model.*;
import io.mixeway.rest.cioperations.model.ScannerType;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import io.mixeway.rest.project.model.OpenSourceConfig;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.repository.CiOperationsRepository;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class CiOperationsService {
    private static final Logger log = LoggerFactory.getLogger(CiOperationsService.class);
    private final CiOperationsRepository ciOperationsRepository;
    private final PermissionFactory permissionFactory;
    private final ProjectRepository projectRepository;
    private final CodeAccessVerifier codeAccessVerifier;
    private final CodeProjectRepository codeProjectRepository;
    private final OpenSourceScanService openSourceScanService;
    private final CodeScanService codeScanService;
    private final VulnTemplate vulnTemplate;
    private final CodeGroupRepository codeGroupRepository;
    private final SecurityQualityGateway securityQualityGateway;
    ArrayList<String> severitiesHigh = new ArrayList<String>() {{
        add("Critical");
        add("High");
    }};

    CiOperationsService(CiOperationsRepository ciOperationsRepository, PermissionFactory permissionFactory,
                        ProjectRepository projectRepository, CodeAccessVerifier codeAccessVerifier,
                        CodeProjectRepository codeProjectRepository, VulnTemplate vulnTemplate,
                        OpenSourceScanService openSourceScanService, CodeScanService codeScanService,
                        CodeGroupRepository codeGroupRepository, SecurityQualityGateway securityQualityGateway){
        this.ciOperationsRepository = ciOperationsRepository;
        this.permissionFactory = permissionFactory;
        this.codeGroupRepository = codeGroupRepository;
        this.projectRepository = projectRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.openSourceScanService = openSourceScanService;
        this.codeScanService = codeScanService;
        this.codeAccessVerifier = codeAccessVerifier;
        this.vulnTemplate = vulnTemplate;
        this.securityQualityGateway = securityQualityGateway;
    }

    public ResponseEntity<List<OverAllVulnTrendChartData>> getVulnTrendData(Principal principal) {
        List<Project> projects = permissionFactory.getProjectForPrincipal(principal);
        return new ResponseEntity<>(ciOperationsRepository.getCiTrend(projects.stream().map(Project::getId).collect(Collectors.toList())), HttpStatus.OK);
    }

    public ResponseEntity<CiResultModel> getResultData(Principal principal) {
        CiResultModel ciResultModel = new CiResultModel();
        List<Project> projects = permissionFactory.getProjectForPrincipal(principal);
        ciResultModel.setNotOk(ciOperationsRepository.countByResultAndProjectIn("Not Ok", projects));
        ciResultModel.setOk(ciOperationsRepository.countByResultAndProjectIn("Ok", projects));
        return new ResponseEntity<>( ciResultModel, HttpStatus.OK);
    }

    public ResponseEntity<List<CiOperations>> getTableData(Principal principal) {
        return new ResponseEntity<>(ciOperationsRepository.findByProjectInOrderByInsertedDesc(permissionFactory.getProjectForPrincipal(principal)), HttpStatus.OK);
    }

    public ResponseEntity<Status> startPipeline(Long projectId, String groupName, String codeProjectName, String commitId, Principal principal) {
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            SASTRequestVerify verifyRequest = codeAccessVerifier.verifyPermissions(projectId, groupName, codeProjectName, true);
            if (verifyRequest.getValid()) {
                Optional<CiOperations> operation = ciOperationsRepository.findByCodeProjectAndCommitId(verifyRequest.getCp(),commitId);
                if (operation.isPresent()){
                    return new ResponseEntity<>(HttpStatus.OK);
                } else if (StringUtils.isNotBlank(verifyRequest.getCp().getCommitid())) {
                    CiOperations newOperation = new CiOperations();
                    newOperation.setProject(project.get());
                    newOperation.setCodeGroup(verifyRequest.getCg());
                    newOperation.setCodeProject(verifyRequest.getCp());
                    newOperation.setCommitId(commitId);
                    ciOperationsRepository.save(newOperation);
                    verifyRequest.getCp().setCommitid(commitId);
                    codeProjectRepository.save(verifyRequest.getCp());
                    log.info("Creating CI Operation for {} - {} with commitid {}", project.get().getName(), verifyRequest.getCp().getName(), LogUtil.prepare(commitId));
                    return new ResponseEntity<>(HttpStatus.CREATED);
                }
            }
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> codeScan(Long id, String groupName, String projectName, String commitId, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        return codeScanService.createScanForCodeProject(id,groupName,projectName);
    }

    public ResponseEntity<CIVulnManageResponse> codeVerify(String codeGroup, String codeProject, Long id, String commitid, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())) {
            SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyPermissions(id,codeGroup,codeProject,false);
            if (sastRequestVerify.getValid()){
                CodeProject codeProjectToVerify =sastRequestVerify.getCp();
                CIVulnManageResponse ciVulnManageResponse = new CIVulnManageResponse();
                if (StringUtils.isNotBlank(codeProjectToVerify.getdTrackUuid())){
                    openSourceScanService.loadVulnerabilities(codeProjectToVerify);
                }
                List<VulnManageResponse> vmr = createVulnManageResponseForCodeProject(codeProjectToVerify);
                ciVulnManageResponse.setVulnManageResponseList(vmr);
                if (vmr.size()>3){
                    ciVulnManageResponse.setResult("Not Ok");
                } else {
                    ciVulnManageResponse.setResult("Ok");
                }
                ciVulnManageResponse.setInQueue(codeProjectToVerify.getInQueue() != null ? codeProjectToVerify.getInQueue() : false);
                ciVulnManageResponse.setRunning(codeProjectToVerify.getRunning() != null ? codeProjectToVerify.getRunning() : false);
                ciVulnManageResponse.setCommitId(codeProjectToVerify.getCommitid());
                updateCiOperation(ciVulnManageResponse, codeProjectToVerify);
                return new ResponseEntity<>(ciVulnManageResponse,HttpStatus.OK);
            } else {
                return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
            }
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    private void updateCiOperation(CIVulnManageResponse ciVulnManageResponse, CodeProject codeProject) {
        Optional<CiOperations> operation = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject,codeProject.getCommitid());
        if (operation.isPresent()){
            if ( !codeProject.getRunning() && !codeProject.getInQueue()) {
                operation.get().setEnded(new Date());
                operation.get().setResult(ciVulnManageResponse.getResult());
                ciOperationsRepository.save(operation.get());
            }
        }
    }

    private List<VulnManageResponse> createVulnManageResponseForCodeProject(CodeProject cp){
        List<VulnManageResponse> vulnManageResponses = new ArrayList<>();
        List<ProjectVulnerability> codeVulns = null;
        try (Stream<ProjectVulnerability> vulnsForProject = vulnTemplate.projectVulnerabilityRepository
                .findByCodeProjectAndVulnerabilitySourceAndSeverityAndAnalysis(cp, vulnTemplate.SOURCE_SOURCECODE,
                        Constants.VULN_CRITICALITY_CRITICAL,
                        Constants.FORTIFY_ANALYSIS_EXPLOITABLE)) {
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
            vmr.setDateDiscovered(spv.getInserted());
            vulnManageResponses.add(vmr);
        }
        return vulnManageResponses;
    }

    public ResponseEntity<List<CiOperations>> getTableDataForProject(Principal principal, Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            return new ResponseEntity<>(ciOperationsRepository.findTop20ByProjectOrderByIdDesc(project.get()), HttpStatus.OK);
        } else
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    /**
     * Get Request and based on repoURL, check of CodeProject with given name exists. If not it create system and CodeProject
     * and then it create project on DTrack
     * only DTrack
     * @param getInfoRequest request with url
     * @param principal
     * @return info about scanners
     */
    public ResponseEntity<PrepareCIOperation> getInfoForCI(GetInfoRequest getInfoRequest, Principal principal) throws Exception {
        switch (getInfoRequest.getScope()){
            case Constants.CI_SCOPE_OPENSOURCE:
                CodeProject codeProject = openSourceScanService.getCodeProjectByRepoUrl(getInfoRequest.getRepoUrl(), getInfoRequest.getBranch(),principal);
                if (StringUtils.isBlank(codeProject.getdTrackUuid())){
                    openSourceScanService.createProjectOnOpenSourceScanner(codeProject);
                }
                OpenSourceConfig openSourceConfig = openSourceScanService
                        .getOpenSourceScannerConfiguration(
                                codeProject.getCodeGroup().getProject().getId(),
                                codeProject.getName(),
                                codeProject.getName(),
                                principal)
                        .getBody();
                // FOR NOW owasp dtrack hardcoded
                return new ResponseEntity<>(new PrepareCIOperation(openSourceConfig, codeProject,"OWASP Dependency Track"), HttpStatus.OK);
        }
        return null;
    }

    public ResponseEntity<Status> infoScanPerformed(InfoScanPerformed infoScanPerformed, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(infoScanPerformed.getCodeProjectId());
        if (codeProject.isPresent() && infoScanPerformed.getScope().equals(Constants.CI_SCOPE_OPENSOURCE)){
            Optional<CiOperations> ciOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject.get(), infoScanPerformed.getCommitId());
            if (!ciOperations.isPresent()){
                ciOperationsRepository.save(new CiOperations(codeProject.get(), infoScanPerformed));
            }
            codeProject.get().setCommitid(infoScanPerformed.getCommitId());
            codeProjectRepository.save(codeProject.get());
            openSourceScanService.loadVulnerabilities(codeProject.get());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @Transactional
    public ResponseEntity<Status> loadVulnerabilitiesFromCICDToProject(List<VulnerabilityModel> vulns, Long projectId,
                                                                       String codeProjectName, String branch,
                                                                       String commitId, Principal principal) {
        Optional<Project> project;
        if (projectId == null){
            Optional<List<Project>> projectList = projectRepository.findByNameAndOwner("CICD Project", permissionFactory.getUserFromPrincipal(principal));
            if (projectList.isPresent() && projectList.get().size()==1){
                project = Optional.of(projectList.get().get(0));
            } else {
                Project newProject = new Project();
                newProject.setOwner(permissionFactory.getUserFromPrincipal(principal));
                newProject.setName("CICD Project");
                newProject.setCiid("0");
                newProject.setEnableVulnManage(false);
                newProject.setDescription("Project created by CICD pipeline");
                project = Optional.of(projectRepository.save(newProject));
            }
        }else {
            project = projectRepository.findById(projectId);
        }
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<CodeProject> codeProject = codeProjectRepository.getCodeProjectByProjectNameAndBranch(project.get().getId(), codeProjectName, branch);
            CodeProject codeProjectToLoad;
            if (codeProject.isPresent()){
                log.info("[CICD] Get results for {}, proceeding with load", codeProject.get().getName());
                codeProjectToLoad = codeProject.get();
                codeProjectToLoad.setCommitid(commitId);

            } else {
                log.info("[CICD] Get results for unknown codeproject, creating new with name {}", codeProjectName);
                Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName(project.get(), codeProjectName);
                if (codeGroup.isPresent()){
                    codeProjectToLoad = codeProjectRepository.save(new CodeProject(codeProjectName,branch,codeGroup.get(),commitId));
                } else {
                    CodeGroup newCodeGroup = codeGroupRepository.save(new CodeGroup(project.get(), codeProjectName));
                    codeProjectToLoad = codeProjectRepository.save(new CodeProject(codeProjectName,branch,newCodeGroup,commitId));
                }
            }
            List<VulnerabilityModel> sastVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.SAST)).collect(Collectors.toList());
            if (sastVulns.size() > 0 ){
                codeScanService.loadVulnsFromCICDToCodeProject(codeProjectToLoad, sastVulns);
            } else {
                codeScanService.loadVulnsFromCICDToCodeProject(codeProjectToLoad, new ArrayList<>());

            }
            List<VulnerabilityModel> openSourceVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.OPENSOURCE)).collect(Collectors.toList());
            if (openSourceVulns.size() > 0) {
                openSourceScanService.loadVulnsFromCICDToCodeProject(codeProjectToLoad, openSourceVulns);
            } else {
                openSourceScanService.loadVulnsFromCICDToCodeProject(codeProjectToLoad, new ArrayList<>());
            }
            return new ResponseEntity<>(new Status(createCIOperationsForCICDRequest(codeProjectToLoad).getResult()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

    public ResponseEntity<Status> loadVulnerabilitiesForAnonymousProject(List<VulnerabilityModel> vulns, String codeProjectName, Principal principal) {
        Optional<List<Project>> findUnknownProject = projectRepository.findByNameAndOwner(Constants.PROJECT_UNKNOWN, permissionFactory.getUserFromPrincipal(principal));
        Project unknownProject = null;
        // Get unknown project
        if (findUnknownProject.isPresent() && findUnknownProject.get().size() == 1){
            unknownProject = findUnknownProject.get().get(0);
        } else if (!findUnknownProject.isPresent() || (findUnknownProject.get().isEmpty())) {
            unknownProject = projectRepository.saveAndFlush(new Project(Constants.PROJECT_UNKNOWN,
                    "unknown project created for anynomous CICD",
                    false,
                    "none",
                    permissionFactory.getUserFromPrincipal(principal)));
            permissionFactory.grantPermissionToProjectForUser(unknownProject, principal);
        }
        // Get CodeProject to load vulns to
        if (unknownProject != null){
            Optional<CodeProject> codeProjectToCheck = codeProjectRepository.getCodeProjectByProjectName(unknownProject.getId(),codeProjectName);
            CodeProject codeProject = null;
            if (codeProjectToCheck.isPresent()){
                codeProject = codeProjectToCheck.get();
            } else {
                CodeGroup codeGroup = codeGroupRepository.save(new CodeGroup(unknownProject,codeProjectName));
                codeProject = codeProjectRepository.save(new CodeProject(codeProjectName,"unknown", codeGroup, "unknown"));
            }
            List<VulnerabilityModel> sastVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.SAST)).collect(Collectors.toList());
            if (sastVulns.size() > 0 ){
                codeScanService.loadVulnsFromCICDToCodeProject(codeProject, sastVulns);
            }
            List<VulnerabilityModel> openSourceVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.OPENSOURCE)).collect(Collectors.toList());
            if (openSourceVulns.size() > 0){
                openSourceScanService.loadVulnsFromCICDToCodeProject(codeProject, openSourceVulns);
            }
            return new ResponseEntity<>(new Status(createCIOperationsForCICDRequest(codeProject).getResult()),HttpStatus.OK);
        }else {
            return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
        }
    }

    /**
     * Create CICD Operations based on CICD response
     */
    private CiOperations createCIOperationsForCICDRequest(CodeProject codeProject){
        SecurityGatewayEntry securityGatewayEntry = securityQualityGateway.buildGatewayResponse(vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject));
        Optional<CiOperations> optionalCiOperations = ciOperationsRepository.findByCodeProjectAndCommitId(codeProject, codeProject.getCommitid());
        CiOperations ciOperations = null;
        ciOperations = optionalCiOperations.orElseGet(CiOperations::new);
        ciOperations.setResult(securityGatewayEntry.isPassed() ? "Ok" : "Not Ok");
        ciOperations.setCodeGroup(codeProject.getCodeGroup());
        ciOperations.setCodeProject(codeProject);
        ciOperations.setInserted(new Date());
        ciOperations.setEnded(new Date());
        ciOperations.setOpenSourceScan(true);
        ciOperations.setSastScan(true);
        ciOperations.setProject(codeProject.getCodeGroup().getProject());
        ciOperations.setCommitId(codeProject.getCommitid()!=null? codeProject.getCommitid() : "unknown");
        ciOperations.setSastHigh(securityGatewayEntry.getSastHigh());
        ciOperations.setSastCrit(securityGatewayEntry.getSastCritical());
        ciOperations.setOpenSourceCrit(securityGatewayEntry.getOsCritical());
        ciOperations.setOpenSourceHigh(securityGatewayEntry.getOsHigh());
        return ciOperationsRepository.save(ciOperations);

    }
}
