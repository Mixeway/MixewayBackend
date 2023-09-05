package io.mixeway.api.cioperations.service;

import io.mixeway.api.cioperations.model.*;
import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.api.protocol.cioperations.GetInfoRequest;
import io.mixeway.api.protocol.cioperations.InfoScanPerformed;
import io.mixeway.api.protocol.cioperations.PrepareCIOperation;
import io.mixeway.api.protocol.securitygateway.SecurityGatewayResponse;
import io.mixeway.api.protocol.vulnerability.Vuln;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.domain.service.cioperations.CreateCiOperationsService;
import io.mixeway.domain.service.cioperations.FindCiOperationsService;
import io.mixeway.domain.service.cioperations.UpdateCiOperationsService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.GetOrCreateWebAppService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.CodeAccessVerifier;
import io.mixeway.scanmanager.model.SASTRequestVerify;
import io.mixeway.scanmanager.model.WebAppScanModel;
import io.mixeway.scanmanager.service.code.CodeScanService;
import io.mixeway.scanmanager.service.opensource.OpenSourceScanService;
import io.mixeway.scanmanager.service.webapp.WebAppScanService;
import io.mixeway.utils.*;
import io.mixeway.utils.ScannerType;
import io.mixeway.utils.Status;
import io.mixeway.utils.VulnerabilityModel;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Log4j2
@RequiredArgsConstructor
//@Transactional
public class CiOperationsService {
    private final PermissionFactory permissionFactory;
    private final ProjectRepository projectRepository;
    private final CodeAccessVerifier codeAccessVerifier;
    private final CodeProjectRepository codeProjectRepository;
    private final OpenSourceScanService openSourceScanService;
    private final CodeScanService codeScanService;
    private final VulnTemplate vulnTemplate;
    private final SecurityQualityGateway securityQualityGateway;
    private final FindCiOperationsService findCiOperationsService;
    private final CreateCiOperationsService createCiOperationsService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final UpdateCiOperationsService updateCiOperationsService;
    private final FindCodeProjectService findCodeProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final FindProjectService findProjectService;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final CreateOrGetVulnerabilityService CreateOrGetVulnerabilityService;
    private final WebAppScanService WebAppScanService;
    ArrayList<String> severitiesHigh = new ArrayList<String>() {{
        add("Critical");
        add("High");
    }};


    public ResponseEntity<List<OverAllVulnTrendChartData>> getVulnTrendData(Principal principal) {
        List<Project> projects = permissionFactory.getProjectForPrincipal(principal);
        return new ResponseEntity<>(findCiOperationsService.getVulnTrendData(projects), HttpStatus.OK);
    }

    public ResponseEntity<CiResultModel> getResultData(Principal principal) {
        CiResultModel ciResultModel = new CiResultModel();
        List<Project> projects = permissionFactory.getProjectForPrincipal(principal);
        ciResultModel.setNotOk(findCiOperationsService.countByResultAndProject(Constants.NOT_OK, projects));
        ciResultModel.setOk(findCiOperationsService.countByResultAndProject(Constants.OK, projects));
        return new ResponseEntity<>( ciResultModel, HttpStatus.OK);
    }

    public ResponseEntity<List<CiOperations>> getTableData(Principal principal) {
        return new ResponseEntity<>(findCiOperationsService.findByProjects(permissionFactory.getProjectForPrincipal(principal)), HttpStatus.OK);
    }

    public ResponseEntity<Status> startPipeline(Long projectId, String codeProjectName, String commitId, Principal principal) {
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            SASTRequestVerify verifyRequest = codeAccessVerifier.verifyIfCodeProjectInProject(projectId, codeProjectName);
            if (verifyRequest.getValid()) {
                Optional<CiOperations> operation = findCiOperationsService.findByCodeProjectAndCommitId(verifyRequest.getCp(), commitId);
                if (operation.isPresent()){
                    return new ResponseEntity<>(HttpStatus.OK);
                } else if (StringUtils.isNotBlank(verifyRequest.getCp().getCommitid())) {
                    createCiOperationsService.create(verifyRequest,project.get(), commitId);
                    updateCodeProjectService.changeCommitId(commitId, verifyRequest.getCp());
                    log.info("Creating CI Operation for {} - {} with commitid {}", project.get().getName(), verifyRequest.getCp().getName(), LogUtil.prepare(commitId));
                    return new ResponseEntity<>(HttpStatus.CREATED);
                }
            }
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> codeScan(Long id, String groupName, String projectName, String commitId, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, ParseException, IOException, JSONException {
        return codeScanService.createScanForCodeProject(id,projectName);
    }

    @Transactional
    public ResponseEntity<CIVulnManageResponse> codeVerify(String codeGroup, String codeProject, Long id, String commitid, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())) {
            SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyIfCodeProjectInProject(id,codeProject);
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
                ciVulnManageResponse.setInQueue( codeProjectToVerify.getInQueue());
                ciVulnManageResponse.setRunning(codeProjectToVerify.getRunning());
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
        Optional<CiOperations> operation = findCiOperationsService.findByCodeProjectAndCommitId(codeProject, codeProject.getCommitid());
        if (operation.isPresent()){
            if ( !codeProject.getRunning() && !codeProject.getInQueue()) {
                updateCiOperationsService.updateCiOperations(operation.get(), ciVulnManageResponse);
            }
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
            vmr.setDateDiscovered(spv.getInserted());
            vulnManageResponses.add(vmr);
        }
        return vulnManageResponses;
    }

    public ResponseEntity<List<CiOperations>> getTableDataForProject(Principal principal, Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            return new ResponseEntity<>(findCiOperationsService.findTop20(project.get()), HttpStatus.OK);
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
        try {
            switch (getInfoRequest.getScope()) {
                case Constants.CI_SCOPE_OPENSOURCE:
                    CodeProject codeProject = createOrGetCodeProjectService.createOrGetCodeProject(getInfoRequest.getRepoUrl(), getInfoRequest.getBranch(), getInfoRequest.getRepoName(), principal);
                    if (StringUtils.isBlank(codeProject.getdTrackUuid())) {
                        openSourceScanService.createProjectOnOpenSourceScanner(codeProject);
                    }
                    OpenSourceConfig openSourceConfig = openSourceScanService
                            .getOpenSourceScannerConfiguration(
                                    codeProject.getProject().getId(),
                                    codeProject.getName(),
                                    codeProject.getName(),
                                    principal)
                            .getBody();
                    // FOR NOW owasp dtrack hardcoded
                    return new ResponseEntity<>(new PrepareCIOperation(openSourceConfig, codeProject, "OWASP Dependency Track"), HttpStatus.OK);
            }
        } catch (Exception e){
            log.error("[CICD] Exception occured during preparation of data for CICD - {}", e.getLocalizedMessage());
            e.printStackTrace();
        }
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    public ResponseEntity<Status> infoScanPerformed(InfoScanPerformed infoScanPerformed, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(infoScanPerformed.getCodeProjectId());
        if (codeProject.isPresent() && infoScanPerformed.getScope().equals(Constants.CI_SCOPE_OPENSOURCE)){
            Optional<CiOperations> ciOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject.get(), infoScanPerformed.getCommitId());
            if (!ciOperations.isPresent()){
                createCiOperationsService.create(codeProject.get(), infoScanPerformed);
            }
            updateCodeProjectService.changeCommitId(infoScanPerformed.getCommitId(), codeProject.get());
            openSourceScanService.loadVulnerabilities(codeProject.get());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @Transactional
    public ResponseEntity<Status> loadVulnerabilitiesFromCICDToProject(List<VulnerabilityModel> vulns, Long projectId,
                                                                       String codeProjectName, String branch,
                                                                       String commitId, Principal principal) throws Exception {
        Optional<Project> project = findProjectService.findProjectById(projectId);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            CodeProject codeProject = createOrGetCodeProjectService.getOrCreateCodeProject(project.get(),codeProjectName, branch);
            codeProject.setCommitid(commitId);

            // to support legacy application where client call SAST while it should be IAC
            List<VulnerabilityModel> sastVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.SAST)).collect(Collectors.toList());
            if (sastVulns.size() > 0 ){
                codeScanService.loadVulnsFromCICDToCodeProject(codeProject, sastVulns, ScannerType.IAC);
            } else {
                codeScanService.loadVulnsFromCICDToCodeProject(codeProject, new ArrayList<>(), ScannerType.IAC);
            }
            List<VulnerabilityModel> gitLeaksVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.GITLEAKS)).collect(Collectors.toList());
            if (gitLeaksVulns.size() > 0 ){
                codeScanService.loadVulnsFromCICDToCodeProject(codeProject, gitLeaksVulns, ScannerType.GITLEAKS);
            } else {
                codeScanService.loadVulnsFromCICDToCodeProject(codeProject, new ArrayList<>(), ScannerType.GITLEAKS);
            }
            List<VulnerabilityModel> openSourceVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.OPENSOURCE)).collect(Collectors.toList());
            if (openSourceVulns.size() > 0) {
                openSourceScanService.loadVulnsFromCICDToCodeProject(codeProject, openSourceVulns);
            } else {
                openSourceScanService.loadVulnsFromCICDToCodeProject(codeProject, new ArrayList<>());
            }

            return new ResponseEntity<>(new Status(createCIOperationsForCICDRequest(codeProject).getResult()), HttpStatus.OK);

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
                codeProject = createOrGetCodeProjectService.createCodeProject(unknownProject, codeProjectName, "");
            }
            List<VulnerabilityModel> sastVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.SAST)).collect(Collectors.toList());
            if (sastVulns.size() > 0 ){
                codeScanService.loadVulnsFromCICDToCodeProject(codeProject, sastVulns,ScannerType.SAST);
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
        Optional<CiOperations> optionalCiOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject, codeProject.getCommitid());
        return createCiOperationsService.create(securityGatewayEntry, codeProject, optionalCiOperations);
    }

    public ResponseEntity<PrepareCIOperation> getInfoForCIForProject(GetInfoRequest getInfoRequest, Principal principal, Long projectid) throws Exception {
        Optional<Project> project = projectRepository.findById(projectid);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            switch (getInfoRequest.getScope()) {
                case Constants.CI_SCOPE_OPENSOURCE:
                    CodeProject codeProject = createOrGetCodeProjectService.createOrGetCodeProject(getInfoRequest.getRepoUrl(), getInfoRequest.getBranch(), principal, project.get());
                    if (StringUtils.isBlank(codeProject.getdTrackUuid())) {
                        openSourceScanService.createProjectOnOpenSourceScanner(codeProject);
                    }
                    OpenSourceConfig openSourceConfig = openSourceScanService
                            .getOpenSourceScannerConfiguration(
                                    codeProject.getProject().getId(),
                                    codeProject.getName(),
                                    codeProject.getName(),
                                    principal)
                            .getBody();
                    // FOR NOW owasp dtrack hardcoded
                    return new ResponseEntity<>(new PrepareCIOperation(openSourceConfig, codeProject, "OWASP Dependency Track"), HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<Status> performSastScanForCodeProject(Long codeProjectId, Principal principal) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(codeProjectId);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
            codeScanService.putCodeProjectToQueue(codeProjectId,principal);
            if (StringUtils.isNotBlank(codeProject.get().getdTrackUuid())) {
                openSourceScanService.loadVulnerabilities(codeProject.get());
                log.info("[CICD] {} Loaded OpenSource Vulns for project - {}", principal.getName(), codeProject.get().getName());
            }
            log.info("[CICD] {} put SAST Project in queue - {}", principal.getName(), codeProject.get().getName());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            log.error("[CICD] {} tries to run SAST scan for id {} but project doesnt exist or user has no permision to do so.", principal.getName(), codeProjectId);
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<CIVulnManageResponse> verifyCodeProject(Long codeProjectId, Principal principal) {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(codeProjectId);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
            SecurityGatewayEntry securityGatewayEntry = securityQualityGateway.buildGatewayResponse(vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject.get()));
            return new ResponseEntity<CIVulnManageResponse>(CIVulnManageResponse
                    .builder()
                    .result(securityGatewayEntry.isPassed() ? Constants.OK : Constants.NOT_OK)
                    .running(codeProject.get().getRunning())
                    .inQueue(codeProject.get().getInQueue())
                    .build(), HttpStatus.OK);
        }
        else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Getting vulnerabilies related with particular code project
     * @param codeProjectId to load vulns
     * @param principal user requesting
     * @return returning list of vulnerbilities
     */
    // TODO Status & grade
    public ResponseEntity<SecurityGatewayResponse> getVulnerabilitiesForCodeProject(Long codeProjectId, Principal principal) throws IOException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException {
        Optional<CodeProject> codeProject = codeProjectRepository.findById(codeProjectId);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
            List<ProjectVulnerability> vulns = vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject.get());
            openSourceScanService.loadVulnerabilities(codeProject.get());
            List<Vuln> vulnList = new ArrayList<>();
            for (ProjectVulnerability pv : vulns){
                if (pv.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId())){
                    vulnList.add(new Vuln(pv,null,null,pv.getCodeProject(),Constants.API_SCANNER_OPENSOURCE));
                } else if (pv.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId())){
                    vulnList.add(new Vuln(pv,null,null,pv.getCodeProject(),Constants.API_SCANNER_CODE));
                } else if (pv.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_GITLEAKS.getId())){
                    vulnList.add(new Vuln(pv,null,null,pv.getCodeProject(),Constants.API_SCANNER_CODE));
                } else if (pv.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_IAC.getId())){
                    vulnList.add(new Vuln(pv,null,null,pv.getCodeProject(),Constants.API_SCANNER_CODE));
                }
            }

            SecurityGatewayEntry securityGatewayEntry = securityQualityGateway.buildGatewayResponse(vulns);
            updateCiOperationWithSecurityGatewayResponse(codeProject.get(), securityGatewayEntry);
            return new ResponseEntity<SecurityGatewayResponse>(
                    new SecurityGatewayResponse(securityGatewayEntry.isPassed(),
                            securityGatewayEntry.isPassed() ? Constants.SECURITY_GATEWAY_PASSED : Constants.SECURITY_GATEWAY_FAILED,
                            vulnList),
                    HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Updating CIOperations entry (for codeproject, branch and commitid) with scan performed, result and vulnerabilities number
     * @param codeProject to edit cioperations
     * @param securityGatewayEntry to check vulnerabilities number
     */
    private void updateCiOperationWithSecurityGatewayResponse(CodeProject codeProject, SecurityGatewayEntry securityGatewayEntry) {
        Optional<CiOperations> ciOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject, codeProject.getCommitid());
        if (ciOperations.isPresent()){
            updateCiOperationsService.updateCiOperations(ciOperations.get(), securityGatewayEntry,codeProject);
        }
    }
    /**
     * ZAP reports
     */

     @Transactional
     public ResponseEntity<Status> loadVulnZap(ZapReportModel loadVulnModel, String ciid, Principal principal) throws ParseException {
            log.info("ZAP DAST JSON report received for ciid {}", ciid);
            return WebAppScanService.prepareAndLoadZapVulns(loadVulnModel,ciid,principal);
     }

    }

