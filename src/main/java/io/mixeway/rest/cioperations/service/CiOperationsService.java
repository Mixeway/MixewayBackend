package io.mixeway.rest.cioperations.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.codescan.service.CodeScanService;
import io.mixeway.integrations.opensourcescan.plugins.mvndependencycheck.model.SASTRequestVerify;
import io.mixeway.integrations.opensourcescan.service.OpenSourceScanService;
import io.mixeway.integrations.utils.CodeAccessVerifier;
import io.mixeway.pojo.*;
import io.mixeway.pojo.Status;
import io.mixeway.rest.cioperations.model.CiResultModel;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.repository.CiOperationsRepository;

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
    ArrayList<String> severitiesHigh = new ArrayList<String>() {{
        add("Critical");
        add("High");
    }};

    CiOperationsService(CiOperationsRepository ciOperationsRepository, PermissionFactory permissionFactory,
                        ProjectRepository projectRepository, CodeAccessVerifier codeAccessVerifier,
                        CodeProjectRepository codeProjectRepository, VulnTemplate vulnTemplate,
                        OpenSourceScanService openSourceScanService, CodeScanService codeScanService){
        this.ciOperationsRepository = ciOperationsRepository;
        this.permissionFactory = permissionFactory;
        this.projectRepository = projectRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.openSourceScanService = openSourceScanService;
        this.codeScanService = codeScanService;
        this.codeAccessVerifier = codeAccessVerifier;
        this.vulnTemplate = vulnTemplate;
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

    public ResponseEntity<Status> startPipeline(Long projectId, String groupName, String codeProjectName, String commitId) {
        Optional<Project> project = projectRepository.findById(projectId);
        if (project.isPresent()) {
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

    public ResponseEntity<Status> codeScan(Long id, String groupName, String projectName, String commitId) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        return codeScanService.createScanForCodeProject(id,groupName,projectName);
    }

    public ResponseEntity<CIVulnManageResponse> codeVerify(String codeGroup, String codeProject, Long id, String commitid) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()) {
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
}
