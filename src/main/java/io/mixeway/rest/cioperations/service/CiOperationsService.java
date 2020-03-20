package io.mixeway.rest.cioperations.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SoftwarePacketVulnerabilityRepository;
import io.mixeway.plugins.audit.dependencytrack.apiclient.DependencyTrackApiClient;
import io.mixeway.plugins.audit.mvndependencycheck.model.SASTRequestVerify;
import io.mixeway.plugins.codescan.service.CodeScanClient;
import io.mixeway.plugins.utils.CodeAccessVerifier;
import io.mixeway.pojo.*;
import io.mixeway.pojo.Status;
import io.mixeway.rest.cioperations.model.CiResultModel;
import io.mixeway.rest.model.OverAllVulnTrendChartData;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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

@Service
public class CiOperationsService {
    private static final Logger log = LoggerFactory.getLogger(CiOperationsService.class);
    private final CiOperationsRepository ciOperationsRepository;
    private final PermissionFactory permissionFactory;
    private final ProjectRepository projectRepository;
    private final CodeAccessVerifier codeAccessVerifier;
    private final CodeProjectRepository codeProjectRepository;
    private final List<CodeScanClient> codeScanClients;
    private final DependencyTrackApiClient dependencyTrackApiClient;
    private final SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;
    @Autowired
    CiOperationsService(CiOperationsRepository ciOperationsRepository, PermissionFactory permissionFactory,
                        ProjectRepository projectRepository, CodeAccessVerifier codeAccessVerifier,
                        CodeProjectRepository codeProjectRepository, List<CodeScanClient> codeScanClients,
                        DependencyTrackApiClient dependencyTrackApiClient, SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository){
        this.ciOperationsRepository = ciOperationsRepository;
        this.permissionFactory = permissionFactory;
        this.softwarePacketVulnerabilityRepository = softwarePacketVulnerabilityRepository;
        this.projectRepository = projectRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.dependencyTrackApiClient = dependencyTrackApiClient;
        this.codeAccessVerifier = codeAccessVerifier;
        this.codeScanClients = codeScanClients;
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

    public ResponseEntity<Status> startPipeline(long projectId, String groupName, String codeProjectName, String commitId) {
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
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()) {
            SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyPermissions(id,groupName,projectName,false);
            if (sastRequestVerify.getValid()){
                for(CodeScanClient codeScanClient : codeScanClients){
                    if (codeScanClient.canProcessRequest(sastRequestVerify.getCg())){
                        if (codeScanClient.runScan(sastRequestVerify.getCg(),sastRequestVerify.getCp())){
                            return new ResponseEntity<>(HttpStatus.CREATED);
                        } else {
                            return new ResponseEntity<>(HttpStatus.CREATED);
                        }
                    }
                }
            } else {
                return new ResponseEntity<Status>(new Status("Scan for given resource is not yet configured.",null), HttpStatus.PRECONDITION_FAILED);
            }
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<CIVulnManageResponse> codeVerify(String codeGroup, String codeProject, Long id, String commitid) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()) {
            SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyPermissions(id,codeGroup,codeProject,false);
            if (sastRequestVerify.getValid()){
                CodeProject codeProjectToVerify =sastRequestVerify.getCp();
                CIVulnManageResponse ciVulnManageResponse = new CIVulnManageResponse();
                if (StringUtils.isNotBlank(codeProjectToVerify.getdTrackUuid())){
                    dependencyTrackApiClient.loadVulnerabilities(codeProjectToVerify);
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
        List<WebAppVuln> vulnsForCP = cp.getWebAppVulns().stream()
                .filter(wav -> wav.getSeverity().equals(Constants.API_SEVERITY_HIGH))
                .collect(Collectors.toList());
        List<CodeVuln> codeVulnsForCP = cp.getVulns().stream()
                .filter (cv -> cv.getSeverity().equals(Constants.API_SEVERITY_CRITICAL))
                .filter (cv -> cv.getAnalysis().equals(Constants.FORTIFY_ANALYSIS_EXPLOITABLE))
                .collect(Collectors.toList());
        List<SoftwarePacketVulnerability> softVulnForCP = softwarePacketVulnerabilityRepository.getSoftwareVulnsForCodeProject(cp.getId())
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

    public ResponseEntity<List<CiOperations>> getTableDataForProject(Principal principal, Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal,project.get())){
            return new ResponseEntity<>(ciOperationsRepository.findTop20ByProjectOrderByIdDesc(project.get()), HttpStatus.OK);
        } else
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
}
