package io.mixeway.plugins.codescan.service;

import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.plugins.codescan.model.CodeScanRequestModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeVuln;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.db.repository.CodeVulnRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.plugins.utils.CodeAccessVerifier;
import io.mixeway.pojo.Status;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;

@SuppressWarnings("OptionalGetWithoutIsPresent")
@Service
public class CodeScanService {
    private static final Logger log = LoggerFactory.getLogger(CodeScanService.class);
    private final ProjectRepository projectRepository;
    private final CodeGroupRepository codeGroupRepository;
    private final CodeProjectRepository codeProjectRepository;
    private final CodeVulnRepository codeVulnRepository;
    private final CodeAccessVerifier codeAccessVerifier;
    private final VaultOperations operations;
    private final List<CodeScanClient> codeScanClients;

    @Autowired
    CodeScanService(ProjectRepository projectRepository, CodeGroupRepository codeGroupRepository, CodeProjectRepository codeProjectRepository,
                    CodeVulnRepository codeVulnRepository, CodeAccessVerifier codeAccessVerifier, VaultOperations operations,
                    List<CodeScanClient> codeScanClients){
        this.projectRepository = projectRepository;
        this.codeGroupRepository = codeGroupRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.codeVulnRepository = codeVulnRepository;
        this.codeAccessVerifier = codeAccessVerifier;
        this.operations = operations;
        this.codeScanClients = codeScanClients;
    }

    //PREPARE SCAN

    public ResponseEntity<List<CodeVuln>> getResultsForProject(long projectId, String groupName, String projectName){

        if (codeAccessVerifier.verifyPermissions(projectId,groupName,projectName).getValid()){
            CodeProject cp = codeProjectRepository.findByCodeGroupAndName(codeGroupRepository
                    .findByProjectAndName(projectRepository.findById(projectId).get(),groupName).get(),projectName).get();
            List<CodeVuln> codeVulns = codeVulnRepository.findByCodeProjectAndAnalysisNot(cp,"Not an Issue");
            new ResponseEntity<>(codeVulns, HttpStatus.OK);

        } else
            new ResponseEntity<List<CodeVuln>>(new ArrayList<>(), HttpStatus.PRECONDITION_FAILED);


        return null;
    }
    public ResponseEntity<List<CodeVuln>> getResultsForGroup(long projectId, String groupName){

        if (codeAccessVerifier.verifyPermissions(projectId,groupName,null).getValid()){
            CodeGroup cg = codeGroupRepository
                    .findByProjectAndName(projectRepository.findById(projectId).get(),groupName).get();
            List<CodeVuln> codeVulns = codeVulnRepository.findByCodeGroupAndAnalysisNot(cg,"Not an Issue");
            new ResponseEntity<>(codeVulns, HttpStatus.OK);

        } else
            new ResponseEntity<List<CodeVuln>>(new ArrayList<>(), HttpStatus.PRECONDITION_FAILED);


        return null;
    }

    public ResponseEntity<Status> performScanFromScanManager(CodeScanRequestModel codeScanRequest) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        if (codeScanRequest.getCiid() != null && !codeScanRequest.getCiid().equals("")){
            Optional<List<Project>> projects = projectRepository.findByCiid(codeScanRequest.getCiid());
            Project project;
            if (projects.isPresent()){
                project = projects.get().stream().findFirst().get();
            } else {
                project = new Project();
                project.setName(codeScanRequest.getProjectName());
                project.setCiid(codeScanRequest.getCiid());
                project = projectRepository.save(project);
            }

            String requestId = verifyAndCreateOrUpdateCodeProjectInformations(codeScanRequest,project);
            return new ResponseEntity<>(new Status("Scan requested",requestId), HttpStatus.CREATED);

        } else {
            return new ResponseEntity<>(new Status("Missing information about project."), HttpStatus.BAD_REQUEST);
        }
    }

    private String verifyAndCreateOrUpdateCodeProjectInformations(CodeScanRequestModel codeScanRequest, Project project) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        String requestId;
        Optional<CodeGroup> codeGroup = codeGroupRepository.findByProjectAndName(project,codeScanRequest.getCodeGroupName());
        if (codeGroup.isPresent()){
            Optional<CodeProject> codeProject = codeProjectRepository.findByCodeGroupAndName(codeGroup.get(),codeScanRequest.getCodeProjectName());
            if (codeProject.isPresent()){
                CodeGroup updatedCodeGroup = updateCodeGroup(codeScanRequest,codeGroup.get());
                CodeProject updatedCodeProject = updateCodeProject(codeScanRequest,project,codeProject.get());
                for(CodeScanClient codeScanClient : codeScanClients){
                    if (codeScanClient.canProcessRequest(updatedCodeGroup)){
                        codeScanClient.runScan(updatedCodeGroup,updatedCodeProject);
                    }
                }
                requestId = codeProjectRepository.findById(updatedCodeProject.getId()).get().getRequestId();
            } else {
                CodeGroup updatedCodeGroup = updateCodeGroup(codeScanRequest,codeGroup.get());
                CodeProject newCodeProject = createNewCodeProject(codeScanRequest,project,updatedCodeGroup);
                for(CodeScanClient codeScanClient : codeScanClients){
                    if (codeScanClient.canProcessRequest(updatedCodeGroup)){
                        codeScanClient.runScan(updatedCodeGroup,newCodeProject);
                    }
                }
                requestId = codeProjectRepository.findById(newCodeProject.getId()).get().getRequestId();
            }
        } else {
            CodeGroup newCodeGroup = createNewCodeGroup(codeScanRequest,project);
            CodeProject newCodeProject = createNewCodeProject(codeScanRequest,project,newCodeGroup);
            for(CodeScanClient codeScanClient : codeScanClients){
                if (codeScanClient.canProcessRequest(newCodeGroup)){
                    codeScanClient.runScan(newCodeGroup,newCodeProject);
                }
            }
            requestId = codeProjectRepository.findById(newCodeProject.getId()).get().getRequestId();
        }
        return requestId;
    }

    private CodeProject createNewCodeProject(CodeScanRequestModel codeScanRequest, Project project, CodeGroup newCodeGroup) {
        CodeProject codeProject = new CodeProject();
        codeProject.setName(codeScanRequest.getCodeProjectName());
        codeProject.setCodeGroup(newCodeGroup);
        codeProject.setTechnique(codeScanRequest.getTech());
        codeProject.setBranch(codeScanRequest.getBranch());
        codeProject.setRepoUrl(codeScanRequest.getRepoUrl());
        codeProject = codeProjectRepository.save(codeProject);
        log.info("{} - Created new CodeProject [{}] {}", "ScanManager", project.getName(), codeProject.getName());
        return codeProject;
    }
    private CodeProject updateCodeProject(CodeScanRequestModel codeScanRequest, Project project, CodeProject codeProject) {
        codeProject.setTechnique(codeScanRequest.getTech());
        codeProject.setBranch(codeScanRequest.getBranch());
        codeProject.setRepoUrl(codeScanRequest.getRepoUrl());
        codeProject = codeProjectRepository.save(codeProject);
        log.info("{} - Updated CodeProject [{}] {}", "ScanManager", project.getName(), codeProject.getName());
        return codeProject;
    }

    private CodeGroup createNewCodeGroup(CodeScanRequestModel codeScanRequest, Project project){
        CodeGroup newCodeGroup = new CodeGroup();
        newCodeGroup.setProject(project);
        newCodeGroup.setName(codeScanRequest.getCodeGroupName());
        newCodeGroup.setHasProjects(false);
        newCodeGroup.setAuto(false);
        newCodeGroup = updateCodeGroup(codeScanRequest, newCodeGroup);
        log.info("{} - Created new CodeGroup [{}] {}", "ScanManager", project.getName(), newCodeGroup.getName());
        return newCodeGroup;
    }

    @NotNull
    private CodeGroup updateCodeGroup(CodeScanRequestModel codeScanRequest, CodeGroup newCodeGroup) {
        newCodeGroup.setTechnique(codeScanRequest.getTech());
        newCodeGroup.setRepoUrl(codeScanRequest.getRepoUrl());
        newCodeGroup.setRepoPassword(UUID.randomUUID().toString());
        newCodeGroup.setVersionIdAll(codeScanRequest.getFortifySSCVersionId());
        newCodeGroup = codeGroupRepository.save(newCodeGroup);
        Map<String, String> mapa = new HashMap<>();
        mapa.put("password", codeScanRequest.getRepoPassword());
        operations.write("secret/"+newCodeGroup.getRepoPassword(), mapa);
        return newCodeGroup;
    }
}
