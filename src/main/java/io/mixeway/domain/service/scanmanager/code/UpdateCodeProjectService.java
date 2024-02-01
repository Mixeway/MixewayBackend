package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeProjectBranch;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import io.mixeway.utils.ProjectRiskAnalyzer;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class UpdateCodeProjectService {
    private final CodeProjectRepository codeProjectRepository;
    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final FindCodeProjectService findCodeProjectService;

    /**
     * Updates CodeProjcet base on configuration from CodeScanRequest
     * Fields to update:
     * 1. Branch
     * 2. Repo URL
     * 3. Technique
     *
     * @param codeScanRequest CodeScanRequest from REST API
     * @param codeProject CodeProject to update
     * @return created CodeProject
     */
    @Transactional
    public CodeProject updateCodeProject(CodeScanRequestModel codeScanRequest, CodeProject codeProject) {
        codeProjectRepository.updateCodeProjectBranch(codeProject.getId(), codeScanRequest.getBranch());
        codeProject.setTechnique(codeScanRequest.getTech());
        codeProject.setRepoUrl(codeScanRequest.getRepoUrl());
        log.info("{} - Updated CodeProject [{}] {}", "ScanManager", codeProject.getProject().getName(), codeProject.getName());
        return codeProjectRepository.saveAndFlush(codeProject);
    }

    /**
     *  Update Code project and put to scan queue
     */
    @Transactional
    public CodeProject updateCodeProjectAndPutToQueue(CodeScanRequestModel codeScanRequest, CodeProject codeProject) {
        codeProject.setTechnique(codeScanRequest.getTech());
        codeProject.setRepoUrl(codeScanRequest.getRepoUrl());
        codeProject.setInQueue(true);
        codeProject.setRequestId(UUID.randomUUID().toString());
        codeProject = codeProjectRepository.save(codeProject);
        log.info("{} - Updated CodeProject [{}] {}", "ScanManager", codeProject.getProject().getName(), codeProject.getName());
        return codeProjectRepository.saveAndFlush(codeProject);
    }

    /**
     * Putting Code Project to scan queue
     */
    public CodeProject putCodeProjectToQueue(CodeProject codeProject) {
        if (!codeProject.getInQueue() && !codeProject.getRunning()) {
            codeProject.setInQueue(true);
            codeProject.setRequestId(UUID.randomUUID().toString());
            codeProject = codeProjectRepository.save(codeProject);
        }
        return codeProject;
    }

    public void endScan(CodeProject codeProject) {
        codeProject.setRunning(false);
        codeProject.setJobId(null);
        codeProject.setRisk(projectRiskAnalyzer.getCodeProjectRisk(codeProject) + projectRiskAnalyzer.getCodeProjectOpenSourceRisk(codeProject));
        codeProjectRepository.save(codeProject);
    }
    public CodeProject removeFromQueue(CodeProject codeProject){
        codeProject.setInQueue(false);
        return codeProjectRepository.saveAndFlush(codeProject);
    }
    public void changeCommitId(String commitId, CodeProject codeProject){
        codeProject.setCommitid(commitId);
        codeProjectRepository.save(codeProject);
    }

    @Transactional
    public void setRisk() {
        for (CodeProject codeProject: codeProjectRepository.findAll()){
            codeProject.setRisk(Math.min(projectRiskAnalyzer.getCodeProjectRisk(codeProject) + projectRiskAnalyzer.getCodeProjectOpenSourceRisk(codeProject), 100));
            codeProjectRepository.save(codeProject);
        }
    }

    public void startScan(CodeProject codeProject) {
        codeProject.setRunning(true);
        codeProjectRepository.save(codeProject);
    }

    public CodeProject removeFromQueueAndStart(CodeProject codeProject) {
        codeProject.setInQueue(false);
        codeProject.setJobId(null);
        codeProject.setRunning(true);
        return codeProjectRepository.saveAndFlush(codeProject);
    }

    @Transactional
    public void changeProjectForCodeProject(Project source, Project destination){
        for( CodeProject cp : findCodeProjectService.findByProject(source)){
            cp.setProject(destination);
            codeProjectRepository.saveAndFlush(cp);
        }
    }

    public void updateOpenSourceSettings(CodeProject codeProject, String remoteId, String remoteName){
        codeProject.setdTrackUuid(remoteId);
        codeProject.setRemotename(remoteName);
        codeProjectRepository.save(codeProject);
    }

    @Transactional
    public void updateActiveBranch(CodeProject codeProject, CodeProjectBranch codeProjectBranch) {
        codeProject.setActiveBranch(codeProjectBranch.getName());
        codeProjectRepository.save(codeProject);
        log.info("[UpdateCodeProject] Updated project {} set branch to {}", codeProject.getName(), codeProjectBranch.getName());
    }
}
