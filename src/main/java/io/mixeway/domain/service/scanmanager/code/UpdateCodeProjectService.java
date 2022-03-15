package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
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
        codeProject.setTechnique(codeScanRequest.getTech());
        codeProject.setBranch(codeScanRequest.getBranch());
        codeProject.setRepoUrl(codeScanRequest.getRepoUrl());
        log.info("{} - Updated CodeProject [{}] {}", "ScanManager", codeProject.getCodeGroup().getProject().getName(), codeProject.getName());
        return codeProject;
    }

    /**
     *  Update Code project and put to scan queue
     */
    @Transactional
    public CodeProject updateCodeProjectAndPutToQueue(CodeScanRequestModel codeScanRequest, CodeProject codeProject) {
        codeProject.setTechnique(codeScanRequest.getTech());
        codeProject.setBranch(codeScanRequest.getBranch());
        codeProject.setRepoUrl(codeScanRequest.getRepoUrl());
        codeProject.setInQueue(true);
        codeProject.setRequestId(UUID.randomUUID().toString());
        codeProject = codeProjectRepository.save(codeProject);
        log.info("{} - Updated CodeProject [{}] {}", "ScanManager", codeProject.getCodeGroup().getProject().getName(), codeProject.getName());
        return codeProject;
    }

    /**
     * Putting Code Project to scan queue
     */
    public CodeProject putCodeProjectToQueue(CodeProject codeProject) {
        codeProject.setInQueue(true);
        codeProject.setRequestId(UUID.randomUUID().toString());
        codeProject = codeProjectRepository.save(codeProject);
        return codeProject;
    }
}
