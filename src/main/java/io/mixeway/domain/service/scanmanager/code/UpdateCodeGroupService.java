package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.domain.service.projectvulnerability.UpdateProjectVulnerabilityService;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotNull;
import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class UpdateCodeGroupService {
    private final CodeGroupRepository codeGroupRepository;
    private final VaultHelper vaultHelper;
    private final UpdateProjectVulnerabilityService updateProjectVulnerabilityService;

    /**
     * Method which update CodeGroup with values from CodeScanRequest
     * Update fields:
     * 1. Technique
     * 2. RepoURL
     * 3. versionIdAll
     *
     * @param codeScanRequest CodeScanRequest from REST API
     * @param codeGroup updated CodeGroup
     * @return CodeGroup which was updated
     */
    @NotNull
    public CodeGroup updateCodeGroup(CodeScanRequestModel codeScanRequest, CodeGroup codeGroup) {
        codeGroup.setTechnique(codeScanRequest.getTech());
        codeGroup.setRepoUrl(codeScanRequest.getRepoUrl());
        codeGroup.setVersionIdAll(codeScanRequest.getFortifySSCVersionId());
        String uuidToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(codeScanRequest.getRepoPassword(), uuidToken)){
            codeGroup.setRepoPassword(uuidToken);
        } else {
            codeGroup.setRepoPassword(codeScanRequest.getRepoPassword());
        }
        codeGroup = codeGroupRepository.save(codeGroup);
        return codeGroup;
    }

    public void endScan(CodeGroup codeGroup) {
        codeGroup.setRunning(false);
        codeGroup.setRequestid(null);
        codeGroup.setScanid(null);
        codeGroup.setScope(null);
        codeGroup.setScanid(null);
        codeGroupRepository.save(codeGroup);
    }
    public void transferCodeGroup(CodeGroup codeGroup, Project project) {
        Project oldProject = codeGroup.getProject();
        log.info("Transfering CodeGroup {}, from Project {} to {}", codeGroup.getName(), oldProject.getName(), project.getName());
        codeGroup.setProject(project);
        codeGroupRepository.save(codeGroup);
        for (CodeProject codeProject : codeGroup.getProjects()){
            updateProjectVulnerabilityService.transferCodeGroup(codeProject,project,oldProject);
        }
    }
}
