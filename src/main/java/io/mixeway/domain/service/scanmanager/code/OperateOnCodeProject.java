package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.api.project.model.EditCodeProjectModel;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class OperateOnCodeProject {
    private final CodeProjectRepository codeProjectRepository;
    private final VaultHelper vaultHelper;
    private final VulnTemplate vulnTemplate;

    /**
     * Method which verify if CodeProject scan can be started
     * @param cp CodeProject to be verified
     * @return true if scan can be run, false if not
     */
    public boolean canScanCodeProject(CodeProject cp) {
        return !cp.getRunning();
    }


    public void deleteCodeProject(CodeProject codeProject) {
        List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject);
        vulnTemplate.projectVulnerabilityRepository.deleteAll(projectVulnerabilities);
        codeProject.setProject(null);
        codeProject = codeProjectRepository.save(codeProject);
        codeProjectRepository.delete(codeProject);
    }

    public void setSCA(CodeProject codeProject, EditCodeProjectModel editCodeProjectModel) {
        codeProject.setdTrackUuid(editCodeProjectModel.getRemoteId());
        if(StringUtils.isNotBlank(editCodeProjectModel.getRemoteName())){
            codeProject.setRemotename(editCodeProjectModel.getRemoteName());
        }
        codeProjectRepository.save(codeProject);
    }

    public void setVersionId(CodeProject codeProject, EditCodeProjectModel editCodeProjectModel) {
        codeProject.setVersionIdsingle(editCodeProjectModel.getSastProject());
        codeProject.setVersionIdAll(editCodeProjectModel.getSastProject());
        codeProjectRepository.save(codeProject);
    }

    @Modifying
    @Transactional
    public void setBranch(CodeProject codeProject, String branch) {
        codeProjectRepository.updateCodeProjectBranch(codeProject.getId(), branch);
    }

    public void setRepoUsername(CodeProject codeProject, EditCodeProjectModel editCodeProjectModel) {
        codeProject.setRepoUsername(editCodeProjectModel.getRepoUsername());
        codeProjectRepository.save(codeProject);
    }

    public void setRepoUrl(CodeProject codeProject, EditCodeProjectModel editCodeProjectModel) {
        codeProject.setRepoUrl(editCodeProjectModel.getRepoUrl());
        codeProjectRepository.save(codeProject);
    }

    public void setRepoPassword(CodeProject codeProject, EditCodeProjectModel editCodeProjectModel) {
        String uuidToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(editCodeProjectModel.getRepoPassword(), uuidToken)) {
            codeProject.setRepoPassword(uuidToken);
        } else {
            codeProject.setRepoPassword(editCodeProjectModel.getRepoPassword());
        }
    }
}
