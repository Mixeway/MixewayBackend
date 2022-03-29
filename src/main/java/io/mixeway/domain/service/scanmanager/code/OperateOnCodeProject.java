package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.api.project.model.EditCodeProjectModel;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class OperateOnCodeProject {
    private final CodeProjectRepository codeProjectRepository;
    private final VaultHelper vaultHelper;

    /**
     * Method which verify if CodeProject scan can be started
     * @param cp CodeProject to be verified
     * @return true if scan can be run, false if not
     */
    public boolean canScanCodeProject(CodeProject cp) {
        return !cp.getRunning();
    }


    public void deleteCodeProject(CodeProject codeProject) {
        codeProjectRepository.delete(codeProject);
    }

    public void setDtrackUUID(CodeProject codeProject, EditCodeProjectModel editCodeProjectModel) {
        UUID uuid = UUID.fromString(editCodeProjectModel.getDTrackUuid());
        codeProject.setdTrackUuid(editCodeProjectModel.getDTrackUuid());
        codeProjectRepository.save(codeProject);
    }

    public void setVersionId(CodeProject codeProject, EditCodeProjectModel editCodeProjectModel) {
        codeProject.setVersionIdsingle(editCodeProjectModel.getSastProject());
        codeProject.setVersionIdAll(editCodeProjectModel.getSastProject());
        codeProjectRepository.save(codeProject);
    }

    public void setBranch(CodeProject codeProject, String branch) {
        codeProject.setBranch(branch);
        codeProjectRepository.save(codeProject);
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
