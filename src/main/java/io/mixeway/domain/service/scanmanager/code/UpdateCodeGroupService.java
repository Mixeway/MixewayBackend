package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.repository.CodeGroupRepository;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotNull;
import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class UpdateCodeGroupService {
    private final CodeGroupRepository codeGroupRepository;
    private final VaultHelper vaultHelper;

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
}
