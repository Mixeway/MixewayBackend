package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeProjectBranch;
import io.mixeway.db.repository.CodeProjectBranchRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

@Service
@Log4j2
@RequiredArgsConstructor
public class GetOrCreateCodeProjectBranchService {
    private final CodeProjectBranchRepository codeProjectBranchRepository;
    private final CreateCodeProjectBranchService createCodeProjectBranchService;

    public CodeProjectBranch getOrCreateCodeProjectBranch(CodeProject codeProject, String branch){
        CodeProjectBranch codeProjectBranch = codeProjectBranchRepository.findCodeProjectBranchByCodeProjectAndName(codeProject,branch);
        if (codeProjectBranch == null){
            codeProjectBranch = createCodeProjectBranchService.createCodeProjectBranch(codeProject,branch);
        } else {
            return codeProjectBranch;
        }
        return codeProjectBranch;
    }
}
